//! How the SDK reaches the server: the built-in transport (Tor SOCKS proxy,
//! or direct to a server on this machine) or a wallet's own transport
//! ([`PerseverusTransport`]).
//!
//! Every request belongs to a **circuit**, named by a tag:
//!
//! | tag            | used for                                           | lifetime              |
//! |----------------|----------------------------------------------------|-----------------------|
//! | `query-…`      | `/v1/meta`, filter downloads, the codebook         | one per `Perseverus`  |
//! | `purchase-…`   | `buy_tokens` and that purchase's `purchase_status` | one per purchase      |
//! | `issuance-…`   | `redeem`                                           | one per redeem        |
//! | `board-…`      | each card pack's board publish                     | one per publish       |
//! | `spend-…`      | the token spends of one `analyze_inputs`           | one per analysis      |
//!
//! Requests with different tags must leave Tor through different circuits;
//! otherwise the server could see one exit address both downloading filters
//! and spending a token (or paying by card) and link the two.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use perseverus_client_native::net::{new_circuit_tag, ExternalRequest, ExternalResponse, ExternalTransport, Http};
use perseverus_client_native::transport;

use crate::PerseverusError;

/// One HTTP header.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A request the SDK wants sent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransportRequest {
    /// `"GET"` or `"POST"`.
    pub method: String,
    /// Full URL, e.g. `https://api.btcmedusa.com/v1/meta`.
    pub url: String,
    pub headers: Vec<Header>,
    /// Request body (JSON for POSTs; empty for GETs).
    pub body: Vec<u8>,
    /// Requests with different `circuit` values MUST go over different Tor
    /// circuits. Requests with the same value may share one. Looks like
    /// `"spend-3f9ac1d2e4b07788"`.
    pub circuit: String,
    /// Give up after this many milliseconds (0 = your default).
    pub timeout_ms: u64,
}

/// The server's answer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransportResponse {
    /// HTTP status. Return the response for every status, including 4xx and
    /// 5xx: the SDK reads the server's error message from the body.
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// Throw this when no response arrived (Tor not ready, circuit failed,
/// timeout). The SDK surfaces it as `PerseverusException.Network`.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum TransportError {
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TransportError::Failed { reason: format!("transport threw an unexpected exception: {}", e.reason) }
    }
}

/// A wallet-provided way to send the SDK's HTTP requests, e.g. over the
/// wallet's own Tor client. Implement it in Kotlin or Swift and pass it as
/// `Transport.Custom`.
///
/// Rules:
///   * Route every request through Tor. Never fall back to a direct
///     connection: that would show the server the user's IP address.
///   * Requests with different `circuit` tags must use different Tor
///     circuits (different exit relays). Requests with the same tag may
///     share one.
///   * Return the response for any HTTP status; throw `TransportError` only
///     when there is no response.
///
/// `send` is called on the thread that called the SDK method (the SDK is
/// blocking), so it may block: in Kotlin, `runBlocking { … }` inside `send`
/// is fine. The SDK may call it from several threads at once.
#[uniffi::export(with_foreign)]
pub trait PerseverusTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError>;
}

/// Adapts a [`PerseverusTransport`] to the clients' [`ExternalTransport`].
struct Adapter(Arc<dyn PerseverusTransport>);

impl ExternalTransport for Adapter {
    fn send(&self, r: ExternalRequest) -> Result<ExternalResponse, String> {
        let req = TransportRequest {
            method: r.method,
            url: r.url,
            headers: r.headers.into_iter().map(|(name, value)| Header { name, value }).collect(),
            body: r.body,
            circuit: r.circuit,
            timeout_ms: r.timeout_ms,
        };
        match self.0.send(req) {
            Ok(resp) => Ok(ExternalResponse {
                status: resp.status,
                headers: resp.headers.into_iter().map(|h| (h.name, h.value)).collect(),
                body: resp.body,
            }),
            Err(TransportError::Failed { reason }) => Err(reason),
        }
    }
}

/// Which circuit a request goes over.
pub(crate) enum Circuit<'a> {
    /// The shared query circuit (meta, filters, codebook).
    Query,
    /// A fresh circuit just for this activity ("issuance", "spend", …).
    Fresh(&'static str),
    /// A named circuit (e.g. one purchase), stable across calls.
    Named(&'a str),
}

enum Kind {
    Builtin,
    Custom(Arc<dyn ExternalTransport>),
}

/// The SDK's way to the server.
pub(crate) struct Net {
    base_url: String,
    kind: Kind,
    query_tag: String,
    /// Circuit tag per purchase_id, so a purchase's status polls stay on the
    /// circuit it was bought on and off every other one.
    purchase_tags: Mutex<HashMap<String, String>>,
    timeout: Duration,
}

impl Net {
    pub(crate) fn builtin(base_url: &str, timeout: Duration) -> Self {
        Self::new(base_url, Kind::Builtin, timeout)
    }

    pub(crate) fn custom(base_url: &str, t: Arc<dyn PerseverusTransport>, timeout: Duration) -> Self {
        Self::new(base_url, Kind::Custom(Arc::new(Adapter(t))), timeout)
    }

    fn new(base_url: &str, kind: Kind, timeout: Duration) -> Self {
        Net {
            base_url: base_url.to_string(),
            kind,
            query_tag: new_circuit_tag("query"),
            purchase_tags: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// An HTTP client whose requests all travel over `circuit`.
    pub(crate) fn http(&self, circuit: Circuit<'_>) -> Result<Http, PerseverusError> {
        match &self.kind {
            Kind::Custom(t) => {
                let tag = match circuit {
                    Circuit::Query => self.query_tag.clone(),
                    Circuit::Fresh(purpose) => new_circuit_tag(purpose),
                    Circuit::Named(tag) => tag.to_string(),
                };
                Ok(Http::external(t.clone(), tag, self.timeout))
            }
            Kind::Builtin => {
                if crate::is_loopback_endpoint(&self.base_url) {
                    // Tor refuses to connect to 127.0.0.1, and there is no
                    // network path to hide for a server on this machine.
                    return reqwest::blocking::Client::builder()
                        .no_proxy()
                        .timeout(self.timeout)
                        .build()
                        .map(Into::into)
                        .map_err(PerseverusError::network);
                }
                let c = match circuit {
                    Circuit::Query => transport::build_client(self.timeout),
                    Circuit::Fresh(purpose) => transport::build_tagged_client(&new_circuit_tag(purpose), self.timeout),
                    Circuit::Named(tag) => transport::build_tagged_client(tag, self.timeout),
                };
                c.map(Into::into).map_err(PerseverusError::network)
            }
        }
    }

    /// A new circuit tag for a purchase about to be made.
    pub(crate) fn new_purchase_tag(&self) -> String {
        new_circuit_tag("purchase")
    }

    /// Remember which circuit `purchase_id` was bought on.
    pub(crate) fn remember_purchase(&self, purchase_id: &str, tag: String) {
        self.purchase_tags.lock().unwrap_or_else(|e| e.into_inner()).insert(purchase_id.to_string(), tag);
    }

    /// The circuit for `purchase_id`: the one it was bought on, or (for a
    /// purchase made before a restart or on another device) a new one that
    /// its later polls then reuse.
    pub(crate) fn purchase_tag(&self, purchase_id: &str) -> String {
        self.purchase_tags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(purchase_id.to_string())
            .or_insert_with(|| new_circuit_tag("purchase"))
            .clone()
    }

    pub(crate) fn forget_purchase(&self, purchase_id: &str) {
        self.purchase_tags.lock().unwrap_or_else(|e| e.into_inner()).remove(purchase_id);
    }

    pub(crate) fn get_json<T: serde::de::DeserializeOwned>(&self, circuit: Circuit<'_>, path: &str) -> Result<T, PerseverusError> {
        let resp = self.http(circuit)?.get(format!("{}{path}", self.base_url)).send()?;
        json_or_error(resp)
    }

    pub(crate) fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        circuit: Circuit<'_>,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, PerseverusError> {
        let resp = self.http(circuit)?.post(format!("{}{path}", self.base_url)).json(body).send()?;
        json_or_error(resp)
    }
}

fn json_or_error<T: serde::de::DeserializeOwned>(resp: perseverus_client_native::net::Response) -> Result<T, PerseverusError> {
    let status = resp.status();
    if !status.is_success() {
        let message = crate::error::server_reason(resp.text().unwrap_or_default());
        return Err(PerseverusError::Server { status: status.as_u16(), reason: message });
    }
    resp.json().map_err(|e| PerseverusError::Internal { reason: format!("bad response: {e}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo(Mutex<Vec<String>>);
    impl PerseverusTransport for Echo {
        fn send(&self, r: TransportRequest) -> Result<TransportResponse, TransportError> {
            self.0.lock().unwrap().push(r.circuit);
            Ok(TransportResponse { status: 200, headers: vec![], body: b"{}".to_vec() })
        }
    }

    #[test]
    fn circuits_by_purpose() {
        let echo = Arc::new(Echo(Mutex::new(vec![])));
        let net = Net::custom("https://api.example.com", echo.clone(), Duration::from_secs(5));
        let send = |c: Circuit<'_>| {
            let _: serde_json::Value = net.get_json(c, "/v1/x").unwrap();
        };
        send(Circuit::Query);
        send(Circuit::Query);
        send(Circuit::Fresh("spend"));
        send(Circuit::Fresh("spend"));
        send(Circuit::Fresh("issuance"));
        send(Circuit::Named("purchase-abc"));
        send(Circuit::Named("purchase-abc"));
        let c = echo.0.lock().unwrap();
        assert_eq!(c[0], c[1], "one query circuit");
        assert!(c[0].starts_with("query-"));
        assert!(c[2].starts_with("spend-") && c[3].starts_with("spend-"));
        assert_ne!(c[2], c[3], "every analysis gets a new spend circuit");
        assert!(c[4].starts_with("issuance-"));
        assert_eq!(c[5], "purchase-abc");
        assert_eq!(c[6], "purchase-abc");
        let distinct: std::collections::HashSet<_> = c.iter().collect();
        assert_eq!(distinct.len(), 5);
    }

    #[test]
    fn a_purchase_keeps_its_circuit_until_forgotten() {
        let net = Net::builtin("http://127.0.0.1:1", Duration::from_secs(1));
        let a = net.purchase_tag("ln_1");
        assert_eq!(net.purchase_tag("ln_1"), a);
        assert_ne!(net.purchase_tag("ln_2"), a);
        net.forget_purchase("ln_1");
        assert_ne!(net.purchase_tag("ln_1"), a);
    }
}
