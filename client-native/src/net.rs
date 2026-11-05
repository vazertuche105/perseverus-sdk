//! The HTTP layer every client in this crate uses.
//!
//! [`Http`] sends requests one of two ways:
//!
//!   * **built-in**: a `reqwest` client (direct, or through a Tor SOCKS proxy,
//!     see [`crate::transport`]). Exactly the behaviour this crate always had.
//!   * **external**: an [`ExternalTransport`] the wallet provides. The wallet's
//!     own code (e.g. its own Tor client) sends each request. Every request
//!     carries a **circuit tag**; requests with different tags MUST travel over
//!     different Tor circuits, so the server can't link, say, filter downloads
//!     to token spends by their exit address.
//!
//! The request/response API mirrors the subset of `reqwest::blocking` the
//! clients use (`get`/`post`, `.json()`, `.header()`, `.timeout()`, `.send()`,
//! `status()`, `text()`, `json()`, `bytes()`, `error_for_status()`, `Read`), so
//! the clients didn't change shape.

use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

pub use reqwest::StatusCode;

/// One request, as handed to an [`ExternalTransport`].
#[derive(Debug, Clone)]
pub struct ExternalRequest {
    /// "GET" or "POST".
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Requests with different tags MUST NOT share a Tor circuit. Requests
    /// with the same tag may (they belong to one activity, e.g. one analysis).
    /// Looks like `"spend-3f9ac1d2e4b07788"`: a purpose, then random hex.
    pub circuit: String,
    /// Give up after this long (0 = the transport's own default).
    pub timeout_ms: u64,
}

/// The server's answer, as returned by an [`ExternalTransport`].
#[derive(Debug, Clone)]
pub struct ExternalResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A wallet-provided way to send HTTP requests (e.g. over the wallet's own
/// Tor client). Must return the server's response for any HTTP status;
/// return `Err` only when no response arrived (connection failed, timeout).
pub trait ExternalTransport: Send + Sync {
    fn send(&self, request: ExternalRequest) -> Result<ExternalResponse, String>;
}

/// How many times a request refused with `403 tor_required` is retried on a
/// new circuit. The server's clearnet endpoint refuses connections from exit
/// relays that aren't on the Tor Project's exit list yet (new relays can take
/// about an hour to appear); the refusal happens before the server acts on
/// the request, so retrying is always safe.
pub const TOR_REQUIRED_RETRIES: u32 = 2;

fn is_tor_required(status: StatusCode, body: &[u8]) -> bool {
    status == StatusCode::FORBIDDEN
        && serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|v| v["error"]["code"] == "tor_required")
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A random circuit tag for `purpose` ("query", "spend", "issuance", …).
pub fn new_circuit_tag(purpose: &str) -> String {
    format!("{purpose}-{:016x}", rand::random::<u64>())
}

#[derive(Clone)]
enum Kind {
    Builtin(reqwest::blocking::Client),
    /// `circuit` is shared by clones, so when a circuit is replaced (see
    /// [`TOR_REQUIRED_RETRIES`]) every clone moves to the new one.
    External { transport: Arc<dyn ExternalTransport>, circuit: Arc<std::sync::Mutex<String>> },
}

/// Sends HTTP requests over the built-in client or a wallet's transport.
/// Cheap to clone.
#[derive(Clone)]
pub struct Http {
    kind: Kind,
    default_timeout: Option<Duration>,
}

impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Builtin(_) => f.write_str("Http(builtin)"),
            Kind::External { circuit, .. } => write!(f, "Http(external, circuit {})", lock(circuit)),
        }
    }
}

impl From<reqwest::blocking::Client> for Http {
    fn from(c: reqwest::blocking::Client) -> Self {
        Http { kind: Kind::Builtin(c), default_timeout: None }
    }
}

impl From<&reqwest::blocking::Client> for Http {
    fn from(c: &reqwest::blocking::Client) -> Self {
        c.clone().into()
    }
}

impl From<&Http> for Http {
    fn from(h: &Http) -> Self {
        h.clone()
    }
}

impl Http {
    /// A default built-in client (no proxy configured, `timeout` per request).
    pub fn builtin_default(timeout: Duration) -> Self {
        reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .expect("default blocking client must build")
            .into()
    }

    /// Requests go through `transport`, all on circuit `circuit`.
    pub fn external(transport: Arc<dyn ExternalTransport>, circuit: impl Into<String>, default_timeout: Duration) -> Self {
        Http {
            kind: Kind::External { transport, circuit: Arc::new(std::sync::Mutex::new(circuit.into())) },
            default_timeout: Some(default_timeout),
        }
    }

    /// True if requests go through a wallet-provided transport.
    pub fn is_external(&self) -> bool {
        matches!(self.kind, Kind::External { .. })
    }

    /// For an external transport: the same transport on a fresh circuit
    /// for `purpose`. `None` for the built-in client, whose isolation is
    /// handled by [`crate::transport::build_isolated_client`].
    pub fn isolated(&self, purpose: &str) -> Option<Http> {
        match &self.kind {
            Kind::External { transport, .. } => Some(Http {
                kind: Kind::External {
                    transport: transport.clone(),
                    circuit: Arc::new(std::sync::Mutex::new(new_circuit_tag(purpose))),
                },
                default_timeout: self.default_timeout,
            }),
            Kind::Builtin(_) => None,
        }
    }

    /// The current circuit tag, for an external transport.
    pub fn circuit(&self) -> Option<String> {
        match &self.kind {
            Kind::External { circuit, .. } => Some(lock(circuit).clone()),
            Kind::Builtin(_) => None,
        }
    }

    pub fn get(&self, url: impl Into<String>) -> RequestBuilder {
        self.request("GET", url.into())
    }

    pub fn post(&self, url: impl Into<String>) -> RequestBuilder {
        self.request("POST", url.into())
    }

    fn request(&self, method: &'static str, url: String) -> RequestBuilder {
        RequestBuilder {
            http: self.clone(),
            method,
            url,
            headers: Vec::new(),
            body: Vec::new(),
            timeout: self.default_timeout,
            error: None,
        }
    }
}

/// A request being built; `send()` it.
pub struct RequestBuilder {
    http: Http,
    method: &'static str,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    timeout: Option<Duration>,
    error: Option<NetError>,
}

impl RequestBuilder {
    /// JSON body (sets `Content-Type: application/json`).
    pub fn json<T: serde::Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(b) => {
                self.body = b;
                self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
                self.headers.push(("Content-Type".into(), "application/json".into()));
            }
            Err(e) => self.error = Some(NetError::Encode(e.to_string())),
        }
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    pub fn send(self) -> Result<Response, NetError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        match &self.http.kind {
            Kind::Builtin(client) => {
                let m = if self.method == "POST" { reqwest::Method::POST } else { reqwest::Method::GET };
                let mut rb = client.request(m, &self.url);
                for (k, v) in &self.headers {
                    rb = rb.header(k.as_str(), v.as_str());
                }
                if !self.body.is_empty() || self.method == "POST" {
                    rb = rb.body(self.body);
                }
                if let Some(t) = self.timeout {
                    rb = rb.timeout(t);
                }
                Ok(Response { inner: Inner::Builtin(rb.send()?) })
            }
            Kind::External { transport, circuit } => {
                let mut attempt = 0;
                loop {
                    let tag = lock(circuit).clone();
                    let req = ExternalRequest {
                        method: self.method.to_string(),
                        url: self.url.clone(),
                        headers: self.headers.clone(),
                        body: self.body.clone(),
                        circuit: tag.clone(),
                        timeout_ms: self.timeout.map(|t| t.as_millis() as u64).unwrap_or(0),
                    };
                    let r = transport.send(req).map_err(NetError::Transport)?;
                    let status = StatusCode::from_u16(r.status)
                        .map_err(|_| NetError::Transport(format!("transport returned invalid HTTP status {}", r.status)))?;
                    if attempt < TOR_REQUIRED_RETRIES && is_tor_required(status, &r.body) {
                        // The exit relay isn't on the server's list yet. Move
                        // this activity to a new circuit (unless another
                        // request already did) and try again there.
                        let mut c = lock(circuit);
                        if *c == tag {
                            *c = new_circuit_tag(tag.split('-').next().unwrap_or("circuit"));
                        }
                        drop(c);
                        attempt += 1;
                        continue;
                    }
                    return Ok(Response { inner: Inner::External { status, body: std::io::Cursor::new(r.body) } });
                }
            }
        }
    }
}

enum Inner {
    Builtin(reqwest::blocking::Response),
    External { status: StatusCode, body: std::io::Cursor<Vec<u8>> },
}

/// A server response.
pub struct Response {
    inner: Inner,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        match &self.inner {
            Inner::Builtin(r) => r.status(),
            Inner::External { status, .. } => *status,
        }
    }

    pub fn bytes(self) -> Result<Vec<u8>, NetError> {
        match self.inner {
            Inner::Builtin(r) => Ok(r.bytes()?.to_vec()),
            Inner::External { body, .. } => Ok(body.into_inner()),
        }
    }

    pub fn text(self) -> Result<String, NetError> {
        match self.inner {
            Inner::Builtin(r) => Ok(r.text()?),
            Inner::External { body, .. } => Ok(String::from_utf8_lossy(&body.into_inner()).into_owned()),
        }
    }

    pub fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, NetError> {
        match self.inner {
            Inner::Builtin(r) => Ok(r.json()?),
            Inner::External { body, .. } => {
                serde_json::from_slice(&body.into_inner()).map_err(|e| NetError::Decode(e.to_string()))
            }
        }
    }

    /// `Err` for a 4xx/5xx status, like `reqwest`'s.
    pub fn error_for_status(self) -> Result<Self, NetError> {
        let s = self.status();
        if s.is_client_error() || s.is_server_error() {
            Err(NetError::Status(s.as_u16()))
        } else {
            Ok(self)
        }
    }
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            Inner::Builtin(r) => r.read(buf),
            Inner::External { body, .. } => body.read(buf),
        }
    }
}

/// A failure sending a request or reading its response.
#[derive(Debug)]
pub enum NetError {
    /// From the built-in client.
    Builtin(reqwest::Error),
    /// The wallet's transport couldn't deliver the request (no response).
    Transport(String),
    /// `error_for_status` on a 4xx/5xx.
    Status(u16),
    /// The response body wasn't what was expected.
    Decode(String),
    /// The request body couldn't be encoded.
    Encode(String),
}

impl NetError {
    /// The HTTP status, if the server answered.
    pub fn status(&self) -> Option<u16> {
        match self {
            NetError::Builtin(e) => e.status().map(|s| s.as_u16()),
            NetError::Status(s) => Some(*s),
            _ => None,
        }
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Builtin(e) => {
                // the whole cause chain ("error sending request: error connecting to socks proxy: …")
                write!(f, "{e}")?;
                let mut cur = std::error::Error::source(e);
                while let Some(c) = cur {
                    write!(f, ": {c}")?;
                    cur = c.source();
                }
                Ok(())
            }
            NetError::Transport(m) => write!(f, "transport: {m}"),
            NetError::Status(s) => write!(f, "HTTP status {s}"),
            NetError::Decode(m) => write!(f, "bad response: {m}"),
            NetError::Encode(m) => write!(f, "couldn't encode request: {m}"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<reqwest::Error> for NetError {
    fn from(e: reqwest::Error) -> Self {
        NetError::Builtin(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Recorder {
        seen: Mutex<Vec<ExternalRequest>>,
        reply: (u16, Vec<u8>),
    }

    impl ExternalTransport for Recorder {
        fn send(&self, r: ExternalRequest) -> Result<ExternalResponse, String> {
            self.seen.lock().unwrap().push(r);
            Ok(ExternalResponse { status: self.reply.0, headers: vec![], body: self.reply.1.clone() })
        }
    }

    #[test]
    fn external_requests_carry_circuit_body_headers_and_timeout() {
        let t = Arc::new(Recorder { seen: Mutex::new(vec![]), reply: (200, br#"{"a":1}"#.to_vec()) });
        let http = Http::external(t.clone(), "query-1", Duration::from_secs(30));
        #[derive(serde::Deserialize)]
        struct A {
            a: u32,
        }
        let a: A = http.post("http://x/y").json(&serde_json::json!({"k": 2})).header("Idempotency-Key", "z").send().unwrap().json().unwrap();
        assert_eq!(a.a, 1);
        let iso = http.isolated("spend").unwrap();
        assert!(iso.circuit().unwrap().starts_with("spend-"));
        iso.get("http://x/z").timeout(Duration::from_millis(1500)).send().unwrap();
        let seen = t.seen.lock().unwrap();
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].circuit, "query-1");
        assert_eq!(seen[0].body, br#"{"k":2}"#);
        assert!(seen[0].headers.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert!(seen[0].headers.iter().any(|(k, v)| k == "Idempotency-Key" && v == "z"));
        assert_eq!(seen[0].timeout_ms, 30_000);
        assert_eq!(seen[1].method, "GET");
        assert_ne!(seen[1].circuit, "query-1");
        assert_eq!(seen[1].timeout_ms, 1500);
    }

    /// Refuses with tor_required until the circuit changes `n` times.
    struct NewExits {
        seen: Mutex<Vec<String>>,
        refuse_first: usize,
    }

    impl ExternalTransport for NewExits {
        fn send(&self, r: ExternalRequest) -> Result<ExternalResponse, String> {
            let mut seen = self.seen.lock().unwrap();
            seen.push(r.circuit.clone());
            let distinct = seen.iter().collect::<std::collections::HashSet<_>>().len();
            if distinct <= self.refuse_first {
                let body = br#"{"error":{"code":"tor_required","message":"x","retryable":true}}"#.to_vec();
                return Ok(ExternalResponse { status: 403, headers: vec![], body });
            }
            Ok(ExternalResponse { status: 200, headers: vec![], body: b"{}".to_vec() })
        }
    }

    #[test]
    fn tor_required_moves_the_activity_to_a_new_circuit() {
        let t = Arc::new(NewExits { seen: Mutex::new(vec![]), refuse_first: 2 });
        let http = Http::external(t.clone(), "query-aaaa", Duration::from_secs(1));
        let clone = http.clone();
        assert_eq!(http.post("http://x/v1/filters/batch").json(&1).send().unwrap().status().as_u16(), 200);
        let seen = t.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "two refusals, then success: {seen:?}");
        assert_eq!(seen[0], "query-aaaa");
        assert!(seen[1].starts_with("query-") && seen[2].starts_with("query-"));
        assert!(seen[0] != seen[1] && seen[1] != seen[2]);
        // later requests, from any clone, stay on the circuit that worked
        clone.get("http://x/v1/meta").send().unwrap();
        assert_eq!(t.seen.lock().unwrap().last().unwrap(), &seen[2]);
        assert_eq!(http.circuit().unwrap(), seen[2]);
    }

    #[test]
    fn tor_required_retries_are_limited() {
        let t = Arc::new(NewExits { seen: Mutex::new(vec![]), refuse_first: 100 });
        let http = Http::external(t.clone(), "spend-1", Duration::from_secs(1));
        let r = http.get("http://x").send().unwrap();
        assert_eq!(r.status().as_u16(), 403, "the last refusal is returned");
        assert_eq!(t.seen.lock().unwrap().len(), 1 + TOR_REQUIRED_RETRIES as usize);
    }

    #[test]
    fn external_status_and_errors() {
        let t = Arc::new(Recorder { seen: Mutex::new(vec![]), reply: (404, b"nope".to_vec()) });
        let http = Http::external(t, "c", Duration::from_secs(1));
        let r = http.get("http://x").send().unwrap();
        assert_eq!(r.status().as_u16(), 404);
        assert!(matches!(r.error_for_status(), Err(NetError::Status(404))));

        struct Down;
        impl ExternalTransport for Down {
            fn send(&self, _: ExternalRequest) -> Result<ExternalResponse, String> {
                Err("circuit failed".into())
            }
        }
        let e = Http::external(Arc::new(Down), "c", Duration::from_secs(1)).get("http://x").send().err().unwrap();
        assert!(e.status().is_none());
        assert!(e.to_string().contains("circuit failed"));
        assert!(Http::builtin_default(Duration::from_secs(1)).isolated("x").is_none());
    }
}
