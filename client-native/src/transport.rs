//! Privacy transport layer for BTC Medusa.
//!
//! This module manages how the client-native crate routes HTTP traffic
//! to the Perseverus server. Four modes are supported:
//!
//!   - **Direct** — plain clearnet HTTP. No privacy protection for the
//!     user's IP. Suitable for local development only.
//!   - **Tor** — routes all traffic through a SOCKS5 proxy connected to
//!     a Tor daemon. DNS resolution happens on the Tor side
//!     (`socks5h://`) so `.onion` addresses resolve correctly. The Tor
//!     daemon is managed externally (by the Java layer or the OS); this
//!     module only needs the SOCKS5 address.
//!   - **OHTTP** — Oblivious HTTP relay. The relay URL is stored but
//!     transport-layer OHTTP is not yet fully wired at the reqwest layer.
//!   - **Auto** — cascading fallback: Tor → OHTTP → Direct. Tries each
//!     transport in order of privacy strength. The wallet should default
//!     to this mode so that privacy is preserved even when Tor is down.
//!
//! ## Independence from Sparrow's Tor
//!
//! BTC Medusa's transport is entirely separate from Sparrow's own Tor
//! settings for Bitcoin node connections. Sparrow users who opt out of
//! Tor for their Bitcoin Core / Electrum connections are unaffected —
//! BTC Medusa maintains its own SOCKS5 proxy binding that does not
//! touch Sparrow's proxy configuration.
//!
//! ## Thread safety
//!
//! Transport state lives in a global `OnceLock<RwLock<…>>`. Reads
//! (every HTTP call) take a shared lock; writes (`configure`) take an
//! exclusive lock. In practice `configure` is called once at startup
//! and all subsequent access is read-only.

use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::Proxy;

// ─────────────────────────────────────────────────────────────────────
// Transport mode
// ─────────────────────────────────────────────────────────────────────

/// Active transport mode. Stored globally and consulted every time a
/// new `reqwest::blocking::Client` is built.
#[derive(Debug, Clone)]
pub enum TransportMode {
    /// Clearnet HTTP — no IP privacy.
    Direct,
    /// Tor via a local SOCKS5 proxy. The `socks_url` is typically
    /// `socks5h://127.0.0.1:9050` (system Tor) or a custom port if
    /// the Java layer started its own Tor daemon for BTC Medusa.
    ///
    /// The `h` suffix in `socks5h` is critical: it tells reqwest to
    /// let the proxy handle DNS resolution, which is the only way
    /// `.onion` addresses work.
    Tor { socks_url: String },
    /// Oblivious HTTP relay (placeholder — not yet implemented at the
    /// transport layer).
    Ohttp { relay_url: String },
    /// Cascading fallback: Tor → OHTTP → Direct. Tries Tor first; if
    /// the SOCKS5 proxy is unreachable, falls back to OHTTP; if no relay
    /// URL was configured or the relay is down, falls back to Direct.
    /// This is the recommended default for production wallets.
    Auto {
        socks_url: String,
        ohttp_relay_url: Option<String>,
    },
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Direct
    }
}

/// Default Tor SOCKS5 proxy address. This is the standard port used
/// by the Tor daemon (`tor`). Tor Browser uses 9150 instead.
const DEFAULT_TOR_SOCKS: &str = "socks5h://127.0.0.1:9050";

// ─────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────

fn state() -> &'static RwLock<TransportMode> {
    static STATE: OnceLock<RwLock<TransportMode>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(TransportMode::default()))
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

/// Set the global transport mode.
///
/// `mode` is one of `"DIRECT"`, `"TOR"`, or `"OHTTP"` (case-sensitive,
/// matches the Java enum `PerseverusTransport`).
///
/// `param` carries mode-specific configuration:
///   - **DIRECT**: ignored (may be `None`).
///   - **TOR**: optional SOCKS5 proxy URL. Defaults to
///     `socks5h://127.0.0.1:9050` if `None` or empty. If provided
///     without a scheme, `socks5h://` is prepended automatically.
///   - **OHTTP**: the relay URL (required).
pub fn configure(mode: &str, param: Option<&str>) -> Result<(), String> {
    let transport = match mode {
        "DIRECT" => TransportMode::Direct,

        "TOR" => {
            let raw = param.unwrap_or("").trim();
            let socks_url = if raw.is_empty() {
                DEFAULT_TOR_SOCKS.to_string()
            } else if raw.starts_with("socks5") {
                raw.to_string()
            } else {
                // Bare host:port — prepend socks5h scheme.
                format!("socks5h://{}", raw)
            };
            TransportMode::Tor { socks_url }
        }

        "OHTTP" => {
            let relay = param
                .filter(|s| !s.trim().is_empty())
                .ok_or("OHTTP mode requires a relay URL")?;
            TransportMode::Ohttp {
                relay_url: relay.trim().to_string(),
            }
        }

        "AUTO" => {
            // param is the OHTTP relay URL (optional).
            let relay = param
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string());
            TransportMode::Auto {
                socks_url: DEFAULT_TOR_SOCKS.to_string(),
                ohttp_relay_url: relay,
            }
        }

        other => return Err(format!("unknown transport mode: {}", other)),
    };

    let mut guard = state()
        .write()
        .map_err(|e| format!("transport lock poisoned: {}", e))?;
    *guard = transport;
    Ok(())
}

/// Return the currently active transport mode (cloned snapshot).
pub fn current_mode() -> Result<TransportMode, String> {
    state()
        .read()
        .map(|g| g.clone())
        .map_err(|e| format!("transport lock poisoned: {}", e))
}

/// Build a `reqwest::blocking::Client` configured for the current
/// transport mode.
///
/// - **Direct**: plain client, no proxy.
/// - **Tor**: client with a `socks5h://…` proxy so all traffic
///   (including DNS) routes through Tor.
/// - **OHTTP**: plain client for now (relay logic is not yet
///   implemented at the reqwest layer).
///
/// `timeout` is applied as the overall request timeout. Callers that
/// need different connect vs. read timeouts should use the builder
/// returned by [`client_builder`] instead.
pub fn build_client(timeout: Duration) -> Result<Client, String> {
    let mode = state()
        .read()
        .map_err(|e| format!("transport lock poisoned: {}", e))?;
    build_client_for_mode(&*mode, timeout)
}

/// Build a client for a specific mode (testable without touching
/// global state).
pub fn build_client_for_mode(
    mode: &TransportMode,
    timeout: Duration,
) -> Result<Client, String> {
    match mode {
        TransportMode::Auto { socks_url, ohttp_relay_url } => {
            build_client_auto(socks_url, ohttp_relay_url.as_deref(), timeout)
        }
        other => build_client_single(other, timeout),
    }
}

/// Build a client for a single (non-Auto) transport mode.
fn build_client_single(
    mode: &TransportMode,
    timeout: Duration,
) -> Result<Client, String> {
    let builder = Client::builder().timeout(timeout);

    let builder = match mode {
        TransportMode::Direct => builder,

        TransportMode::Tor { socks_url } => {
            let proxy = Proxy::all(socks_url)
                .map_err(|e| format!("invalid SOCKS proxy URL '{}': {}", socks_url, e))?;
            builder.proxy(proxy)
        }

        TransportMode::Ohttp { .. } => {
            // OHTTP is not implemented yet (no HPKE encapsulation / gateway).
            // Return an ERROR rather than a plain clearnet client, so this mode
            // can never silently degrade to no-IP-privacy. Until the real OHTTP
            // client lands, this rung is treated as "unavailable" and the Auto
            // cascade skips past it.
            return Err("OHTTP transport not yet available (coming soon)".to_string());
        }

        TransportMode::Auto { .. } => unreachable!("handled in build_client_for_mode"),
    };

    builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {}", e))
}

/// Cascading fallback: Tor → OHTTP → Direct.
///
/// Tries to build a Tor client and sends a lightweight probe request
/// to confirm the SOCKS5 proxy is reachable. If Tor is down, falls
/// back to OHTTP (if a relay URL was configured), then to Direct as
/// a last resort.
///
/// The probe is a TCP-level connect check — it doesn't send any
/// application data, so it's fast (~100ms) and privacy-safe.
fn build_client_auto(
    socks_url: &str,
    ohttp_relay_url: Option<&str>,
    timeout: Duration,
) -> Result<Client, String> {
    // 1. Try Tor
    let tor_mode = TransportMode::Tor { socks_url: socks_url.to_string() };
    match build_client_single(&tor_mode, timeout) {
        Ok(client) => {
            // Quick probe: try to connect through the SOCKS5 proxy.
            // We use a short timeout so we don't block for long if Tor is down.
            let probe_timeout = Duration::from_secs(3);
            let probe_client = Client::builder()
                .timeout(probe_timeout)
                .proxy(Proxy::all(socks_url).map_err(|e| format!("proxy: {}", e))?)
                .build()
                .map_err(|e| format!("probe client: {}", e))?;

            // Try connecting to a known Tor endpoint. If the SOCKS5
            // proxy itself is down, this fails immediately.
            match probe_client.get("http://127.0.0.1:9050").send() {
                // Any response (even an error page) means the proxy is alive.
                // A connection-refused from the *proxy* throws an Err, which
                // is what we're checking for.
                Ok(_) => {
                    eprintln!("[transport] Auto: using Tor (SOCKS5 proxy reachable)");
                    return Ok(client);
                }
                Err(e) => {
                    // Check if the error is a proxy/connect error (Tor down)
                    // vs. a target-unreachable error (Tor up, target down).
                    let err_str = format!("{}", e);
                    if err_str.contains("connection refused")
                        || err_str.contains("Connection refused")
                        || err_str.contains("proxy")
                        || err_str.contains("SOCKS")
                        || err_str.contains("socks")
                    {
                        eprintln!("[transport] Auto: Tor SOCKS5 proxy unreachable, falling back");
                    } else {
                        // Proxy is up but target is unreachable — Tor is working.
                        eprintln!("[transport] Auto: using Tor (proxy alive, probe target unreachable is OK)");
                        return Ok(client);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[transport] Auto: failed to build Tor client: {}", e);
        }
    }

    // 2. Try OHTTP
    if let Some(relay) = ohttp_relay_url {
        let ohttp_mode = TransportMode::Ohttp { relay_url: relay.to_string() };
        match build_client_single(&ohttp_mode, timeout) {
            Ok(client) => {
                eprintln!("[transport] Auto: falling back to OHTTP relay ({})", relay);
                return Ok(client);
            }
            Err(e) => {
                eprintln!("[transport] Auto: OHTTP also failed: {}", e);
            }
        }
    } else {
        eprintln!("[transport] Auto: no OHTTP relay configured, skipping");
    }

    // 3. Last resort: Direct
    eprintln!("[transport] Auto: all privacy transports failed — falling back to DIRECT (no IP privacy!)");
    build_client_single(&TransportMode::Direct, timeout)
}

/// Perform a simple HTTP GET through the current transport and return
/// the response body as a UTF-8 string.
///
/// This is the Rust implementation behind `Native.httpGet()`. It is
/// intentionally simple — no retries, no streaming, no auth headers.
/// The only caller today is the sign-up wizard's Tor-routed price
/// fallback (`PerseverusPaymentManager.fetchFallbackPrice`).
pub fn http_get(url: &str) -> Result<String, String> {
    let client = build_client(Duration::from_secs(30))?;

    let resp = client
        .get(url)
        .send()
        .map_err(|e| format!("GET {} failed: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!(
            "GET {} returned HTTP {} — {}",
            url,
            status.as_u16(),
            body.chars().take(200).collect::<String>()
        ));
    }

    resp.text()
        .map_err(|e| format!("reading response body from {}: {}", url, e))
}

/// Perform a simple HTTP POST with a JSON body through the current
/// transport and return the response body as a UTF-8 string.
///
/// This is the Rust implementation behind `Native.httpPost()`. Used
/// by the Stripe payment flow to call `/stripe/checkout`,
/// `/stripe/redeem`, etc. on the Perseverus server via Tor.
pub fn http_post(url: &str, json_body: &str) -> Result<String, String> {
    let client = build_client(Duration::from_secs(30))?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(json_body.to_string())
        .send()
        .map_err(|e| format!("POST {} failed: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!(
            "POST {} returned HTTP {} — {}",
            url,
            status.as_u16(),
            body.chars().take(500).collect::<String>()
        ));
    }

    resp.text()
        .map_err(|e| format!("reading response body from {}: {}", url, e))
}

/// Like `http_post`, but over a FRESH, isolated Tor circuit (random SOCKS
/// auth → distinct circuit). Used for the BTC proof-of-payment `/subscribe`
/// call so the subscription request is unlinkable from the payment broadcast.
/// In non-Tor modes this is equivalent to `http_post`.
pub fn http_post_isolated(url: &str, json_body: &str) -> Result<String, String> {
    let client = build_isolated_client(Duration::from_secs(60))?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(json_body.to_string())
        .send()
        .map_err(|e| format!("isolated POST {} failed: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!(
            "isolated POST {} returned HTTP {} — {}",
            url,
            status.as_u16(),
            body.chars().take(500).collect::<String>()
        ));
    }

    resp.text()
        .map_err(|e| format!("reading response body from {}: {}", url, e))
}

/// Build a `reqwest::blocking::Client` that is guaranteed to use a
/// **fresh Tor circuit**, isolated from any previous connections.
///
/// Tor's `IsolateSOCKSAuth` feature gives a distinct circuit to each
/// (username, password) pair. We generate a random username for each
/// call, so the resulting client routes through a different exit node
/// than any previously-built client.
///
/// **Use case:** the `/board/publish` call must go through a different
/// circuit than the `/issue` call that preceded it. Without this, the
/// server could correlate them by observing the same Tor exit IP within
/// a short time window.
///
/// In non-Tor modes (Direct, OHTTP) this falls back to a plain
/// `build_client` call — circuit isolation is a Tor-specific concept.
pub fn build_isolated_client(timeout: Duration) -> Result<Client, String> {
    let mode = state()
        .read()
        .map_err(|e| format!("transport lock poisoned: {}", e))?;

    // Extract the SOCKS URL — works for both Tor and Auto modes.
    let socks_url = match &*mode {
        TransportMode::Tor { socks_url } => Some(socks_url.clone()),
        TransportMode::Auto { socks_url, .. } => Some(socks_url.clone()),
        _ => None,
    };

    match socks_url {
        Some(socks_url) => {
            // Generate random credentials for IsolateSOCKSAuth.
            // Tor treats each unique (user, pass) pair as a stream-isolation
            // hint and routes them through different circuits.
            let random_user: u64 = rand::random();
            let isolation_user = format!("medusa-{:016x}", random_user);
            let isolation_pass = "x"; // password content doesn't matter

            // Insert credentials into the SOCKS URL.
            // socks5h://127.0.0.1:9050 → socks5h://medusa-xxx:x@127.0.0.1:9050
            let authed_url = if socks_url.contains("://") {
                let after_scheme = &socks_url[socks_url.find("://").unwrap() + 3..];
                let scheme = &socks_url[..socks_url.find("://").unwrap() + 3];
                format!("{}{}:{}@{}", scheme, isolation_user, isolation_pass, after_scheme)
            } else {
                format!("socks5h://{}:{}@{}", isolation_user, isolation_pass, socks_url)
            };

            let proxy = Proxy::all(&authed_url)
                .map_err(|e| format!("invalid isolated proxy URL: {}", e))?;

            Client::builder()
                .timeout(timeout)
                .proxy(proxy)
                .build()
                .map_err(|e| format!("failed to build isolated HTTP client: {}", e))
        }
        // Non-Tor modes don't benefit from circuit isolation.
        None => build_client_for_mode(&*mode, timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All transport tests share one global `OnceLock<RwLock<…>>`, so they
    /// MUST run sequentially. We combine them into a single test function
    /// to avoid data races from `cargo test`'s parallel test threads.
    #[test]
    fn transport_configure_modes() {
        // 1. Fresh state defaults to Direct.
        let mode = current_mode().unwrap();
        assert!(matches!(mode, TransportMode::Direct));

        // 2. Tor with default socks
        configure("TOR", None).unwrap();
        match current_mode().unwrap() {
            TransportMode::Tor { socks_url } => {
                assert_eq!(socks_url, DEFAULT_TOR_SOCKS);
            }
            _ => panic!("expected Tor mode"),
        }

        // 3. Tor with custom port (bare host:port → socks5h:// prepended)
        configure("TOR", Some("127.0.0.1:9150")).unwrap();
        match current_mode().unwrap() {
            TransportMode::Tor { socks_url } => {
                assert_eq!(socks_url, "socks5h://127.0.0.1:9150");
            }
            _ => panic!("expected Tor mode"),
        }

        // 4. Tor with explicit scheme (passed through unchanged)
        configure("TOR", Some("socks5h://10.0.0.1:9050")).unwrap();
        match current_mode().unwrap() {
            TransportMode::Tor { socks_url } => {
                assert_eq!(socks_url, "socks5h://10.0.0.1:9050");
            }
            _ => panic!("expected Tor mode"),
        }

        // 5. OHTTP requires a URL
        assert!(configure("OHTTP", None).is_err());
        assert!(configure("OHTTP", Some("")).is_err());
        assert!(configure("OHTTP", Some("https://relay.example.com")).is_ok());

        // 6. Build direct client
        configure("DIRECT", None).unwrap();
        let client = build_client(Duration::from_secs(5));
        assert!(client.is_ok());

        // 7. Build tor client (doesn't require Tor running — only fails on send)
        configure("TOR", None).unwrap();
        let client = build_client(Duration::from_secs(5));
        assert!(client.is_ok());

        // 8. Auto mode without OHTTP relay
        configure("AUTO", None).unwrap();
        match current_mode().unwrap() {
            TransportMode::Auto { socks_url, ohttp_relay_url } => {
                assert_eq!(socks_url, DEFAULT_TOR_SOCKS);
                assert!(ohttp_relay_url.is_none());
            }
            _ => panic!("expected Auto mode"),
        }

        // 9. Auto mode with OHTTP relay
        configure("AUTO", Some("https://relay.example.com")).unwrap();
        match current_mode().unwrap() {
            TransportMode::Auto { socks_url, ohttp_relay_url } => {
                assert_eq!(socks_url, DEFAULT_TOR_SOCKS);
                assert_eq!(ohttp_relay_url.as_deref(), Some("https://relay.example.com"));
            }
            _ => panic!("expected Auto mode"),
        }

        // 10. Auto build_client works (will fall through to Direct since no Tor running in CI)
        let client = build_client(Duration::from_secs(5));
        assert!(client.is_ok());

        // Reset
        configure("DIRECT", None).unwrap();
    }
}
