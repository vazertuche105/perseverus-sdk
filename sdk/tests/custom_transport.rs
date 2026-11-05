//! `Transport.Custom`: the wallet's own transport sends every request, each
//! tagged with its circuit, and the SDK never opens a connection itself.
//!
//! The test transport plays the wallet's Tor client: it records each request
//! and forwards it to a local fake server, whatever host the URL names (so
//! an `https://api.example.com` endpoint works without a certificate).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use perseverus_sdk::{
    Config, Header, PayMethod, Perseverus, PerseverusError, PerseverusTransport, Plan, PurchaseState, Transport,
    TransportError, TransportRequest, TransportResponse,
};

const META: &str = r#"{"api_version":"1.0.0","min_client_version":"0.1.0","server_pubkey_hex":"641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695","current_month":202611,"test_clock":false,"circuit":{"version":"v11","pk_sha256":null,"vk_sha256":null}}"#;

/// A fake server: /v1/meta, a Lightning purchase, and its status.
fn fake_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let line = req.lines().next().unwrap_or("").to_string();
            let (status, body) = if line.starts_with("GET /v1/meta ") {
                (200, META.to_string())
            } else if line.starts_with("POST /v1/tokens/purchase ") {
                (200, r#"{"purchase_id":"ln_test123","packs":1,"tokens":100,"expires_at":1900000000,"payment":{"kind":"lightning","bolt11":"lnbc1test","amount_sat":1000,"checkout_url":null}}"#.to_string())
            } else if line.starts_with("GET /v1/tokens/purchase/ln_test123/status ") {
                (200, r#"{"state":"pending"}"#.to_string())
            } else {
                (404, r#"{"error":{"code":"not_found","message":"no such route"}}"#.to_string())
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// Records every request, then forwards it to `server`.
struct Recorder {
    server: String,
    seen: Mutex<Vec<TransportRequest>>,
    fail: bool,
}

impl PerseverusTransport for Recorder {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        self.seen.lock().unwrap().push(request.clone());
        if self.fail {
            return Err(TransportError::Failed { reason: "tor circuit failed".into() });
        }
        let path = &request.url[request.url.find("/v1/").expect("SDK request path")..];
        let url = format!("{}{path}", self.server);
        let client = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let mut rb = if request.method == "POST" { client.post(&url).body(request.body.clone()) } else { client.get(&url) };
        for h in &request.headers {
            rb = rb.header(h.name.as_str(), h.value.as_str());
        }
        let r = rb.send().map_err(|e| TransportError::Failed { reason: e.to_string() })?;
        let status = r.status().as_u16();
        let headers = r
            .headers()
            .iter()
            .map(|(k, v)| Header { name: k.to_string(), value: v.to_str().unwrap_or("").to_string() })
            .collect();
        Ok(TransportResponse { status, headers, body: r.bytes().unwrap().to_vec() })
    }
}

fn connect(endpoint: &str, t: Arc<Recorder>) -> Result<Arc<Perseverus>, PerseverusError> {
    let dir = std::env::temp_dir().join(format!(
        "perseverus-custom-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    Perseverus::connect(Config {
        endpoint: endpoint.into(),
        data_dir: dir.to_string_lossy().into(),
        transport: Transport::Custom { transport: t },
        expected_server_pubkey: None,
        proving_key_path: None,
    })
}

fn recorder(fail: bool) -> Arc<Recorder> {
    Arc::new(Recorder { server: fake_server(), seen: Mutex::new(vec![]), fail })
}

#[test]
fn every_request_goes_through_the_transport_with_purpose_circuits() {
    let t = recorder(false);
    let m = connect("https://api.example.com", t.clone()).expect("connect over custom transport");
    assert_eq!(m.current_month().unwrap(), 202611);
    let p = m.buy_tokens(PayMethod::Lightning, Plan::Onetime).unwrap();
    assert_eq!(p.purchase_id, "ln_test123");
    assert_eq!(m.purchase_status(p.purchase_id.clone()).unwrap(), PurchaseState::Pending);
    assert_eq!(m.purchase_status(p.purchase_id.clone()).unwrap(), PurchaseState::Pending);

    let seen = t.seen.lock().unwrap();
    let urls: Vec<_> = seen.iter().map(|r| format!("{} {}", r.method, r.url)).collect();
    assert_eq!(
        urls,
        [
            "GET https://api.example.com/v1/meta",
            "GET https://api.example.com/v1/meta",
            "POST https://api.example.com/v1/tokens/purchase",
            "GET https://api.example.com/v1/tokens/purchase/ln_test123/status",
            "GET https://api.example.com/v1/tokens/purchase/ln_test123/status",
        ]
    );
    let tag = |i: usize| seen[i].circuit.as_str();
    // meta: the query circuit, the same each time
    assert!(tag(0).starts_with("query-") && tag(0) == tag(1), "{seen:?}");
    // the purchase and its polls: one purchase circuit, not the query one
    assert!(tag(2).starts_with("purchase-"), "{}", tag(2));
    assert_ne!(tag(2), tag(0));
    assert_eq!(tag(3), tag(2));
    assert_eq!(tag(4), tag(2));
    // the purchase body is JSON and says so
    assert!(seen[2].headers.iter().any(|h| h.name.eq_ignore_ascii_case("content-type") && h.value == "application/json"));
    assert_eq!(seen[2].body, br#"{"method":"lightning","plan":"onetime"}"#);
    assert!(seen.iter().all(|r| r.timeout_ms > 0));
}

#[test]
fn a_purchase_added_by_id_gets_its_own_circuit() {
    let t = recorder(false);
    let m = connect("https://api.example.com", t.clone()).unwrap();
    m.add_purchase("ln_test123".into(), Plan::Onetime).unwrap();
    m.purchase_status("ln_test123".into()).unwrap();
    m.purchase_status("ln_test123".into()).unwrap();
    let seen = t.seen.lock().unwrap();
    assert!(seen[1].circuit.starts_with("purchase-"));
    assert_eq!(seen[1].circuit, seen[2].circuit);
    assert_ne!(seen[1].circuit, seen[0].circuit);
}

#[test]
fn server_errors_come_back_as_server_errors() {
    let t = recorder(false);
    let m = connect("https://api.example.com", t).unwrap();
    match m.purchase_status("ln_unknown".into()) {
        Err(PerseverusError::Server { status: 404, reason }) => assert_eq!(reason, "not_found: no such route"),
        other => panic!("expected Server 404, got {other:?}"),
    }
}

#[test]
fn a_transport_failure_is_a_network_error() {
    match connect("https://api.example.com", recorder(true)) {
        Err(PerseverusError::Network { reason }) => assert!(reason.contains("tor circuit failed"), "{reason}"),
        Err(e) => panic!("expected Network, got {e:?}"),
        Ok(_) => panic!("expected Network, connected"),
    }
}

#[test]
fn clearnet_endpoints_must_use_https() {
    for endpoint in ["http://api.example.com", "http://178.105.65.132:3030"] {
        let t = recorder(false);
        match connect(endpoint, t.clone()) {
            Err(PerseverusError::InvalidArgument { reason }) => assert!(reason.contains("https"), "{reason}"),
            Err(e) => panic!("{endpoint}: expected InvalidArgument, got {e:?}"),
            Ok(_) => panic!("{endpoint}: expected InvalidArgument, connected"),
        }
        assert!(t.seen.lock().unwrap().is_empty(), "{endpoint}: refused before any request");
    }
    // .onion over plain http is fine: Tor encrypts end to end
    let t = recorder(false);
    connect("http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion", t).expect("onion over http");
}

#[test]
fn built_in_tor_also_needs_https_for_clearnet() {
    let dir = std::env::temp_dir().join("perseverus-custom-tor-http");
    let r = Perseverus::connect(Config {
        endpoint: "http://api.example.com".into(),
        data_dir: dir.to_string_lossy().into(),
        transport: Transport::Tor { socks_proxy: None },
        expected_server_pubkey: None,
        proving_key_path: None,
    });
    assert!(matches!(r, Err(PerseverusError::InvalidArgument { .. })), "{:?}", r.err());
}
