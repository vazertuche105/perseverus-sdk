//! Without Tor, nothing goes out over clearnet: not before `configure` is
//! called, and not in "AUTO" mode (which used to fall back to Direct when
//! Tor looked unreachable). Uses a SOCKS port nothing listens on and a
//! server that IS reachable directly, so any fallback would succeed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use perseverus_client_native::transport;

#[test]
fn no_clearnet_fallback_without_tor() {
    let hits = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let mut b = [0u8; 1024];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    let url = format!("http://127.0.0.1:{port}/");
    // A port with nothing listening stands in for "Tor isn't running".
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dead_socks = format!("socks5h://127.0.0.1:{dead}");

    // 1. Before configure(): the default is Tor, not Direct.
    let c = transport::build_client(Duration::from_secs(5)).unwrap();
    assert!(c.get(&url).send().is_err(), "unconfigured transport must not go direct");

    // 2. AUTO with Tor down: fails, no fallback.
    transport::configure("AUTO", Some("https://relay.example.com")).unwrap();
    for client in [transport::build_client(Duration::from_secs(5)).unwrap(), transport::build_isolated_client(Duration::from_secs(5)).unwrap()] {
        assert!(client.get(&url).send().is_err(), "AUTO must fail closed");
    }

    // 3. TOR pointed at a dead proxy: fails with a SOCKS error that says why.
    transport::configure("TOR", Some(&dead_socks)).unwrap();
    let err = transport::http_get(&url).unwrap_err();
    assert!(err.contains("GET"), "{err}");

    // 4. OHTTP isn't implemented: refuses instead of connecting directly.
    transport::configure("OHTTP", Some("https://relay.example.com")).unwrap();
    assert!(transport::build_client(Duration::from_secs(5)).is_err());

    assert_eq!(hits.load(Ordering::SeqCst), 0, "the server was reached directly");

    // Sanity: the server really is reachable directly, so the checks above mean something.
    transport::configure("DIRECT", None).unwrap();
    assert_eq!(transport::http_get(&url).unwrap(), "ok");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    tor_hint_says_whether_tor_is_running();
}

/// Called from the test above: transport state is global, so these run in sequence.
fn tor_hint_says_whether_tor_is_running() {
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    transport::configure("TOR", Some(&format!("socks5h://127.0.0.1:{dead}"))).unwrap();
    let h = transport::tor_hint().unwrap();
    assert!(h.contains("Tor isn't running"), "{h}");

    let live = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = live.local_addr().unwrap().port();
    transport::configure("AUTO", None).unwrap();
    transport::configure("TOR", Some(&format!("127.0.0.1:{port}"))).unwrap();
    let h = transport::tor_hint().unwrap();
    assert!(h.contains("Tor is running"), "{h}");

    transport::configure("DIRECT", None).unwrap();
    assert!(transport::tor_hint().is_none());
}
