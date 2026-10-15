//! Regression test: requests really go through the Tor SOCKS proxy.
//!
//! reqwest silently fails every SOCKS connection when it's built without a
//! TLS backend ("failed to create underlying connection"), which once made
//! the SDK unable to reach the .onion service at all. This runs a minimal
//! SOCKS5 proxy (no-auth and the user/password auth used for circuit
//! isolation) in front of a tiny HTTP server, and checks both client kinds
//! reach an `.onion` hostname through it with remote DNS (`socks5h`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn http_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

/// SOCKS5 proxy forwarding every CONNECT to `target`. Records the hostnames
/// it was asked for and whether user/password auth was used.
fn socks_proxy(target: u16, seen: Arc<Mutex<Vec<(String, bool)>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let _ = serve(c, target, seen);
            });
        }
    });
    port
}

fn serve(mut c: TcpStream, target: u16, seen: Arc<Mutex<Vec<(String, bool)>>>) -> std::io::Result<()> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    let mut methods = vec![0u8; b[1] as usize];
    c.read_exact(&mut methods)?;
    let auth = methods.contains(&2);
    c.write_all(&[5, if auth { 2 } else { 0 }])?;
    if auth {
        let mut v = [0u8; 2];
        c.read_exact(&mut v)?;
        let mut user = vec![0u8; v[1] as usize];
        c.read_exact(&mut user)?;
        let mut pl = [0u8; 1];
        c.read_exact(&mut pl)?;
        let mut pass = vec![0u8; pl[0] as usize];
        c.read_exact(&mut pass)?;
        c.write_all(&[1, 0])?;
    }
    let mut h = [0u8; 4];
    c.read_exact(&mut h)?;
    assert_eq!(h[3], 3, "client must send the hostname (socks5h), not resolve it locally");
    let mut len = [0u8; 1];
    c.read_exact(&mut len)?;
    let mut host = vec![0u8; len[0] as usize];
    c.read_exact(&mut host)?;
    let mut p = [0u8; 2];
    c.read_exact(&mut p)?;
    seen.lock().unwrap().push((String::from_utf8_lossy(&host).into_owned(), auth));
    let mut up = TcpStream::connect(("127.0.0.1", target))?;
    c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, (target >> 8) as u8, target as u8])?;
    let mut down = c.try_clone()?;
    let mut up2 = up.try_clone()?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut c, &mut up2);
    });
    let _ = std::io::copy(&mut up, &mut down);
    Ok(())
}

#[test]
fn requests_go_through_the_socks_proxy() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let proxy = socks_proxy(http_server(), seen.clone());
    perseverus_client_native::transport::configure("TOR", Some(&format!("socks5h://127.0.0.1:{proxy}"))).unwrap();
    let url = "http://medusaexample.onion/v1/meta";

    let plain = perseverus_client_native::transport::build_client(Duration::from_secs(10)).unwrap();
    let r = plain.get(url).send().expect("request through the SOCKS proxy");
    assert_eq!(r.text().unwrap(), "ok");

    let isolated = perseverus_client_native::transport::build_isolated_client(Duration::from_secs(10)).unwrap();
    assert_eq!(isolated.get(url).send().expect("isolated request through the SOCKS proxy").text().unwrap(), "ok");

    let seen = seen.lock().unwrap();
    assert_eq!(*seen, vec![("medusaexample.onion".to_string(), false), ("medusaexample.onion".to_string(), true)]);
}
