//! `connect` refuses a server on a different spend circuit with a clear
//! `Unsupported` error, instead of every later spend failing to verify.

use std::io::{Read, Write};
use std::net::TcpListener;

use perseverus_sdk::{Config, Perseverus, PerseverusError, Transport};

/// Serves one fixed `/v1/meta` body to every request.
fn meta_server(circuit: Option<&str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let circuit = match circuit {
        Some(v) => format!(r#","circuit":{{"version":"{v}","pk_sha256":null,"vk_sha256":null}}"#),
        None => String::new(),
    };
    let body = format!(
        r#"{{"api_version":"1.0.0","min_client_version":"0.1.0","server_pubkey_hex":"dc03c12db41ba08872513309b777f2375e35215ea46ba5efd8c4a4542c13560b","current_month":202610,"test_clock":false{circuit}}}"#
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn connect(endpoint: String) -> Result<std::sync::Arc<Perseverus>, PerseverusError> {
    let dir = std::env::temp_dir().join(format!("perseverus-circuit-{}", rand_suffix()));
    Perseverus::connect(Config {
        endpoint,
        data_dir: dir.to_string_lossy().into(),
        transport: Transport::Direct,
        expected_server_pubkey: None,
        proving_key_path: None,
    })
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[test]
fn refuses_a_server_on_another_circuit() {
    match connect(meta_server(Some("v10"))) {
        Err(PerseverusError::Unsupported { reason }) => {
            assert!(reason.contains("v10") && reason.contains("v11"), "reason names both circuits: {reason}")
        }
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, connected"),
    }
}

#[test]
fn accepts_a_v11_server() {
    connect(meta_server(Some("v11"))).expect("v11 server accepted");
}
