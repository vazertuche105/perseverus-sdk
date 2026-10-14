//! Standalone v5 query smoke test — no JNI, no Sparrow GUI.
//!
//! Exercises the exact pipeline the wallet uses: download the v5 filter, scan
//! Column A for the txid, fetch + verify the codebook, do a fresh OPRF round
//! against the server, decrypt the code, and map it to a 24-bit v3-lean tag.
//!
//! Usage:
//!   cargo run --release --example v5_query -- <server_url> <txid_hex> <vout> <height>
//!
//! Example (txid/height from extract_test_utxos.py):
//!   cargo run --release --example v5_query -- \
//!       http://127.0.0.1:3030 <64-hex-txid> 0 902675
//!
//! If the txid isn't found in the given byte order, the tool retries with the
//! bytes reversed (display vs. internal order) and reports which one matched —
//! that tells us the convention the filters were built in.

use perseverus_client_native::QueryClient;
use perseverus_client_native::query::{private_query, NoProgress, QueryConfig, TagPayload};
use rand::thread_rng;

fn parse_hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim()).expect("txid must be hex");
    assert_eq!(b.len(), 32, "txid must be 32 bytes (64 hex chars)");
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

fn run(client: &QueryClient, txid: [u8; 32], vout: u32, height: u32) -> Result<TagPayload, String> {
    let cfg = QueryConfig::default();
    let mut rng = thread_rng();
    private_query(client, txid, vout, height, &cfg, &NoProgress, &mut rng)
        .map(|r| r.tag)
        .map_err(|e| e.to_string())
}

fn report(which: &str, t: &TagPayload) {
    match t {
        TagPayload::V3Lean(v) => {
            let grade = ["A+/A/B", "C", "D", "F"][((v >> 1) & 0b11) as usize];
            println!("OK [{which}]  V3LEAN tag=0x{v:06x}  grade={grade}");
        }
        TagPayload::Kyc(k) => println!("OK [{which}]  KYC tag={k:?}"),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: v5_query <server_url> <txid_hex> <vout> <height>");
        std::process::exit(1);
    }
    let url = a[1].clone();
    let txid = parse_hex32(&a[2]);
    let vout: u32 = a[3].parse().expect("vout must be a number");
    let height: u32 = a[4].parse().expect("height must be a number");

    let client = QueryClient::new(url);

    match run(&client, txid, vout, height) {
        Ok(t) => {
            report("as-given", &t);
            return;
        }
        Err(e) => eprintln!("[as-given byte order] {e}"),
    }

    let mut rev = txid;
    rev.reverse();
    match run(&client, rev, vout, height) {
        Ok(t) => {
            eprintln!("note: matched only with REVERSED txid byte order");
            report("reversed", &t);
        }
        Err(e) => {
            eprintln!("[reversed byte order] {e}");
            eprintln!("FAILED: txid not found in either byte order");
            std::process::exit(2);
        }
    }
}
