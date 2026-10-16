//! Client-side private query pipeline (blocking).
//!
//! Port of the async `perseverus-cli/src/query.rs` to blocking I/O so
//! it can run from JNI without a tokio runtime. Implements Whitepaper
//! Sections 7 (OPRF) and 9 (decoy anonymisation).
//!
//! Two on-disk filter formats are supported and auto-detected from the
//! version byte (offset 4 of the serialized filter):
//!
//!   * **v3** (legacy, interleaved Golomb stream, per-OUTPOINT keying):
//!     decrypts a 2-byte CTR-encrypted `KycTag`.
//!   * **v5** (two-column codebook, per-TRANSACTION keying): scans Column A
//!     for the txid, decrypts the Column-B codebook code, and maps it through
//!     the global codebook to a 24-bit v3-lean tag.
//!
//! The seven logical steps (filter download, scan, blind, OPRF, DLEQ verify,
//! unblind, decrypt) are identical between versions; only the keyed material
//! (outpoint vs txid) and the payload (KycTag vs codebook code) differ.

use ark_ed_on_bn254::EdwardsProjective;
use ark_ff::Field;

type G1Projective = EdwardsProjective;
use rand::Rng;

use perseverus_core::{
    KycTag, TxOutpoint,
    aes::{decrypt_tag_ctr, derive_nonce, derive_tag_key, TAG_CIPHERTEXT_LEN_V3},
    filter::{
        BlockFilterV3, scan_filter_for_match_v3,
        BlockFilterV5, scan_filter_v5, decrypt_code_v5,
        FILTER_FORMAT_VERSION_V3, FILTER_FORMAT_VERSION_V5,
    },
    golomb::{InterleavedGolombDecoder, reconstruct_from_deltas},
    oprf::{blind, verify_batch},
};

use crate::codebook::Codebook;
use crate::query_client::{QueryClient, QueryClientError};

// ─────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────

/// Configuration for the query pipeline.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    pub num_decoys: usize,
    pub laplace_scale: f64,
    pub max_txs_per_filter: Option<usize>,
    pub chain_tip: u32,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            num_decoys: 8,
            laplace_scale: 5.0,
            max_txs_per_filter: None,
            chain_tip: 840_000,
        }
    }
}

/// The decrypted tag payload. Legacy v3 filters yield a [`KycTag`]; v5 filters
/// yield a raw 24-bit v3-lean tag (only the low 24 bits are significant). The
/// JNI layer renders each to the string the Java `parseTag` understands.
#[derive(Debug, Clone)]
pub enum TagPayload {
    /// Legacy v3 KYC enum tag.
    Kyc(KycTag),
    /// v5 codebook result: a 24-bit v3-lean tag (see SPEC.md §2a).
    V3Lean(u32),
}

/// Result of a private query for a single UTXO.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub txid: [u8; 32],
    pub vout_index: u32,
    pub block_height: u32,
    pub tag: TagPayload,
    pub decoy_count: usize,
    /// The actual decoy block heights selected by Laplace noise.
    pub decoy_heights: Vec<u32>,
    /// Human-readable log lines from the query pipeline.
    pub log_lines: Vec<String>,
}

/// Errors that can occur during the query pipeline.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("client error: {0}")]
    Client(#[from] QueryClientError),

    #[error("UTXO {txid_prefix}...:{vout} not found in filter for block {height}")]
    UtxoNotFound {
        txid_prefix: String,
        vout: u32,
        height: u32,
    },

    #[error("DLEQ proof verification failed — server may be dishonest")]
    DleqVerificationFailed,

    #[error("blinding factor has no inverse")]
    BlindingInverse,

    #[error("{0}")]
    Other(String),
}

/// Progress callback for the query pipeline. Called from the scan
/// thread so the Java/UI layer can update progress bars.
pub trait QueryProgress: Send {
    /// A filter build has started for the given block height.
    fn filter_downloading(&self, _height: u32) {}
    /// A filter build has completed (success or cached).
    fn filter_downloaded(&self, _height: u32) {}
}

#[cfg(test)]
mod cover_tests {
    use super::*;

    #[test]
    fn cover_set_always_contains_the_block_and_enough_decoys() {
        let mut rng = rand::thread_rng();
        for h in [1u32, 5, 500_000, 899_999, 900_000] {
            let set = cover_set(h, 8, 5.0, 900_000, &mut rng);
            assert!(set.contains(&h));
            assert!(set.len() >= MIN_DECOYS_PER_LOOKUP + 1, "h={} set={:?}", h, set);
            assert!(set.iter().all(|&x| (1..=900_000).contains(&x)));
        }
    }

    /// F14: with too few decoys or no chain tip, a cache miss must fail
    /// before any request is made (the client points at a closed port, so
    /// reaching the network would surface as a client error instead).
    #[test]
    fn lone_height_is_never_requested() {
        let client = QueryClient::new("http://127.0.0.1:9");
        let mut rng = rand::thread_rng();
        let h = 812_345;
        for cfg in [
            QueryConfig { num_decoys: 0, chain_tip: 900_000, ..QueryConfig::default() },
            QueryConfig { num_decoys: 3, chain_tip: 900_000, ..QueryConfig::default() },
            QueryConfig { num_decoys: 8, chain_tip: 0, ..QueryConfig::default() },
        ] {
            match filter_with_cover(&client, h, &cfg, &mut rng) {
                Err(QueryError::Other(msg)) => assert!(msg.starts_with("refusing"), "{}", msg),
                other => panic!("expected a refusal, got {:?}", other.map(|v| v.len())),
            }
        }
    }

    /// F14: on a cache miss the real height goes out in one batch with its
    /// decoys, never on its own. A one-shot local HTTP server records what
    /// was asked for.
    #[test]
    fn cache_miss_fetches_inside_a_decoy_set() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(String, Vec<u32>)>();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 8192];
            // Read headers + body (Content-Length) of the single request.
            loop {
                let n = sock.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len = text.lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
                        .unwrap_or(0);
                    if req.len() >= i + 4 + len { break; }
                }
            }
            let text = String::from_utf8_lossy(&req).to_string();
            let line = text.lines().next().unwrap().to_string();
            let body = &text[text.find("\r\n\r\n").unwrap() + 4..];
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            let heights: Vec<u32> = v["heights"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
            let filters: Vec<_> = heights.iter().map(|h| serde_json::json!({"height": h, "filter_hex": "ab"})).collect();
            let out = serde_json::json!({"filters": filters, "missing": []}).to_string();
            write!(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", out.len(), out).unwrap();
            tx.send((line, heights)).unwrap();
        });

        let client = QueryClient::new(format!("http://{}", addr));
        let h = 777_777; // unique to this test: the filter cache is process-wide
        let cfg = QueryConfig { num_decoys: 8, chain_tip: 900_000, ..QueryConfig::default() };
        let data = filter_with_cover(&client, h, &cfg, &mut rand::thread_rng()).expect("fetch");
        assert_eq!(data, vec![0xab]);

        let (line, heights) = rx.recv().unwrap();
        assert!(line.starts_with("POST ") && line.contains("/filters/batch"), "{}", line);
        assert!(heights.contains(&h));
        assert!(heights.len() >= MIN_DECOYS_PER_LOOKUP + 1, "{:?}", heights);
        // Sent sorted, so the real block's position says nothing.
        assert!(heights.windows(2).all(|w| w[0] < w[1]));
        // Served from cache now, with no further request.
        assert_eq!(filter_with_cover(&client, h, &cfg, &mut rand::thread_rng()).unwrap(), vec![0xab]);
    }
}

/// No-op progress reporter for tests and non-UI usage.
pub struct NoProgress;
impl QueryProgress for NoProgress {}

// ─────────────────────────────────────────────────────────────────────
// Public entry points (version-dispatching)
// ─────────────────────────────────────────────────────────────────────

/// Run the full private query pipeline for a single UTXO, doing a fresh OPRF
/// round-trip with the server. Blocking — intended for JNI or CLI usage.
pub fn private_query<R: Rng>(
    client: &QueryClient,
    txid: [u8; 32],
    vout_index: u32,
    block_height: u32,
    config: &QueryConfig,
    _progress: &dyn QueryProgress,
    rng: &mut R,
) -> Result<QueryResult, QueryError> {
    let filter_data = filter_with_cover(client, block_height, config, rng)?;
    dispatch(client, txid, vout_index, block_height, &filter_data, rng, None)
}

/// Authenticated query: uses a pre-computed `gamma` (from a prior
/// `SpendClient::spend`) to decrypt without a fresh OPRF round-trip.
///
/// NOTE: the supplied `gamma` must be `γ = k·H2C(input)` over the SAME input the
/// filter was keyed on — the 36-byte outpoint for v3, the 32-byte txid for v5.
pub fn private_query_authenticated<R: Rng>(
    client: &QueryClient,
    txid: [u8; 32],
    vout_index: u32,
    block_height: u32,
    config: &QueryConfig,
    _progress: &dyn QueryProgress,
    rng: &mut R,
    gamma: G1Projective,
) -> Result<QueryResult, QueryError> {
    let filter_data = filter_with_cover(client, block_height, config, rng)?;
    dispatch(client, txid, vout_index, block_height, &filter_data, rng, Some(gamma))
}

/// The fewest decoys a lookup will fetch alongside a real block. Matches the
/// SDK's `MIN_DECOYS_PER_INPUT`.
pub const MIN_DECOYS_PER_LOOKUP: usize = 4;

/// The filter for `block_height`, from the cache if a decoy prefetch already
/// fetched it, otherwise fetched **inside a fresh decoy set**.
///
/// Security review F14: this used to call `download_filter_cached`, which on
/// a cache miss downloaded the real height alone. Wallets prefetch filters
/// with decoys first, but when that prefetch failed or ran long (common over
/// Tor) every lookup then told the server exactly which block it was for.
/// Now a lone height is never requested: a miss fetches the real height
/// mixed with `config.num_decoys` Laplace decoys in one batch, and a config
/// with too few decoys, or no chain tip to draw them from, is refused.
fn filter_with_cover<R: Rng>(
    client: &QueryClient,
    block_height: u32,
    config: &QueryConfig,
    rng: &mut R,
) -> Result<Vec<u8>, QueryError> {
    if let Some(data) = QueryClient::cached_filter(block_height) {
        return Ok(data);
    }
    if config.num_decoys < MIN_DECOYS_PER_LOOKUP {
        return Err(QueryError::Other(format!(
            "refusing to fetch a block with {} decoys (minimum {})",
            config.num_decoys, MIN_DECOYS_PER_LOOKUP
        )));
    }
    if config.chain_tip < block_height {
        return Err(QueryError::Other(
            "refusing to fetch a block without a chain tip to draw decoys from".into(),
        ));
    }
    let scale = if config.laplace_scale > 0.0 { config.laplace_scale } else { 5.0 };
    let mut heights = cover_set(block_height, config.num_decoys, scale, config.chain_tip, rng);
    if heights.len() < MIN_DECOYS_PER_LOOKUP + 1 {
        return Err(QueryError::Other(
            "could not draw enough distinct decoy heights; refusing to fetch the block alone".into(),
        ));
    }
    heights.sort_unstable();

    let batch = client.download_filters_batch(&heights)?;
    let mut found = None;
    for (h, data) in batch.filters {
        if h == block_height {
            found = Some(data.clone());
        }
        QueryClient::cache_filter(h, data);
    }
    found.ok_or_else(|| QueryError::Other(format!("no filter available for block {}", block_height)))
}

/// `block_height` plus up to `num_decoys` distinct Laplace decoys in `[1, tip]`.
fn cover_set<R: Rng>(block_height: u32, num_decoys: usize, scale: f64, tip: u32, rng: &mut R) -> Vec<u32> {
    perseverus_core::laplace::select_decoy_blocks(block_height, num_decoys, scale, 1, tip, rng)
}

/// Inspect the version byte and route to the v3 or v5 implementation.
fn dispatch<R: Rng>(
    client: &QueryClient,
    txid: [u8; 32],
    vout_index: u32,
    block_height: u32,
    filter_data: &[u8],
    rng: &mut R,
    gamma: Option<G1Projective>,
) -> Result<QueryResult, QueryError> {
    let version = filter_data.get(4).copied().unwrap_or(0);
    if version == FILTER_FORMAT_VERSION_V5 {
        query_v5(client, txid, vout_index, block_height, filter_data, rng, gamma)
    } else if version == FILTER_FORMAT_VERSION_V3 {
        query_v3(client, txid, vout_index, block_height, filter_data, rng, gamma)
    } else {
        Err(QueryError::Other(format!(
            "unsupported filter version {} for block {}",
            version, block_height
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────
// v5 pipeline — per-transaction keying, codebook payload
// ─────────────────────────────────────────────────────────────────────

fn query_v5<R: Rng>(
    client: &QueryClient,
    txid: [u8; 32],
    vout_index: u32,
    block_height: u32,
    filter_data: &[u8],
    rng: &mut R,
    gamma_in: Option<G1Projective>,
) -> Result<QueryResult, QueryError> {
    let mut log_lines: Vec<String> = Vec::new();
    log_lines.push(format!("FILTER   v5   block={}", block_height));

    let filter = BlockFilterV5::deserialize(filter_data)
        .map_err(|e| QueryError::Other(format!("v5 filter deserialize: {}", e)))?;

    // ─── Load + verify the global codebook ──────────────────
    let cb_bytes = client.download_codebook()?;
    let codebook = Codebook::parse(&cb_bytes)
        .map_err(|e| QueryError::Other(format!("codebook parse: {}", e)))?;
    if codebook.id != filter.codebook_id {
        return Err(QueryError::Other(format!(
            "codebook id mismatch: filter wants {:02x?}, server has {:02x?}",
            filter.codebook_id, codebook.id
        )));
    }


    // ─── Scan Column A for the txid (per-TX keying) ─────────
    let sorted_hashes = filter.decode_hashes()
        .map_err(|e| QueryError::Other(format!("v5 Golomb decode: {}", e)))?;

    // Filters are keyed on the txid's INTERNAL byte order. Callers may hand us
    // either orientation (Sparrow's Sha256Hash vs. display/RPC order), so try
    // the given bytes first, then the reversed bytes, and use whichever scans.
    // The OPRF + decryption MUST then use that same orientation (`txid_used`),
    // since the filter's γ and nonce were derived from it.
    let (txid_used, rank) = match scan_filter_v5(
        &sorted_hashes, &txid, &filter.block_hash, filter.num_entries, filter.golomb_p,
    ) {
        Some(r) => (txid, r),
        None => {
            let mut rev = txid;
            rev.reverse();
            match scan_filter_v5(
                &sorted_hashes, &rev, &filter.block_hash, filter.num_entries, filter.golomb_p,
            ) {
                Some(r) => (rev, r),
                None => {
                    return Err(QueryError::UtxoNotFound {
                        txid_prefix: hex::encode(&txid[..8]),
                        vout: vout_index,
                        height: block_height,
                    })
                }
            }
        }
    };

    let enc_code = filter.enc_code_at(rank);

    // ─── Recover γ = k·H2C(txid): fresh OPRF or supplied ────
    let gamma = match gamma_in {
        Some(g) => g,
        None => oprf_recover_gamma(client, &txid_used, rng)?, // blind over the 32-byte txid
    };

    // ─── Decrypt the code and map through the codebook ──────
    let code = decrypt_code_v5(&gamma, &txid_used, &filter.block_hash, enc_code, filter.code_bits);
    let tag24 = codebook.tag_for(code).ok_or_else(|| QueryError::Other(format!(
        "decrypted code {} out of codebook range (len {})", code, codebook.len()
    )))?;


    Ok(QueryResult {
        txid,
        vout_index,
        block_height,
        tag: TagPayload::V3Lean(tag24),
        decoy_count: 0,
        decoy_heights: Vec::new(),
        log_lines,
    })
}

// ─────────────────────────────────────────────────────────────────────
// v3 pipeline — per-outpoint keying, KycTag payload (legacy)
// ─────────────────────────────────────────────────────────────────────

fn query_v3<R: Rng>(
    client: &QueryClient,
    txid: [u8; 32],
    vout_index: u32,
    block_height: u32,
    filter_data: &[u8],
    rng: &mut R,
    gamma_in: Option<G1Projective>,
) -> Result<QueryResult, QueryError> {
    let outpoint = TxOutpoint::new(txid, vout_index);
    let outpoint_bytes = outpoint.to_bytes();
    let mut log_lines: Vec<String> = Vec::new();
    log_lines.push(format!("FILTER   v3   block={}", block_height));

    let filter = BlockFilterV3::deserialize(filter_data)
        .map_err(|e| QueryError::Other(format!("v3 filter deserialize: {}", e)))?;

    let mut decoder = InterleavedGolombDecoder::new(
        &filter.stream, filter.golomb_p, TAG_CIPHERTEXT_LEN_V3,
    );
    let (deltas, enc_tags) = decoder
        .decode_all(filter.num_entries as usize)
        .map_err(|e| QueryError::Other(format!("Golomb decode: {}", e)))?;
    let sorted_hashes = reconstruct_from_deltas(&deltas);

    let match_idx = scan_filter_for_match_v3(
        &sorted_hashes,
        &outpoint,
        &filter.block_hash,
        filter.num_entries,
        filter.golomb_p,
    )
    .ok_or_else(|| QueryError::UtxoNotFound {
        txid_prefix: hex::encode(&txid[..8]),
        vout: vout_index,
        height: block_height,
    })?;

    // Recover γ = k·H2C(outpoint): fresh OPRF or supplied.
    let gamma = match gamma_in {
        Some(g) => g,
        None => oprf_recover_gamma(client, &outpoint_bytes, rng)?,
    };

    // Derive AES key, decrypt the 2-byte CTR tag.
    let aes_key = derive_tag_key(&gamma);
    let nonce = derive_nonce(&outpoint_bytes, &filter.block_hash);
    let encrypted_tag: &[u8] = &enc_tags[match_idx];
    let ct: [u8; TAG_CIPHERTEXT_LEN_V3] = encrypted_tag.try_into()
        .map_err(|_| QueryError::Other("tag length mismatch".into()))?;
    let decrypted_bytes = decrypt_tag_ctr(&aes_key, &nonce, &ct);
    let tag = KycTag::from_bytes(&decrypted_bytes)
        .map_err(|e| QueryError::Other(format!("tag deserialize: {}", e)))?;

    Ok(QueryResult {
        txid,
        vout_index,
        block_height,
        tag: TagPayload::Kyc(tag),
        decoy_count: 0,
        decoy_heights: Vec::new(),
        log_lines,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Shared OPRF helper
// ─────────────────────────────────────────────────────────────────────

/// Blind `input`, submit to the server's OPRF, verify the DLEQ proof, and
/// unblind to recover `γ = k·H2C(input)`. The caller passes the outpoint bytes
/// (v3) or the txid (v5) as `input`.
fn oprf_recover_gamma<R: Rng>(
    client: &QueryClient,
    input: &[u8],
    rng: &mut R,
) -> Result<G1Projective, QueryError> {
    let server_pubkey = client.get_server_pubkey()?;
    let blinded_query = blind(input, rng)
        .map_err(|e| QueryError::Other(format!("blinding: {}", e)))?;

    let (evaluated_points, proof) = client.oprf_evaluate(&[blinded_query.blinded_point])?;
    if evaluated_points.len() != 1 {
        return Err(QueryError::Other(format!(
            "expected 1 evaluated point, got {}", evaluated_points.len()
        )));
    }

    verify_batch(
        &server_pubkey,
        &[blinded_query.blinded_point],
        &evaluated_points,
        &proof,
    )
    .map_err(|_| QueryError::DleqVerificationFailed)?;

    let rho_inv = blinded_query
        .blinding_factor
        .inverse()
        .ok_or(QueryError::BlindingInverse)?;
    Ok(evaluated_points[0] * rho_inv)
}
