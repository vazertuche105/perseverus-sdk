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
    _config: &QueryConfig,
    _progress: &dyn QueryProgress,
    rng: &mut R,
) -> Result<QueryResult, QueryError> {
    let filter_data = client.download_filter_cached(block_height)?;
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
    _config: &QueryConfig,
    _progress: &dyn QueryProgress,
    rng: &mut R,
    gamma: G1Projective,
) -> Result<QueryResult, QueryError> {
    let filter_data = client.download_filter_cached(block_height)?;
    dispatch(client, txid, vout_index, block_height, &filter_data, rng, Some(gamma))
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
