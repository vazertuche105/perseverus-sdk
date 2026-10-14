//! Blocking HTTP client for the Perseverus filter + OPRF query flow.
//!
//! This mirrors the async `PerseverusClient` from `perseverus-cli` but
//! uses `reqwest::blocking` so it can be called directly from JNI
//! without forcing a tokio runtime on the JVM.
//!
//! Endpoints hit:
//!   - `GET  /server/pubkey`           → OPRF public key (G1 compressed)
//!   - `GET  /filters/{height}/exists` → filter cache check
//!   - `POST /filters/build/{height}`  → trigger filter construction
//!   - `GET  /filters/{height}`        → download filter bytes
//!   - `POST /oprf/evaluate`           → blinded OPRF evaluation

use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type G1Projective = EdwardsProjective;
type G1Affine = EdwardsAffine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use perseverus_core::dleq::DleqProof;

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide in-memory filter cache. Populated by the prefetch JNI
/// call and read by `download_filter_cached`. Keyed on block height.
fn filter_cache() -> &'static Mutex<HashMap<u32, Vec<u8>>> {
    static CACHE: OnceLock<Mutex<HashMap<u32, Vec<u8>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Process-wide cache of the global v5 codebook bytes, keyed by server base URL.
/// The codebook is small and immutable for a given epoch, so one fetch per
/// server suffices for the whole session.
fn codebook_cache() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Download progress tracking — Java polls these via JNI.
static PREFETCH_DOWNLOADED: AtomicU64 = AtomicU64::new(0);
static PREFETCH_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Reset progress counters (call before starting a new prefetch).
pub fn prefetch_progress_reset() {
    PREFETCH_DOWNLOADED.store(0, Ordering::Relaxed);
    PREFETCH_TOTAL.store(0, Ordering::Relaxed);
}

/// Read current progress: (downloaded_bytes, total_bytes).
pub fn prefetch_progress() -> (u64, u64) {
    (
        PREFETCH_DOWNLOADED.load(Ordering::Relaxed),
        PREFETCH_TOTAL.load(Ordering::Relaxed),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum QueryClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("server error ({status}): {body}")]
    ServerStatus { status: u16, body: String },

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("ark deserialization error: {0}")]
    ArkSerde(String),

    #[error("{0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────
// Wire types (JSON)
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct PubkeyResponse {
    pubkey_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OprfRequest {
    blinded_points: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OprfResponse {
    evaluated_points: Vec<String>,
    proof_challenge: String,
    proof_response: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BuildFilterRequest {
    max_txs: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildFilterInfo {
    pub height: u32,
    pub num_entries: u32,
    pub num_outputs: usize,
    pub num_transactions: usize,
    pub filter_size_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct FilterResponse {
    filter_hex: String,
    height: u32,
    num_entries: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExistsResponse {
    exists: bool,
}

// ─────────────────────────────────────────────────────────────────────
// Client
// ─────────────────────────────────────────────────────────────────────

/// Blocking HTTP client for the filter-query OPRF flow.
///
/// Unlike [`crate::IssuanceClient`] and [`crate::SpendClient`], this
/// client does NOT hold a server pubkey at construction time — the
/// pubkey is fetched lazily on the first query so the caller doesn't
/// have to know it up front.
pub struct QueryClient {
    http: reqwest::blocking::Client,
    base_url: String,
}

/// Result of a batch filter download: the filters we got + heights
/// the server didn't have cached.
pub struct BatchResult {
    pub filters: Vec<(u32, Vec<u8>)>,
    pub missing: Vec<u32>,
}

impl QueryClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        // For a loopback server, build a client that ignores any system / env
        // proxy (ALL_PROXY, HTTP_PROXY, macOS system proxy). Otherwise a Tor
        // SOCKS proxy in the environment would try to route 127.0.0.1 through
        // Tor, which refuses loopback — surfacing as "error sending request".
        // Non-loopback hosts (e.g. .onion) keep the default client so the
        // configured proxy still applies.
        let lower = base_url.to_ascii_lowercase();
        let is_loopback = lower.contains("127.0.0.1")
            || lower.contains("//localhost")
            || lower.contains("[::1]");
        let http = if is_loopback {
            reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new())
        } else {
            reqwest::blocking::Client::new()
        };
        Self { http, base_url }
    }

    /// Replace the HTTP client — useful for routing through a Tor
    /// SOCKS5 proxy or injecting a custom timeout / TLS config.
    pub fn with_http(mut self, http: reqwest::blocking::Client) -> Self {
        self.http = http;
        self
    }

    /// Fetch the server's OPRF public key V = k·G.
    pub fn get_server_pubkey(&self) -> Result<G1Projective, QueryClientError> {
        let resp: PubkeyResponse = self.http
            .get(format!("{}/server/pubkey", self.base_url))
            .send()?
            .error_for_status()?
            .json()?;

        let bytes = hex::decode(&resp.pubkey_hex)?;
        let affine = G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|e| QueryClientError::ArkSerde(format!("invalid G1 pubkey: {}", e)))?;
        Ok(affine.into())
    }

    /// Check if the server has a cached filter for this block height.
    pub fn filter_exists(&self, height: u32) -> Result<bool, QueryClientError> {
        let resp = self.http
            .get(format!("{}/filters/{}/exists", self.base_url, height))
            .send()?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let exists: ExistsResponse = resp.json()?;
        Ok(exists.exists)
    }

    /// Download a pre-built filter as raw bytes.
    pub fn download_filter(&self, height: u32) -> Result<Vec<u8>, QueryClientError> {
        let resp = self.http
            .get(format!("{}/filters/{}", self.base_url, height))
            .send()?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(QueryClientError::ServerStatus { status, body });
        }

        let filter_resp: FilterResponse = resp.json()?;
        let data = hex::decode(&filter_resp.filter_hex)?;
        Ok(data)
    }

    /// Download a filter, using the in-memory cache first. If the cache
    /// has data for this height, returns it immediately without any HTTP
    /// call. Otherwise downloads from the server and stores in cache.
    pub fn download_filter_cached(&self, height: u32) -> Result<Vec<u8>, QueryClientError> {
        // Check cache first.
        if let Ok(cache) = filter_cache().lock() {
            if let Some(data) = cache.get(&height) {
                return Ok(data.clone());
            }
        }
        // Cache miss — download and store.
        let data = self.download_filter(height)?;
        if let Ok(mut cache) = filter_cache().lock() {
            cache.insert(height, data.clone());
        }
        Ok(data)
    }

    /// Download the global v5 tag codebook (PSCB bytes) from `GET /codebook`,
    /// caching per server base URL. Returns the raw bytes for [`crate::codebook::Codebook::parse`].
    pub fn download_codebook(&self) -> Result<Vec<u8>, QueryClientError> {
        if let Ok(cache) = codebook_cache().lock() {
            if let Some(data) = cache.get(&self.base_url) {
                return Ok(data.clone());
            }
        }

        #[derive(serde::Deserialize)]
        struct CodebookResp { codebook_hex: String, #[allow(dead_code)] len: usize }

        let resp = self.http
            .get(format!("{}/codebook", self.base_url))
            .send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(QueryClientError::ServerStatus { status, body });
        }
        let cb: CodebookResp = resp.json()?;
        let data = hex::decode(&cb.codebook_hex)?;

        if let Ok(mut cache) = codebook_cache().lock() {
            cache.insert(self.base_url.clone(), data.clone());
        }
        Ok(data)
    }

    /// Batch-download filters for many block heights. The server caps a single
    /// batch at 200 heights, so this splits the request into ≤200-height chunks
    /// (one round-trip each) and aggregates the results. Global progress counters
    /// accumulate across chunks so the Java UI shows a real, moving progress bar
    /// even for large decoy sets.
    pub fn download_filters_batch(&self, heights: &[u32]) -> Result<BatchResult, QueryClientError> {
        const MAX_BATCH_HEIGHTS: usize = 200;
        // Realistic-ish per-filter JSON estimate so the bar tracks sensibly
        // (refined to the actual byte total when everything is in).
        const PER_FILTER_EST: u64 = 12 * 1024;

        PREFETCH_TOTAL.store((heights.len() as u64 * PER_FILTER_EST).max(1), Ordering::Relaxed);
        PREFETCH_DOWNLOADED.store(0, Ordering::Relaxed);

        let mut all_filters: Vec<(u32, Vec<u8>)> = Vec::with_capacity(heights.len());
        let mut all_missing: Vec<u32> = Vec::new();

        let nchunks = (heights.len() + MAX_BATCH_HEIGHTS - 1) / MAX_BATCH_HEIGHTS;
        for (i, chunk) in heights.chunks(MAX_BATCH_HEIGHTS).enumerate() {
            eprintln!("[prefetch] batch chunk {}/{} ({} heights)", i + 1, nchunks, chunk.len());
            let (filters, missing) = self.download_filters_batch_chunk(chunk)?;
            all_filters.extend(filters);
            all_missing.extend(missing);
        }

        // Finalize the bar to the true byte total.
        let actual: u64 = all_filters.iter().map(|(_, d)| d.len() as u64).sum::<u64>().max(1);
        PREFETCH_TOTAL.store(actual, Ordering::Relaxed);
        PREFETCH_DOWNLOADED.store(actual, Ordering::Relaxed);

        if !all_missing.is_empty() {
            eprintln!("[prefetch] {} heights out of coverage (no filter)", all_missing.len());
        }
        Ok(BatchResult { filters: all_filters, missing: all_missing })
    }

    /// One batch request (≤200 heights). Streams the body, adding bytes to the
    /// shared PREFETCH_DOWNLOADED counter (does NOT reset it — the caller owns
    /// the totals so progress accumulates across chunks).
    fn download_filters_batch_chunk(
        &self,
        heights: &[u32],
    ) -> Result<(Vec<(u32, Vec<u8>)>, Vec<u32>), QueryClientError> {
        use std::io::Read;

        #[derive(serde::Serialize)]
        struct Req { heights: Vec<u32> }
        #[derive(serde::Deserialize)]
        struct FilterEntry { filter_hex: String, height: u32 }
        #[derive(serde::Deserialize)]
        struct Resp { filters: Vec<FilterEntry>, missing: Vec<u32> }

        let mut resp = self.http
            .post(format!("{}/filters/batch", self.base_url))
            .json(&Req { heights: heights.to_vec() })
            .send()?
            .error_for_status()?;

        let mut body = Vec::new();
        let mut buf = [0u8; 32768];
        loop {
            let n = resp.read(&mut buf)
                .map_err(|e| QueryClientError::Other(format!("read error: {}", e)))?;
            if n == 0 { break; }
            body.extend_from_slice(&buf[..n]);
            PREFETCH_DOWNLOADED.fetch_add(n as u64, Ordering::Relaxed);
        }

        let parsed: Resp = serde_json::from_slice(&body)
            .map_err(|e| QueryClientError::Other(format!("json parse: {}", e)))?;

        let mut result = Vec::with_capacity(parsed.filters.len());
        for entry in parsed.filters {
            let data = hex::decode(&entry.filter_hex)?;
            result.push((entry.height, data));
        }
        Ok((result, parsed.missing))
    }

    /// Store filter bytes in the in-memory cache (used by the prefetch
    /// JNI call to warm the cache before queries start).
    pub fn cache_filter(height: u32, data: Vec<u8>) {
        if let Ok(mut cache) = filter_cache().lock() {
            cache.insert(height, data);
        }
    }

    /// Submit blinded OPRF points and receive evaluated points + DLEQ proof.
    pub fn oprf_evaluate(
        &self,
        blinded_points: &[G1Projective],
    ) -> Result<(Vec<G1Projective>, DleqProof), QueryClientError> {
        // Serialize to hex
        let mut points_hex = Vec::with_capacity(blinded_points.len());
        for pt in blinded_points {
            let mut buf = Vec::new();
            pt.into_affine()
                .serialize_compressed(&mut buf)
                .map_err(|e| QueryClientError::ArkSerde(format!("point serialize: {}", e)))?;
            points_hex.push(hex::encode(&buf));
        }

        let resp = self.http
            .post(format!("{}/oprf/evaluate", self.base_url))
            .json(&OprfRequest { blinded_points: points_hex })
            .send()?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(QueryClientError::ServerStatus { status, body });
        }

        let oprf_resp: OprfResponse = resp.json()?;

        // Deserialize evaluated points
        let mut evaluated = Vec::with_capacity(oprf_resp.evaluated_points.len());
        for hex_str in &oprf_resp.evaluated_points {
            let bytes = hex::decode(hex_str)?;
            let affine = G1Affine::deserialize_compressed(&bytes[..])
                .map_err(|e| QueryClientError::ArkSerde(format!("evaluated G1: {}", e)))?;
            evaluated.push(G1Projective::from(affine));
        }

        // Deserialize DLEQ proof scalars
        let challenge = Fr::deserialize_compressed(&hex::decode(&oprf_resp.proof_challenge)?[..])
            .map_err(|e| QueryClientError::ArkSerde(format!("proof challenge: {}", e)))?;
        let response = Fr::deserialize_compressed(&hex::decode(&oprf_resp.proof_response)?[..])
            .map_err(|e| QueryClientError::ArkSerde(format!("proof response: {}", e)))?;

        Ok((evaluated, DleqProof { challenge, response }))
    }
}
