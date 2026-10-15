//! Native `SpendClient` — the wallet-side end of the spend path (v9).
//!
//! ```text
//!  caller ─► SpendClient::spend(issued, spend_idx, input, current_month, rng)
//!     │         │
//!     │         ├─ derive P_i = Poseidon(seed, pack_id, idx)·H_TOKEN
//!     │         ├─ GET  /revocation/root + /revocation/proof/{pack_id}
//!     │         ├─ Groth16::prove(RevocationSpendCircuit)
//!     │         ├─ POST /oprf/evaluate {α, SpendProof}
//!     │         └─ DLEQ-verify + unblind β
//!     ▼
//!   G1Projective: γ
//! ```
//!
//! ### Privacy boundary (v6)
//!
//! The v6 circuit no longer references the bulletin board at all. The
//! proof demonstrates SMT non-inclusion (pack not revoked) instead of
//! board membership. The wallet fetches the revocation root and a
//! non-inclusion proof for its pack_id — the server cannot distinguish
//! which pack is being spent because ALL non-revoked packs share the
//! same revocation root.
//!
//! ### Changes from v4
//!
//! - Removed: bulletin board fetch + leaf position lookup
//! - Removed: α-binding (OPRF blinding handled off-circuit)
//! - Removed: blinding_factor / Pedersen commitment usage
//! - Added: revocation root fetch + SMT non-inclusion proof
//! - Circuit: `RevocationSpendCircuit` (6 constraints, 3 public inputs)

use std::sync::Mutex;
use std::time::Duration;

use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::Rng;
use serde::{Deserialize, Serialize};

type G1Projective = EdwardsProjective;
type G1Affine = EdwardsAffine;

use ark_ff::UniformRand;

use perseverus_circuits::{CircuitField, RevocationSpendCircuit};
use perseverus_core::dleq::{DleqProof, bjj_scalar_to_poseidon_field};
use perseverus_core::oprf::{blind, verify_batch};
use perseverus_core::issuance::IssuedPack;
use perseverus_core::nullifier::compute_nullifier;
use perseverus_core::poseidon::PoseidonField;
use perseverus_core::smt::{revocation_key, SparseMerkleTree};
use perseverus_core::types::PerseverusError;

/// Per-proof Groth16 generation timings (milliseconds) from the most
/// recent `spend_batch` call. Written by `spend_batch`, read by JNI's
/// `spendBatchProofTimingsMs`.
static BATCH_PROOF_TIMINGS_MS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Returns the per-proof timings from the last `spend_batch` call.
pub fn last_batch_proof_timings_ms() -> Vec<u64> {
    BATCH_PROOF_TIMINGS_MS.lock().unwrap().clone()
}

/// Error surface for the spend client.
#[derive(Debug, thiserror::Error)]
pub enum SpendClientError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned {status}: {body}")]
    ServerStatus { status: u16, body: String },
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("ark serialization: {0}")]
    ArkSerde(String),
    #[error("crypto: {0}")]
    Crypto(#[from] PerseverusError),
    #[error("proof generation: {0}")]
    Proof(String),
    #[error("pack has been revoked — cannot spend")]
    PackRevoked,
    #[error("unexpected response shape: {0}")]
    BadResponse(String),
}

impl From<ark_serialize::SerializationError> for SpendClientError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::ArkSerde(e.to_string())
    }
}

// ─── Wire types (must match server/src/api/routes.rs) ──────────────

#[derive(Debug, Serialize, Deserialize)]
struct RevocationRootResponseWire {
    revocation_root_hex: String,
    /// Legacy only; `/v1` doesn't send it.
    #[serde(default)]
    tree_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct RevocationListResponseWire {
    revocation_root_hex: String,
    revoked_keys_hex: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RevocationProofResponseWire {
    siblings_hex: Vec<String>,
    path_bits: Vec<bool>,
    is_included: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpendProofWire {
    nullifier_hex: String,
    current_month: u64,
    revocation_root_hex: String,
    proof_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OprfRequestWire {
    blinded_points: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spend: Option<SpendProofWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OprfResponseWire {
    evaluated_points: Vec<String>,
    proof_challenge: String,
    proof_response: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchOprfRequestWire {
    requests: Vec<OprfRequestWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchOprfResponseWire {
    responses: Vec<BatchOprfEntryWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchOprfEntryWire {
    ok: bool,
    evaluated_points: Option<Vec<String>>,
    proof_challenge: Option<String>,
    proof_response: Option<String>,
    error: Option<String>,
}

// ─── Client ────────────────────────────────────────────────────────

/// Blocking HTTP client for the `/oprf/evaluate` spend path (v6).
///
/// Holds the proving key (large — several MB) plus pinned server
/// pubkeys. Cheap to clone; `Arc`s inside.
#[derive(Clone)]
pub struct SpendClient {
    base_url: String,
    http: reqwest::blocking::Client,
    poseidon: PoseidonConfig<PoseidonField>,
    pk: ProvingKey<Bn254>,
    server_pubkey_g1: G1Projective,
    /// "" for the legacy routes (Sparrow), "/v1" for the versioned API.
    api_prefix: &'static str,
}

impl std::fmt::Debug for SpendClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl SpendClient {
    /// Build a client bound to a specific server URL and set of pinned
    /// public parameters.
    pub fn new(
        base_url: impl Into<String>,
        pk: ProvingKey<Bn254>,
        server_pubkey_g1: G1Projective,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("default blocking client must build"),
            poseidon: perseverus_core::poseidon::poseidon_config(),
            pk,
            server_pubkey_g1,
            api_prefix: "",
        }
    }

    /// Use the versioned `/v1` API (revocation and `/v1/analyze/batch`).
    /// Legacy routes stay the default for Sparrow.
    pub fn with_v1(mut self) -> Self {
        self.api_prefix = "/v1";
        self
    }

    /// Replace the HTTP client.
    pub fn with_http(mut self, http: reqwest::blocking::Client) -> Self {
        self.http = http;
        self
    }

    /// Override the Poseidon config.
    pub fn with_poseidon(mut self, cfg: PoseidonConfig<PoseidonField>) -> Self {
        self.poseidon = cfg;
        self
    }

    /// Fetch and deserialize the server's Groth16 proving key.
    pub fn fetch_proving_key(
        base_url: &str,
        http: &reqwest::blocking::Client,
    ) -> Result<ProvingKey<Bn254>, SpendClientError> {
        let url = format!("{}/circuit/pk", base_url.trim_end_matches('/'));
        let resp = http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let bytes = resp.bytes()?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&bytes[..])?;
        Ok(pk)
    }

    /// Load the proving key from a local cache file, or fetch from the
    /// server and write it to the cache path for next time.
    pub fn fetch_proving_key_cached(
        base_url: &str,
        http: &reqwest::blocking::Client,
        cache_path: &std::path::Path,
    ) -> Result<ProvingKey<Bn254>, SpendClientError> {
        if cache_path.exists() {
            eprintln!("[bootstrap] loading cached pk from {}", cache_path.display());
            let bytes = std::fs::read(cache_path)
                .map_err(|e| SpendClientError::Proof(format!("read cache: {}", e)))?;
            match ProvingKey::<Bn254>::deserialize_compressed(&bytes[..]) {
                Ok(pk) => {
                    eprintln!("[bootstrap] cached pk loaded ({} bytes)", bytes.len());
                    return Ok(pk);
                }
                Err(e) => {
                    eprintln!("[bootstrap] cached pk invalid ({}), re-downloading", e);
                    let _ = std::fs::remove_file(cache_path);
                }
            }
        }

        eprintln!("[bootstrap] downloading pk from server...");
        let url = format!("{}/circuit/pk", base_url.trim_end_matches('/'));
        let resp = http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let bytes = resp.bytes()?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&bytes[..])?;

        if let Some(parent) = cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(cache_path, &bytes) {
            eprintln!("[bootstrap] warning: failed to cache pk: {}", e);
        } else {
            eprintln!("[bootstrap] pk cached to {}", cache_path.display());
        }

        Ok(pk)
    }

    /// Fetch and deserialize the server's Groth16 verifying key.
    pub fn fetch_verifying_key(
        base_url: &str,
        http: &reqwest::blocking::Client,
    ) -> Result<ark_groth16::VerifyingKey<Bn254>, SpendClientError> {
        let url = format!("{}/circuit/vk", base_url.trim_end_matches('/'));
        let resp = http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let bytes = resp.bytes()?;
        let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..])?;
        Ok(vk)
    }

    /// Full bootstrap: fetch `pk` and build a `SpendClient`.
    pub fn bootstrap(
        base_url: impl Into<String>,
        server_pubkey_g1: G1Projective,
    ) -> Result<Self, SpendClientError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("default blocking client must build");
        let pk = Self::fetch_proving_key(&base_url, &http)?;

        Ok(Self {
            base_url,
            http,
            poseidon: perseverus_core::poseidon::poseidon_config(),
            pk,
            server_pubkey_g1,
            api_prefix: "",
        })
    }

    /// Bootstrap with a pre-configured HTTP client (e.g. one routed
    /// through a Tor SOCKS5 proxy).
    pub fn bootstrap_with_http(
        base_url: impl Into<String>,
        server_pubkey_g1: G1Projective,
        http: reqwest::blocking::Client,
    ) -> Result<Self, SpendClientError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let pk = Self::fetch_proving_key(&base_url, &http)?;

        Ok(Self {
            base_url,
            http,
            poseidon: perseverus_core::poseidon::poseidon_config(),
            pk,
            server_pubkey_g1,
            api_prefix: "",
        })
    }

    /// Bootstrap with a local PK cache.
    pub fn bootstrap_with_cache(
        base_url: impl Into<String>,
        server_pubkey_g1: G1Projective,
        http: reqwest::blocking::Client,
        cache_path: &std::path::Path,
    ) -> Result<Self, SpendClientError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let pk = Self::fetch_proving_key_cached(&base_url, &http, cache_path)?;

        Ok(Self {
            base_url,
            http,
            poseidon: perseverus_core::poseidon::poseidon_config(),
            pk,
            server_pubkey_g1,
            api_prefix: "",
        })
    }

    /// Fetch the current revocation tree root from the server.
    pub fn fetch_revocation_root(&self) -> Result<(PoseidonField, usize), SpendClientError> {
        let url = format!("{}{}/revocation/root", self.base_url, self.api_prefix);
        let resp = self.http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let wire: RevocationRootResponseWire = resp.json()?;
        let bytes = hex::decode(&wire.revocation_root_hex)?;
        let root = PoseidonField::deserialize_compressed(&bytes[..])?;
        Ok((root, wire.tree_size))
    }

    /// Download the whole revocation list and rebuild the tree locally.
    ///
    /// Every wallet downloads the same list, so the request says nothing
    /// about which pack this wallet holds; non-inclusion proofs are then
    /// built on the device (`revocation_proof_local`). Fails if the keys
    /// don't hash to the root the server published alongside them.
    pub fn fetch_revocation_tree(&self) -> Result<(SparseMerkleTree, PoseidonField), SpendClientError> {
        let url = format!("{}{}/revocation/list", self.base_url, self.api_prefix);
        let resp = self.http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let wire: RevocationListResponseWire = resp.json()?;
        let mut keys = Vec::with_capacity(wire.revoked_keys_hex.len());
        for h in &wire.revoked_keys_hex {
            keys.push(PoseidonField::deserialize_compressed(&hex::decode(h)?[..])?);
        }
        let root = PoseidonField::deserialize_compressed(&hex::decode(&wire.revocation_root_hex)?[..])?;
        let tree = SparseMerkleTree::from_keys(keys);
        if tree.root() != root {
            return Err(SpendClientError::BadResponse(
                "revocation list does not hash to the published root".into(),
            ));
        }
        Ok((tree, root))
    }

    /// Whether `pack_id` is revoked in `tree` (checked on the device).
    pub fn is_pack_revoked(&self, tree: &SparseMerkleTree, pack_id: u64) -> bool {
        tree.is_slot_occupied(revocation_key(&self.poseidon, PoseidonField::from(pack_id)))
    }

    /// Build a pack's non-inclusion proof on the device from a tree
    /// returned by `fetch_revocation_tree`. Nothing is sent to the server.
    pub fn revocation_proof_local(
        &self,
        tree: &SparseMerkleTree,
        pack_id: u64,
    ) -> Result<(Vec<PoseidonField>, Vec<bool>), SpendClientError> {
        let key = revocation_key(&self.poseidon, PoseidonField::from(pack_id));
        let proof = tree.try_prove_non_inclusion(key).ok_or(SpendClientError::PackRevoked)?;
        Ok((proof.siblings, proof.path_bits))
    }

    /// Fetch the SMT non-inclusion proof for a pack_id from the server.
    ///
    /// Deprecated: this puts `pack_id` on the wire, which lets the server
    /// link spends from the same pack. Spends use `fetch_revocation_tree`
    /// + `revocation_proof_local` instead.
    #[deprecated(note = "reveals pack_id to the server; use fetch_revocation_tree + revocation_proof_local")]
    pub fn fetch_revocation_proof(
        &self,
        pack_id: u64,
    ) -> Result<(Vec<PoseidonField>, Vec<bool>), SpendClientError> {
        let url = format!("{}{}/revocation/proof/{}", self.base_url, self.api_prefix, pack_id);
        let resp = self.http.get(&url).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let wire: RevocationProofResponseWire = resp.json()?;
        if wire.is_included {
            return Err(SpendClientError::PackRevoked);
        }
        let mut siblings = Vec::with_capacity(wire.siblings_hex.len());
        for hex_str in &wire.siblings_hex {
            let bytes = hex::decode(hex_str)?;
            siblings.push(PoseidonField::deserialize_compressed(&bytes[..])?);
        }
        Ok((siblings, wire.path_bits))
    }

    /// Run the full spend round-trip (v6).
    ///
    /// Arguments:
    /// - `issued`: the pack issued earlier (via `IssuanceClient::issue_pack`).
    /// - `spend_idx`: which token in the pack to burn.
    /// - `input`: OPRF query input (e.g. TXID for filter decryption).
    /// - `current_month`: the current month in YYYYMM format.
    ///
    /// Returns the unblinded γ = v·H2C(input). On success, the spend
    /// has been committed on the server side (nullifier burned).
    pub fn spend<R: Rng + rand::CryptoRng>(
        &self,
        issued: &IssuedPack,
        spend_idx: usize,
        input: &[u8],
        current_month: u32,
        rng: &mut R,
    ) -> Result<G1Projective, SpendClientError> {
        if spend_idx >= issued.pack.tokens.len() {
            return Err(SpendClientError::Proof(format!(
                "spend_idx {} out of range (pack has {} tokens)",
                spend_idx,
                issued.pack.tokens.len()
            )));
        }

        // 1. Blind the OPRF query input.
        let query = blind(input, rng)
            .map_err(|e| SpendClientError::Proof(format!("blind query: {}", e)))?;

        // 2. Download the public revocation list and prove non-inclusion
        //    on the device (pack_id never leaves it).
        let (revocation_tree, revocation_root) = self.fetch_revocation_tree()?;
        let (smt_siblings, smt_path_bits) = self.revocation_proof_local(&revocation_tree, issued.pack_id)?;

        // 3. Compute circuit inputs.
        let spend_idx_f = CircuitField::from(spend_idx as u64);
        let pack_id_f = CircuitField::from(issued.pack_id);
        let nullifier = compute_nullifier(
            &self.poseidon,
            issued.token_seed,
            pack_id_f,
            spend_idx_f,
        );

        let dleq_proof = &issued.poseidon_dleq_proofs[spend_idx];
        let token = &issued.pack.tokens[spend_idx];
        let blinded_sig = G1Projective::from(token.blinded_sig);

        // 4. Build + prove the v9 circuit (pk_server as constant, activation epoch).
        let current_month_field = CircuitField::from(current_month as u64);
        let expiration_month_field = CircuitField::from(issued.expiration_month as u64);
        let start_month_field = CircuitField::from(issued.start_month as u64);

        let circuit = RevocationSpendCircuit {
            // Public inputs
            nullifier: Some(nullifier),
            current_month: Some(current_month_field),
            revocation_root: Some(revocation_root),
            // Constant (baked into R1CS at setup time)
            pk_server: self.server_pubkey_g1,
            // Witnesses
            token_seed: Some(issued.token_seed),
            pack_id: Some(pack_id_f),
            token_index: Some(spend_idx_f),
            blinded_sig: Some(blinded_sig),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(expiration_month_field),
            start_month: Some(start_month_field),
            smt_siblings: Some(smt_siblings),
            smt_path_bits: Some(smt_path_bits),
        };

        // ── diagnostic: dump public inputs used for proving ──
        {
            use ark_serialize::CanonicalSerialize as _;
            let mut null_dbg = Vec::new();
            nullifier.serialize_compressed(&mut null_dbg).ok();
            let mut cm_dbg = Vec::new();
            current_month_field.serialize_compressed(&mut cm_dbg).ok();
            let mut root_dbg = Vec::new();
            revocation_root.serialize_compressed(&mut root_dbg).ok();
            let mut pk_srv_dbg = Vec::new();
            self.server_pubkey_g1.into_affine().serialize_compressed(&mut pk_srv_dbg).ok();
            eprintln!(
                "[spend-client] prove: nullifier={} current_month_raw={} current_month_field={} rev_root={} pk_server={}",
                hex::encode(&null_dbg),
                current_month,
                hex::encode(&cm_dbg),
                hex::encode(&root_dbg),
                hex::encode(&pk_srv_dbg),
            );
        }

        let proof = Groth16::<Bn254>::prove(&self.pk, circuit, rng)
            .map_err(|e| SpendClientError::Proof(format!("Groth16 prove: {}", e)))?;

        // 5. POST /oprf/evaluate carrying the spend witness.
        let mut alpha_query_buf = Vec::new();
        query.blinded_point.into_affine().serialize_compressed(&mut alpha_query_buf)?;
        let mut proof_buf = Vec::new();
        proof.serialize_compressed(&mut proof_buf)?;
        let mut null_buf = Vec::new();
        nullifier.serialize_compressed(&mut null_buf)?;
        let mut rev_root_buf = Vec::new();
        revocation_root.serialize_compressed(&mut rev_root_buf)?;

        let body = OprfRequestWire {
            blinded_points: vec![hex::encode(&alpha_query_buf)],
            spend: Some(SpendProofWire {
                nullifier_hex: hex::encode(&null_buf),
                current_month: current_month as u64,
                revocation_root_hex: hex::encode(&rev_root_buf),
                proof_hex: hex::encode(&proof_buf),
            }),
        };
        let url = format!("{}/oprf/evaluate", self.base_url);
        let resp = self.http.post(&url).json(&body).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let wire: OprfResponseWire = resp.json()?;

        // 6. Decode β, verify DLEQ, unblind.
        if wire.evaluated_points.is_empty() {
            return Err(SpendClientError::BadResponse(
                "expected at least 1 evaluated point".into(),
            ));
        }
        let beta_query_bytes = hex::decode(&wire.evaluated_points[0])?;
        let beta_query: G1Projective = G1Affine::deserialize_compressed(&beta_query_bytes[..])?.into();

        let challenge_bytes = hex::decode(&wire.proof_challenge)?;
        let response_bytes = hex::decode(&wire.proof_response)?;
        let challenge = Fr::deserialize_compressed(&challenge_bytes[..])?;
        let response = Fr::deserialize_compressed(&response_bytes[..])?;
        let dleq = DleqProof { challenge, response };

        verify_batch(
            &self.server_pubkey_g1,
            &[query.blinded_point],
            &[beta_query],
            &dleq,
        )?;

        // γ = ρ⁻¹ · β = v · H2C(input)
        let rho_inv = query.blinding_factor
            .inverse()
            .ok_or(PerseverusError::InvalidCurvePoint)?;
        Ok(beta_query * rho_inv)
    }

    /// Batch spend — generate all proofs locally, then send them to the
    /// server in one HTTP round trip. Returns a Vec of Results, one per
    /// input. The revocation list is downloaded once and every
    /// non-inclusion proof is built on the device.
    pub fn spend_batch<R: Rng + rand::CryptoRng>(
        &self,
        spend_items: &[(&IssuedPack, usize, &[u8])],
        current_month: u32,
        rng: &mut R,
    ) -> Result<Vec<Result<G1Projective, SpendClientError>>, SpendClientError> {
        if spend_items.is_empty() {
            return Ok(Vec::new());
        }
        let revocation = self.fetch_revocation_tree()?;
        self.spend_batch_with_revocation(spend_items, current_month, &revocation, rng)
    }

    /// `spend_batch` with a revocation tree the caller already downloaded
    /// (`fetch_revocation_tree`), e.g. to skip revoked packs before
    /// reserving tokens. Returns `PackRevoked` before sending anything if
    /// any item's pack is revoked in that tree.
    pub fn spend_batch_with_revocation<R: Rng + rand::CryptoRng>(
        &self,
        spend_items: &[(&IssuedPack, usize, &[u8])],
        current_month: u32,
        revocation: &(SparseMerkleTree, PoseidonField),
        rng: &mut R,
    ) -> Result<Vec<Result<G1Projective, SpendClientError>>, SpendClientError> {
        if spend_items.is_empty() {
            return Ok(Vec::new());
        }
        let (revocation_tree, revocation_root) = (&revocation.0, revocation.1);

        // 2. Generate all proofs locally.
        struct PreparedSpend {
            query: perseverus_core::oprf::BlindedQuery,
            request: OprfRequestWire,
        }

        // Clear per-proof timing accumulator.
        {
            let mut timings = BATCH_PROOF_TIMINGS_MS.lock().unwrap();
            timings.clear();
            timings.reserve(spend_items.len());
        }

        let mut proof_cache: std::collections::HashMap<u64, (Vec<PoseidonField>, Vec<bool>)> =
            std::collections::HashMap::new();
        let mut prepared: Vec<PreparedSpend> = Vec::with_capacity(spend_items.len());
        for (i, &(issued, spend_idx, input)) in spend_items.iter().enumerate() {
            let t_proof = std::time::Instant::now();
            if spend_idx >= issued.pack.tokens.len() {
                return Err(SpendClientError::Proof(format!(
                    "spend_idx {} out of range (pack has {} tokens)",
                    spend_idx, issued.pack.tokens.len()
                )));
            }

            let query = blind(input, rng)
                .map_err(|e| SpendClientError::Proof(format!("blind query: {}", e)))?;

            // Non-inclusion proof, built locally once per pack.
            let (smt_siblings, smt_path_bits) = match proof_cache.get(&issued.pack_id) {
                Some(p) => p.clone(),
                None => {
                    let p = self.revocation_proof_local(revocation_tree, issued.pack_id)?;
                    proof_cache.insert(issued.pack_id, p.clone());
                    p
                }
            };

            let spend_idx_f = CircuitField::from(spend_idx as u64);
            let pack_id_f = CircuitField::from(issued.pack_id);
            let nullifier = compute_nullifier(
                &self.poseidon, issued.token_seed, pack_id_f, spend_idx_f,
            );

            let dleq_proof = &issued.poseidon_dleq_proofs[spend_idx];
            let token = &issued.pack.tokens[spend_idx];
            let blinded_sig = G1Projective::from(token.blinded_sig);
            let current_month_field = CircuitField::from(current_month as u64);
            let expiration_month_field = CircuitField::from(issued.expiration_month as u64);
            let start_month_field = CircuitField::from(issued.start_month as u64);

            // ── diagnostic: dump proving inputs for batch item ──
            if i == 0 {
                use ark_serialize::CanonicalSerialize as _;
                let mut null_dbg = Vec::new();
                nullifier.serialize_compressed(&mut null_dbg).ok();
                let mut cm_dbg = Vec::new();
                current_month_field.serialize_compressed(&mut cm_dbg).ok();
                let mut root_dbg = Vec::new();
                revocation_root.serialize_compressed(&mut root_dbg).ok();
                let mut pk_srv_dbg = Vec::new();
                self.server_pubkey_g1.into_affine().serialize_compressed(&mut pk_srv_dbg).ok();
                eprintln!(
                    "[spend_batch] item[0] prove: nullifier={} current_month_raw={} current_month_field={} rev_root={} pk_server={}",
                    hex::encode(&null_dbg),
                    current_month,
                    hex::encode(&cm_dbg),
                    hex::encode(&root_dbg),
                    hex::encode(&pk_srv_dbg),
                );
            }

            let circuit = RevocationSpendCircuit {
                nullifier: Some(nullifier),
                current_month: Some(current_month_field),
                revocation_root: Some(revocation_root),
                pk_server: self.server_pubkey_g1,
                token_seed: Some(issued.token_seed),
                pack_id: Some(pack_id_f),
                token_index: Some(spend_idx_f),
                blinded_sig: Some(blinded_sig),
                dleq_c: Some(dleq_proof.challenge),
                dleq_s: Some(dleq_proof.response),
                expiration_month: Some(expiration_month_field),
                start_month: Some(start_month_field),
                smt_siblings: Some(smt_siblings.clone()),
                smt_path_bits: Some(smt_path_bits.clone()),
            };

            // ── diagnostic: pre-circuit checks BEFORE proving ──
            {
                use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
                use perseverus_core::dleq::dleq_verify_poseidon;
                use perseverus_core::h2c::token_base_point;
                use ark_ec::PrimeGroup;

                // 0. Print pk_server for comparison with setup/server
                {
                    let mut pk_buf = Vec::new();
                    self.server_pubkey_g1.into_affine()
                        .serialize_compressed(&mut pk_buf)
                        .expect("pk serialize");
                    eprintln!("[diag] pk_server (client): {}", hex::encode(&pk_buf));
                }

                // 1. Verify base-point derivation matches stored token
                let p_i_derived = token_base_point(
                    &self.poseidon, issued.token_seed, pack_id_f, spend_idx_f,
                );
                let p_i_stored = G1Projective::from(token.base_point);
                let bp_match = p_i_derived.into_affine() == p_i_stored.into_affine();
                eprintln!("[diag] base_point match: {}", bp_match);

                // 2. Verify DLEQ proof outside circuit (pure Rust, no R1CS)
                let g_bjj = G1Projective::generator();
                let dleq_ok = dleq_verify_poseidon(
                    dleq_proof, &g_bjj, &self.server_pubkey_g1,
                    &p_i_stored, &blinded_sig,
                );
                eprintln!("[diag] DLEQ verify (off-circuit): {:?}", dleq_ok);

                // 3. Check nullifier
                let null_check = compute_nullifier(
                    &self.poseidon, issued.token_seed, pack_id_f, spend_idx_f,
                );
                eprintln!("[diag] nullifier match: {}", nullifier == null_check);

                // 4. Check expiration/activation
                let cm = current_month as u64;
                let exp = issued.expiration_month as u64;
                let start = issued.start_month as u64;
                eprintln!("[diag] expiration={} >= current_month={}: {}", exp, cm, exp >= cm);
                eprintln!("[diag] current_month={} >= start_month={}: {}", cm, start, cm >= start);

                // 5. Check SMT
                eprintln!("[diag] smt_siblings count: {}, smt_path_bits count: {}",
                    smt_siblings.len(), smt_path_bits.len());
                eprintln!("[diag] revocation_root is_zero: {}",
                    revocation_root == CircuitField::from(0u64));

                // 6. Full circuit satisfiability check
                let diag_cs = ConstraintSystem::<perseverus_circuits::CircuitField>::new_ref();
                let diag_circuit = RevocationSpendCircuit {
                    nullifier: Some(nullifier),
                    current_month: Some(current_month_field),
                    revocation_root: Some(revocation_root),
                    pk_server: self.server_pubkey_g1,
                    token_seed: Some(issued.token_seed),
                    pack_id: Some(pack_id_f),
                    token_index: Some(spend_idx_f),
                    blinded_sig: Some(blinded_sig),
                    dleq_c: Some(dleq_proof.challenge),
                    dleq_s: Some(dleq_proof.response),
                    expiration_month: Some(expiration_month_field),
                    start_month: Some(start_month_field),
                    smt_siblings: Some(smt_siblings),
                    smt_path_bits: Some(smt_path_bits),
                };
                diag_circuit.generate_constraints(diag_cs.clone()).unwrap();
                let satisfied = diag_cs.is_satisfied().unwrap();
                let nc = diag_cs.num_constraints();
                if satisfied {
                    eprintln!("[spend_batch] ✓ circuit SATISFIED ({} constraints) — proof should verify", nc);
                } else {
                    let which = diag_cs.which_is_unsatisfied().unwrap();
                    eprintln!("[spend_batch] ✗ circuit NOT SATISFIED ({} constraints) — unsatisfied: {:?}", nc, which);
                }
            }

            let proof = Groth16::<Bn254>::prove(&self.pk, circuit, rng)
                .map_err(|e| SpendClientError::Proof(format!("Groth16 prove: {}", e)))?;

            // Serialize for wire
            let mut alpha_query_buf = Vec::new();
            query.blinded_point.into_affine().serialize_compressed(&mut alpha_query_buf)?;
            let mut proof_buf = Vec::new();
            proof.serialize_compressed(&mut proof_buf)?;
            let mut null_buf = Vec::new();
            nullifier.serialize_compressed(&mut null_buf)?;
            let mut rev_root_buf = Vec::new();
            revocation_root.serialize_compressed(&mut rev_root_buf)?;

            prepared.push(PreparedSpend {
                query,
                request: OprfRequestWire {
                    blinded_points: vec![hex::encode(&alpha_query_buf)],
                    spend: Some(SpendProofWire {
                        nullifier_hex: hex::encode(&null_buf),
                        current_month: current_month as u64,
                        revocation_root_hex: hex::encode(&rev_root_buf),
                        proof_hex: hex::encode(&proof_buf),
                    }),
                },
            });
            let proof_ms = t_proof.elapsed().as_millis() as u64;
            BATCH_PROOF_TIMINGS_MS.lock().unwrap().push(proof_ms);
            eprintln!("[spend_batch] proof {}/{} generated in {}ms (token #{}, pack_id={})",
                i + 1, spend_items.len(), proof_ms,
                spend_idx, issued.pack_id);
        }

        // 3. One HTTP round trip for all proofs.
        eprintln!("[spend_batch] sending batch of {} proofs to server", prepared.len());
        let t_http = std::time::Instant::now();
        let batch_body = BatchOprfRequestWire {
            requests: prepared.iter().map(|p| OprfRequestWire {
                blinded_points: p.request.blinded_points.clone(),
                spend: p.request.spend.clone(),
            }).collect(),
        };
        let (url, body_json) = if self.api_prefix == "/v1" {
            // /v1 shape: one blinded point per entry.
            let reqs: Vec<serde_json::Value> = batch_body
                .requests
                .iter()
                .map(|r| serde_json::json!({ "blinded_point": r.blinded_points[0], "spend": r.spend }))
                .collect();
            (format!("{}/v1/analyze/batch", self.base_url), serde_json::json!({ "requests": reqs }))
        } else {
            (
                format!("{}/oprf/evaluate/batch", self.base_url),
                serde_json::to_value(&batch_body).map_err(|e| SpendClientError::BadResponse(e.to_string()))?,
            )
        };
        let resp = self.http.post(&url)
            .timeout(Duration::from_secs(60))
            .json(&body_json)
            .send()?;
        eprintln!("[spend_batch] server responded in {}ms (status={})",
            t_http.elapsed().as_millis(), resp.status().as_u16());
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(SpendClientError::ServerStatus { status, body });
        }
        let batch_resp: BatchOprfResponseWire = if self.api_prefix == "/v1" {
            // Normalize the /v1 response to the legacy shape so decoding below
            // is shared. Error objects become "<code>: <message>".
            #[derive(Deserialize)]
            struct V1Err { code: String, message: String }
            #[derive(Deserialize)]
            struct V1Entry {
                ok: bool,
                evaluated_point: Option<String>,
                proof_challenge: Option<String>,
                proof_response: Option<String>,
                error: Option<V1Err>,
            }
            #[derive(Deserialize)]
            struct V1Resp { responses: Vec<V1Entry> }
            let v: V1Resp = resp.json()?;
            BatchOprfResponseWire {
                responses: v
                    .responses
                    .into_iter()
                    .map(|e| BatchOprfEntryWire {
                        ok: e.ok,
                        evaluated_points: e.evaluated_point.map(|p| vec![p]),
                        proof_challenge: e.proof_challenge,
                        proof_response: e.proof_response,
                        error: e.error.map(|x| format!("{}: {}", x.code, x.message)),
                    })
                    .collect(),
            }
        } else {
            resp.json()?
        };

        if batch_resp.responses.len() != prepared.len() {
            return Err(SpendClientError::BadResponse(format!(
                "expected {} responses, got {}",
                prepared.len(), batch_resp.responses.len()
            )));
        }

        // 4. Decode and verify each response independently.
        let mut results = Vec::with_capacity(prepared.len());
        for (i, entry) in batch_resp.responses.into_iter().enumerate() {
            if !entry.ok {
                let err_msg = entry.error.unwrap_or_else(|| "unknown batch error".into());
                eprintln!("[spend_batch] entry {} rejected: {}", i, err_msg);
                results.push(Err(SpendClientError::BadResponse(err_msg)));
                continue;
            }

            let result = (|| -> Result<G1Projective, SpendClientError> {
                let eval_pts = entry.evaluated_points
                    .ok_or_else(|| SpendClientError::BadResponse("missing evaluated_points".into()))?;
                if eval_pts.is_empty() {
                    return Err(SpendClientError::BadResponse("no evaluated points".into()));
                }
                let beta_query_bytes = hex::decode(&eval_pts[0])?;
                let beta_query: G1Projective = G1Affine::deserialize_compressed(&beta_query_bytes[..])?.into();

                let challenge_hex = entry.proof_challenge
                    .ok_or_else(|| SpendClientError::BadResponse("missing proof_challenge".into()))?;
                let response_hex = entry.proof_response
                    .ok_or_else(|| SpendClientError::BadResponse("missing proof_response".into()))?;
                let challenge = Fr::deserialize_compressed(&hex::decode(&challenge_hex)?[..])?;
                let response = Fr::deserialize_compressed(&hex::decode(&response_hex)?[..])?;
                let dleq = DleqProof { challenge, response };

                verify_batch(
                    &self.server_pubkey_g1,
                    &[prepared[i].query.blinded_point],
                    &[beta_query],
                    &dleq,
                )?;

                let rho_inv = prepared[i].query.blinding_factor
                    .inverse()
                    .ok_or(PerseverusError::InvalidCurvePoint)?;
                Ok(beta_query * rho_inv)
            })();
            results.push(result);
        }

        Ok(results)
    }
}
