//! Native `IssuanceClient` — wraps the full token-pack round trip so
//! callers (the Sparrow JNI layer, the CLI, tests) don't have to
//! re-implement the request/response plumbing.
//!
//! ```text
//!  caller ─► IssuanceClient::issue_pack(n, expiration_month, rng)
//!     │         │
//!     │         ├─ prepare_pack_request   (client keeps seed + blinds)
//!     │         ├─ POST /issue            (server signs α_i → β_i + Poseidon DLEQ proofs)
//!     │         └─ finalize_pack          (verify DLEQ + unblind)
//!     ▼
//!   IssuedPack { pack_id, token_seed, pack, quota,
//!                expiration_month, poseidon_dleq_proofs }
//! ```
//!
//! After issuance the wallet publishes an attribution entry to the
//! bulletin board via `publish_board_entry`. This must be done over a
//! separate connection (e.g. fresh Tor circuit) so the server cannot
//! link issuance to submission.
//!
//! The server never sees `P_i`, `σ_i`, or the seed. Losing the client's
//! [`perseverus_core::issuance::PackSecrets`] between preparation and
//! finalization would brick the pack — `issue_pack` keeps them on the
//! stack for the duration of one call so that's not a concern here.
//!
//! All HTTP is synchronous via `reqwest::blocking`. The wallet calls this
//! from JNI on its own thread; forcing a tokio runtime across the JNI
//! boundary would be a usability tax with no real benefit.

use std::time::Duration;

use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type G1Projective = EdwardsProjective;
type G1Affine = EdwardsAffine;
use rand::Rng;
use serde::{Deserialize, Serialize};

use perseverus_core::dleq::{DleqProof, PoseidonDleqProof};
use perseverus_core::issuance::{
    finalize_pack, prepare_pack_request_with_pack_id, IssuedPack, PackRequest,
    PackResponse, PackSecrets, MAX_TOKENS_PER_PACK,
};
use perseverus_core::poseidon::PoseidonField;
use perseverus_core::types::PerseverusError;

/// Published commitment response from the bulletin board.
#[derive(Debug, Clone)]
pub struct PublishResult {
    pub board_size: usize,
    pub board_root_hex: String,
}

/// Error surface for the issuance client.
///
/// We keep this separate from `PerseverusError` so that transport
/// failures (which have nothing to do with the crypto) don't get
/// coerced into `SerializationError` and mislead callers during
/// debugging.
#[derive(Debug, thiserror::Error)]
pub enum IssuanceClientError {
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
    #[error("transport: {0}")]
    Transport(String),
}

impl From<ark_serialize::SerializationError> for IssuanceClientError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::ArkSerde(e.to_string())
    }
}

// ─── Wire types (must match server/src/api/routes.rs) ──────────────
//
// We keep these *duplicated* here rather than re-exporting from
// perseverus-server because client-native must build without pulling in
// the server's axum/tokio/electrum footprint. The struct shape is small
// and stable; a drift test below catches round-trip breakage.

#[derive(Debug, Serialize, Deserialize)]
struct IssueRequestWire {
    alphas: Vec<String>,
    base_points: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IssueResponseWire {
    betas: Vec<String>,
    proof_challenge: String,
    proof_response: String,
    poseidon_proofs: Vec<[String; 2]>,
}

// Stripe redemption wire shape — kept in lockstep with the server's stripe.rs.

#[derive(Debug, Serialize, Deserialize)]
struct RedeemRequestWire {
    redemption_code: String,
    alphas: Vec<String>,
    base_points: Vec<String>,
}

// BTC silent-payment redemption — server's /btc/redeem. Same as the Stripe
// shape but the one-time code field is named `code` (a scanner-minted
// `psbtc1.…` HMAC code rather than a Stripe redemption code).
#[derive(Debug, Serialize, Deserialize)]
struct BtcRedeemRequestWire {
    code: String,
    alphas: Vec<String>,
    base_points: Vec<String>,
}

// Lightning claim — server's /ln/claim. The one-time credential is the secret
// `nonce` returned by /ln/invoice (held only by the wallet that requested it).
#[derive(Debug, Serialize, Deserialize)]
struct LnClaimRequestWire {
    nonce: String,
    alphas: Vec<String>,
    base_points: Vec<String>,
}

// Batch (yearly) redemption: one code → N packs in a single request.
#[derive(Debug, Serialize, Deserialize)]
struct PackBlindedWire {
    alphas: Vec<String>,
    base_points: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedeemBatchRequestWire {
    redemption_code: String,
    packs: Vec<PackBlindedWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedeemBatchResponseWire {
    packs: Vec<IssueResponseWire>,
}

// Bulletin board wire shapes — kept in lockstep with the server's Axum types.

#[derive(Debug, Serialize, Deserialize)]
struct PublishCommitmentRequestWire {
    pack_id: u64,
    tag_hex: String,
    expiration_month: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublishCommitmentResponseWire {
    board_size: usize,
    board_root_hex: String,
}

// ─── Client ────────────────────────────────────────────────────────

/// Blocking HTTP client for the `/issue` endpoint.
///
/// Cheap to clone (`reqwest::blocking::Client` is an `Arc` inside).
/// Prefer reusing one instance per wallet session to avoid reopening
/// TCP connections for every pack.
#[derive(Debug, Clone)]
pub struct IssuanceClient {
    base_url: String,
    http: reqwest::blocking::Client,
    poseidon: PoseidonConfig<PoseidonField>,
    server_pubkey: G1Projective,
}

impl IssuanceClient {
    /// Build a client bound to a specific server URL and that server's
    /// OPRF public key.
    ///
    /// Fetching + verifying `server_pubkey` is the caller's job — the
    /// wallet typically pins it at first contact (or compiles it in)
    /// and only calls `issue_pack` with a key it already trusts.
    pub fn new(base_url: impl Into<String>, server_pubkey: G1Projective) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            // 30s is generous for a ~256-token batch on a laptop-class
            // server; large deployments can override via `with_timeout`.
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("default blocking client must build"),
            poseidon: perseverus_core::poseidon::poseidon_config(),
            server_pubkey,
        }
    }

    /// Replace the HTTP client — useful for custom TLS, proxies, or a
    /// tuned timeout.
    pub fn with_http(mut self, http: reqwest::blocking::Client) -> Self {
        self.http = http;
        self
    }

    /// Override the Poseidon config (rarely needed; tests use this to
    /// share a cached config and skip the MDS/ark regeneration cost).
    pub fn with_poseidon(mut self, cfg: PoseidonConfig<PoseidonField>) -> Self {
        self.poseidon = cfg;
        self
    }

    /// Fetch the set of occupied 16-bit revocation slots from the server
    /// (`GET /board/slots`). Used to re-roll pack_ids before blinding so
    /// the depth-16 revocation SMT stays collision-free — two packs that
    /// shared a leaf slot would strand each other on revocation.
    ///
    /// Degrades gracefully: on any transport/parse error (e.g. an older
    /// server without the endpoint) this returns an empty set, restoring
    /// the previous random-pack_id behavior; the server's 409 on
    /// `/board/publish` remains the backstop.
    fn fetch_occupied_slots_or_empty(&self) -> std::collections::HashSet<u16> {
        let url = format!("{}/board/slots", self.base_url);
        let fetch = || -> Result<Vec<u16>, IssuanceClientError> {
            let resp = self.http.get(&url).send()?;
            if !resp.status().is_success() {
                return Err(IssuanceClientError::ServerStatus {
                    status: resp.status().as_u16(),
                    body: resp.text().unwrap_or_default(),
                });
            }
            #[derive(Deserialize)]
            struct Wire {
                slots: Vec<u16>,
            }
            let wire: Wire = resp.json()?;
            Ok(wire.slots)
        };
        match fetch() {
            Ok(slots) => slots.into_iter().collect(),
            Err(e) => {
                eprintln!(
                    "[perseverus] /board/slots unavailable ({e}); \
                     proceeding with un-checked random pack_id"
                );
                std::collections::HashSet::new()
            }
        }
    }

    /// Draw a pack_id whose revocation slot is not in `occupied`, then
    /// prepare the blinded pack request with it.
    ///
    /// The re-roll MUST happen here, before blinding/signing — pack_id is
    /// baked into every base point `P_i = Poseidon(seed, pack_id, i)·H`,
    /// so it cannot change once the server has signed. The chosen slot is
    /// inserted into `occupied` so batch callers (yearly plan) also stay
    /// collision-free among their own packs.
    fn prepare_with_unique_slot<R: Rng>(
        &self,
        n: usize,
        rng: &mut R,
        occupied: &mut std::collections::HashSet<u16>,
    ) -> Result<(PackRequest, PackSecrets), IssuanceClientError> {
        const MAX_REROLLS: usize = 256;
        for _ in 0..MAX_REROLLS {
            let pack_id: u64 = rng.gen();
            let slot =
                perseverus_core::smt::revocation_slot(&self.poseidon, pack_id);
            if occupied.contains(&slot) {
                continue; // slot taken — re-roll before any blinding
            }
            let pair =
                prepare_pack_request_with_pack_id(&self.poseidon, n, pack_id, rng)?;
            occupied.insert(slot);
            return Ok(pair);
        }
        Err(IssuanceClientError::Transport(
            "could not find a free revocation slot after 256 re-rolls — \
             revocation tree nearly full?"
                .into(),
        ))
    }

    /// Run the full issuance round-trip.
    ///
    /// `expiration_month` is in YYYYMM format (e.g. 202612). It is
    /// included in the board leaf hash and verified by the spend circuit.
    ///
    /// Returns a spendable [`IssuedPack`] on success. Caller is
    /// responsible for persisting `issued.token_seed`, `issued.pack`,
    /// and `issued.pack_id` — losing them means losing the ability to
    /// spend the tokens.
    ///
    /// After `issue_pack` returns, call `publish_board_entry` to post the
    /// attribution entry to the bulletin board. Do this from a separate
    /// network path for privacy.
    pub fn issue_pack<R: Rng>(
        &self,
        n: usize,
        expiration_month: u32,
        start_month: u32,
        rng: &mut R,
    ) -> Result<IssuedPack, IssuanceClientError> {
        if n == 0 || n > MAX_TOKENS_PER_PACK {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::SerializationError(format!(
                    "pack size {} out of range [1, {}]",
                    n, MAX_TOKENS_PER_PACK
                )),
            ));
        }

        // 1. Client draws seed + blinds, computes α_i = r_i · P_i.
        //    pack_id is re-rolled against the occupied revocation slots
        //    BEFORE blinding (it is baked into every P_i).
        let mut occupied = self.fetch_occupied_slots_or_empty();
        let (request, secrets) =
            self.prepare_with_unique_slot(n, rng, &mut occupied)?;

        // 2. Send α_i to the server, receive β_i + batched DLEQ proof.
        let response = self.post_issue(&request, &secrets)?;

        // 3. Verify DLEQ, unblind each token, fold into the pack Merkle tree.
        let issued = finalize_pack(
            &self.poseidon,
            &request,
            &secrets,
            &response,
            &self.server_pubkey,
            expiration_month,
            start_month,
            rng,
        )?;

        Ok(issued)
    }

    /// Publish an attribution entry to the bulletin board (v6).
    ///
    /// **Privacy: circuit isolation enforced.** This method builds a
    /// fresh HTTP client with randomized SOCKS5 credentials, forcing Tor
    /// to route the request through a different circuit than `/issue`.
    /// Without this, the server could correlate issuance and board-publish
    /// by observing the same Tor exit IP within a short time window.
    ///
    /// The `tag` is a public identifier binding the board entry to its
    /// encrypted attribution blob (for CC chargeback lookup). The wallet
    /// derives it from `Poseidon(pack_id, payment_method_hash)` or similar.
    ///
    /// Returns the new board size and root hex.
    pub fn publish_board_entry(
        &self,
        issued: &IssuedPack,
        tag: PoseidonField,
    ) -> Result<PublishResult, IssuanceClientError> {
        let mut tag_buf = Vec::new();
        tag.serialize_compressed(&mut tag_buf)?;

        let wire = PublishCommitmentRequestWire {
            pack_id: issued.pack_id,
            tag_hex: hex::encode(&tag_buf),
            expiration_month: issued.expiration_month,
        };
        let url = format!("{}/board/publish", self.base_url);

        // Build an isolated client — a different Tor circuit than issue_pack,
        // so the server can't correlate issuance with board-publish. For a
        // loopback server there is no Tor and circuit isolation is moot, so use
        // a direct no-proxy client (a Tor SOCKS proxy can't reach 127.0.0.1).
        let is_loopback = {
            let l = self.base_url.to_ascii_lowercase();
            l.contains("127.0.0.1") || l.contains("//localhost") || l.contains("[::1]")
        };
        let isolated_http = if is_loopback {
            reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(IssuanceClientError::Http)?
        } else {
            crate::transport::build_isolated_client(Duration::from_secs(30))
                .map_err(|e| IssuanceClientError::Transport(e))?
        };

        // Try the isolated client first. If the request can't be sent (e.g. the
        // local Tor SOCKS port rejects stream-isolation auth), fall back to the
        // main client — for a .onion there is no exit node, so the fresh-circuit
        // isolation matters far less than the publish actually succeeding.
        let resp = match isolated_http.post(&url).json(&wire).send() {
            Ok(r) => r,
            Err(_) if !is_loopback => {
                self.http.post(&url).json(&wire).send()?
            }
            Err(e) => return Err(e.into()),
        };
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        let wire: PublishCommitmentResponseWire = resp.json()?;
        Ok(PublishResult {
            board_size: wire.board_size,
            board_root_hex: wire.board_root_hex,
        })
    }

    /// Issue a token pack via the `/stripe/redeem` payment-gated endpoint.
    ///
    /// Identical to [`issue_pack`] except the HTTP request goes to
    /// `/stripe/redeem` with a `redemption_code` field. The server
    /// validates the code (one-time use), signs the blinded tokens, and
    /// deletes the code. After this point, token spends are
    /// cryptographically unlinkable to the Stripe payment.
    ///
    /// **Privacy invariant:** the blinded tokens are sent in the same
    /// request that consumes the code, so there is no second call to
    /// `/issue` that could be correlated. The redemption code is the
    /// ONLY link between "who paid" and "who got tokens."
    pub fn redeem_pack<R: Rng>(
        &self,
        n: usize,
        expiration_month: u32,
        start_month: u32,
        redemption_code: &str,
        rng: &mut R,
    ) -> Result<IssuedPack, IssuanceClientError> {
        if n == 0 || n > MAX_TOKENS_PER_PACK {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::SerializationError(format!(
                    "pack size {} out of range [1, {}]",
                    n, MAX_TOKENS_PER_PACK
                )),
            ));
        }

        // 1. Client draws seed + blinds, computes α_i = r_i · P_i.
        //    pack_id is re-rolled against the occupied revocation slots
        //    BEFORE blinding (it is baked into every P_i).
        let mut occupied = self.fetch_occupied_slots_or_empty();
        let (request, secrets) =
            self.prepare_with_unique_slot(n, rng, &mut occupied)?;

        // 2. Send α_i + redemption_code to /stripe/redeem.
        let response = self.post_redeem(&request, &secrets, redemption_code)?;

        // 3. Verify DLEQ, unblind each token, fold into the pack Merkle tree.
        let issued = finalize_pack(
            &self.poseidon,
            &request,
            &secrets,
            &response,
            &self.server_pubkey,
            expiration_month,
            start_month,
            rng,
        )?;

        Ok(issued)
    }

    /// Redeem a BTC silent-payment proof-of-payment code (`psbtc1.…`) for one
    /// token pack via `/btc/redeem`. Identical blind/finalize flow as
    /// `redeem_pack`; only the endpoint and code field differ.
    pub fn redeem_pack_btc<R: Rng>(
        &self,
        n: usize,
        expiration_month: u32,
        start_month: u32,
        code: &str,
        rng: &mut R,
    ) -> Result<IssuedPack, IssuanceClientError> {
        if n == 0 || n > MAX_TOKENS_PER_PACK {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::SerializationError(format!(
                    "pack size {} out of range [1, {}]",
                    n, MAX_TOKENS_PER_PACK
                )),
            ));
        }
        let mut occupied = self.fetch_occupied_slots_or_empty();
        let (request, secrets) = self.prepare_with_unique_slot(n, rng, &mut occupied)?;
        let response = self.post_redeem_btc(&request, &secrets, code)?;
        let issued = finalize_pack(
            &self.poseidon,
            &request,
            &secrets,
            &response,
            &self.server_pubkey,
            expiration_month,
            start_month,
            rng,
        )?;
        Ok(issued)
    }

    /// Claim a Lightning-paid token pack via `/ln/claim`, using the secret
    /// `nonce` from `/ln/invoice` as the bearer credential. Identical
    /// blind/finalize flow as `redeem_pack`; only the endpoint + field differ.
    pub fn redeem_pack_ln<R: Rng>(
        &self,
        n: usize,
        expiration_month: u32,
        start_month: u32,
        nonce: &str,
        rng: &mut R,
    ) -> Result<IssuedPack, IssuanceClientError> {
        if n == 0 || n > MAX_TOKENS_PER_PACK {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::SerializationError(format!(
                    "pack size {} out of range [1, {}]",
                    n, MAX_TOKENS_PER_PACK
                )),
            ));
        }
        let mut occupied = self.fetch_occupied_slots_or_empty();
        let (request, secrets) = self.prepare_with_unique_slot(n, rng, &mut occupied)?;
        let response = self.post_ln_claim(&request, &secrets, nonce)?;
        let issued = finalize_pack(
            &self.poseidon,
            &request,
            &secrets,
            &response,
            &self.server_pubkey,
            expiration_month,
            start_month,
            rng,
        )?;
        Ok(issued)
    }

    /// Redeem ONE code for N packs in a single batch request (yearly plan).
    /// `schedule[i] = (expiration_month, start_month)` for pack i. All blinded
    /// packs + the code travel in one request (single linkage event); the
    /// server signs each pack and deletes the code once.
    pub fn redeem_packs<R: Rng>(
        &self,
        n: usize,
        schedule: &[(u32, u32)],
        redemption_code: &str,
        rng: &mut R,
    ) -> Result<Vec<IssuedPack>, IssuanceClientError> {
        if schedule.is_empty() {
            return Err(IssuanceClientError::Crypto(PerseverusError::SerializationError(
                "empty pack schedule".into())));
        }
        if n == 0 || n > MAX_TOKENS_PER_PACK {
            return Err(IssuanceClientError::Crypto(PerseverusError::SerializationError(
                format!("pack size {} out of range [1, {}]", n, MAX_TOKENS_PER_PACK))));
        }

        // 1. Prepare a fresh blinded request per pack. One slot fetch for
        //    the whole batch; `occupied` accumulates the batch's own slots
        //    so the 13 yearly packs are also collision-free among themselves.
        let mut occupied = self.fetch_occupied_slots_or_empty();
        let mut prepared: Vec<(PackRequest, PackSecrets)> = Vec::with_capacity(schedule.len());
        for _ in 0..schedule.len() {
            prepared.push(self.prepare_with_unique_slot(n, rng, &mut occupied)?);
        }

        // 2. One batch request → one signed response per pack.
        let responses = self.post_redeem_batch(&prepared, redemption_code)?;
        if responses.len() != prepared.len() {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::BatchedDleqVerificationFailed));
        }

        // 3. Finalize each pack with its own activation/expiration months.
        let mut issued = Vec::with_capacity(prepared.len());
        for (i, (request, secrets)) in prepared.iter().enumerate() {
            let (expiration_month, start_month) = schedule[i];
            issued.push(finalize_pack(
                &self.poseidon, request, secrets, &responses[i],
                &self.server_pubkey, expiration_month, start_month, rng,
            )?);
        }
        Ok(issued)
    }

    // ── Internals ──

    /// POST all packs' blinded points + the code to `/stripe/redeem-batch`,
    /// decode one `PackResponse` per pack.
    fn post_redeem_batch(
        &self,
        prepared: &[(PackRequest, PackSecrets)],
        redemption_code: &str,
    ) -> Result<Vec<PackResponse>, IssuanceClientError> {
        let mut packs_wire = Vec::with_capacity(prepared.len());
        for (request, secrets) in prepared {
            let mut alphas_hex = Vec::with_capacity(request.alphas.len());
            for alpha in &request.alphas {
                let mut buf = Vec::new();
                alpha.into_affine().serialize_compressed(&mut buf)?;
                alphas_hex.push(hex::encode(&buf));
            }
            let mut base_points_hex = Vec::with_capacity(secrets.base_points.len());
            for bp in &secrets.base_points {
                let mut buf = Vec::new();
                bp.into_affine().serialize_compressed(&mut buf)?;
                base_points_hex.push(hex::encode(&buf));
            }
            packs_wire.push(PackBlindedWire { alphas: alphas_hex, base_points: base_points_hex });
        }

        let wire = RedeemBatchRequestWire {
            redemption_code: redemption_code.to_string(),
            packs: packs_wire,
        };
        let url = format!("{}/stripe/redeem-batch", self.base_url);
        let http_resp = self.http.post(&url).json(&wire).send()?;
        if !http_resp.status().is_success() {
            let status = http_resp.status().as_u16();
            let body = http_resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        let resp_wire: RedeemBatchResponseWire = http_resp.json()?;
        let mut out = Vec::with_capacity(resp_wire.packs.len());
        for (pi, w) in resp_wire.packs.iter().enumerate() {
            let expected = prepared[pi].0.alphas.len();
            if w.betas.len() != expected {
                return Err(IssuanceClientError::Crypto(
                    PerseverusError::BatchedDleqVerificationFailed));
            }
            let mut betas: Vec<G1Projective> = Vec::with_capacity(w.betas.len());
            for (i, h) in w.betas.iter().enumerate() {
                let bytes = hex::decode(h).map_err(|e|
                    IssuanceClientError::ArkSerde(format!("pack{} beta{} hex: {}", pi, i, e)))?;
                betas.push(G1Affine::deserialize_compressed(&bytes[..])?.into());
            }
            let cb = hex::decode(&w.proof_challenge)?;
            let rb = hex::decode(&w.proof_response)?;
            let challenge = Fr::deserialize_compressed(&cb[..])?;
            let response = Fr::deserialize_compressed(&rb[..])?;
            let mut pproofs = Vec::with_capacity(w.poseidon_proofs.len());
            for [c_hex, s_hex] in &w.poseidon_proofs {
                let c = PoseidonField::deserialize_compressed(&hex::decode(c_hex)?[..])?;
                let s = PoseidonField::deserialize_compressed(&hex::decode(s_hex)?[..])?;
                pproofs.push(PoseidonDleqProof { challenge: c, response: s });
            }
            out.push(PackResponse {
                betas,
                proof: DleqProof { challenge, response },
                poseidon_proofs: pproofs,
            });
        }
        Ok(out)
    }

    fn post_issue(
        &self,
        request: &PackRequest,
        secrets: &PackSecrets,
    ) -> Result<PackResponse, IssuanceClientError> {
        // Serialize α_i → compressed G1 hex.
        let mut alphas_hex = Vec::with_capacity(request.alphas.len());
        for alpha in &request.alphas {
            let mut buf = Vec::new();
            alpha.into_affine().serialize_compressed(&mut buf)?;
            alphas_hex.push(hex::encode(&buf));
        }

        // Serialize P_i → compressed G1 hex.
        let mut base_points_hex = Vec::with_capacity(secrets.base_points.len());
        for bp in &secrets.base_points {
            let mut buf = Vec::new();
            bp.into_affine().serialize_compressed(&mut buf)?;
            base_points_hex.push(hex::encode(&buf));
        }

        let wire = IssueRequestWire {
            alphas: alphas_hex,
            base_points: base_points_hex,
        };

        let url = format!("{}/issue", self.base_url);
        let http_resp = self.http.post(&url).json(&wire).send()?;

        if !http_resp.status().is_success() {
            let status = http_resp.status().as_u16();
            let body = http_resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        let wire: IssueResponseWire = http_resp.json()?;

        if wire.betas.len() != request.alphas.len() {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::BatchedDleqVerificationFailed,
            ));
        }

        // Decode β_i.
        let mut betas: Vec<G1Projective> = Vec::with_capacity(wire.betas.len());
        for (i, hex_str) in wire.betas.iter().enumerate() {
            let bytes = hex::decode(hex_str)
                .map_err(|e| {
                    IssuanceClientError::ArkSerde(format!(
                        "beta[{}] hex: {}",
                        i, e
                    ))
                })?;
            let affine = G1Affine::deserialize_compressed(&bytes[..])?;
            betas.push(affine.into());
        }

        let challenge_bytes = hex::decode(&wire.proof_challenge)?;
        let response_bytes = hex::decode(&wire.proof_response)?;
        let challenge = Fr::deserialize_compressed(&challenge_bytes[..])?;
        let response = Fr::deserialize_compressed(&response_bytes[..])?;

        // Decode per-token Poseidon DLEQ proofs.
        let mut poseidon_proofs = Vec::with_capacity(wire.poseidon_proofs.len());
        for (i, [c_hex, s_hex]) in wire.poseidon_proofs.iter().enumerate() {
            let c_bytes = hex::decode(c_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] challenge hex: {}", i, e))
            })?;
            let s_bytes = hex::decode(s_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] response hex: {}", i, e))
            })?;
            let c = PoseidonField::deserialize_compressed(&c_bytes[..])?;
            let s = PoseidonField::deserialize_compressed(&s_bytes[..])?;
            poseidon_proofs.push(PoseidonDleqProof { challenge: c, response: s });
        }

        Ok(PackResponse {
            betas,
            proof: DleqProof {
                challenge,
                response,
            },
            poseidon_proofs,
        })
    }

    /// Send blinded tokens + redemption code to `/stripe/redeem`.
    /// Response format is identical to `/issue`.
    fn post_redeem(
        &self,
        request: &PackRequest,
        secrets: &PackSecrets,
        redemption_code: &str,
    ) -> Result<PackResponse, IssuanceClientError> {
        // Serialize α_i → compressed G1 hex.
        let mut alphas_hex = Vec::with_capacity(request.alphas.len());
        for alpha in &request.alphas {
            let mut buf = Vec::new();
            alpha.into_affine().serialize_compressed(&mut buf)?;
            alphas_hex.push(hex::encode(&buf));
        }

        // Serialize P_i → compressed G1 hex.
        let mut base_points_hex = Vec::with_capacity(secrets.base_points.len());
        for bp in &secrets.base_points {
            let mut buf = Vec::new();
            bp.into_affine().serialize_compressed(&mut buf)?;
            base_points_hex.push(hex::encode(&buf));
        }

        let wire = RedeemRequestWire {
            redemption_code: redemption_code.to_string(),
            alphas: alphas_hex,
            base_points: base_points_hex,
        };

        let url = format!("{}/stripe/redeem", self.base_url);
        let http_resp = self.http.post(&url).json(&wire).send()?;

        if !http_resp.status().is_success() {
            let status = http_resp.status().as_u16();
            let body = http_resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        // Response is the same shape as IssueResponseWire.
        let wire: IssueResponseWire = http_resp.json()?;

        if wire.betas.len() != request.alphas.len() {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::BatchedDleqVerificationFailed,
            ));
        }

        // Decode β_i.
        let mut betas: Vec<G1Projective> = Vec::with_capacity(wire.betas.len());
        for (i, hex_str) in wire.betas.iter().enumerate() {
            let bytes = hex::decode(hex_str)
                .map_err(|e| {
                    IssuanceClientError::ArkSerde(format!("beta[{}] hex: {}", i, e))
                })?;
            let affine = G1Affine::deserialize_compressed(&bytes[..])?;
            betas.push(affine.into());
        }

        let challenge_bytes = hex::decode(&wire.proof_challenge)?;
        let response_bytes = hex::decode(&wire.proof_response)?;
        let challenge = Fr::deserialize_compressed(&challenge_bytes[..])?;
        let response = Fr::deserialize_compressed(&response_bytes[..])?;

        // Decode per-token Poseidon DLEQ proofs.
        let mut poseidon_proofs = Vec::with_capacity(wire.poseidon_proofs.len());
        for (i, [c_hex, s_hex]) in wire.poseidon_proofs.iter().enumerate() {
            let c_bytes = hex::decode(c_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] challenge hex: {}", i, e))
            })?;
            let s_bytes = hex::decode(s_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] response hex: {}", i, e))
            })?;
            let c = PoseidonField::deserialize_compressed(&c_bytes[..])?;
            let s = PoseidonField::deserialize_compressed(&s_bytes[..])?;
            poseidon_proofs.push(PoseidonDleqProof { challenge: c, response: s });
        }

        Ok(PackResponse {
            betas,
            proof: DleqProof { challenge, response },
            poseidon_proofs,
        })
    }

    /// POST blinded points + a BTC proof-of-payment code to `/btc/redeem`.
    /// Same response shape as `/stripe/redeem`.
    fn post_redeem_btc(
        &self,
        request: &PackRequest,
        secrets: &PackSecrets,
        code: &str,
    ) -> Result<PackResponse, IssuanceClientError> {
        let mut alphas_hex = Vec::with_capacity(request.alphas.len());
        for alpha in &request.alphas {
            let mut buf = Vec::new();
            alpha.into_affine().serialize_compressed(&mut buf)?;
            alphas_hex.push(hex::encode(&buf));
        }
        let mut base_points_hex = Vec::with_capacity(secrets.base_points.len());
        for bp in &secrets.base_points {
            let mut buf = Vec::new();
            bp.into_affine().serialize_compressed(&mut buf)?;
            base_points_hex.push(hex::encode(&buf));
        }

        let wire = BtcRedeemRequestWire {
            code: code.to_string(),
            alphas: alphas_hex,
            base_points: base_points_hex,
        };

        let url = format!("{}/btc/redeem", self.base_url);
        let http_resp = self.http.post(&url).json(&wire).send()?;
        if !http_resp.status().is_success() {
            let status = http_resp.status().as_u16();
            let body = http_resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        let wire: IssueResponseWire = http_resp.json()?;
        if wire.betas.len() != request.alphas.len() {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::BatchedDleqVerificationFailed,
            ));
        }

        let mut betas: Vec<G1Projective> = Vec::with_capacity(wire.betas.len());
        for (i, hex_str) in wire.betas.iter().enumerate() {
            let bytes = hex::decode(hex_str).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("beta[{}] hex: {}", i, e))
            })?;
            let affine = G1Affine::deserialize_compressed(&bytes[..])?;
            betas.push(affine.into());
        }

        let challenge_bytes = hex::decode(&wire.proof_challenge)?;
        let response_bytes = hex::decode(&wire.proof_response)?;
        let challenge = Fr::deserialize_compressed(&challenge_bytes[..])?;
        let response = Fr::deserialize_compressed(&response_bytes[..])?;

        let mut poseidon_proofs = Vec::with_capacity(wire.poseidon_proofs.len());
        for (i, [c_hex, s_hex]) in wire.poseidon_proofs.iter().enumerate() {
            let c_bytes = hex::decode(c_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] challenge hex: {}", i, e))
            })?;
            let s_bytes = hex::decode(s_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] response hex: {}", i, e))
            })?;
            let c = PoseidonField::deserialize_compressed(&c_bytes[..])?;
            let s = PoseidonField::deserialize_compressed(&s_bytes[..])?;
            poseidon_proofs.push(PoseidonDleqProof { challenge: c, response: s });
        }

        Ok(PackResponse {
            betas,
            proof: DleqProof { challenge, response },
            poseidon_proofs,
        })
    }

    /// POST blinded points + a Lightning claim nonce to `/ln/claim`.
    /// Same response shape as `/stripe/redeem`.
    fn post_ln_claim(
        &self,
        request: &PackRequest,
        secrets: &PackSecrets,
        nonce: &str,
    ) -> Result<PackResponse, IssuanceClientError> {
        let mut alphas_hex = Vec::with_capacity(request.alphas.len());
        for alpha in &request.alphas {
            let mut buf = Vec::new();
            alpha.into_affine().serialize_compressed(&mut buf)?;
            alphas_hex.push(hex::encode(&buf));
        }
        let mut base_points_hex = Vec::with_capacity(secrets.base_points.len());
        for bp in &secrets.base_points {
            let mut buf = Vec::new();
            bp.into_affine().serialize_compressed(&mut buf)?;
            base_points_hex.push(hex::encode(&buf));
        }

        let wire = LnClaimRequestWire {
            nonce: nonce.to_string(),
            alphas: alphas_hex,
            base_points: base_points_hex,
        };

        let url = format!("{}/ln/claim", self.base_url);
        let http_resp = self.http.post(&url).json(&wire).send()?;
        if !http_resp.status().is_success() {
            let status = http_resp.status().as_u16();
            let body = http_resp.text().unwrap_or_default();
            return Err(IssuanceClientError::ServerStatus { status, body });
        }

        let wire: IssueResponseWire = http_resp.json()?;
        if wire.betas.len() != request.alphas.len() {
            return Err(IssuanceClientError::Crypto(
                PerseverusError::BatchedDleqVerificationFailed,
            ));
        }

        let mut betas: Vec<G1Projective> = Vec::with_capacity(wire.betas.len());
        for (i, hex_str) in wire.betas.iter().enumerate() {
            let bytes = hex::decode(hex_str).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("beta[{}] hex: {}", i, e))
            })?;
            let affine = G1Affine::deserialize_compressed(&bytes[..])?;
            betas.push(affine.into());
        }

        let challenge_bytes = hex::decode(&wire.proof_challenge)?;
        let response_bytes = hex::decode(&wire.proof_response)?;
        let challenge = Fr::deserialize_compressed(&challenge_bytes[..])?;
        let response = Fr::deserialize_compressed(&response_bytes[..])?;

        let mut poseidon_proofs = Vec::with_capacity(wire.poseidon_proofs.len());
        for (i, [c_hex, s_hex]) in wire.poseidon_proofs.iter().enumerate() {
            let c_bytes = hex::decode(c_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] challenge hex: {}", i, e))
            })?;
            let s_bytes = hex::decode(s_hex).map_err(|e| {
                IssuanceClientError::ArkSerde(format!("poseidon_proof[{}] response hex: {}", i, e))
            })?;
            let c = PoseidonField::deserialize_compressed(&c_bytes[..])?;
            let s = PoseidonField::deserialize_compressed(&s_bytes[..])?;
            poseidon_proofs.push(PoseidonDleqProof { challenge: c, response: s });
        }

        Ok(PackResponse {
            betas,
            proof: DleqProof { challenge, response },
            poseidon_proofs,
        })
    }
}
