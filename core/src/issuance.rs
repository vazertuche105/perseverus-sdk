//! Token-pack issuance flow (v6 — revocation-based).
//!
//! Composes four existing primitives into the full client ⇄ server
//! token-pack protocol:
//!
//!   1. [`crate::h2c::token_base_point`] — deterministic derivation of
//!      `P_i = Poseidon(seed, pack_id, i) · H_TOKEN`. Must match the
//!      in-circuit gadget exactly, or spend proofs will fail.
//!   2. [`crate::oprf::evaluate_batch`] — server-side `β_i = v · α_i` with
//!      one aggregated Chaum-Pedersen DLEQ proof covering the whole pack.
//!   3. [`crate::oprf::verify_batch`] + [`crate::oprf::unblind_token`] —
//!      client-side DLEQ check and per-token unblind.
//!   4. [`crate::token_pack::TokenPack`] — fixed-depth Merkle fold for
//!      compact local storage.
//!
//! ## Flow at a glance
//!
//! ```text
//!  client                                server
//!  ──────                                ──────
//!  prepare_pack_request(n) ─────────────► sign_pack_batch(alphas)
//!     { PackRequest, PackSecrets }         { PackResponse }
//!  finalize_pack(request, response) ◄──── (betas, batched DLEQ proof)
//!     → IssuedPack { seed, pack, pack_root,
//!                     pack_id, quota, poseidon_dleq_proofs }
//!
//!  [immediately]
//!  client sends attribution entry to server
//!  server posts to attribution board (for CC chargeback tracking only)
//! ```
//!
//! ## v6 changes
//!
//! - Removed: Pedersen commitment (blinding_factor, commitment field)
//! - The spend circuit no longer references the bulletin board.
//! - Tokens are spendable immediately — the circuit proves non-revocation
//!   via the Sparse Merkle Tree, not board membership.
//! - pack_id now generated as a simple random u64 (no Pedersen wrapper).
//! - Base-point derivation includes pack_id: P_i = Poseidon(seed, pack_id, i)·H
//!
//! ## What the server sees (v11 — corrected; see security review F12)
//!
//! The server sees every base point `P_i` (it needs them to sign) and the
//! signatures `σ_i = v·Q_i` it produces. It never sees the `token_seed`, the
//! blinding scalars, or anything that lets it compute a nullifier: since v11
//! the nullifier is a domain-separated Poseidon hash, not the scalar behind
//! `P_i`, so a spend cannot be matched to the issuance that produced it.
//! Up to v10 this comment claimed the server never saw `P_i`; that was false,
//! and together with `nullifier == s` it linked every spend to its purchase.
//!
//! ## Validity months (v11 — security review F1)
//!
//! The server chooses `expiration_month` and `start_month` from the plan that
//! was paid for and signs the dated point
//! `Q_i = P_i + expiration_month·H_EXP + start_month·H_START`
//! ([`crate::h2c::dated_token_point`]). The spend circuit rebuilds `Q_i` from
//! the months, so a wallet cannot claim months the server did not sign.
//!
//! The `token_seed` and per-token blinds are kept in [`PackSecrets`],
//! which must stay client-side for the life of the pack. Losing them
//! means losing the ability to spend the tokens.

use ark_ed_on_bn254::{EdwardsProjective, Fr};
type G1Projective = EdwardsProjective;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::UniformRand;
use rand::Rng;

use crate::dleq::{DleqProof, PoseidonDleqProof, dleq_prove_poseidon, dleq_verify_poseidon};
use crate::h2c::{dated_token_point, token_base_point};
use crate::oprf::{evaluate_batch, verify_batch, OprfServerKey};
use crate::poseidon::PoseidonField;
use crate::token_pack::{Token, TokenPack, MAX_PACK_SIZE};
use crate::types::PerseverusError;
use ark_ec::PrimeGroup;

/// Inclusive upper bound on pack size at issuance. Hard ceiling is the
/// Merkle tree's [`MAX_PACK_SIZE`] from `token_pack.rs`. Deployments
/// typically issue much smaller packs (~50–256 tokens).
pub const MAX_TOKENS_PER_PACK: usize = MAX_PACK_SIZE;

/// Public-facing issuance request. Everything here is fine for the
/// server to see.
#[derive(Debug, Clone)]
pub struct PackRequest {
    /// `α_i = r_i · P_i` — the blinded base points sent to the server.
    pub alphas: Vec<G1Projective>,
}

/// Client-kept secrets paired with [`PackRequest`]. Must never leave
/// the client. Storing these out to disk is the wallet's responsibility.
#[derive(Debug, Clone)]
pub struct PackSecrets {
    /// Master seed used to derive every base point in the pack. Also
    /// feeds the nullifier at spend time. One 254-bit field element.
    pub token_seed: PoseidonField,
    /// Random 64-bit pack identifier. Used in base-point derivation
    /// and as the revocation key.
    pub pack_id: u64,
    /// Per-token blinding scalars `r_i`. Same length as `alphas`.
    pub blinds: Vec<Fr>,
    /// Per-token base points `P_i = Poseidon(seed, pack_id, i) · H_TOKEN`.
    /// Cached so `finalize_pack` doesn't recompute them.
    pub base_points: Vec<G1Projective>,
}

/// Server's response to [`PackRequest`]. One aggregated DLEQ proof
/// covers every `β_i` in the batch; a single bad `β_i` aborts the whole
/// pack.
#[derive(Debug, Clone)]
pub struct PackResponse {
    pub betas: Vec<G1Projective>,
    pub proof: DleqProof,
    /// v11: the signed tokens, `σ_i = v·Q_i` over the dated point.
    pub sigmas: Vec<G1Projective>,
    /// Per-token Poseidon DLEQ proofs for in-circuit verification.
    /// v11: each proves `σ_i = v·Q_i` using Poseidon Fiat-Shamir.
    pub poseidon_proofs: Vec<PoseidonDleqProof>,
    /// v11: the validity window the server chose and signed into every `Q_i`.
    pub expiration_month: u32,
    pub start_month: u32,
}

/// Final result of a successful issuance round (v6). All the state a
/// client needs to spend any token in the pack later.
#[derive(Debug, Clone)]
pub struct IssuedPack {
    /// Per-pack random scalar — wallet secret used in nullifier and base-point.
    pub token_seed: PoseidonField,
    /// The spendable pack — holds `(P_i, σ_i)` pairs in Merkle form.
    pub pack: TokenPack,
    /// Convenience accessor; equals `pack.root`.
    pub pack_root: PoseidonField,
    /// Random 64-bit identifier. Used in base-point derivation and as
    /// the revocation key in the Sparse Merkle Tree.
    pub pack_id: u64,
    /// Number of tokens in this pack.
    pub quota: u64,
    /// Per-token Poseidon DLEQ proofs for in-circuit verification.
    /// `poseidon_dleq_proofs[i]` proves σ_i = v·P_i.
    pub poseidon_dleq_proofs: Vec<PoseidonDleqProof>,
    /// Expiration month in YYYYMM format (e.g. 202605).
    pub expiration_month: u32,
    /// Activation month in YYYYMM format — the epoch when this pack becomes spendable.
    /// For single-month packs, equals expiration_month.
    /// For yearly prepaid, each monthly pack has its own start_month.
    pub start_month: u32,
}

// ─── Client-side: prepare ──────────────────────────────────────────

/// Build a fresh [`PackRequest`] + [`PackSecrets`] pair (v6).
///
/// `n` is the number of tokens the client wants to buy. Must be
/// non-zero and at most [`MAX_TOKENS_PER_PACK`].
///
/// The `pack_id` is generated first, then used in base-point derivation:
/// `P_i = Poseidon(seed, pack_id, i) · H_TOKEN`.
///
/// Side effects: draws `2 + n` scalars from `rng` (one seed, one pack_id,
/// one blind per token). Does `n` scalar multiplications client-side.
pub fn prepare_pack_request<R: Rng>(
    cfg: &PoseidonConfig<PoseidonField>,
    n: usize,
    rng: &mut R,
) -> Result<(PackRequest, PackSecrets), PerseverusError> {
    let pack_id: u64 = rng.gen();
    prepare_pack_request_with_pack_id(cfg, n, pack_id, rng)
}

/// Like [`prepare_pack_request`], but with a caller-supplied `pack_id`.
///
/// Used by clients that enforce revocation-slot uniqueness: the caller
/// draws candidate pack_ids, computes the 16-bit slot via
/// [`crate::smt::revocation_slot`], re-rolls any pack_id whose slot is
/// already occupied on the bulletin board, and only then commits to the
/// pack_id here. The re-roll MUST happen before this call — pack_id is
/// baked into every base point `P_i`, so it cannot change after signing.
pub fn prepare_pack_request_with_pack_id<R: Rng>(
    cfg: &PoseidonConfig<PoseidonField>,
    n: usize,
    pack_id: u64,
    rng: &mut R,
) -> Result<(PackRequest, PackSecrets), PerseverusError> {
    if n == 0 {
        return Err(PerseverusError::SerializationError(
            "pack must contain at least one token".into(),
        ));
    }
    if n > MAX_TOKENS_PER_PACK {
        return Err(PerseverusError::SerializationError(format!(
            "pack size {} exceeds MAX_TOKENS_PER_PACK {}",
            n, MAX_TOKENS_PER_PACK
        )));
    }

    let token_seed = PoseidonField::rand(rng);
    let pack_id_f = PoseidonField::from(pack_id);

    let mut base_points = Vec::with_capacity(n);
    let mut blinds = Vec::with_capacity(n);
    let mut alphas = Vec::with_capacity(n);

    for i in 0..n {
        let idx_f = PoseidonField::from(i as u64);
        // v6: base-point includes pack_id. Must match in-circuit derivation.
        let p_i = token_base_point(cfg, token_seed, pack_id_f, idx_f);
        let r_i = Fr::rand(rng);
        let alpha_i = p_i * r_i;

        base_points.push(p_i);
        blinds.push(r_i);
        alphas.push(alpha_i);
    }

    let request = PackRequest { alphas };
    let secrets = PackSecrets {
        token_seed,
        pack_id,
        blinds,
        base_points,
    };

    Ok((request, secrets))
}

// ─── Server-side: sign ─────────────────────────────────────────────

/// Server evaluates a batch of blinded base points and returns the
/// signed batch plus an aggregated DLEQ proof.
///
/// v11: also signs each dated point `Q_i = P_i + exp·H_EXP + start·H_START`
/// with months the server chose (from the plan that was paid for — never
/// from the client), and returns `σ_i = v·Q_i` with a per-token Poseidon
/// DLEQ proof for the spend circuit. The server needs the raw base points
/// `P_i` for this; since v11 that is safe, because no spend input can be
/// computed from them (see the module docs).
///
/// The proof transcript is stable across runs for a fixed RNG, which
/// is the guarantee the `DleqProof` API provides. Production servers
/// must use a cryptographically secure RNG here.
pub fn sign_pack_batch<R: Rng>(
    server_key: &OprfServerKey,
    alphas: &[G1Projective],
    base_points: &[G1Projective],
    expiration_month: u32,
    start_month: u32,
    rng: &mut R,
) -> PackResponse {
    let (betas, proof) = evaluate_batch(server_key, alphas, rng);

    let g = G1Projective::generator();
    let mut sigmas = Vec::with_capacity(base_points.len());
    let mut poseidon_proofs = Vec::with_capacity(base_points.len());
    for p_i in base_points {
        let q_i = dated_token_point(p_i, expiration_month, start_month);
        let sigma_i = q_i * server_key.secret;
        poseidon_proofs.push(dleq_prove_poseidon(
            &server_key.secret, &g, &server_key.pubkey, &q_i, &sigma_i, rng,
        ));
        sigmas.push(sigma_i);
    }

    PackResponse { betas, proof, sigmas, poseidon_proofs, expiration_month, start_month }
}

// ─── Client-side: finalize ─────────────────────────────────────────

/// Validate the server's response, unblind every token, and assemble
/// the spendable [`IssuedPack`] (v6).
///
/// Fails if:
///   - response length doesn't match request length,
///   - batched DLEQ proof doesn't verify under `server_pubkey`, or
///   - any blinding scalar can't be inverted (probability 1/r, i.e.
///     astronomically small; returned as `InvalidCurvePoint`).
///
/// Tokens are immediately spendable — the v6 circuit proves
/// non-revocation via the SMT, not board membership.
pub fn finalize_pack<R: Rng>(
    cfg: &PoseidonConfig<PoseidonField>,
    request: &PackRequest,
    secrets: &PackSecrets,
    response: &PackResponse,
    server_pubkey: &G1Projective,
    expiration_month: u32,
    start_month: u32,
    _rng: &mut R,
) -> Result<IssuedPack, PerseverusError> {
    if request.alphas.len() != response.betas.len() {
        return Err(PerseverusError::BatchedDleqVerificationFailed);
    }
    if secrets.blinds.len() != request.alphas.len()
        || secrets.base_points.len() != request.alphas.len()
    {
        return Err(PerseverusError::SerializationError(
            "PackSecrets length mismatch with PackRequest".into(),
        ));
    }
    if response.poseidon_proofs.len() != request.alphas.len()
        || response.sigmas.len() != request.alphas.len()
    {
        return Err(PerseverusError::SerializationError(
            "Poseidon DLEQ proofs / sigmas length mismatch with request".into(),
        ));
    }
    // The server decides the validity window. The caller passes what it
    // expects from the plan it bought; refuse a pack signed for anything else
    // rather than store tokens the wallet would show with the wrong dates.
    if response.expiration_month != expiration_month || response.start_month != start_month {
        return Err(PerseverusError::SerializationError(format!(
            "server signed months {}..={} but {}..={} was expected",
            response.start_month, response.expiration_month, start_month, expiration_month
        )));
    }

    // One aggregated DLEQ proof covers the whole batch. Any β_i
    // computed with the wrong key poisons the aggregate and the proof
    // fails with probability ≈ 1/|Fr|.
    verify_batch(server_pubkey, &request.alphas, &response.betas, &response.proof)?;

    // v11: each token is σ_i = v·Q_i over the dated point. Verify every
    // per-token Poseidon DLEQ against the Q_i we rebuild ourselves from our
    // own P_i and the agreed months — exactly what the spend circuit will do.
    let g = G1Projective::generator();
    let mut tokens = Vec::with_capacity(request.alphas.len());
    for ((p_i, proof), sigma_i) in secrets
        .base_points
        .iter()
        .zip(response.poseidon_proofs.iter())
        .zip(response.sigmas.iter())
    {
        let q_i = dated_token_point(p_i, expiration_month, start_month);
        dleq_verify_poseidon(proof, &g, server_pubkey, &q_i, sigma_i)
            .map_err(|_| PerseverusError::DleqVerificationFailed)?;
        tokens.push(Token::from_projective(*p_i, *sigma_i));
    }

    // Fold into the fixed-depth pack Merkle tree.
    let pack = TokenPack::build(cfg, tokens)
        .map_err(|msg| PerseverusError::SerializationError(msg.into()))?;
    let pack_root = pack.root;

    let quota = request.alphas.len() as u64;

    Ok(IssuedPack {
        token_seed: secrets.token_seed,
        pack,
        pack_root,
        pack_id: secrets.pack_id,
        quota,
        poseidon_dleq_proofs: response.poseidon_proofs.clone(),
        expiration_month,
        start_month,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2c::token_base_point;
    use crate::poseidon::poseidon_config;
    use ark_ec::CurveGroup;
    use rand::thread_rng;

    #[test]
    fn full_issuance_round_trip() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 32, &mut rng).unwrap();
        let resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);
        let issued =
            finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202612, &mut rng).unwrap();

        assert_eq!(issued.token_seed, secrets.token_seed);
        assert_eq!(issued.pack.tokens.len(), 32);
        assert_eq!(issued.pack_root, issued.pack.root);
        assert_eq!(issued.quota, 32);
        assert_eq!(issued.pack_id, secrets.pack_id);

        // Every token must equal v · P_i where P_i is derivable from seed + pack_id.
        let pack_id_f = PoseidonField::from(issued.pack_id);
        for (i, token) in issued.pack.tokens.iter().enumerate() {
            let p_i = token_base_point(&cfg, issued.token_seed, pack_id_f, PoseidonField::from(i as u64));
            let q_i = dated_token_point(&p_i, 202612, 202612);
            let expected_sigma = (q_i * server_key.secret).into_affine();
            assert_eq!(
                token.blinded_sig, expected_sigma,
                "token {} σ mismatch",
                i
            );
            assert_eq!(token.base_point, p_i.into_affine(), "token {} P mismatch", i);
        }
    }

    #[test]
    fn pack_id_is_preserved() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 50, &mut rng).unwrap();
        let resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);
        let issued =
            finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202612, &mut rng).unwrap();

        assert_eq!(issued.pack_id, secrets.pack_id);
        assert_eq!(issued.quota, 50);
        assert_eq!(issued.expiration_month, 202612);
    }

    #[test]
    fn wrong_server_pubkey_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);
        let attacker_pubkey = OprfServerKey::generate(&mut rng).pubkey;

        let (req, secrets) = prepare_pack_request(&cfg, 8, &mut rng).unwrap();
        let resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);

        let err = finalize_pack(&cfg, &req, &secrets, &resp, &attacker_pubkey, 202612, 202612, &mut rng)
            .expect_err("different pubkey must break DLEQ");
        matches!(err, PerseverusError::BatchedDleqVerificationFailed);
    }

    #[test]
    fn one_poisoned_beta_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);
        let wrong_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 10, &mut rng).unwrap();
        let mut resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);

        // Swap one β_i for one computed with a different key. Aggregated
        // DLEQ must fail even though 9/10 tokens are correctly signed.
        resp.betas[5] = req.alphas[5] * wrong_key.secret;

        let err = finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202612, &mut rng)
            .expect_err("poisoned beta must fail batched DLEQ");
        matches!(err, PerseverusError::BatchedDleqVerificationFailed);
    }

    #[test]
    fn length_mismatch_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 4, &mut rng).unwrap();
        let mut resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);
        resp.betas.pop();

        let err = finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202612, &mut rng)
            .expect_err("length mismatch must fail");
        matches!(err, PerseverusError::BatchedDleqVerificationFailed);
    }

    /// v11 (F1): the wallet must not be able to relabel a pack's months.
    /// Rewriting the months in the response breaks every per-token DLEQ,
    /// because the proofs were made over Q_i with the server's months.
    #[test]
    fn relabelled_months_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 4, &mut rng).unwrap();
        let mut resp =
            sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202605, 202605, &mut rng);
        resp.expiration_month = 209912;

        let err = finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 209912, 202605, &mut rng)
            .expect_err("months the server did not sign must fail the DLEQ");
        assert!(matches!(err, PerseverusError::DleqVerificationFailed), "{:?}", err);
    }

    /// v11: finalize refuses a pack signed for a different window than expected.
    #[test]
    fn unexpected_months_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 4, &mut rng).unwrap();
        let resp =
            sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202605, 202605, &mut rng);
        let err = finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202601, &mut rng)
            .expect_err("a window mismatch must be refused");
        assert!(matches!(err, PerseverusError::SerializationError(_)), "{:?}", err);
    }

    #[test]
    fn zero_size_pack_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let err = prepare_pack_request(&cfg, 0, &mut rng)
            .expect_err("zero-size pack must be rejected");
        matches!(err, PerseverusError::SerializationError(_));
    }

    #[test]
    fn oversized_pack_rejected() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let err = prepare_pack_request(&cfg, MAX_TOKENS_PER_PACK + 1, &mut rng)
            .expect_err("oversized pack must be rejected");
        matches!(err, PerseverusError::SerializationError(_));
    }

    #[test]
    fn pack_root_matches_manual_recomputation() {
        let mut rng = thread_rng();
        let cfg = poseidon_config();
        let server_key = OprfServerKey::generate(&mut rng);

        let (req, secrets) = prepare_pack_request(&cfg, 16, &mut rng).unwrap();
        let resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202612, 202612, &mut rng);
        let issued =
            finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202612, 202612, &mut rng).unwrap();

        // Rebuild from scratch using only the secret seed + pack_id + server key.
        let pack_id_f = PoseidonField::from(issued.pack_id);
        let mut expected_tokens = Vec::with_capacity(16);
        for i in 0..16 {
            let p_i = token_base_point(
                &cfg,
                issued.token_seed,
                pack_id_f,
                PoseidonField::from(i as u64),
            );
            let sigma_i = dated_token_point(&p_i, 202612, 202612) * server_key.secret;
            expected_tokens.push(Token::from_projective(p_i, sigma_i));
        }
        let expected_pack = TokenPack::build(&cfg, expected_tokens).unwrap();

        assert_eq!(expected_pack.root, issued.pack_root);
    }
}
