//! Chaum-Pedersen Discrete Log Equivalence (DLEQ) proofs.
//!
//! Proves that two pairs of group elements (G, V) and (α, β) share the same
//! discrete log: log_G(V) == log_α(β) == k, without revealing k.
//!
//! Used in the VOPRF to prove correct evaluation:
//! - Single proof: proves Y_t = k · X_t (Section 7)
//! - Batched proof: proves all β_i = k · α_i in token issuance (Section 3)
//!
//! Non-interactive via Fiat-Shamir transform.

use ark_ed_on_bn254::{EdwardsProjective, Fr};
type G1Projective = EdwardsProjective;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::poseidon::{poseidon_config, poseidon_hash_many, PoseidonField};
use crate::types::PerseverusError;

/// A non-interactive DLEQ proof (Fiat-Shamir transformed)
#[derive(Debug, Clone)]
pub struct DleqProof {
    /// Challenge scalar c
    pub challenge: Fr,
    /// Response scalar s = r + c·k (where r is the nonce)
    pub response: Fr,
}

/// Generate a DLEQ proof.
///
/// Proves: log_G(V) == log_α(β) == k
///
/// Given:
///   V = k·G
///   β = k·α
///
/// Protocol:
///   1. Pick random nonce r
///   2. R1 = r·G, R2 = r·α
///   3. c = H(DST || G || V || α || β || R1 || R2)   (v11: full statement)
///   4. s = r + c·k mod n
pub fn dleq_prove<R: Rng>(
    secret: &Fr,         // k
    g: &G1Projective,    // G (generator)
    v: &G1Projective,    // V = k·G
    alpha: &G1Projective, // α
    beta: &G1Projective,  // β = k·α
    rng: &mut R,
) -> DleqProof {
    // Step 1: random nonce
    let r = Fr::rand(rng);

    // Step 2: commitments
    let r1 = *g * r;
    let r2 = *alpha * r;

    // Step 3: Fiat-Shamir challenge over the whole statement (v11, F9)
    let challenge = compute_challenge(g, v, alpha, beta, &r1, &r2);

    // Step 4: response
    let response = r + challenge * secret;

    DleqProof {
        challenge,
        response,
    }
}

/// Verify a DLEQ proof.
///
/// Checks: log_G(V) == log_α(β)
///
/// Recomputes:
///   R1' = s·G - c·V
///   R2' = s·α - c·β
/// Then checks H(DST || G || V || α || β || R1' || R2') == c
pub fn dleq_verify(
    proof: &DleqProof,
    g: &G1Projective,
    v: &G1Projective,
    alpha: &G1Projective,
    beta: &G1Projective,
) -> Result<(), PerseverusError> {
    let r1_prime = *g * proof.response - *v * proof.challenge;
    let r2_prime = *alpha * proof.response - *beta * proof.challenge;

    let expected_challenge = compute_challenge(g, v, alpha, beta, &r1_prime, &r2_prime);

    if proof.challenge == expected_challenge {
        Ok(())
    } else {
        Err(PerseverusError::DleqVerificationFailed)
    }
}

/// Generate a batched DLEQ proof for multiple (α_i, β_i) pairs.
///
/// Uses the random-linear-combination trick (BLS-style):
///   1. Seed = H(DST_BATCH || G || V || n || α_1..α_n || β_1..β_n); c_i = H(seed || i)
///      (v11, F9: every coefficient depends on the whole batch, so no single
///      β_i can be chosen after seeing the others' coefficients)
///   2. Aggregate: α* = Σ c_i · α_i,  β* = Σ c_i · β_i
///   3. Produce one DLEQ proof for (G, V, α*, β*)
///
/// If any β_i was computed with the wrong key, the aggregated proof fails
/// with probability ≈ 1/ℓ where ℓ is the curve order.
/// (Whitepaper Section 3)
pub fn batched_dleq_prove<R: Rng>(
    secret: &Fr,
    g: &G1Projective,
    v: &G1Projective,
    alphas: &[G1Projective],
    betas: &[G1Projective],
    rng: &mut R,
) -> DleqProof {
    assert_eq!(alphas.len(), betas.len(), "alphas and betas must have same length");

    // Compute per-element challenge scalars (bound to the whole batch)
    let coeffs = compute_batch_coefficients(g, v, alphas, betas);

    // Aggregate
    let alpha_star = multi_scalar_mul(alphas, &coeffs);
    let beta_star = multi_scalar_mul(betas, &coeffs);

    // Single DLEQ proof on the aggregated pair
    dleq_prove(secret, g, v, &alpha_star, &beta_star, rng)
}

/// Verify a batched DLEQ proof.
pub fn batched_dleq_verify(
    proof: &DleqProof,
    g: &G1Projective,
    v: &G1Projective,
    alphas: &[G1Projective],
    betas: &[G1Projective],
) -> Result<(), PerseverusError> {
    assert_eq!(alphas.len(), betas.len(), "alphas and betas must have same length");

    let coeffs = compute_batch_coefficients(g, v, alphas, betas);

    let alpha_star = multi_scalar_mul(alphas, &coeffs);
    let beta_star = multi_scalar_mul(betas, &coeffs);

    dleq_verify(proof, g, v, &alpha_star, &beta_star)
        .map_err(|_| PerseverusError::BatchedDleqVerificationFailed)
}

// ─── Poseidon Fiat-Shamir DLEQ (for in-circuit verification) ───
//
// The circuit verifies DLEQ proofs using Poseidon for the Fiat-Shamir
// challenge (instead of SHA-256), saving tens of thousands of R1CS
// constraints. The server must generate per-token proofs using this
// variant so they can be verified inside the ZK circuit.
//
// Key subtlety: Poseidon operates on Fr(BN254) = Fq(BabyJubJub) (point
// coordinates), but scalar multiplication uses Fr(BabyJubJub). Since
// |Fr(BJJ)| < |Fr(BN254)|, we reduce the challenge mod |Fr(BJJ)| for
// the DLEQ arithmetic, and any Fr(BJJ) scalar fits losslessly in Fr(BN254).

/// A DLEQ proof using Poseidon Fiat-Shamir, for in-circuit verification.
///
/// Both fields are in Fr(BN254) = PoseidonField. The `challenge` is the
/// raw Poseidon output; `response` holds an Fr(BJJ) value lifted to Fr(BN254).
#[derive(Debug, Clone)]
pub struct PoseidonDleqProof {
    /// Challenge c = Poseidon(TAG, PK, P, σ, R1, R2) — see [`poseidon_dleq_challenge`]
    pub challenge: PoseidonField,
    /// Response s = r + c_bjj · k (Fr(BJJ) value, stored as PoseidonField)
    pub response: PoseidonField,
}

/// Public label behind [`poseidon_dleq_tag`].
const POSEIDON_DLEQ_TAG_LABEL: &[u8] = b"perseverus/dleq-poseidon/v11";

/// Constant absorbed first into every Poseidon DLEQ challenge (v11). The
/// spend circuit bakes in the same value.
pub fn poseidon_dleq_tag() -> PoseidonField {
    PoseidonField::from_be_bytes_mod_order(POSEIDON_DLEQ_TAG_LABEL)
}

/// Compute the Poseidon Fiat-Shamir challenge for DLEQ (v11, security review
/// F9: binds the base point too, under a domain tag):
///
/// c = Poseidon(TAG, PK.x, PK.y, P.x, P.y, σ.x, σ.y, R1.x, R1.y, R2.x, R2.y)
///
/// Must match `circuits::gadgets::enforce_dleq_signature` exactly.
fn poseidon_dleq_challenge(
    pk: &G1Projective,
    base: &G1Projective,
    sigma: &G1Projective,
    r1: &G1Projective,
    r2: &G1Projective,
) -> PoseidonField {
    let cfg = poseidon_config();
    let pk_a = pk.into_affine();
    let base_a = base.into_affine();
    let sigma_a = sigma.into_affine();
    let r1_a = r1.into_affine();
    let r2_a = r2.into_affine();
    poseidon_hash_many(&cfg, &[
        poseidon_dleq_tag(),
        pk_a.x, pk_a.y,
        base_a.x, base_a.y,
        sigma_a.x, sigma_a.y,
        r1_a.x, r1_a.y,
        r2_a.x, r2_a.y,
    ])
}

/// Convert a PoseidonField (Fr(BN254)) value to Fr(BJJ) by reducing mod |Fr(BJJ)|.
fn poseidon_field_to_bjj_scalar(f: &PoseidonField) -> Fr {
    let bytes = f.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Lift an Fr(BJJ) scalar to PoseidonField (Fr(BN254)). Lossless since |Fr(BJJ)| < |Fr(BN254)|.
pub fn bjj_scalar_to_poseidon_field(s: &Fr) -> PoseidonField {
    let bytes = s.into_bigint().to_bytes_le();
    PoseidonField::from_le_bytes_mod_order(&bytes)
}

/// Generate a per-token DLEQ proof using Poseidon Fiat-Shamir.
///
/// Proves: log_G(PK) == log_{P_i}(σ_i) == v (the server secret).
///
/// This variant MUST be used for proofs that will be verified inside the
/// ZK circuit. The server generates one proof per token (not batched).
///
/// # Arguments
/// - `secret`: server OPRF secret key v (Fr(BJJ))
/// - `g`: BabyJubJub generator G
/// - `pk`: server public key PK = v·G
/// - `p_i`: token base point P_i
/// - `sigma_i`: server-signed point σ_i = v·P_i
pub fn dleq_prove_poseidon<R: Rng>(
    secret: &Fr,
    g: &G1Projective,
    pk: &G1Projective,
    p_i: &G1Projective,
    sigma_i: &G1Projective,
    rng: &mut R,
) -> PoseidonDleqProof {
    // Step 1: random nonce r ∈ Fr(BJJ)
    let r = Fr::rand(rng);

    // Step 2: commitments R1 = r·G, R2 = r·P_i
    let r1 = *g * r;
    let r2 = *p_i * r;

    // Step 3: Poseidon Fiat-Shamir challenge (in Fr(BN254))
    let c_bn = poseidon_dleq_challenge(pk, p_i, sigma_i, &r1, &r2);

    // Step 4: reduce to Fr(BJJ) for scalar arithmetic
    let c_bjj = poseidon_field_to_bjj_scalar(&c_bn);

    // Step 5: response s = r + c_bjj · v (in Fr(BJJ))
    let s = r + c_bjj * secret;

    // Step 6: lift s back to Fr(BN254)
    let s_bn = bjj_scalar_to_poseidon_field(&s);

    PoseidonDleqProof {
        challenge: c_bn,
        response: s_bn,
    }
}

/// Verify a per-token DLEQ proof using Poseidon Fiat-Shamir.
///
/// Recomputes:
///   R1' = s·G - c·PK
///   R2' = s·P_i - c·σ_i
/// Then checks Poseidon(PK, σ_i, R1', R2') == c
pub fn dleq_verify_poseidon(
    proof: &PoseidonDleqProof,
    g: &G1Projective,
    pk: &G1Projective,
    p_i: &G1Projective,
    sigma_i: &G1Projective,
) -> Result<(), PerseverusError> {
    // Convert challenge and response from Fr(BN254) to Fr(BJJ) for scalar ops
    let c_bjj = poseidon_field_to_bjj_scalar(&proof.challenge);
    let s_bjj = poseidon_field_to_bjj_scalar(&proof.response);

    // Recompute R1' = s·G - c·PK, R2' = s·P_i - c·σ_i
    let r1_prime = *g * s_bjj - *pk * c_bjj;
    let r2_prime = *p_i * s_bjj - *sigma_i * c_bjj;

    // Recompute challenge
    let expected_c = poseidon_dleq_challenge(pk, p_i, sigma_i, &r1_prime, &r2_prime);

    if proof.challenge == expected_c {
        Ok(())
    } else {
        Err(PerseverusError::DleqVerificationFailed)
    }
}

// ─── Internal helpers ───

/// Domain separation tags (v11). Distinct for the challenge and the batch
/// coefficients, so a value hashed for one can never be replayed as the other.
const DST_DLEQ: &[u8] = b"perseverus/dleq-sha256/v11";
const DST_DLEQ_BATCH: &[u8] = b"perseverus/dleq-sha256-batch/v11";

fn hash_point(hasher: &mut Sha256, p: &G1Projective) {
    let mut buf = Vec::new();
    p.into_affine().serialize_compressed(&mut buf).unwrap();
    hasher.update(&buf);
}

/// Fiat-Shamir challenge over the full statement (v11, security review F9):
/// c = H(DST || G || V || α || β || R1 || R2) mod n. Up to v10 this hashed only
/// (V, β, R1, R2).
fn compute_challenge(
    g: &G1Projective,
    v: &G1Projective,
    alpha: &G1Projective,
    beta: &G1Projective,
    r1: &G1Projective,
    r2: &G1Projective,
) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DST_DLEQ);
    for p in [g, v, alpha, beta, r1, r2] {
        hash_point(&mut hasher, p);
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

/// Per-element coefficients for batched DLEQ, all derived from one seed that
/// commits to the whole batch: seed = H(DST_BATCH || G || V || n || α* || β*),
/// c_i = H(DST_BATCH || seed || i).
fn compute_batch_coefficients(
    g: &G1Projective,
    v: &G1Projective,
    alphas: &[G1Projective],
    betas: &[G1Projective],
) -> Vec<Fr> {
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(DST_DLEQ_BATCH);
    hash_point(&mut seed_hasher, g);
    hash_point(&mut seed_hasher, v);
    seed_hasher.update((alphas.len() as u64).to_le_bytes());
    for p in alphas.iter().chain(betas.iter()) {
        hash_point(&mut seed_hasher, p);
    }
    let seed = seed_hasher.finalize();

    (0..alphas.len())
        .map(|i| {
            let mut h = Sha256::new();
            h.update(DST_DLEQ_BATCH);
            h.update(&seed);
            h.update((i as u64).to_le_bytes());
            Fr::from_be_bytes_mod_order(&h.finalize())
        })
        .collect()
}

/// Simple multi-scalar multiplication: Σ s_i · P_i
fn multi_scalar_mul(points: &[G1Projective], scalars: &[Fr]) -> G1Projective {
    points
        .iter()
        .zip(scalars.iter())
        .fold(G1Projective::default(), |acc, (p, s)| acc + *p * *s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_poseidon_dleq_prove_verify() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let pk = g * k;

        let p_i = G1Projective::generator() * Fr::rand(&mut rng);
        let sigma_i = p_i * k;

        let proof = dleq_prove_poseidon(&k, &g, &pk, &p_i, &sigma_i, &mut rng);
        assert!(dleq_verify_poseidon(&proof, &g, &pk, &p_i, &sigma_i).is_ok());
    }

    #[test]
    fn test_poseidon_dleq_wrong_key_fails() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let k_wrong = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let pk = g * k;

        let p_i = G1Projective::generator() * Fr::rand(&mut rng);
        let sigma_i = p_i * k_wrong; // wrong key!

        let proof = dleq_prove_poseidon(&k, &g, &pk, &p_i, &sigma_i, &mut rng);
        assert!(dleq_verify_poseidon(&proof, &g, &pk, &p_i, &sigma_i).is_err());
    }

    #[test]
    fn test_poseidon_dleq_per_token_batch() {
        // Simulate server generating N individual Poseidon DLEQ proofs
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let pk = g * k;

        let n = 50;
        for _ in 0..n {
            let p_i = G1Projective::generator() * Fr::rand(&mut rng);
            let sigma_i = p_i * k;
            let proof = dleq_prove_poseidon(&k, &g, &pk, &p_i, &sigma_i, &mut rng);
            assert!(dleq_verify_poseidon(&proof, &g, &pk, &p_i, &sigma_i).is_ok());
        }
    }

    #[test]
    fn test_dleq_prove_verify() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let v = g * k;

        let alpha = G1Projective::generator() * Fr::rand(&mut rng);
        let beta = alpha * k;

        let proof = dleq_prove(&k, &g, &v, &alpha, &beta, &mut rng);
        assert!(dleq_verify(&proof, &g, &v, &alpha, &beta).is_ok());
    }

    #[test]
    fn test_dleq_wrong_key_fails() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let k_wrong = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let v = g * k;

        let alpha = G1Projective::generator() * Fr::rand(&mut rng);
        let beta = alpha * k_wrong; // wrong key!

        let proof = dleq_prove(&k, &g, &v, &alpha, &beta, &mut rng);
        // The proof was made with k, but beta was made with k_wrong
        // This should fail (proof says log_α(β) == k, but β = k_wrong·α)
        // Actually the prove function takes the secret and computes internally,
        // so the proof proves k. But beta != k·alpha. Let's verify:
        assert!(dleq_verify(&proof, &g, &v, &alpha, &beta).is_err());
    }

    #[test]
    fn test_batched_dleq_prove_verify() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let v = g * k;

        let n = 50; // simulate a 50-token pack
        let alphas: Vec<G1Projective> = (0..n)
            .map(|_| G1Projective::generator() * Fr::rand(&mut rng))
            .collect();
        let betas: Vec<G1Projective> = alphas.iter().map(|a| *a * k).collect();

        let proof = batched_dleq_prove(&k, &g, &v, &alphas, &betas, &mut rng);
        assert!(batched_dleq_verify(&proof, &g, &v, &alphas, &betas).is_ok());
    }

    #[test]
    fn test_batched_dleq_one_bad_beta_fails() {
        let mut rng = thread_rng();
        let k = Fr::rand(&mut rng);
        let k_wrong = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let v = g * k;

        let n = 10;
        let alphas: Vec<G1Projective> = (0..n)
            .map(|_| G1Projective::generator() * Fr::rand(&mut rng))
            .collect();
        let mut betas: Vec<G1Projective> = alphas.iter().map(|a| *a * k).collect();

        // Poison one beta with a different key
        betas[5] = alphas[5] * k_wrong;

        let proof = batched_dleq_prove(&k, &g, &v, &alphas, &betas, &mut rng);
        assert!(
            batched_dleq_verify(&proof, &g, &v, &alphas, &betas).is_err(),
            "batched DLEQ should fail if any beta was computed with wrong key"
        );
    }
}
