//! VOPRF (Verifiable Oblivious Pseudorandom Function) implementation.
//!
//! Implements the core OPRF operations from Whitepaper Sections 3 and 7:
//! - Client: blind, unblind
//! - Server: evaluate
//! 
//! The VOPRF allows a client to get a PRF evaluation k·H2C(input) without
//! the server learning the input, and without the client learning the key k.

use ark_ed_on_bn254::{EdwardsProjective, Fr};
type G1Projective = EdwardsProjective;
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand};
use rand::Rng;

use crate::dleq::{DleqProof, batched_dleq_prove, batched_dleq_verify, dleq_prove, dleq_verify};
use crate::h2c::hash_to_curve;
use crate::types::PerseverusError;

/// Server's OPRF secret key
#[derive(Debug, Clone)]
pub struct OprfServerKey {
    /// Secret scalar k
    pub secret: Fr,
    /// Public key V = k·G
    pub pubkey: G1Projective,
}

impl OprfServerKey {
    /// Generate a new random server key
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let secret = Fr::rand(rng);
        let pubkey = G1Projective::generator() * secret;
        Self { secret, pubkey }
    }

    /// Create from an existing secret scalar
    pub fn from_secret(secret: Fr) -> Self {
        let pubkey = G1Projective::generator() * secret;
        Self { secret, pubkey }
    }
}

/// Client-side blinding state for a single OPRF query
#[derive(Debug, Clone)]
pub struct BlindedQuery {
    /// The blinded point sent to the server: X_t = ρ_t · H2C(input)
    pub blinded_point: G1Projective,
    /// The blinding factor (secret, kept by client)
    pub blinding_factor: Fr,
    /// The original H2C(input) point (kept by client for verification)
    pub base_point: G1Projective,
}

/// Server-side evaluation result
#[derive(Debug, Clone)]
pub struct OprfEvaluation {
    /// The evaluated point: Y_t = k · X_t
    pub evaluated_point: G1Projective,
    /// DLEQ proof that evaluation used the correct key
    pub proof: DleqProof,
}

/// Result of unblinding on the client side
#[derive(Debug, Clone)]
pub struct OprfOutput {
    /// The unblinded OPRF output: γ_t = k · H2C(input)
    pub gamma: G1Projective,
}

// ─── Client operations ───

/// Blind an input for OPRF evaluation.
///
/// Computes X_t = ρ_t · H2C(input) where ρ_t is a random blinding factor.
/// (Whitepaper Section 7: query blinding)
pub fn blind<R: Rng>(input: &[u8], rng: &mut R) -> Result<BlindedQuery, PerseverusError> {
    let base_point = hash_to_curve(input);
    let blinding_factor = Fr::rand(rng);
    let blinded_point = base_point * blinding_factor;

    Ok(BlindedQuery {
        blinded_point,
        blinding_factor,
        base_point,
    })
}

/// Blind with a specific blinding factor (used in token issuance where
/// the blinding factor is the Poseidon secret p_i).
///
/// Computes α_i = p_i · P_i (Whitepaper Section 3)
pub fn blind_with_scalar(
    base_point: G1Projective,
    blinding_scalar: Fr,
) -> G1Projective {
    base_point * blinding_scalar
}

/// Unblind the server's OPRF evaluation to get the final output.
///
/// Computes γ_t = ρ_t⁻¹ · Y_t = k · H2C(input)
/// (Whitepaper Section 7: response unblinding)
pub fn unblind(
    evaluation: &OprfEvaluation,
    blinded_query: &BlindedQuery,
    server_pubkey: &G1Projective,
) -> Result<OprfOutput, PerseverusError> {
    // Verify the DLEQ proof: proves Y_t = k · X_t with same k as in V = k·G
    let g = G1Projective::generator();
    dleq_verify(
        &evaluation.proof,
        &g,
        server_pubkey,
        &blinded_query.blinded_point,
        &evaluation.evaluated_point,
    )?;

    // Unblind: γ_t = ρ_t⁻¹ · Y_t
    let rho_inv = blinded_query
        .blinding_factor
        .inverse()
        .ok_or(PerseverusError::InvalidCurvePoint)?;
    let gamma = evaluation.evaluated_point * rho_inv;

    Ok(OprfOutput { gamma })
}

/// Unblind a token evaluation (no DLEQ verification here — done in batch).
///
/// Computes β'_i = p_i⁻¹ · β_i = k · P_i
/// (Whitepaper Section 3: token unblinding)
pub fn unblind_token(
    beta: &G1Projective,
    blinding_scalar: &Fr,
) -> Result<G1Projective, PerseverusError> {
    let p_inv = blinding_scalar
        .inverse()
        .ok_or(PerseverusError::InvalidCurvePoint)?;
    Ok(*beta * p_inv)
}

// ─── Server operations ───

/// Evaluate the OPRF on a blinded point.
///
/// Computes Y_t = k · X_t and generates a DLEQ proof.
/// (Whitepaper Section 7: server evaluation)
pub fn evaluate<R: Rng>(
    server_key: &OprfServerKey,
    blinded_point: &G1Projective,
    rng: &mut R,
) -> OprfEvaluation {
    let evaluated_point = *blinded_point * server_key.secret;

    // Generate DLEQ proof: prove log_G(V) == log_{X_t}(Y_t) == k
    let g = G1Projective::generator();
    let proof = dleq_prove(
        &server_key.secret,
        &g,
        &server_key.pubkey,
        blinded_point,
        &evaluated_point,
        rng,
    );

    OprfEvaluation {
        evaluated_point,
        proof,
    }
}

/// Evaluate a batch of blinded points (for token issuance).
///
/// Computes β_i = k · α_i for each blinded element, with a single batched DLEQ proof.
/// (Whitepaper Section 3: server-side token evaluation)
pub fn evaluate_batch<R: Rng>(
    server_key: &OprfServerKey,
    blinded_points: &[G1Projective],
    rng: &mut R,
) -> (Vec<G1Projective>, DleqProof) {
    let betas: Vec<G1Projective> = blinded_points
        .iter()
        .map(|alpha| *alpha * server_key.secret)
        .collect();

    let g = G1Projective::generator();
    let proof = batched_dleq_prove(
        &server_key.secret,
        &g,
        &server_key.pubkey,
        blinded_points,
        &betas,
        rng,
    );

    (betas, proof)
}

/// Verify a batch evaluation (client-side).
pub fn verify_batch(
    server_pubkey: &G1Projective,
    alphas: &[G1Projective],
    betas: &[G1Projective],
    proof: &DleqProof,
) -> Result<(), PerseverusError> {
    let g = G1Projective::generator();
    batched_dleq_verify(proof, &g, server_pubkey, alphas, betas)
}

// ─── Direct OPRF evaluation (server-side, for filter construction) ───

/// Compute γ_r = k · H2C(record_id) directly (no blinding).
/// Used by the server when constructing encrypted block filters (Section 6).
pub fn evaluate_direct(
    server_key: &OprfServerKey,
    record_id: &[u8],
) -> Result<G1Projective, PerseverusError> {
    let point = hash_to_curve(record_id);
    Ok(point * server_key.secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use rand::thread_rng;

    #[test]
    fn test_oprf_blind_evaluate_unblind() {
        let mut rng = thread_rng();
        let server_key = OprfServerKey::generate(&mut rng);

        let input = b"test-txid:0";

        // Client blinds
        let blinded = blind(input, &mut rng).expect("blind should succeed");

        // Server evaluates
        let eval = evaluate(&server_key, &blinded.blinded_point, &mut rng);

        // Client unblinds
        let output = unblind(&eval, &blinded, &server_key.pubkey)
            .expect("unblind should succeed");

        // Verify: output should equal k · H2C(input)
        let expected = hash_to_curve(input) * server_key.secret;
        assert_eq!(
            output.gamma.into_affine(),
            expected.into_affine(),
            "OPRF output must equal k·H2C(input)"
        );
    }

    #[test]
    fn test_oprf_different_inputs_different_outputs() {
        let mut rng = thread_rng();
        let server_key = OprfServerKey::generate(&mut rng);

        let blind1 = blind(b"txid-a:0", &mut rng).unwrap();
        let blind2 = blind(b"txid-b:0", &mut rng).unwrap();

        let eval1 = evaluate(&server_key, &blind1.blinded_point, &mut rng);
        let eval2 = evaluate(&server_key, &blind2.blinded_point, &mut rng);

        let out1 = unblind(&eval1, &blind1, &server_key.pubkey).unwrap();
        let out2 = unblind(&eval2, &blind2, &server_key.pubkey).unwrap();

        assert_ne!(
            out1.gamma.into_affine(),
            out2.gamma.into_affine(),
            "different inputs must produce different OPRF outputs"
        );
    }

    #[test]
    fn test_oprf_batch_evaluation() {
        let mut rng = thread_rng();
        let server_key = OprfServerKey::generate(&mut rng);

        // Simulate token issuance: 5 blinded elements
        let n = 5;
        let mut base_points = Vec::new();
        let mut blinding_scalars = Vec::new();
        let mut alphas = Vec::new();

        for i in 0..n {
            let data = format!("token_seed_{}", i);
            let p = hash_to_curve(data.as_bytes());
            let s = Fr::rand(&mut rng);
            let alpha = p * s;

            base_points.push(p);
            blinding_scalars.push(s);
            alphas.push(alpha);
        }

        // Server evaluates batch
        let (betas, proof) = evaluate_batch(&server_key, &alphas, &mut rng);

        // Client verifies batch
        verify_batch(&server_key.pubkey, &alphas, &betas, &proof)
            .expect("batch verification should succeed");

        // Client unblinds each token
        for i in 0..n {
            let beta_prime = unblind_token(&betas[i], &blinding_scalars[i]).unwrap();
            let expected = base_points[i] * server_key.secret;
            assert_eq!(
                beta_prime.into_affine(),
                expected.into_affine(),
                "unblinded token {} must equal k·P_i", i
            );
        }
    }

    #[test]
    fn test_oprf_wrong_key_fails_dleq() {
        let mut rng = thread_rng();
        let server_key = OprfServerKey::generate(&mut rng);
        let wrong_key = OprfServerKey::generate(&mut rng);

        let input = b"test-txid:0";
        let blinded = blind(input, &mut rng).unwrap();

        // Evaluate with correct key but present wrong pubkey
        let eval = evaluate(&server_key, &blinded.blinded_point, &mut rng);

        // Unblind with wrong pubkey should fail DLEQ verification
        let result = unblind(&eval, &blinded, &wrong_key.pubkey);
        assert!(result.is_err(), "DLEQ verification should fail with wrong pubkey");
    }
}
