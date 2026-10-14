//! Shared Poseidon configuration.
//!
//! The Merkle tree over a user's token pack is hashed with Poseidon-2. The
//! **exact** same `PoseidonConfig` must be used by:
//!   - `perseverus-core` when the server builds the tree and publishes the root
//!   - `perseverus-circuits` when the prover hashes a leaf and folds up to verify membership
//! Mismatched round constants or MDS matrices would produce different roots
//! and every Groth16 proof would fail — this module is the single source of truth.
//!
//! ## Parameter choice
//!
//! - State width = 3 (rate 2, capacity 1) — enough to absorb two field elements
//!   per permutation, which is exactly what a 2-to-1 Merkle CRH needs.
//! - α = 5 — standard for BN254-size fields; gcd(5, p−1) = 1 for Fr(BN254).
//! - 8 full rounds, 57 partial rounds — derived from the Grassi et al. security
//!   analysis for a ~254-bit prime field at the 128-bit security level, matching
//!   the standard Poseidon parameterisation used by Zcash, Hermez, and others.
//! - Round constants + MDS matrix are generated deterministically from the
//!   field and round counts via `find_poseidon_ark_and_mds`, so re-deriving
//!   them on every process start produces identical output across builds.

use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};

/// Field Poseidon operates over. Equals `Fr(BN254)` = `Fq(BabyJubJub)`.
/// We pin the type to `ark_bn254::Fr` so it matches `circuits::CircuitField`
/// without any awkward conversions — BabyJubJub point coordinates live in this
/// field natively.
pub type PoseidonField = ark_bn254::Fr;

/// Full (= unpartial) rounds. 4 at the start + 4 at the end by convention.
pub const FULL_ROUNDS: usize = 8;
/// Partial rounds in the middle.
pub const PARTIAL_ROUNDS: usize = 57;
/// S-box exponent. 5 is coprime with Fr(BN254) p − 1.
pub const ALPHA: u64 = 5;
/// Sponge rate. 2 field elements absorbed per permutation.
pub const RATE: usize = 2;
/// Sponge capacity. Must be ≥ 1 for 2-to-1 CRH to be collision-resistant.
pub const CAPACITY: usize = 1;

/// Bit width of Fr(BN254). This is the ~254-bit scalar field of BN254,
/// which is also the base field of BabyJubJub.
const PRIME_BITS: u64 = 254;

/// Return the canonical Poseidon-2 config for Fr(BN254).
///
/// Cheap to call — `find_poseidon_ark_and_mds` is deterministic but not free,
/// so callers that hash many values should cache the returned `PoseidonConfig`.
pub fn poseidon_config() -> PoseidonConfig<PoseidonField> {
    let (ark, mds) = find_poseidon_ark_and_mds::<PoseidonField>(
        PRIME_BITS,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        /* skip_matrices = */ 0,
    );
    PoseidonConfig::new(
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        ALPHA,
        mds,
        ark,
        RATE,
        CAPACITY,
    )
}

/// Native two-to-one Poseidon compression:  `hash(left, right)`.
///
/// Used by the server to build the token-pack Merkle tree. Matches the
/// in-circuit 2-to-1 CRH exactly (same parameters, same absorb order).
pub fn poseidon_two_to_one(
    cfg: &PoseidonConfig<PoseidonField>,
    left: PoseidonField,
    right: PoseidonField,
) -> PoseidonField {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    let mut sponge = PoseidonSponge::<PoseidonField>::new(cfg);
    sponge.absorb(&left);
    sponge.absorb(&right);
    sponge.squeeze_field_elements(1)[0]
}

/// Variadic native Poseidon hash — absorbs `inputs` in order and squeezes one
/// field element. Used for nullifier and leaf commitments (more than two inputs).
pub fn poseidon_hash_many(
    cfg: &PoseidonConfig<PoseidonField>,
    inputs: &[PoseidonField],
) -> PoseidonField {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    let mut sponge = PoseidonSponge::<PoseidonField>::new(cfg);
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn config_is_deterministic() {
        let c1 = poseidon_config();
        let c2 = poseidon_config();
        assert_eq!(c1.ark, c2.ark);
        assert_eq!(c1.mds, c2.mds);
    }

    #[test]
    fn two_to_one_matches_variadic() {
        let cfg = poseidon_config();
        let mut rng = ark_std::test_rng();
        let a = PoseidonField::rand(&mut rng);
        let b = PoseidonField::rand(&mut rng);
        assert_eq!(
            poseidon_two_to_one(&cfg, a, b),
            poseidon_hash_many(&cfg, &[a, b]),
        );
    }

    #[test]
    fn two_to_one_is_order_sensitive() {
        let cfg = poseidon_config();
        let mut rng = ark_std::test_rng();
        let a = PoseidonField::rand(&mut rng);
        let b = PoseidonField::rand(&mut rng);
        assert_ne!(
            poseidon_two_to_one(&cfg, a, b),
            poseidon_two_to_one(&cfg, b, a),
        );
    }
}
