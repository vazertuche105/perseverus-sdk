//! Hash-to-curve for BabyJubJub (twisted Edwards curve on BN254).
//!
//! Maps arbitrary byte strings to BabyJubJub points in the prime-order subgroup.
//! Used throughout the VOPRF protocol for blinding TXIDs and deriving token base
//! points.
//!
//! BabyJubJub is defined over Fr(BN254), so point coordinates are native field
//! elements inside the BN254 Groth16 circuit — no non-native arithmetic needed.
//!
//! Hash-to-curve uses try-and-increment (hash, check if x maps to a point,
//! increment counter if not, cofactor-clear to land in the prime-order subgroup).
//! DSTs are bumped to V3 for the curve migration from BLS12-377.

use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, EdwardsProjective, Fq};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AffineRepr, AdditiveGroup};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use sha2::{Digest, Sha256};

use crate::poseidon::{poseidon_hash_many, PoseidonField};

/// Domain separation tag for the Perseverus VOPRF
const DST_OPRF: &[u8] = b"Perseverus-V3-VOPRF-BabyJubJub_SHA256_TAI_";

/// Domain separation tag for token base point derivation
const DST_TOKEN: &[u8] = b"Perseverus-V3-TOKEN-BabyJubJub_SHA256_TAI_";

/// Domain separation tag for the NUMS generator used in in-circuit token base
/// point derivation. See [`h_token`].
const DST_H_TOKEN: &[u8] = b"Perseverus-V3-HTOKEN-BabyJubJub_SHA256_TAI_";

/// Label hashed to produce the NUMS generator. Any fixed public string works;
/// choosing a human-readable one makes the construction auditable.
const H_TOKEN_LABEL: &[u8] = b"perseverus-h-token-nums-generator-v3";

/// Hash arbitrary data to a BabyJubJub point using the VOPRF domain.
///
/// This is H2C(data) in the whitepaper. Used for:
/// - Hashing (TXID || vout_index) for OPRF queries (Section 7)
/// - Hashing (token_seed || index) for token base points (Section 3)
///
/// Uses try-and-increment with SHA-256 and cofactor clearing.
pub fn hash_to_curve(data: &[u8]) -> EdwardsProjective {
    hash_to_curve_with_dst(data, DST_OPRF)
}

/// Hash to BabyJubJub with a specific domain separation tag.
///
/// Try-and-increment: hash(DST || data || counter) → field element x,
/// attempt to lift to a curve point, cofactor-clear into the prime-order subgroup.
pub fn hash_to_curve_with_dst(data: &[u8], dst: &[u8]) -> EdwardsProjective {
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(dst);
        hasher.update(data);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        // Interpret hash as a BabyJubJub base field element (= Fr(BN254))
        let x = Fq::from_be_bytes_mod_order(&hash);

        // Try to lift x to a point on the twisted Edwards curve:
        //   a·x² + y² = 1 + d·x²·y²
        //   y² = (1 − a·x²) / (1 − d·x²)
        let x_sq = x.square();
        let a = EdwardsConfig::COEFF_A;
        let d = EdwardsConfig::COEFF_D;
        let numerator = Fq::ONE - a * x_sq;
        let denominator = Fq::ONE - d * x_sq;

        if denominator.is_zero() {
            continue;
        }

        let y_sq = numerator * denominator.inverse().unwrap();

        if let Some(y) = y_sq.sqrt() {
            let point = EdwardsAffine::new_unchecked(x, y);

            // Sanity: must be on curve
            if !point.is_on_curve() {
                continue;
            }

            // Cofactor-clear into the prime-order subgroup (cofactor = 8 for BJJ)
            let cleared = point.mul_by_cofactor_to_group();
            if !cleared.is_zero() {
                return cleared;
            }
        }
    }
    unreachable!("try-and-increment must eventually find a valid point")
}

/// Hash data to BabyJubJub using the token derivation domain.
/// Used for P_i = H2C(token_seed_i || i)
pub fn hash_to_curve_token(data: &[u8]) -> EdwardsProjective {
    hash_to_curve_with_dst(data, DST_TOKEN)
}

/// **Nothing-Up-My-Sleeve** BabyJubJub generator for in-circuit token base
/// point derivation.
///
/// The in-circuit hash-to-curve is:
///
/// ```text
/// P_i = Poseidon(token_seed, token_index) · H_TOKEN
/// ```
///
/// Soundness requires `log_{G}(H_TOKEN)` to be unknown to everyone —
/// otherwise a malicious client could pick a scalar `a` it knows, set
/// `P = a·G` and `β = a·V`, and forge a valid DLEQ for an "origin-free"
/// token. We derive `H_TOKEN` from a fixed public label via try-and-increment
/// H2C, which is a standard NUMS construction.
///
/// The value is deterministic across all processes — same label + same DST
/// always produces the same point. Callers that use it many times should
/// cache the result.
pub fn h_token() -> EdwardsProjective {
    hash_to_curve_with_dst(H_TOKEN_LABEL, DST_H_TOKEN)
}

/// Compute the token base point for `(seed, pack_id, index)` as used by both
/// the server's token-issuance pipeline and the in-circuit
/// `enforce_base_point_derivation` gadget:
///
/// ```text
/// P = Poseidon(seed, pack_id, index) · H_TOKEN
/// ```
///
/// The hash output is an element of `Fr(BN254)` (≈ 254 bits). It is
/// scalar-multiplied into BabyJubJub by interpreting its canonical little-endian
/// integer representation as a scalar — the group order wraps as usual, and
/// the in-circuit `scalar_mul_le` does the same thing bit-for-bit.
///
/// ### v6 change
///
/// v4 used `Poseidon(seed, index)`. v6 adds `pack_id` so that two packs
/// with the same seed (shouldn't happen, but defense-in-depth) produce
/// different base points and thus different DLEQ signatures.
pub fn token_base_point(
    cfg: &PoseidonConfig<PoseidonField>,
    seed: PoseidonField,
    pack_id: PoseidonField,
    index: PoseidonField,
) -> EdwardsProjective {
    let s = poseidon_hash_many(cfg, &[seed, pack_id, index]);
    // Manual LE double-and-add over the canonical little-endian bits of `s`.
    // This matches the in-circuit `scalar_mul_le` exactly.
    let bits = s.into_bigint().to_bits_le();
    let mut acc = EdwardsProjective::ZERO;
    let mut base = h_token();
    for bit in bits {
        if bit {
            acc += base;
        }
        base.double_in_place();
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    #[test]
    fn test_hash_to_curve_deterministic() {
        let data = b"test-txid-data";
        let p1 = hash_to_curve(data);
        let p2 = hash_to_curve(data);
        assert_eq!(p1.into_affine(), p2.into_affine(), "H2C must be deterministic");
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        let p1 = hash_to_curve(b"input-a");
        let p2 = hash_to_curve(b"input-b");
        assert_ne!(p1.into_affine(), p2.into_affine(), "different inputs should give different points");
    }

    #[test]
    fn test_hash_to_curve_on_curve() {
        let p = hash_to_curve(b"on-curve-test");
        let affine = p.into_affine();
        assert!(affine.is_on_curve(), "point must be on BabyJubJub");
        assert!(affine.is_in_correct_subgroup_assuming_on_curve(), "point must be in prime-order subgroup");
    }

    #[test]
    fn test_different_dst_different_points() {
        let data = b"same-data";
        let p1 = hash_to_curve(data);
        let p2 = hash_to_curve_token(data);
        assert_ne!(p1.into_affine(), p2.into_affine(), "different DSTs should give different points");
    }

    #[test]
    fn h_token_is_deterministic_and_on_curve() {
        let h1 = h_token().into_affine();
        let h2 = h_token().into_affine();
        assert_eq!(h1, h2, "H_TOKEN must be deterministic across calls");
        assert!(h1.is_on_curve());
        assert!(h1.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn token_base_point_is_deterministic() {
        use crate::poseidon::poseidon_config;
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let pack_id = PoseidonField::from(42u64);
        let idx = PoseidonField::from(3u64);
        let p1 = token_base_point(&cfg, seed, pack_id, idx).into_affine();
        let p2 = token_base_point(&cfg, seed, pack_id, idx).into_affine();
        assert_eq!(p1, p2);
        assert!(p1.is_on_curve());
        assert!(p1.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn token_base_point_differs_for_different_inputs() {
        use crate::poseidon::poseidon_config;
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let pack_id = PoseidonField::from(42u64);
        let p1 = token_base_point(&cfg, seed, pack_id, PoseidonField::from(0u64)).into_affine();
        let p2 = token_base_point(&cfg, seed, pack_id, PoseidonField::from(1u64)).into_affine();
        let p3 = token_base_point(&cfg, PoseidonField::from(8u64), pack_id, PoseidonField::from(0u64)).into_affine();
        let p4 = token_base_point(&cfg, seed, PoseidonField::from(99u64), PoseidonField::from(0u64)).into_affine();
        assert_ne!(p1, p2, "different index must give different base point");
        assert_ne!(p1, p3, "different seed must give different base point");
        assert_ne!(p1, p4, "different pack_id must give different base point");
    }
}
