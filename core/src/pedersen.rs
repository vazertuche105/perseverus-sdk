//! Pedersen commitment scheme on BabyJubJub (Whitepaper Section 10).
//!
//! A **Pedersen commitment** `C = r·G_PED + q·H_PED` binds the issuer to an
//! exact token quota `q` for each pack, while the blinding factor `r` keeps
//! that quota hidden from everyone except the committer.
//!
//! ## Generators
//!
//! `G_PED` and `H_PED` are Nothing-Up-My-Sleeve (NUMS) BabyJubJub points
//! derived via try-and-increment H2C from fixed public labels. Their
//! discrete-log relationship is unknown, which is the binding guarantee:
//! `C = r·G + q·H` can only be opened to `(r, q)` — changing either value
//! requires solving DLP in the prime-order subgroup.
//!
//! ## Bulletin board
//!
//! Each commitment is posted to an append-only public log (the "bulletin
//! board") together with a random `pack_id`. The board is auditable: anyone
//! can download it and verify that every commitment corresponds to a
//! standard-sized quota (the server publishes a proof or the quota is
//! included as a public input in the spend circuit).
//!
//! ## Security properties
//!
//! - **Hiding**: `r` is uniform in `Z_n`, so `C` reveals nothing about `q`
//!   (perfect hiding under the DLOG assumption).
//! - **Binding**: finding `(q', r') ≠ (q, r)` with `C = r'·G + q'·H`
//!   requires solving DLP in the BabyJubJub prime-order subgroup.
//! - **Fingerprint resistance**: the server cannot slip a wallet a
//!   non-standard quota because (a) `q` is a public input to the spend
//!   circuit and must match the commitment, and (b) the commitment is
//!   posted to the public board where out-of-bucket quotas are visible.

use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ed_on_bn254::EdwardsProjective;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use rand::Rng;

use crate::h2c::hash_to_curve_with_dst;
use crate::poseidon::PoseidonField;

/// Domain separation tag for the Pedersen blinding generator G_PED.
const DST_G_PED: &[u8] = b"Perseverus-V3-PEDERSEN-G-BabyJubJub_SHA256_TAI_";

/// Domain separation tag for the Pedersen value generator H_PED.
const DST_H_PED: &[u8] = b"Perseverus-V3-PEDERSEN-H-BabyJubJub_SHA256_TAI_";

/// Label for G_PED NUMS derivation.
const G_PED_LABEL: &[u8] = b"perseverus-pedersen-g-nums-generator-v3";

/// Label for H_PED NUMS derivation.
const H_PED_LABEL: &[u8] = b"perseverus-pedersen-h-nums-generator-v3";

/// The allowed standard quota sizes. Any commitment whose `q` is not in
/// this set is visibly anomalous on the public bulletin board.
pub const STANDARD_QUOTAS: &[u64] = &[30, 50, 100, 200, 500, 1000];

/// NUMS generator for the blinding factor component of the Pedersen
/// commitment: `C = r·G_PED + q·H_PED`.
///
/// Deterministic across all processes — same label + DST always produces
/// the same BabyJubJub point. Callers should cache the result.
pub fn g_ped() -> EdwardsProjective {
    hash_to_curve_with_dst(G_PED_LABEL, DST_G_PED)
}

/// NUMS generator for the quota component of the Pedersen commitment.
pub fn h_ped() -> EdwardsProjective {
    hash_to_curve_with_dst(H_PED_LABEL, DST_H_PED)
}

/// A Pedersen commitment `C = r·G_PED + q·H_PED` along with its opening.
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    /// Random 64-bit pack identifier (written to the bulletin board).
    pub pack_id: u64,
    /// The quota (number of tokens in this pack).
    pub quota: u64,
    /// Blinding factor (secret — only the wallet knows this).
    pub blinding_factor: PoseidonField,
    /// The commitment point `C = r·G_PED + q·H_PED`.
    pub commitment: EdwardsProjective,
}

/// Compute `C = r·G_PED + q·H_PED` from a quota and blinding factor.
///
/// Uses manual LE double-and-add to match the in-circuit `scalar_mul_le`
/// exactly, just like `token_base_point` in `h2c.rs`.
pub fn commit(quota: u64, blinding_factor: PoseidonField) -> EdwardsProjective {
    let g = g_ped();
    let h = h_ped();

    // r · G_PED
    let r_g = scalar_mul_le(g, blinding_factor);

    // q · H_PED (q is a small u64, but we do it the same way for consistency)
    let q_field = PoseidonField::from(quota);
    let q_h = scalar_mul_le(h, q_field);

    r_g + q_h
}

/// Create a fresh Pedersen commitment for a pack.
///
/// Generates a random `pack_id` and blinding factor `r`, then computes
/// `C = r·G_PED + q·H_PED`.
pub fn create_commitment<R: Rng>(quota: u64, rng: &mut R) -> PedersenCommitment {
    let pack_id: u64 = rng.gen();
    let blinding_factor = PoseidonField::rand(rng);
    let commitment = commit(quota, blinding_factor);

    PedersenCommitment {
        pack_id,
        quota,
        blinding_factor,
        commitment,
    }
}

/// Verify that a commitment `C` opens to `(q, r)`.
///
/// Returns `true` if `C == r·G_PED + q·H_PED`.
pub fn verify_opening(
    commitment: &EdwardsProjective,
    quota: u64,
    blinding_factor: &PoseidonField,
) -> bool {
    let expected = commit(quota, *blinding_factor);
    commitment.into_affine() == expected.into_affine()
}

/// Manual LE double-and-add scalar multiplication.
///
/// Matches the in-circuit `scalar_mul_le(bits)` exactly so that native
/// and in-circuit results agree bit-for-bit.
fn scalar_mul_le(base: EdwardsProjective, scalar: PoseidonField) -> EdwardsProjective {
    let bits = scalar.into_bigint().to_bits_le();
    let mut acc = EdwardsProjective::ZERO;
    let mut cur = base;
    for bit in bits {
        if bit {
            acc += cur;
        }
        cur.double_in_place();
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn generators_are_deterministic_and_distinct() {
        let g1 = g_ped().into_affine();
        let g2 = g_ped().into_affine();
        assert_eq!(g1, g2, "G_PED must be deterministic");

        let h1 = h_ped().into_affine();
        let h2 = h_ped().into_affine();
        assert_eq!(h1, h2, "H_PED must be deterministic");

        assert_ne!(g1, h1, "G_PED and H_PED must be distinct");
    }

    #[test]
    fn generators_are_on_curve_and_in_subgroup() {
        let g = g_ped().into_affine();
        let h = h_ped().into_affine();
        assert!(g.is_on_curve());
        assert!(g.is_in_correct_subgroup_assuming_on_curve());
        assert!(h.is_on_curve());
        assert!(h.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn commitment_opens_correctly() {
        let mut rng = ark_std::test_rng();
        let pc = create_commitment(50, &mut rng);
        assert!(verify_opening(&pc.commitment, pc.quota, &pc.blinding_factor));
    }

    #[test]
    fn wrong_quota_fails_verification() {
        let mut rng = ark_std::test_rng();
        let pc = create_commitment(50, &mut rng);
        assert!(!verify_opening(&pc.commitment, 100, &pc.blinding_factor));
    }

    #[test]
    fn wrong_blinding_fails_verification() {
        let mut rng = ark_std::test_rng();
        let pc = create_commitment(50, &mut rng);
        let wrong_r = PoseidonField::from(999u64);
        assert!(!verify_opening(&pc.commitment, pc.quota, &wrong_r));
    }

    #[test]
    fn zero_quota_commitment_works() {
        let r = PoseidonField::from(42u64);
        let c = commit(0, r);
        // C = r·G_PED + 0·H_PED = r·G_PED
        assert!(!c.is_zero(), "non-zero blinding should produce non-zero point");
        assert!(verify_opening(&c, 0, &r));
    }

    #[test]
    fn different_quotas_different_commitments() {
        let r = PoseidonField::from(42u64);
        let c50 = commit(50, r).into_affine();
        let c100 = commit(100, r).into_affine();
        assert_ne!(c50, c100, "different quotas with same r must differ");
    }

    #[test]
    fn different_blindings_different_commitments() {
        let c1 = commit(50, PoseidonField::from(1u64)).into_affine();
        let c2 = commit(50, PoseidonField::from(2u64)).into_affine();
        assert_ne!(c1, c2, "different r with same q must differ");
    }
}
