//! Nullifier derivation (v11 — domain-separated, token-seed based).
//!
//! A **nullifier** is a one-shot tag revealed by the spending proof that
//! uniquely identifies a token without revealing which pack it came from.
//! The server maintains a global set of seen nullifiers, rejecting any
//! proof whose nullifier is already in the set — this prevents double-spend.
//!
//! ### Construction (v11)
//!
//! ```text
//! nullifier = Poseidon(NULLIFIER_TAG, token_seed, pack_id, token_index)
//! ```
//!
//! **Why the tag (v11, security review F12).** The token base point is
//! `P = s·H_TOKEN` with `s = Poseidon(token_seed, pack_id, token_index)`,
//! and the server sees every `P` at issuance. Up to v10 the nullifier was
//! that same `s`, so the server could compute `nullifier·H_TOKEN`, match it
//! to a `P` it had signed, and link every spend to its purchase. With the
//! leading constant the nullifier is an unrelated Poseidon output: getting
//! from a `P` to its nullifier would need `s` (a discrete log), and getting
//! from a nullifier to `s` would need a Poseidon preimage.
//!
//! - `token_seed`: only the wallet knows this. A per-pack random scalar
//!   chosen at issuance time. Ensures the server cannot precompute
//!   nullifiers for any pack.
//! - `pack_id`: random 64-bit identifier assigned at issuance. Ensures
//!   nullifiers are unique across packs even if two packs happen to
//!   share the same seed (which should never happen, but defense-in-depth).
//! - `token_index`: which token within the pack is being spent.
//!
//! ### Unlinkability
//!
//! The server never learns `token_seed` — it is used only inside the
//! zero-knowledge proof. Without the seed the server cannot derive
//! nullifiers for any pack, and (since v11) it cannot relate a nullifier to
//! the base points it saw at issuance.
//!
//! ### Migration note (v4 → v6)
//!
//! v4 used `Poseidon(blinding_factor, pack_id, token_index)` where
//! `blinding_factor` was the Pedersen commitment randomness. Since v6
//! removes Pedersen commitments entirely, we use `token_seed` directly.
//! This must match exactly what `circuits::gadgets::enforce_nullifier`
//! computes in-circuit.

use crate::poseidon::{poseidon_hash_many, PoseidonField};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;

/// Public label behind [`nullifier_tag`].
const NULLIFIER_TAG_LABEL: &[u8] = b"perseverus/nullifier/v11";

/// The constant absorbed first into every nullifier hash (v11). The circuit
/// bakes in the same value. Derived from a readable label so it is auditable.
pub fn nullifier_tag() -> PoseidonField {
    PoseidonField::from_be_bytes_mod_order(NULLIFIER_TAG_LABEL)
}

/// Compute the nullifier for a token at `(pack_id, token_index)` in a pack
/// with the given `token_seed`. Must match `circuits::gadgets::enforce_nullifier`.
pub fn compute_nullifier(
    cfg: &PoseidonConfig<PoseidonField>,
    token_seed: PoseidonField,
    pack_id: PoseidonField,
    token_index: PoseidonField,
) -> PoseidonField {
    poseidon_hash_many(cfg, &[nullifier_tag(), token_seed, pack_id, token_index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::poseidon_config;

    #[test]
    fn nullifier_is_deterministic() {
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let pack_id = PoseidonField::from(12345u64);
        let idx = PoseidonField::from(3u64);
        assert_eq!(
            compute_nullifier(&cfg, seed, pack_id, idx),
            compute_nullifier(&cfg, seed, pack_id, idx),
        );
    }

    #[test]
    fn different_pack_gives_different_nullifier() {
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let idx = PoseidonField::from(3u64);
        let n1 = compute_nullifier(&cfg, seed, PoseidonField::from(100u64), idx);
        let n2 = compute_nullifier(&cfg, seed, PoseidonField::from(200u64), idx);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_token_gives_different_nullifier() {
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let pack_id = PoseidonField::from(42u64);
        let n_a = compute_nullifier(&cfg, seed, pack_id, PoseidonField::from(0u64));
        let n_b = compute_nullifier(&cfg, seed, pack_id, PoseidonField::from(1u64));
        assert_ne!(n_a, n_b);
    }

    /// F12 regression: nothing the server saw at issuance (the base point
    /// `P = s·H_TOKEN`) may let it compute or recognise the nullifier.
    #[test]
    fn nullifier_is_not_derivable_from_the_base_point() {
        use crate::h2c::{h_token, token_base_point};
        use ark_ec::CurveGroup;
        use ark_ff::BigInteger;
        let cfg = poseidon_config();
        let seed = PoseidonField::from(7u64);
        let pack_id = PoseidonField::from(12345u64);
        let idx = PoseidonField::from(3u64);

        let s = poseidon_hash_many(&cfg, &[seed, pack_id, idx]);
        let n = compute_nullifier(&cfg, seed, pack_id, idx);
        assert_ne!(n, s, "nullifier must not equal the base-point scalar");

        // The v10 attack: nullifier·H_TOKEN == P. Must no longer hold.
        let p = token_base_point(&cfg, seed, pack_id, idx).into_affine();
        let mut acc = ark_ed_on_bn254::EdwardsProjective::default();
        let mut base = h_token();
        for bit in n.into_bigint().to_bits_le() {
            if bit { acc += base; }
            base = base + base;
        }
        assert_ne!(acc.into_affine(), p, "server must not be able to map a nullifier to a P_i");
    }

    #[test]
    fn different_seed_gives_different_nullifier() {
        let cfg = poseidon_config();
        let pack_id = PoseidonField::from(42u64);
        let idx = PoseidonField::from(0u64);
        let n1 = compute_nullifier(&cfg, PoseidonField::from(1u64), pack_id, idx);
        let n2 = compute_nullifier(&cfg, PoseidonField::from(2u64), pack_id, idx);
        assert_ne!(n1, n2);
    }
}
