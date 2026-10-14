//! Nullifier derivation (v6 — token-seed based).
//!
//! A **nullifier** is a one-shot tag revealed by the spending proof that
//! uniquely identifies a token without revealing which pack it came from.
//! The server maintains a global set of seen nullifiers, rejecting any
//! proof whose nullifier is already in the set — this prevents double-spend.
//!
//! ### Construction (v6)
//!
//! ```text
//! nullifier = Poseidon(token_seed, pack_id, token_index)
//! ```
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
//! The server never learns `token_seed` — it is transmitted only inside
//! the zero-knowledge proof. Without the seed, the server cannot derive
//! nullifiers for any token in any pack, so it cannot link a revealed
//! nullifier back to a specific pack or wallet.
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

/// Compute the nullifier for a token at `(pack_id, token_index)` in a pack
/// with the given `token_seed`.
pub fn compute_nullifier(
    cfg: &PoseidonConfig<PoseidonField>,
    token_seed: PoseidonField,
    pack_id: PoseidonField,
    token_index: PoseidonField,
) -> PoseidonField {
    poseidon_hash_many(cfg, &[token_seed, pack_id, token_index])
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
