//! Native token-pack Merkle tree.
//!
//! A **token pack** is a batch of `(P_i, β_i)` VOPRF tokens the server issues
//! to a client in one round. The pack is committed to by a Merkle root that
//! the server signs (or embeds in the SNARK's public inputs). When the client
//! later spends one token to authenticate a filter query, the Groth16 proof
//! shows Merkle membership of `(P_i, β_i)` under that root.
//!
//! ### Leaf encoding
//!
//! Each leaf hashes the (x, y) coordinates of two BabyJubJub points down to a
//! single field element:
//!
//! ```text
//! leaf_i = Poseidon(Px_i, Py_i, βx_i, βy_i)
//! ```
//!
//! BabyJubJub is defined over Fr(BN254), which is exactly our Poseidon field,
//! so point coordinates are native field elements with no conversion overhead.
//!
//! ### Tree shape
//!
//! Fixed depth = [`MERKLE_DEPTH`], so every pack has the same shape and the
//! circuit dimensions are known at setup time. If a pack has fewer than
//! `2^MERKLE_DEPTH` tokens, the remaining leaves are filled with [`EMPTY_LEAF`]
//! so both the server and the circuit fold the tree the same way.

use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::{AdditiveGroup, CurveGroup};

use crate::poseidon::{poseidon_hash_many, poseidon_two_to_one, PoseidonField};

/// Depth of the token-pack Merkle tree. Must match `circuits::MERKLE_DEPTH`.
pub const MERKLE_DEPTH: usize = 10;

/// Max tokens per pack.
pub const MAX_PACK_SIZE: usize = 1 << MERKLE_DEPTH;

/// Sentinel leaf for empty slots. Zero is fine because a real leaf is a
/// Poseidon output and the preimage-resistance of Poseidon makes a collision
/// with zero infeasible.
pub const EMPTY_LEAF: PoseidonField = PoseidonField::ZERO;

/// A single issued VOPRF token, in affine form.
#[derive(Clone, Debug)]
pub struct Token {
    pub base_point: EdwardsAffine,
    pub blinded_sig: EdwardsAffine,
}

impl Token {
    pub fn from_projective(base: EdwardsProjective, sig: EdwardsProjective) -> Self {
        Self {
            base_point: base.into_affine(),
            blinded_sig: sig.into_affine(),
        }
    }
}

/// A sibling hash + selector bit at one level of the authentication path.
#[derive(Clone, Debug)]
pub struct MerkleStep {
    pub sibling: PoseidonField,
    /// `false` → current node is the left child (sibling is on the right).
    /// `true`  → current node is the right child (sibling is on the left).
    pub current_is_right: bool,
}

/// A fully-built token pack with its Merkle tree.
#[derive(Debug, Clone)]
pub struct TokenPack {
    pub tokens: Vec<Token>,
    pub leaves: Vec<PoseidonField>,
    /// All internal levels, from the layer just above the leaves up to the root.
    /// `levels[0]` is the first parent layer; `levels.last()` is a 1-element vector = root.
    pub levels: Vec<Vec<PoseidonField>>,
    pub root: PoseidonField,
}

impl TokenPack {
    /// Build a fixed-depth Merkle tree over `tokens`.
    /// Returns an error if the pack is too large.
    pub fn build(
        cfg: &PoseidonConfig<PoseidonField>,
        tokens: Vec<Token>,
    ) -> Result<Self, &'static str> {
        if tokens.len() > MAX_PACK_SIZE {
            return Err("token pack exceeds MAX_PACK_SIZE");
        }

        // Hash each token into a leaf.
        let mut leaves: Vec<PoseidonField> =
            tokens.iter().map(|t| leaf_hash(cfg, t)).collect();

        // Pad out to 2^MERKLE_DEPTH with sentinel.
        leaves.resize(MAX_PACK_SIZE, EMPTY_LEAF);

        // Fold up.
        let mut levels: Vec<Vec<PoseidonField>> = Vec::with_capacity(MERKLE_DEPTH);
        let mut current = leaves.clone();
        for _ in 0..MERKLE_DEPTH {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                next.push(poseidon_two_to_one(cfg, pair[0], pair[1]));
            }
            levels.push(next.clone());
            current = next;
        }
        debug_assert_eq!(current.len(), 1);
        let root = current[0];

        Ok(TokenPack {
            tokens,
            leaves,
            levels,
            root,
        })
    }

    /// Build the authentication path for the token at `index`.
    pub fn auth_path(&self, index: usize) -> Vec<MerkleStep> {
        assert!(index < MAX_PACK_SIZE, "index out of range");
        let mut path = Vec::with_capacity(MERKLE_DEPTH);
        let mut idx = index;

        // Leaf level first.
        let sibling_idx = idx ^ 1;
        path.push(MerkleStep {
            sibling: self.leaves[sibling_idx],
            current_is_right: (idx & 1) == 1,
        });
        idx >>= 1;

        // Internal levels (levels[0] ... levels[MERKLE_DEPTH - 2]).
        for level in &self.levels[..MERKLE_DEPTH - 1] {
            let sibling_idx = idx ^ 1;
            path.push(MerkleStep {
                sibling: level[sibling_idx],
                current_is_right: (idx & 1) == 1,
            });
            idx >>= 1;
        }

        debug_assert_eq!(path.len(), MERKLE_DEPTH);
        path
    }
}

/// Hash one token into a single field element.
///
/// Absorb order: `[P.x, P.y, β.x, β.y]`. Must match the in-circuit version.
/// Since BabyJubJub coordinates are Fr(BN254) = PoseidonField, no conversion
/// is needed — we absorb the raw coordinates directly.
pub fn leaf_hash(cfg: &PoseidonConfig<PoseidonField>, token: &Token) -> PoseidonField {
    let (px, py) = encode_point(&token.base_point);
    let (bx, by) = encode_point(&token.blinded_sig);
    poseidon_hash_many(cfg, &[px, py, bx, by])
}

/// Extract the (x, y) coordinates of a BabyJubJub point as PoseidonField elements.
/// Since Fq(BabyJubJub) == Fr(BN254) == PoseidonField, this is a direct read.
fn encode_point(p: &EdwardsAffine) -> (PoseidonField, PoseidonField) {
    // BabyJubJub identity is (0, 1) — no separate infinity flag needed.
    (p.x, p.y)
}

/// Recompute the root from a leaf + auth path. Useful in tests and as a
/// reference for the in-circuit fold.
pub fn recompute_root(
    cfg: &PoseidonConfig<PoseidonField>,
    leaf: PoseidonField,
    path: &[MerkleStep],
) -> PoseidonField {
    let mut current = leaf;
    for step in path {
        let (l, r) = if step.current_is_right {
            (step.sibling, current)
        } else {
            (current, step.sibling)
        };
        current = poseidon_two_to_one(cfg, l, r);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::poseidon_config;
    use ark_ec::PrimeGroup;
    use ark_std::UniformRand;

    fn random_token<R: rand::Rng>(rng: &mut R) -> Token {
        let g = EdwardsProjective::generator();
        let a = ark_ed_on_bn254::Fr::rand(rng);
        let b = ark_ed_on_bn254::Fr::rand(rng);
        Token::from_projective(g * a, g * b)
    }

    #[test]
    fn build_and_verify_single_token() {
        let cfg = poseidon_config();
        let mut rng = ark_std::test_rng();
        let tokens = vec![random_token(&mut rng)];
        let pack = TokenPack::build(&cfg, tokens).unwrap();
        let path = pack.auth_path(0);
        let recomputed = recompute_root(&cfg, pack.leaves[0], &path);
        assert_eq!(recomputed, pack.root);
    }

    #[test]
    fn build_and_verify_many_indices() {
        let cfg = poseidon_config();
        let mut rng = ark_std::test_rng();
        let tokens: Vec<_> = (0..17).map(|_| random_token(&mut rng)).collect();
        let pack = TokenPack::build(&cfg, tokens).unwrap();
        for idx in [0, 1, 5, 8, 16] {
            let path = pack.auth_path(idx);
            let recomputed = recompute_root(&cfg, pack.leaves[idx], &path);
            assert_eq!(recomputed, pack.root, "mismatch at index {}", idx);
        }
    }

    #[test]
    fn wrong_leaf_does_not_verify() {
        let cfg = poseidon_config();
        let mut rng = ark_std::test_rng();
        let tokens: Vec<_> = (0..4).map(|_| random_token(&mut rng)).collect();
        let pack = TokenPack::build(&cfg, tokens).unwrap();
        let path = pack.auth_path(2);
        let bogus = PoseidonField::from(999u64);
        let recomputed = recompute_root(&cfg, bogus, &path);
        assert_ne!(recomputed, pack.root);
    }
}
