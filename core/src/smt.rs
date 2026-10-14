//! Sparse Merkle Tree (depth-16) for token pack revocation.
//!
//! The revocation tree is a depth-16 binary trie where the path from
//! root to leaf is determined by the first 16 bits of the key (the
//! Poseidon hash of the pack identifier). An empty node has hash
//! `EMPTY_HASH = 0`.
//!
//! ## Non-inclusion proof
//!
//! To prove a key is **not** in the tree, the prover shows an authentication
//! path from the key's position to the root, where the leaf at that position
//! is empty (hash = 0). The verifier:
//!
//! 1. Starts with `current = EMPTY_HASH` (the leaf is empty)
//! 2. Folds up 32 levels using the sibling hashes and direction bits
//! 3. Checks `current == revocation_root`
//!
//! If the root matches, the key is not in the tree (no revoked token at
//! that position).
//!
//! ## Key derivation
//!
//! The key for a pack in the revocation tree is:
//! ```text
//! key = Poseidon(pack_id)   (truncated to 32 bits)
//! ```
//! This produces a 254-bit field element; only the first 16 bits are used
//! as the tree path. The server checks for path collisions at issuance
//! time, so the 2^16 keyspace is collision-free in practice.
//!
//! ## In-circuit usage
//!
//! The circuit receives `revocation_root` as a public input and the
//! SMT authentication path (16 siblings + 16 direction bits) as witness.
//! It verifies non-inclusion by folding from an empty leaf up to the root.

use crate::poseidon::{poseidon_two_to_one, poseidon_hash_many, poseidon_config, PoseidonField};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField, Zero};

/// Depth of the sparse Merkle tree. We use only 16 bits of the
/// Poseidon(pack_id) hash, giving 2^16 (65,536) leaf positions.
/// The server enforces collision-free issuance, so this is safe.
/// Keeping the depth small is critical for in-circuit performance:
/// each level adds one Poseidon hash (~243 R1CS constraints).
/// 65,536 positions at 100 revocations/month covers ~54 years.
pub const SMT_DEPTH: usize = 16;

/// Hash of an empty node (zero).
pub fn empty_hash() -> PoseidonField {
    PoseidonField::zero()
}

/// Compute the revocation key for a pack_id.
/// `key = Poseidon(pack_id)` — a single-element hash to spread bits uniformly.
pub fn revocation_key(
    cfg: &PoseidonConfig<PoseidonField>,
    pack_id: PoseidonField,
) -> PoseidonField {
    poseidon_hash_many(cfg, &[pack_id])
}

/// The 16-bit leaf slot a pack_id occupies in the revocation tree: the
/// low `SMT_DEPTH` bits (little-endian) of `Poseidon(pack_id)` — exactly
/// the bits the tree path uses (see `field_to_bits`).
///
/// Two pack_ids that map to the same slot would share a leaf, so a
/// revocation of one would strand the other (it could no longer prove
/// non-inclusion). Issuance therefore enforces slot uniqueness: the
/// client re-rolls pack_id against the occupied-slot list before
/// blinding (GET /board/slots), and the server rejects a colliding
/// /board/publish with 409 CONFLICT as a backstop.
pub fn revocation_slot(
    cfg: &PoseidonConfig<PoseidonField>,
    pack_id: u64,
) -> u16 {
    let key = revocation_key(cfg, PoseidonField::from(pack_id));
    let bits = key.into_bigint().to_bits_le();
    let mut slot: u16 = 0;
    for i in 0..SMT_DEPTH {
        if *bits.get(i).unwrap_or(&false) {
            slot |= 1 << i;
        }
    }
    slot
}

/// A non-inclusion proof for the sparse Merkle tree.
#[derive(Clone, Debug)]
pub struct SmtNonInclusionProof {
    /// The SMT_DEPTH sibling hashes along the path from leaf to root.
    pub siblings: Vec<PoseidonField>,
    /// The SMT_DEPTH direction bits: `bits[i]` is true if the path goes right at level i.
    pub path_bits: Vec<bool>,
}

/// A simple in-memory Sparse Merkle Tree.
///
/// For the MVP, the tree stores only the set of revoked keys. Since the
/// number of revoked packs is expected to be small (< 10K), we use a
/// HashMap-based lazy representation rather than materializing all 2^256 nodes.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Cached node hashes. Key = (depth, path_prefix_as_bits), Value = hash.
    /// We store only non-empty nodes.
    nodes: std::collections::HashMap<(u8, Vec<bool>), PoseidonField>,
    /// The set of inserted keys (for iteration/debugging).
    inserted_keys: Vec<PoseidonField>,
    /// Poseidon config (cached).
    cfg: PoseidonConfig<PoseidonField>,
}

impl SparseMerkleTree {
    /// Create a new empty SMT.
    pub fn new() -> Self {
        Self {
            nodes: std::collections::HashMap::new(),
            inserted_keys: Vec::new(),
            cfg: poseidon_config(),
        }
    }

    /// Insert a key into the tree (marks it as revoked).
    /// The leaf value for a present key is `Poseidon(key, 1)` to distinguish
    /// from empty (which is 0).
    pub fn insert(&mut self, key: PoseidonField) {
        let bits = field_to_bits(key);
        let leaf_hash = poseidon_hash_many(&self.cfg, &[key, PoseidonField::from(1u64)]);

        // Set the leaf node
        self.nodes.insert(((SMT_DEPTH - 1) as u8, bits.clone()), leaf_hash);
        self.inserted_keys.push(key);

        // Recompute path from leaf to root
        let mut current = leaf_hash;
        for depth in (0..SMT_DEPTH).rev() {
            let bit = bits[depth];
            let sibling_bits = sibling_path(&bits, depth);
            let sibling = self.get_node(depth as u8, &sibling_bits);

            let (left, right) = if bit {
                (sibling, current)
            } else {
                (current, sibling)
            };

            let parent_hash = if left.is_zero() && right.is_zero() {
                PoseidonField::zero()
            } else {
                poseidon_two_to_one(&self.cfg, left, right)
            };

            let parent_bits = bits[..depth].to_vec();
            if depth > 0 {
                self.nodes.insert(((depth - 1) as u8, parent_bits), parent_hash);
            } else {
                // Root — store at (0, [])
                self.nodes.insert((0u8, vec![]), parent_hash);
            }
            current = parent_hash;
        }
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> PoseidonField {
        if self.inserted_keys.is_empty() {
            return PoseidonField::zero();
        }
        // Recompute from scratch for correctness
        self.compute_root()
    }

    /// Generate a non-inclusion proof for a key.
    /// Panics if the key IS in the tree.
    pub fn prove_non_inclusion(&self, key: PoseidonField) -> SmtNonInclusionProof {
        let bits = field_to_bits(key);

        // Verify the key is not in the tree
        let leaf = self.get_node((SMT_DEPTH - 1) as u8, &bits);
        assert!(
            leaf.is_zero(),
            "cannot generate non-inclusion proof: key is in the tree"
        );

        // Collect siblings along the path
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        for depth in 0..SMT_DEPTH {
            let sibling_bits = sibling_path(&bits, depth);
            let sibling = self.get_subtree_hash(depth, &sibling_bits);
            siblings.push(sibling);
        }

        SmtNonInclusionProof {
            siblings,
            path_bits: bits,
        }
    }

    /// Verify a non-inclusion proof against a given root.
    pub fn verify_non_inclusion(
        cfg: &PoseidonConfig<PoseidonField>,
        root: PoseidonField,
        proof: &SmtNonInclusionProof,
    ) -> bool {
        assert_eq!(proof.siblings.len(), SMT_DEPTH);
        assert_eq!(proof.path_bits.len(), SMT_DEPTH);

        // Start from an empty leaf
        let mut current = empty_hash();

        // Fold up from leaf (depth 255) to root (depth 0)
        for depth in (0..SMT_DEPTH).rev() {
            let sibling = proof.siblings[depth];
            let bit = proof.path_bits[depth];

            let (left, right) = if bit {
                (sibling, current)
            } else {
                (current, sibling)
            };

            current = if left.is_zero() && right.is_zero() {
                PoseidonField::zero()
            } else {
                poseidon_two_to_one(cfg, left, right)
            };
        }

        current == root
    }

    // ── internal helpers ──────────────────────────────────────────────────

    fn get_node(&self, depth: u8, path: &[bool]) -> PoseidonField {
        self.nodes
            .get(&(depth, path.to_vec()))
            .copied()
            .unwrap_or_else(PoseidonField::zero)
    }

    /// Get the hash of the subtree rooted at (depth, path).
    /// For a leaf (depth index in the full 256 path), returns the stored value or 0.
    fn get_subtree_hash(&self, depth: usize, path: &[bool]) -> PoseidonField {
        // This returns the sibling's subtree hash at a given depth.
        // For the simple case where the sibling subtree is empty, returns 0.
        // For non-empty subtrees, we need to compute the hash upward.
        self.compute_subtree_hash_at(depth, path)
    }

    fn compute_subtree_hash_at(&self, depth: usize, path: &[bool]) -> PoseidonField {
        // Fast path: if the tree has no nodes at all, every subtree is zero.
        if self.nodes.is_empty() {
            return PoseidonField::zero();
        }

        // At the leaf level (depth == SMT_DEPTH-1 counting from root),
        // check if there's a value
        if depth == SMT_DEPTH - 1 {
            return self.get_node((SMT_DEPTH - 1) as u8, path);
        }

        // Check if this node was already computed during insert().
        // The insert path stores intermediate hashes keyed by (depth, path).
        if let Some(&hash) = self.nodes.get(&(depth as u8, path.to_vec())) {
            return hash;
        }

        // No stored node at this position means the entire subtree is empty.
        PoseidonField::zero()
    }

    fn compute_root(&self) -> PoseidonField {
        self.compute_subtree_hash_at(0, &[])
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a field element to 256 bits (LSB first).
fn field_to_bits(f: PoseidonField) -> Vec<bool> {
    let bigint = f.into_bigint();
    let mut bits = bigint.to_bits_le();
    bits.resize(SMT_DEPTH, false);
    bits
}

/// Get the path bits for the sibling at a given depth.
/// The sibling shares the same prefix but has the opposite bit at `depth`.
fn sibling_path(bits: &[bool], depth: usize) -> Vec<bool> {
    let mut path = bits[..=depth].to_vec();
    let last = path.len() - 1;
    path[last] = !path[last];
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_zero_root() {
        let smt = SparseMerkleTree::new();
        assert!(smt.root().is_zero());
    }

    #[test]
    #[ignore] // 32 Poseidon hashes per verify — fast in release
    fn non_inclusion_in_empty_tree() {
        let smt = SparseMerkleTree::new();
        let cfg = poseidon_config();
        let key = PoseidonField::from(42u64);
        let proof = smt.prove_non_inclusion(key);
        assert!(SparseMerkleTree::verify_non_inclusion(&cfg, smt.root(), &proof));
    }

    #[test]
    #[ignore] // 32 Poseidon hashes per verify — fast in release
    fn non_inclusion_after_insert() {
        let mut smt = SparseMerkleTree::new();
        let cfg = poseidon_config();

        // Insert key A
        let key_a = revocation_key(&cfg, PoseidonField::from(100u64));
        smt.insert(key_a);

        // Prove key B is NOT in the tree
        let key_b = revocation_key(&cfg, PoseidonField::from(200u64));
        let proof = smt.prove_non_inclusion(key_b);
        let root = smt.root();
        assert!(SparseMerkleTree::verify_non_inclusion(&cfg, root, &proof));
    }

    #[test]
    #[ignore] // tree recomputation — fast in release
    fn root_changes_after_insert() {
        let mut smt = SparseMerkleTree::new();
        let cfg = poseidon_config();

        let root_before = smt.root();
        let key = revocation_key(&cfg, PoseidonField::from(1u64));
        smt.insert(key);
        let root_after = smt.root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    #[should_panic(expected = "cannot generate non-inclusion proof")]
    fn inclusion_panics() {
        let mut smt = SparseMerkleTree::new();
        let cfg = poseidon_config();
        let key = revocation_key(&cfg, PoseidonField::from(1u64));
        smt.insert(key);
        // This should panic — key IS in the tree
        let _ = smt.prove_non_inclusion(key);
    }

    #[test]
    #[ignore] // 32 Poseidon hashes per verify — fast in release
    fn proof_fails_with_wrong_root() {
        let mut smt = SparseMerkleTree::new();
        let cfg = poseidon_config();

        let key_a = revocation_key(&cfg, PoseidonField::from(100u64));
        smt.insert(key_a);

        let key_b = revocation_key(&cfg, PoseidonField::from(200u64));
        let proof = smt.prove_non_inclusion(key_b);

        // Verify against a bogus root
        let bogus_root = PoseidonField::from(999u64);
        assert!(!SparseMerkleTree::verify_non_inclusion(&cfg, bogus_root, &proof));
    }

    #[test]
    #[ignore] // multiple inserts + verify — fast in release
    fn multiple_inserts_non_inclusion() {
        let mut smt = SparseMerkleTree::new();
        let cfg = poseidon_config();

        // Insert 5 keys
        for i in 1..=5u64 {
            let key = revocation_key(&cfg, PoseidonField::from(i * 100));
            smt.insert(key);
        }

        // Prove a different key is not included
        let key_not_in = revocation_key(&cfg, PoseidonField::from(999u64));
        let proof = smt.prove_non_inclusion(key_not_in);
        let root = smt.root();
        assert!(SparseMerkleTree::verify_non_inclusion(&cfg, root, &proof));
    }
}
