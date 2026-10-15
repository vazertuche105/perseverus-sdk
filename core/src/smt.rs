//! Sparse Merkle Tree (depth-16) for token pack revocation.
//!
//! The revocation tree is a depth-16 binary Merkle tree. A key (the
//! Poseidon hash of the pack identifier) lives at leaf index = its low 16
//! bits; bit `i` decides whether the path is a left or right child at
//! level `i` counting up from the leaves, matching the spend circuit. An
//! empty node has hash `EMPTY_HASH = 0`.
//!
//! ## Non-inclusion proof
//!
//! To prove a key is **not** in the tree, the prover shows an authentication
//! path from the key's position to the root, where the leaf at that position
//! is empty (hash = 0). The verifier:
//!
//! 1. Starts with `current = EMPTY_HASH` (the leaf is empty)
//! 2. Folds up 16 levels (leaf first) using the sibling hashes and direction bits
//! 3. Checks `current == revocation_root`
//!
//! If the root matches, the key is not in the tree (no revoked token at
//! that position).
//!
//! ## Key derivation
//!
//! The key for a pack in the revocation tree is:
//! ```text
//! key = Poseidon(pack_id)
//! ```
//! This produces a 254-bit field element; only the low 16 bits are used
//! as the leaf index. The server checks for path collisions at issuance
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
/// the leaf index the key occupies in the tree.
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
    key_slot(revocation_key(cfg, PoseidonField::from(pack_id))) as u16
}

/// A non-inclusion proof for the sparse Merkle tree, in the order the
/// spend circuit consumes it: index 0 is the leaf level, index
/// `SMT_DEPTH - 1` the level just below the root.
#[derive(Clone, Debug)]
pub struct SmtNonInclusionProof {
    /// `siblings[i]` is the sibling of the path node at level `i`
    /// (level 0 = leaves).
    pub siblings: Vec<PoseidonField>,
    /// `path_bits[i]` is true if the path node at level `i` is a right
    /// child. Equals bit `i` (little-endian) of the revocation key, which
    /// the circuit enforces.
    pub path_bits: Vec<bool>,
}

/// The revocation tree: a depth-16 binary Merkle tree whose leaf index is
/// the key's slot (`revocation_slot`, the low 16 bits of the key).
///
/// Level 0 holds the leaves; level `SMT_DEPTH` holds the root. A present
/// leaf hashes to `Poseidon(key, 1)`; an empty leaf is 0; a parent of two
/// zero children is 0, otherwise `Poseidon(left, right)`. This is exactly
/// the fold the spend circuit performs (leaf to root, key bit `i` choosing
/// the side at level `i`), so roots and proofs built here verify in-circuit.
///
/// Only non-empty nodes are stored; the number of revoked packs is small.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Non-empty node hashes, keyed by (level, index at that level).
    nodes: std::collections::HashMap<(u8, u32), PoseidonField>,
    /// Revoked keys in insertion order (`from_keys` of this list
    /// reproduces the tree exactly, including slot-collision overwrites).
    inserted_keys: Vec<PoseidonField>,
    cfg: PoseidonConfig<PoseidonField>,
}

impl SparseMerkleTree {
    /// Create a new empty tree (root 0).
    pub fn new() -> Self {
        Self {
            nodes: std::collections::HashMap::new(),
            inserted_keys: Vec::new(),
            cfg: poseidon_config(),
        }
    }

    /// Rebuild a tree from its revoked keys, in the order they were
    /// inserted. Wallets use this to recompute the server's published
    /// revocation list locally, so they can build their own non-inclusion
    /// proofs without ever telling the server which pack they hold.
    pub fn from_keys<I: IntoIterator<Item = PoseidonField>>(keys: I) -> Self {
        let mut tree = Self::new();
        for k in keys {
            tree.insert(k);
        }
        tree
    }

    /// The revoked keys, in insertion order.
    pub fn keys(&self) -> &[PoseidonField] {
        &self.inserted_keys
    }

    /// Whether `key`'s leaf slot is occupied, i.e. a non-inclusion proof
    /// for it is impossible (the pack is revoked, or shares a slot with one
    /// that is).
    pub fn is_slot_occupied(&self, key: PoseidonField) -> bool {
        !self.node(0, key_slot(key)).is_zero()
    }

    /// Non-panicking `prove_non_inclusion`: `None` when the key's slot is
    /// occupied (revoked).
    pub fn try_prove_non_inclusion(&self, key: PoseidonField) -> Option<SmtNonInclusionProof> {
        if self.is_slot_occupied(key) {
            None
        } else {
            Some(self.prove_non_inclusion(key))
        }
    }

    /// Insert a key (mark it revoked). The leaf value is `Poseidon(key, 1)`
    /// so a present leaf is never 0.
    pub fn insert(&mut self, key: PoseidonField) {
        let slot = key_slot(key);
        let mut current = poseidon_hash_many(&self.cfg, &[key, PoseidonField::from(1u64)]);
        self.nodes.insert((0, slot), current);
        self.inserted_keys.push(key);

        let mut idx = slot;
        for level in 0..SMT_DEPTH as u8 {
            let sibling = self.node(level, idx ^ 1);
            let (left, right) = if idx & 1 == 1 { (sibling, current) } else { (current, sibling) };
            current = self.parent(left, right);
            idx >>= 1;
            self.nodes.insert((level + 1, idx), current);
        }
    }

    /// The root hash (0 for an empty tree).
    pub fn root(&self) -> PoseidonField {
        self.node(SMT_DEPTH as u8, 0)
    }

    /// Generate a non-inclusion proof for a key.
    /// Panics if the key's slot is occupied; see `try_prove_non_inclusion`.
    pub fn prove_non_inclusion(&self, key: PoseidonField) -> SmtNonInclusionProof {
        let slot = key_slot(key);
        assert!(
            self.node(0, slot).is_zero(),
            "cannot generate non-inclusion proof: key is in the tree"
        );
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        let mut path_bits = Vec::with_capacity(SMT_DEPTH);
        for level in 0..SMT_DEPTH {
            let idx = slot >> level;
            siblings.push(self.node(level as u8, idx ^ 1));
            path_bits.push(idx & 1 == 1);
        }
        SmtNonInclusionProof { siblings, path_bits }
    }

    /// Verify a non-inclusion proof against a root: fold from an empty leaf
    /// up to the root, exactly as the spend circuit does.
    pub fn verify_non_inclusion(
        cfg: &PoseidonConfig<PoseidonField>,
        root: PoseidonField,
        proof: &SmtNonInclusionProof,
    ) -> bool {
        if proof.siblings.len() != SMT_DEPTH || proof.path_bits.len() != SMT_DEPTH {
            return false;
        }
        let mut current = empty_hash();
        for i in 0..SMT_DEPTH {
            let (left, right) = if proof.path_bits[i] {
                (proof.siblings[i], current)
            } else {
                (current, proof.siblings[i])
            };
            current = if left.is_zero() && right.is_zero() {
                PoseidonField::zero()
            } else {
                poseidon_two_to_one(cfg, left, right)
            };
        }
        current == root
    }

    fn node(&self, level: u8, idx: u32) -> PoseidonField {
        self.nodes.get(&(level, idx)).copied().unwrap_or_else(PoseidonField::zero)
    }

    fn parent(&self, left: PoseidonField, right: PoseidonField) -> PoseidonField {
        if left.is_zero() && right.is_zero() {
            PoseidonField::zero()
        } else {
            poseidon_two_to_one(&self.cfg, left, right)
        }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// The leaf index of a key: its low `SMT_DEPTH` bits, little-endian
/// (same as `revocation_slot`).
fn key_slot(key: PoseidonField) -> u32 {
    let bits = key.into_bigint().to_bits_le();
    (0..SMT_DEPTH).fold(0u32, |acc, i| if bits[i] { acc | (1 << i) } else { acc })
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
    fn non_inclusion_in_empty_tree() {
        let smt = SparseMerkleTree::new();
        let cfg = poseidon_config();
        let key = PoseidonField::from(42u64);
        let proof = smt.prove_non_inclusion(key);
        assert!(SparseMerkleTree::verify_non_inclusion(&cfg, smt.root(), &proof));
    }

    #[test]
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

    #[test]
    fn from_keys_reproduces_tree_and_proofs() {
        let cfg = poseidon_config();
        let mut server = SparseMerkleTree::new();
        for id in [3u64, 99, 12345, 777_777] {
            server.insert(revocation_key(&cfg, PoseidonField::from(id)));
        }
        let wallet = SparseMerkleTree::from_keys(server.keys().iter().copied());
        assert_eq!(wallet.root(), server.root());
        assert_eq!(wallet.keys(), server.keys());

        let mine = revocation_key(&cfg, PoseidonField::from(42u64));
        let local = wallet.try_prove_non_inclusion(mine).expect("not revoked");
        let remote = server.prove_non_inclusion(mine);
        assert_eq!(local.siblings, remote.siblings);
        assert_eq!(local.path_bits, remote.path_bits);
        assert!(SparseMerkleTree::verify_non_inclusion(&cfg, server.root(), &local));

        let revoked = revocation_key(&cfg, PoseidonField::from(99u64));
        assert!(wallet.is_slot_occupied(revoked));
        assert!(wallet.try_prove_non_inclusion(revoked).is_none());
    }

    #[test]
    fn from_empty_list_is_empty_tree() {
        let t = SparseMerkleTree::from_keys(std::iter::empty());
        assert!(t.root().is_zero());
        assert!(t.keys().is_empty());
    }
}
