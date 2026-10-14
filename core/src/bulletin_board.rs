//! Public bulletin board — append-only attribution tree (v6).
//!
//! The attribution board is an append-only Poseidon Merkle tree storing
//! encrypted attestation blobs. Each entry contains a dual-layer ECDH
//! encrypted payload that records the association between a pack and its
//! payment method (for CC chargeback attribution only).
//!
//! ## v6 changes
//!
//! - **Pedersen commitments removed**: the board no longer stores commitments.
//!   The circuit's spend proof no longer references the board at all — the
//!   circuit now proves non-inclusion in the revocation SMT instead.
//! - **Leaf encoding simplified**: `Poseidon(pack_id, tag, expiration_month)`
//!   where `tag` is a public identifier for the encrypted blob.
//!
//! ## Purpose (attribution only)
//!
//! The board exists solely for the server's chargeback-attribution workflow:
//! when a CC payment is charged back, the server looks up the corresponding
//! pack_id and adds it to the revocation SMT. The board is NOT referenced
//! by the zero-knowledge circuit.
//!
//! ## Sparse tree
//!
//! The tree has a fixed logical depth of [`BOARD_TREE_DEPTH`] (20 levels,
//! ~1M capacity), built sparsely with pre-computed default hashes for empty
//! subtrees.

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::AdditiveGroup;

use crate::poseidon::{poseidon_hash_many, poseidon_two_to_one, PoseidonField};
use crate::token_pack::MerkleStep;

/// Depth of the bulletin board Merkle tree. Depth 20 → up to 1 048 576
/// attribution entries.
pub const BOARD_TREE_DEPTH: usize = 20;

/// Max entries on the board.
pub const MAX_BOARD_SIZE: usize = 1 << BOARD_TREE_DEPTH;

/// Sentinel leaf for empty board slots.
pub const EMPTY_LEAF: PoseidonField = PoseidonField::ZERO;

/// A single entry on the attribution board (v6).
///
/// The `enc_payload_hash` is Poseidon(encrypted_blob) — a binding commitment
/// to the dual-layer ECDH encrypted payload without revealing its contents.
#[derive(Debug, Clone)]
pub struct BoardEntry {
    /// Random pack identifier (same as used in token issuance).
    pub pack_id: u64,
    /// Public tag for the attribution entry (e.g., payment method hash).
    pub tag: PoseidonField,
    /// Expiration month in YYYYMM format (e.g. 202605 = May 2026).
    pub expiration_month: u32,
}

/// Compute the leaf hash for a board entry (v6).
///
/// ```text
/// leaf = Poseidon(pack_id, tag, expiration_month)
/// ```
pub fn board_leaf_hash(
    cfg: &PoseidonConfig<PoseidonField>,
    pack_id: u64,
    tag: PoseidonField,
    expiration_month: u32,
) -> PoseidonField {
    poseidon_hash_many(cfg, &[
        PoseidonField::from(pack_id),
        tag,
        PoseidonField::from(expiration_month as u64),
    ])
}

/// Pre-computed default hashes for each tree level.
///
/// `defaults[0]` = EMPTY_LEAF (= 0)
/// `defaults[i]` = Poseidon(defaults[i-1], defaults[i-1])
///
/// This lets us skip entire empty subtrees — instead of hashing a
/// million zeros, we just reference the pre-computed value.
pub fn compute_defaults(cfg: &PoseidonConfig<PoseidonField>) -> Vec<PoseidonField> {
    let mut defaults = Vec::with_capacity(BOARD_TREE_DEPTH + 1);
    defaults.push(EMPTY_LEAF);
    for _ in 0..BOARD_TREE_DEPTH {
        let prev = *defaults.last().unwrap();
        defaults.push(poseidon_two_to_one(cfg, prev, prev));
    }
    defaults
}

/// A sparse bulletin board Merkle tree.
///
/// Only stores the populated leaf hashes and computes internal nodes
/// on-demand using pre-computed default hashes for empty subtrees.
#[derive(Debug, Clone)]
pub struct BulletinBoard {
    /// The hashed leaves in submission order.
    pub leaf_hashes: Vec<PoseidonField>,
    /// The raw entries (for auditing / leaf list endpoint).
    pub entries: Vec<BoardEntry>,
    /// Current Merkle root.
    pub root: PoseidonField,
    /// Pre-computed default hashes for empty subtrees at each level.
    defaults: Vec<PoseidonField>,
    /// Poseidon config (cached for auth_path computation).
    cfg: PoseidonConfig<PoseidonField>,
}

impl BulletinBoard {
    /// Build a bulletin board tree from a list of entries.
    ///
    /// Cost: O(N · depth) Poseidon hashes where N = number of entries.
    pub fn build(
        cfg: &PoseidonConfig<PoseidonField>,
        entries: Vec<BoardEntry>,
    ) -> Result<Self, String> {
        if entries.len() > MAX_BOARD_SIZE {
            return Err(format!(
                "board has {} entries, max is {}",
                entries.len(),
                MAX_BOARD_SIZE
            ));
        }

        let defaults = compute_defaults(cfg);

        let leaf_hashes: Vec<PoseidonField> = entries
            .iter()
            .map(|e| board_leaf_hash(cfg, e.pack_id, e.tag, e.expiration_month))
            .collect();

        // Compute root using the sparse approach
        let root = sparse_root(cfg, &leaf_hashes, &defaults);

        Ok(Self {
            leaf_hashes,
            entries,
            root,
            defaults,
            cfg: cfg.clone(),
        })
    }

    /// Build an empty board.
    pub fn empty(cfg: &PoseidonConfig<PoseidonField>) -> Self {
        Self::build(cfg, Vec::new()).expect("empty board should always succeed")
    }

    /// Get the authentication path for a leaf at `index`.
    ///
    /// Returns one `MerkleStep` per tree level, from leaf up to root.
    pub fn auth_path(&self, index: usize) -> Vec<MerkleStep> {
        assert!(
            index < self.entries.len(),
            "index {} out of range (board has {} entries)",
            index,
            self.entries.len()
        );

        sparse_auth_path(&self.cfg, &self.leaf_hashes, &self.defaults, index)
    }

    /// Number of real (non-padding) entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the board is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the Merkle root of a sparse tree.
fn sparse_root(
    cfg: &PoseidonConfig<PoseidonField>,
    leaves: &[PoseidonField],
    defaults: &[PoseidonField],
) -> PoseidonField {
    sparse_subtree(cfg, leaves, defaults, BOARD_TREE_DEPTH, 0)
}

/// Compute the hash of a subtree rooted at a given depth and offset.
fn sparse_subtree(
    cfg: &PoseidonConfig<PoseidonField>,
    leaves: &[PoseidonField],
    defaults: &[PoseidonField],
    depth: usize,
    offset: usize,
) -> PoseidonField {
    if depth == 0 {
        return if offset < leaves.len() {
            leaves[offset]
        } else {
            EMPTY_LEAF
        };
    }

    let half = 1 << (depth - 1);

    if offset >= leaves.len() {
        return defaults[depth];
    }

    let left = sparse_subtree(cfg, leaves, defaults, depth - 1, offset);
    let right = if offset + half >= leaves.len() {
        defaults[depth - 1]
    } else {
        sparse_subtree(cfg, leaves, defaults, depth - 1, offset + half)
    };

    poseidon_two_to_one(cfg, left, right)
}

/// Compute the authentication path for a leaf at `index` in a sparse tree.
fn sparse_auth_path(
    cfg: &PoseidonConfig<PoseidonField>,
    leaves: &[PoseidonField],
    defaults: &[PoseidonField],
    index: usize,
) -> Vec<MerkleStep> {
    let mut path = Vec::with_capacity(BOARD_TREE_DEPTH);

    for depth in 0..BOARD_TREE_DEPTH {
        let level_offset = index >> depth;
        let sibling_offset = level_offset ^ 1;
        let current_is_right = (level_offset & 1) == 1;

        let subtree_start = sibling_offset << depth;
        let sibling = sparse_subtree(cfg, leaves, defaults, depth, subtree_start);

        path.push(MerkleStep {
            sibling,
            current_is_right,
        });
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::poseidon_config;

    fn make_entry(id: u64) -> BoardEntry {
        BoardEntry {
            pack_id: id,
            tag: PoseidonField::from(id * 7),
            expiration_month: 202612,
        }
    }

    #[test]
    fn empty_board_has_deterministic_root() {
        let cfg = poseidon_config();
        let b1 = BulletinBoard::empty(&cfg);
        let b2 = BulletinBoard::empty(&cfg);
        assert_eq!(b1.root, b2.root);
    }

    #[test]
    fn empty_board_root_equals_default() {
        let cfg = poseidon_config();
        let defaults = compute_defaults(&cfg);
        let board = BulletinBoard::empty(&cfg);
        assert_eq!(board.root, defaults[BOARD_TREE_DEPTH]);
    }

    #[test]
    fn single_entry_board() {
        let cfg = poseidon_config();
        let board = BulletinBoard::build(&cfg, vec![make_entry(1)]).unwrap();

        assert_eq!(board.len(), 1);
        assert_ne!(board.root, BulletinBoard::empty(&cfg).root);

        let path = board.auth_path(0);
        assert_eq!(path.len(), BOARD_TREE_DEPTH);
    }

    #[test]
    fn auth_path_verifies() {
        let cfg = poseidon_config();

        let entries: Vec<BoardEntry> = (1..=4).map(|i| make_entry(i)).collect();
        let board = BulletinBoard::build(&cfg, entries.clone()).unwrap();

        let path = board.auth_path(2);
        let leaf = board_leaf_hash(&cfg, entries[2].pack_id, entries[2].tag, entries[2].expiration_month);

        let mut current = leaf;
        for step in &path {
            let (left, right) = if step.current_is_right {
                (step.sibling, current)
            } else {
                (current, step.sibling)
            };
            current = poseidon_two_to_one(&cfg, left, right);
        }

        assert_eq!(current, board.root, "auth path must fold to board root");
    }

    #[test]
    fn different_entries_different_roots() {
        let cfg = poseidon_config();

        let board1 = BulletinBoard::build(&cfg, vec![make_entry(1)]).unwrap();
        let board2 = BulletinBoard::build(&cfg, vec![make_entry(2)]).unwrap();

        assert_ne!(board1.root, board2.root);
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let cfg = poseidon_config();
        let entry = make_entry(42);

        let h1 = board_leaf_hash(&cfg, entry.pack_id, entry.tag, entry.expiration_month);
        let h2 = board_leaf_hash(&cfg, entry.pack_id, entry.tag, entry.expiration_month);
        assert_eq!(h1, h2);
    }

    #[test]
    fn all_auth_paths_verify() {
        let cfg = poseidon_config();

        let entries: Vec<BoardEntry> = (1..=8).map(|i| make_entry(i)).collect();
        let board = BulletinBoard::build(&cfg, entries.clone()).unwrap();

        for i in 0..entries.len() {
            let path = board.auth_path(i);
            let leaf = board_leaf_hash(&cfg, entries[i].pack_id, entries[i].tag, entries[i].expiration_month);

            let mut current = leaf;
            for step in &path {
                let (left, right) = if step.current_is_right {
                    (step.sibling, current)
                } else {
                    (current, step.sibling)
                };
                current = poseidon_two_to_one(&cfg, left, right);
            }

            assert_eq!(
                current, board.root,
                "auth path for entry {} must fold to board root",
                i
            );
        }
    }
}
