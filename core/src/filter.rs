//! SipHash-based TXID hashing and block filter data structures.
//!
//! Implements Section 6 of the whitepaper: the block filter construction.
//! Each transaction output (TXID||vout_index) is hashed to a 64-bit value
//! using SipHash keyed with the first 128 bits of the block hash.

use siphasher::sip::SipHasher;
use std::hash::Hasher;

use crate::aes::{TAG_CIPHERTEXT_LEN, TAG_CIPHERTEXT_LEN_V4};
use crate::types::{PerseverusError, TxOutpoint};

/// Wire format version for v2 filters (two-column: hash_stream + encrypted_tags).
///
/// v2: BLS12-377 curve migration + fixed-width encrypted tags (no length
///     prefix). Every encrypted tag is exactly `TAG_CIPHERTEXT_LEN` bytes,
///     which is essential for hiding how much KYC data a block contains.
pub const FILTER_FORMAT_VERSION: u8 = 2;

/// Wire format version for v3 filters (single interleaved stream).
///
/// v3: Combined Golomb-Rice stream with 2-byte AES-CTR encrypted tags
///     interleaved after each delta. No separate tag column. Lower P
///     parameter for better compression.
pub const FILTER_FORMAT_VERSION_V3: u8 = 3;

/// Magic bytes so a stray byte sequence can't masquerade as a filter.
pub const FILTER_MAGIC: [u8; 4] = *b"PSVR";

/// Hash a transaction outpoint to a 64-bit short-ID using SipHash-2-4.
///
/// The key is derived from the first 16 bytes of the block hash,
/// per whitepaper Section 6: "SipHash-2-4 keyed from first 128 bits of block hash"
///
/// This matches BIP-158's approach of using SipHash for filter construction.
pub fn siphash_txout(outpoint: &TxOutpoint, block_hash: &[u8; 32]) -> u64 {
    // Extract 128-bit key from block hash (first 16 bytes → two u64 keys)
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().unwrap());

    let mut hasher = SipHasher::new_with_keys(k0, k1);
    hasher.write(&outpoint.to_bytes());
    hasher.finish()
}

/// An entry in a block filter: hash + encrypted tag
#[derive(Debug, Clone)]
pub struct FilterEntry {
    /// 64-bit SipHash of the transaction outpoint
    pub short_id: u64,
    /// Encrypted KYC tag (AES-256-GCM ciphertext, always exactly
    /// `TAG_CIPHERTEXT_LEN` bytes so blob lengths leak nothing)
    pub encrypted_tag: Vec<u8>,
}

/// A complete encrypted block filter.
///
/// Contains the compressed hash stream (Column A) and ordered encrypted tags (Column B).
#[derive(Debug, Clone)]
pub struct BlockFilter {
    /// Block height
    pub height: u32,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Number of entries in the filter
    pub num_entries: u32,
    /// Golomb-Rice compressed hash stream (Column A)
    pub hash_stream: Vec<u8>,
    /// Ordered encrypted tags (Column B), aligned with the sorted hash order
    pub encrypted_tags: Vec<Vec<u8>>,
}

impl BlockFilter {
    /// Serialize the filter to a compact wire format.
    ///
    /// Layout (v2):
    ///   magic            : 4 bytes  "PSVR"
    ///   version          : 1 byte   (FILTER_FORMAT_VERSION)
    ///   height           : 4 bytes  LE u32
    ///   block_hash       : 32 bytes
    ///   num_entries      : 4 bytes  LE u32
    ///   stream_len       : 4 bytes  LE u32
    ///   hash_stream      : stream_len bytes  (Golomb-Rice)
    ///   encrypted_tags   : num_entries * TAG_CIPHERTEXT_LEN bytes
    ///                      (no length prefix — fixed width, by design)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&FILTER_MAGIC);
        buf.push(FILTER_FORMAT_VERSION);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.num_entries.to_le_bytes());

        // Hash stream length + data
        let stream_len = self.hash_stream.len() as u32;
        buf.extend_from_slice(&stream_len.to_le_bytes());
        buf.extend_from_slice(&self.hash_stream);

        // Encrypted tags: fixed-width, concatenated, no per-tag prefix.
        // This is deliberate — any per-tag size variation would reveal how
        // many KYC-tagged outputs the block contains.
        for tag in &self.encrypted_tags {
            debug_assert_eq!(
                tag.len(),
                TAG_CIPHERTEXT_LEN,
                "encrypted tag must be exactly TAG_CIPHERTEXT_LEN bytes"
            );
            buf.extend_from_slice(tag);
        }

        buf
    }

    /// Deserialize a filter from wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, PerseverusError> {
        // minimum header = magic(4) + version(1) + height(4) + block_hash(32)
        //                + num_entries(4) + stream_len(4) = 49 bytes
        if data.len() < 49 {
            return Err(PerseverusError::FilterError("data too short for header".into()));
        }

        let mut pos = 0;

        if &data[pos..pos + 4] != FILTER_MAGIC {
            return Err(PerseverusError::FilterError(
                "bad filter magic — not a Perseverus filter file".into(),
            ));
        }
        pos += 4;

        let version = data[pos];
        pos += 1;
        if version != FILTER_FORMAT_VERSION {
            return Err(PerseverusError::FilterError(format!(
                "filter format version mismatch: got {}, expected {}",
                version, FILTER_FORMAT_VERSION
            )));
        }

        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let num_entries = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let stream_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if data.len() < pos + stream_len {
            return Err(PerseverusError::FilterError("truncated hash stream".into()));
        }
        let hash_stream = data[pos..pos + stream_len].to_vec();
        pos += stream_len;

        // Fixed-width encrypted tags follow
        let tags_bytes_expected = (num_entries as usize)
            .checked_mul(TAG_CIPHERTEXT_LEN)
            .ok_or_else(|| PerseverusError::FilterError("tag region size overflow".into()))?;
        if data.len() < pos + tags_bytes_expected {
            return Err(PerseverusError::FilterError(
                "truncated encrypted-tag region".into(),
            ));
        }

        let mut encrypted_tags = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            encrypted_tags.push(data[pos..pos + TAG_CIPHERTEXT_LEN].to_vec());
            pos += TAG_CIPHERTEXT_LEN;
        }

        Ok(BlockFilter {
            height,
            block_hash,
            num_entries,
            hash_stream,
            encrypted_tags,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V3 Block Filter: single interleaved stream (Golomb delta + 2-byte CTR tag)
// ─────────────────────────────────────────────────────────────────────────────

/// A v3 block filter: single combined bitstream with interleaved deltas and tags.
///
/// Instead of separate Column A (hash_stream) and Column B (encrypted_tags),
/// v3 packs each entry as: Golomb-Rice encoded delta bits, then 16 raw bits
/// (2 bytes) of AES-CTR encrypted tag. This eliminates the separate tag
/// lookup and reduces per-entry overhead from 12 bytes to 2 bytes.
#[derive(Debug, Clone)]
pub struct BlockFilterV3 {
    /// Block height
    pub height: u32,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Number of entries in the filter
    pub num_entries: u32,
    /// Golomb-Rice P parameter used for this filter
    pub golomb_p: u8,
    /// Combined interleaved bitstream (Golomb deltas + raw tag bytes)
    pub stream: Vec<u8>,
}

impl BlockFilterV3 {
    /// Serialize v3 filter to wire format.
    ///
    /// Layout (v3):
    ///   magic         : 4 bytes  "PSVR"
    ///   version       : 1 byte   (3)
    ///   height        : 4 bytes  LE u32
    ///   block_hash    : 32 bytes
    ///   num_entries   : 4 bytes  LE u32
    ///   golomb_p      : 1 byte
    ///   stream_len    : 4 bytes  LE u32
    ///   stream        : stream_len bytes (interleaved Golomb + tags)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FILTER_MAGIC);
        buf.push(FILTER_FORMAT_VERSION_V3);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.num_entries.to_le_bytes());
        buf.push(self.golomb_p);
        let stream_len = self.stream.len() as u32;
        buf.extend_from_slice(&stream_len.to_le_bytes());
        buf.extend_from_slice(&self.stream);
        buf
    }

    /// Deserialize a v3 filter from wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, PerseverusError> {
        // Header: magic(4) + ver(1) + height(4) + block_hash(32) + num_entries(4) + p(1) + stream_len(4) = 50
        if data.len() < 50 {
            return Err(PerseverusError::FilterError("data too short for v3 header".into()));
        }

        let mut pos = 0;
        if &data[pos..pos + 4] != FILTER_MAGIC {
            return Err(PerseverusError::FilterError("bad filter magic".into()));
        }
        pos += 4;

        let version = data[pos];
        pos += 1;
        if version != FILTER_FORMAT_VERSION_V3 {
            return Err(PerseverusError::FilterError(format!(
                "filter version mismatch: got {}, expected {}",
                version, FILTER_FORMAT_VERSION_V3
            )));
        }

        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let num_entries = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let golomb_p = data[pos];
        pos += 1;

        let stream_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if data.len() < pos + stream_len {
            return Err(PerseverusError::FilterError("truncated v3 stream".into()));
        }
        let stream = data[pos..pos + stream_len].to_vec();

        Ok(BlockFilterV3 {
            height,
            block_hash,
            num_entries,
            golomb_p,
            stream,
        })
    }

    /// Total serialized size in bytes (for logging).
    pub fn serialized_size(&self) -> usize {
        // header(50) + stream
        50 + self.stream.len()
    }
}

/// Build the sorted list of (short_id, tag_index) from outpoints.
/// Returns short_ids sorted ascending, and the permutation indices so we can
/// align the encrypted tags in the same order.
pub fn build_sorted_hash_map(
    outpoints: &[TxOutpoint],
    block_hash: &[u8; 32],
) -> Vec<(u64, usize)> {
    let mut pairs: Vec<(u64, usize)> = outpoints
        .iter()
        .enumerate()
        .map(|(idx, outpoint)| (siphash_txout(outpoint, block_hash), idx))
        .collect();

    pairs.sort_by_key(|(hash, _)| *hash);
    pairs
}

/// Apply BIP-158 range reduction to a raw 64-bit hash.
///
/// Maps from [0, 2^64) to [0, F) where F = num_entries * 2^P.
/// This must match the range reduction applied during filter construction.
pub fn reduce_hash(raw_hash: u64, num_entries: u32, golomb_p: u8) -> u64 {
    let f = (num_entries as u64) * (1u64 << golomb_p);
    ((raw_hash as u128 * f as u128) >> 64) as u64
}

/// Scan a decompressed list of sorted (range-reduced) hashes for a target outpoint.
///
/// The `num_entries` parameter is needed to apply BIP-158 range reduction
/// so the client's hash matches the server's reduced hash space.
/// Returns the index in the sorted list if found.
pub fn scan_filter_for_match(
    sorted_hashes: &[u64],
    target_outpoint: &TxOutpoint,
    block_hash: &[u8; 32],
    num_entries: u32,
) -> Option<usize> {
    let raw_hash = siphash_txout(target_outpoint, block_hash);
    let target_hash = reduce_hash(raw_hash, num_entries, crate::golomb::GOLOMB_P);
    sorted_hashes.binary_search(&target_hash).ok()
}

/// v3 variant: same scan but uses the filter's own Golomb P parameter.
pub fn scan_filter_for_match_v3(
    sorted_hashes: &[u64],
    target_outpoint: &TxOutpoint,
    block_hash: &[u8; 32],
    num_entries: u32,
    golomb_p: u8,
) -> Option<usize> {
    let raw_hash = siphash_txout(target_outpoint, block_hash);
    let target_hash = reduce_hash(raw_hash, num_entries, golomb_p);
    sorted_hashes.binary_search(&target_hash).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// V4 Block Filter: per-TRANSACTION, two-column (GCS hash + separate 3-byte
// pure-AES-CTR heuristic-tag column). OPRF-gated per-tx key, same as v2/v3.
// ─────────────────────────────────────────────────────────────────────────────

use ark_ed_on_bn254::EdwardsProjective as G1ProjectiveV4;

/// Wire format version for v4 filters.
///
/// v4 differs from v2/v3 in three ways:
///   * keyed by **txid** (per transaction), not by output (txid‖vout)
///   * the payload is the 24-bit heuristic tag (3 bytes), AES-CTR encrypted
///   * **two separate columns** (BIP158-style GCS + a byte-aligned 3-byte tag
///     array), so membership can be tested without touching the tag column and
///     a matched tag is O(1) indexable by rank.
pub const FILTER_FORMAT_VERSION_V4: u8 = 4;

/// SipHash-2-4 a 32-byte txid to a 64-bit short-ID (v4: by transaction).
/// Key = first 128 bits of the block hash, identical to the v2/v3 outpoint hash.
pub fn siphash_txid(txid: &[u8; 32], block_hash: &[u8; 32]) -> u64 {
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().unwrap());
    let mut hasher = SipHasher::new_with_keys(k0, k1);
    hasher.write(txid);
    hasher.finish()
}

/// A v4 block filter: two columns, like v2, but txid-keyed with 3-byte CTR tags.
#[derive(Debug, Clone)]
pub struct BlockFilterV4 {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub num_entries: u32,
    /// Golomb-Rice P parameter used for Column A.
    pub golomb_p: u8,
    /// Column A: Golomb-Rice GCS of the sorted, range-reduced txid hashes.
    pub hash_stream: Vec<u8>,
    /// Column B: `num_entries * TAG_CIPHERTEXT_LEN_V4` bytes, byte-aligned,
    /// in the same sorted-hash order as Column A (so tag of rank r =
    /// encrypted_tags[r*3 .. r*3+3]).
    pub encrypted_tags: Vec<u8>,
}

impl BlockFilterV4 {
    /// Layout (v4):
    ///   magic(4) "PSVR" | version(1)=4 | height(4 LE) | block_hash(32)
    ///   | num_entries(4 LE) | golomb_p(1) | stream_len(4 LE)
    ///   | hash_stream(stream_len) | encrypted_tags(num_entries*3)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FILTER_MAGIC);
        buf.push(FILTER_FORMAT_VERSION_V4);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.num_entries.to_le_bytes());
        buf.push(self.golomb_p);
        buf.extend_from_slice(&(self.hash_stream.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.hash_stream);
        debug_assert_eq!(
            self.encrypted_tags.len(),
            self.num_entries as usize * TAG_CIPHERTEXT_LEN_V4
        );
        buf.extend_from_slice(&self.encrypted_tags);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PerseverusError> {
        // header = magic(4)+ver(1)+height(4)+hash(32)+num(4)+p(1)+stream_len(4) = 50
        if data.len() < 50 {
            return Err(PerseverusError::FilterError("data too short for v4 header".into()));
        }
        let mut pos = 0;
        if &data[pos..pos + 4] != FILTER_MAGIC {
            return Err(PerseverusError::FilterError("bad filter magic".into()));
        }
        pos += 4;
        let version = data[pos];
        pos += 1;
        if version != FILTER_FORMAT_VERSION_V4 {
            return Err(PerseverusError::FilterError(format!(
                "filter version mismatch: got {}, expected {}",
                version, FILTER_FORMAT_VERSION_V4
            )));
        }
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let num_entries = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let golomb_p = data[pos];
        pos += 1;
        let stream_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if data.len() < pos + stream_len {
            return Err(PerseverusError::FilterError("truncated v4 hash stream".into()));
        }
        let hash_stream = data[pos..pos + stream_len].to_vec();
        pos += stream_len;

        let tags_bytes = (num_entries as usize)
            .checked_mul(TAG_CIPHERTEXT_LEN_V4)
            .ok_or_else(|| PerseverusError::FilterError("tag region overflow".into()))?;
        if data.len() < pos + tags_bytes {
            return Err(PerseverusError::FilterError("truncated v4 tag region".into()));
        }
        let encrypted_tags = data[pos..pos + tags_bytes].to_vec();

        Ok(BlockFilterV4 {
            height,
            block_hash,
            num_entries,
            golomb_p,
            hash_stream,
            encrypted_tags,
        })
    }

    /// Decode Column A into the sorted, range-reduced hash values (for scanning).
    pub fn decode_hashes(&self) -> Result<Vec<u64>, PerseverusError> {
        let mut dec = crate::golomb::GolombDecoder::new(&self.hash_stream, self.golomb_p);
        let deltas = dec.decode_all(self.num_entries as usize)?;
        Ok(crate::golomb::reconstruct_from_deltas(&deltas))
    }

    /// O(1) fetch of the encrypted 3-byte tag at a given sorted rank.
    pub fn tag_at(&self, rank: usize) -> Option<[u8; TAG_CIPHERTEXT_LEN_V4]> {
        let off = rank.checked_mul(TAG_CIPHERTEXT_LEN_V4)?;
        let end = off + TAG_CIPHERTEXT_LEN_V4;
        if end > self.encrypted_tags.len() {
            return None;
        }
        let mut t = [0u8; TAG_CIPHERTEXT_LEN_V4];
        t.copy_from_slice(&self.encrypted_tags[off..end]);
        Some(t)
    }
}

/// Build a v4 filter for one block from `(txid, 24-bit-tag-plaintext)` entries.
///
/// Steps, mirroring the existing builder but per-transaction:
///   1. For each tx: short_id = reduce(SipHash(txid)); encrypt the 3-byte tag
///      with the OPRF-gated key (γ = k·H2C(txid)) via pure AES-CTR.
///   2. Sort entries by reduced short_id.
///   3. Column A = Golomb-Rice over the delta sequence.
///   4. Column B = the encrypted tags concatenated in that same sorted order.
pub fn build_block_filter_v4(
    height: u32,
    block_hash: &[u8; 32],
    entries: &[([u8; 32], [u8; TAG_CIPHERTEXT_LEN_V4])],
    server_key: &crate::oprf::OprfServerKey,
    golomb_p: u8,
) -> Result<BlockFilterV4, PerseverusError> {
    use crate::aes::{ctr_xor_tag_v4, derive_nonce, derive_tag_key};
    use crate::golomb::{compute_deltas, GolombEncoder};
    use crate::oprf::evaluate_direct;

    let n = entries.len() as u32;
    if n == 0 {
        return Ok(BlockFilterV4 {
            height,
            block_hash: *block_hash,
            num_entries: 0,
            golomb_p,
            hash_stream: Vec::new(),
            encrypted_tags: Vec::new(),
        });
    }

    // 1. per-tx reduced hash + OPRF-gated CTR-encrypted tag
    let mut rows: Vec<(u64, [u8; TAG_CIPHERTEXT_LEN_V4])> = Vec::with_capacity(entries.len());
    for (txid, tag_plain) in entries {
        let raw = siphash_txid(txid, block_hash);
        let reduced = reduce_hash(raw, n, golomb_p);
        let gamma = evaluate_direct(server_key, txid)
            .map_err(|e| PerseverusError::FilterError(format!("oprf evaluate: {e}")))?;
        let key = derive_tag_key(&gamma);
        let nonce = derive_nonce(txid, block_hash);
        let ct = ctr_xor_tag_v4(&key, &nonce, tag_plain);
        rows.push((reduced, ct));
    }

    // 2. sort by reduced short_id
    rows.sort_by_key(|(h, _)| *h);

    // 3. Column A: delta + Golomb-Rice
    let hashes: Vec<u64> = rows.iter().map(|(h, _)| *h).collect();
    let deltas = compute_deltas(&hashes);
    let mut enc = GolombEncoder::new(golomb_p);
    enc.encode_all(&deltas);
    let hash_stream = enc.finish();

    // 4. Column B: tags in the same sorted order, byte-aligned
    let mut encrypted_tags = Vec::with_capacity(rows.len() * TAG_CIPHERTEXT_LEN_V4);
    for (_, ct) in &rows {
        encrypted_tags.extend_from_slice(ct);
    }

    Ok(BlockFilterV4 {
        height,
        block_hash: *block_hash,
        num_entries: n,
        golomb_p,
        hash_stream,
        encrypted_tags,
    })
}

/// Client: locate a target txid in the decoded Column-A hashes. Returns its
/// sorted rank (use it with `tag_at` to pull the encrypted tag).
pub fn scan_filter_v4(
    sorted_hashes: &[u64],
    target_txid: &[u8; 32],
    block_hash: &[u8; 32],
    num_entries: u32,
    golomb_p: u8,
) -> Option<usize> {
    let raw = siphash_txid(target_txid, block_hash);
    let target = reduce_hash(raw, num_entries, golomb_p);
    sorted_hashes.binary_search(&target).ok()
}

/// Client: decrypt a 3-byte v4 tag once γ has been recovered via the OPRF.
pub fn decrypt_tag_v4(
    gamma: &G1ProjectiveV4,
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    ciphertext: &[u8; TAG_CIPHERTEXT_LEN_V4],
) -> [u8; TAG_CIPHERTEXT_LEN_V4] {
    let key = crate::aes::derive_tag_key(gamma);
    let nonce = crate::aes::derive_nonce(txid, block_hash);
    crate::aes::ctr_xor_tag_v4(&key, &nonce, ciphertext)
}

// ─────────────────────────────────────────────────────────────────────────────
// V5 Block Filter: per-TRANSACTION, two-column, with a GLOBAL codebook.
//
// Column B no longer stores the 24-bit tag. It stores a per-tx OPRF-encrypted
// `code_bits`-wide INDEX into a global, public, block-independent codebook
// (realized tag values → compact code). This:
//   * shrinks the payload (e.g. 11 bits vs 24) with NO per-block leak — the
//     codebook is the same for every block, so it reveals nothing about a block;
//   * preserves pay-per-query — each index is encrypted under its own per-tx key,
//     so two txs with the same tag have DIFFERENT ciphertexts (one token each).
//
// Column A's Golomb P is chosen per block as the smallest value that makes the
// member hashes COLLISION-FREE (so each tx maps to a unique rank → unique tag).
// Query-time false positives are a non-issue: the wallet always queries the
// exact block its tx is in, and every tx in the block has an entry.
// ─────────────────────────────────────────────────────────────────────────────

/// Wire format version for v5 (codebook + adaptive collision-free P).
pub const FILTER_FORMAT_VERSION_V5: u8 = 5;

/// Largest Golomb P the adaptive loop will try before giving up.
pub const MAX_GOLOMB_P: u8 = 32;

/// Append `nbits` of `value` (MSB first) to a bit buffer.
fn bits_push(buf: &mut Vec<u8>, bit_pos: &mut u8, value: u32, nbits: u8) {
    for i in (0..nbits).rev() {
        let bit = ((value >> i) & 1) as u8;
        if *bit_pos == 0 {
            buf.push(0);
        }
        if bit == 1 {
            let li = buf.len() - 1;
            buf[li] |= 1 << (7 - *bit_pos);
        }
        *bit_pos = (*bit_pos + 1) % 8;
    }
}

/// Read the `nbits`-wide value at a given rank (MSB first). O(1) random access.
fn bits_read(buf: &[u8], rank: usize, nbits: u8) -> u32 {
    let start = rank * nbits as usize;
    let mut v = 0u32;
    for i in 0..nbits as usize {
        let bitidx = start + i;
        let bit = (buf[bitidx / 8] >> (7 - (bitidx % 8))) & 1;
        v = (v << 1) | bit as u32;
    }
    v
}

#[derive(Debug, Clone)]
pub struct BlockFilterV5 {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub num_entries: u32,
    /// Golomb-Rice P (chosen so member hashes are collision-free).
    pub golomb_p: u8,
    /// Bits per codebook index in Column B.
    pub code_bits: u8,
    /// First 4 bytes of the codebook's id-hash, so a client can confirm it holds
    /// the matching codebook before decoding.
    pub codebook_id: [u8; 4],
    /// Column A: Golomb-Rice GCS of sorted, range-reduced txid hashes.
    pub hash_stream: Vec<u8>,
    /// Column B: bit-packed, per-tx-encrypted `code_bits`-wide indices, in the
    /// same sorted-hash order as Column A.
    pub code_stream: Vec<u8>,
}

impl BlockFilterV5 {
    /// Layout (v5):
    ///   magic(4) "PSVR" | version(1)=5 | height(4 LE) | block_hash(32)
    ///   | num_entries(4 LE) | golomb_p(1) | code_bits(1) | codebook_id(4)
    ///   | stream_len(4 LE) | hash_stream(stream_len) | code_stream(rest)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FILTER_MAGIC);
        buf.push(FILTER_FORMAT_VERSION_V5);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.num_entries.to_le_bytes());
        buf.push(self.golomb_p);
        buf.push(self.code_bits);
        buf.extend_from_slice(&self.codebook_id);
        buf.extend_from_slice(&(self.hash_stream.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.hash_stream);
        buf.extend_from_slice(&self.code_stream);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PerseverusError> {
        // header = magic(4)+ver(1)+height(4)+hash(32)+num(4)+p(1)+code_bits(1)+id(4)+stream_len(4) = 55
        if data.len() < 55 {
            return Err(PerseverusError::FilterError("data too short for v5 header".into()));
        }
        let mut pos = 0;
        if &data[pos..pos + 4] != FILTER_MAGIC {
            return Err(PerseverusError::FilterError("bad filter magic".into()));
        }
        pos += 4;
        if data[pos] != FILTER_FORMAT_VERSION_V5 {
            return Err(PerseverusError::FilterError(format!(
                "filter version mismatch: got {}, expected {}",
                data[pos], FILTER_FORMAT_VERSION_V5
            )));
        }
        pos += 1;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let num_entries = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let golomb_p = data[pos];
        pos += 1;
        let code_bits = data[pos];
        pos += 1;
        let mut codebook_id = [0u8; 4];
        codebook_id.copy_from_slice(&data[pos..pos + 4]);
        pos += 4;
        let stream_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if data.len() < pos + stream_len {
            return Err(PerseverusError::FilterError("truncated v5 hash stream".into()));
        }
        let hash_stream = data[pos..pos + stream_len].to_vec();
        pos += stream_len;

        let code_bytes = ((num_entries as usize * code_bits as usize) + 7) / 8;
        if data.len() < pos + code_bytes {
            return Err(PerseverusError::FilterError("truncated v5 code stream".into()));
        }
        let code_stream = data[pos..pos + code_bytes].to_vec();

        Ok(BlockFilterV5 {
            height, block_hash, num_entries, golomb_p, code_bits, codebook_id, hash_stream, code_stream,
        })
    }

    /// Decode Column A → sorted reduced hashes.
    pub fn decode_hashes(&self) -> Result<Vec<u64>, PerseverusError> {
        let mut dec = crate::golomb::GolombDecoder::new(&self.hash_stream, self.golomb_p);
        let deltas = dec.decode_all(self.num_entries as usize)?;
        Ok(crate::golomb::reconstruct_from_deltas(&deltas))
    }

    /// The encrypted code at a given sorted rank (raw, still OPRF-encrypted).
    pub fn enc_code_at(&self, rank: usize) -> u32 {
        bits_read(&self.code_stream, rank, self.code_bits)
    }
}

/// Build a v5 filter from `(txid, code)` entries, where `code` is the global
/// codebook index for that tx's 24-bit tag. Chooses the smallest P (>= p_start)
/// that makes the member hashes collision-free.
/// Assemble a v5 filter from ALREADY-ENCRYPTED codes `(txid, enc_code)`.
///
/// This is the cheap half of the build: SipHash, the collision-free adaptive-P
/// search, sort, Golomb-Rice, and bit-packing. The expensive half — the per-tx
/// OPRF (`γ = k·H2C(txid)`) and code encryption — is done by the caller, so it
/// can be parallelized across cores (rayon) or offloaded to a GPU MSM. None of
/// this work depends on P, so adaptive-P is essentially free.
pub fn assemble_block_filter_v5(
    height: u32,
    block_hash: &[u8; 32],
    enc_entries: &[([u8; 32], u32)],
    code_bits: u8,
    codebook_id: [u8; 4],
    p_start: u8,
) -> Result<BlockFilterV5, PerseverusError> {
    use crate::golomb::{compute_deltas, GolombEncoder};

    let n = enc_entries.len() as u32;
    if n == 0 {
        return Ok(BlockFilterV5 {
            height, block_hash: *block_hash, num_entries: 0, golomb_p: p_start,
            code_bits, codebook_id, hash_stream: Vec::new(), code_stream: Vec::new(),
        });
    }

    // raw 64-bit siphash per tx (independent of P)
    let raw: Vec<u64> = enc_entries.iter().map(|(txid, _)| siphash_txid(txid, block_hash)).collect();

    // adaptive P: smallest P making the reduced member hashes collision-free
    let mut p = p_start.max(1);
    let golomb_p = loop {
        let mut reduced: Vec<u64> = raw.iter().map(|&h| reduce_hash(h, n, p)).collect();
        reduced.sort_unstable();
        let collision = reduced.windows(2).any(|w| w[0] == w[1]);
        if !collision || p >= MAX_GOLOMB_P {
            break p;
        }
        p += 1;
    };

    let mut rows: Vec<(u64, u32)> = enc_entries
        .iter()
        .enumerate()
        .map(|(i, (_, ct))| (reduce_hash(raw[i], n, golomb_p), *ct))
        .collect();

    // sort by reduced hash (collision-free, so order is well-defined)
    rows.sort_by_key(|(h, _)| *h);

    // Column A
    let hashes: Vec<u64> = rows.iter().map(|(h, _)| *h).collect();
    let deltas = compute_deltas(&hashes);
    let mut enc = GolombEncoder::new(golomb_p);
    enc.encode_all(&deltas);
    let hash_stream = enc.finish();

    // Column B: bit-pack encrypted codes in sorted order
    let mut code_stream = Vec::with_capacity((rows.len() * code_bits as usize + 7) / 8);
    let mut bit_pos = 0u8;
    for (_, ct) in &rows {
        bits_push(&mut code_stream, &mut bit_pos, *ct, code_bits);
    }

    Ok(BlockFilterV5 {
        height, block_hash: *block_hash, num_entries: n, golomb_p, code_bits, codebook_id, hash_stream, code_stream,
    })
}

/// Encrypt one tx's code given a PRE-COMPUTED OPRF point `γ = k·H2C(txid)`.
/// This is the GPU-friendly entry point: a caller that batches `k·P` on a GPU
/// (e.g. `perseverus_gpu::MsmPool`) computes `γ` itself, then calls this.
pub fn encrypt_code_from_gamma(
    gamma: &G1ProjectiveV4,
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    code: u32,
    code_bits: u8,
) -> Result<u32, PerseverusError> {
    use crate::aes::{ctr_keystream_u16, derive_nonce, derive_tag_key};
    let mask: u32 = if code_bits >= 32 { u32::MAX } else { (1u32 << code_bits) - 1 };
    if code & !mask != 0 {
        return Err(PerseverusError::FilterError(format!(
            "code {code} exceeds {code_bits} bits"
        )));
    }
    let key = derive_tag_key(gamma);
    let nonce = derive_nonce(txid, block_hash);
    let ks = ctr_keystream_u16(&key, &nonce) as u32;
    Ok((code ^ ks) & mask)
}

/// Encrypt one tx's code, computing the OPRF on CPU. Exposed so a parallel
/// (rayon) caller can compute these and hand the results to
/// [`assemble_block_filter_v5`]. The GPU path uses [`encrypt_code_from_gamma`].
pub fn encrypt_code_v5(
    server_key: &crate::oprf::OprfServerKey,
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    code: u32,
    code_bits: u8,
) -> Result<u32, PerseverusError> {
    let gamma = crate::oprf::evaluate_direct(server_key, txid)
        .map_err(|e| PerseverusError::FilterError(format!("oprf evaluate: {e}")))?;
    encrypt_code_from_gamma(&gamma, txid, block_hash, code, code_bits)
}

/// Convenience: full v5 build (OPRF + assemble), sequential. For the parallel /
/// GPU path, compute encrypted codes yourself and call [`assemble_block_filter_v5`].
pub fn build_block_filter_v5(
    height: u32,
    block_hash: &[u8; 32],
    entries: &[([u8; 32], u32)],
    server_key: &crate::oprf::OprfServerKey,
    code_bits: u8,
    codebook_id: [u8; 4],
    p_start: u8,
) -> Result<BlockFilterV5, PerseverusError> {
    let mut enc: Vec<([u8; 32], u32)> = Vec::with_capacity(entries.len());
    for (txid, code) in entries {
        let ct = encrypt_code_v5(server_key, txid, block_hash, *code, code_bits)?;
        enc.push((*txid, ct));
    }
    assemble_block_filter_v5(height, block_hash, &enc, code_bits, codebook_id, p_start)
}

/// Client: find a txid's sorted rank in the decoded Column-A hashes.
pub fn scan_filter_v5(
    sorted_hashes: &[u64],
    target_txid: &[u8; 32],
    block_hash: &[u8; 32],
    num_entries: u32,
    golomb_p: u8,
) -> Option<usize> {
    let raw = siphash_txid(target_txid, block_hash);
    let target = reduce_hash(raw, num_entries, golomb_p);
    sorted_hashes.binary_search(&target).ok()
}

/// Client: decrypt the codebook index for a tx once γ is recovered via the OPRF.
/// Returns the codebook code; look it up in the global codebook to get the tag.
pub fn decrypt_code_v5(
    gamma: &G1ProjectiveV4,
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    enc_code: u32,
    code_bits: u8,
) -> u32 {
    let key = crate::aes::derive_tag_key(gamma);
    let nonce = crate::aes::derive_nonce(txid, block_hash);
    let ks = crate::aes::ctr_keystream_u16(&key, &nonce) as u32;
    let mask: u32 = if code_bits >= 32 { u32::MAX } else { (1u32 << code_bits) - 1 };
    (enc_code ^ ks) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v5_codebook_adaptive_p_roundtrip() {
        use crate::oprf::{evaluate_direct, OprfServerKey};
        use rand::SeedableRng;

        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5A5A);
        let server_key = OprfServerKey::generate(&mut rng);
        let block_hash = [0x33u8; 32];
        let code_bits = 11u8;
        let codebook_id = [0xDE, 0xAD, 0xBE, 0xEF];

        // many txs, codes drawn from a small alphabet (lots of repeats)
        let mut entries: Vec<([u8; 32], u32)> = Vec::new();
        for i in 0u32..400 {
            let mut txid = [0u8; 32];
            txid[0..4].copy_from_slice(&i.to_le_bytes());
            txid[31] = 0xCD;
            entries.push((txid, i % 7)); // only 7 distinct codes
        }

        let f = build_block_filter_v5(
            931000, &block_hash, &entries, &server_key, code_bits, codebook_id, 1,
        )
        .unwrap();

        // serialize roundtrip
        let back = BlockFilterV5::deserialize(&f.serialize()).unwrap();
        assert_eq!(back.num_entries, 400);
        assert_eq!(back.code_bits, code_bits);
        assert_eq!(back.codebook_id, codebook_id);

        // adaptive P must have made the members collision-free → decode gives n distinct sorted
        let sorted = back.decode_hashes().unwrap();
        assert_eq!(sorted.len(), 400);
        assert!(sorted.windows(2).all(|w| w[0] < w[1]), "members must be collision-free (strictly increasing)");

        // every tx resolves to its correct code
        for (txid, code) in &entries {
            let rank = scan_filter_v5(&sorted, txid, &block_hash, back.num_entries, back.golomb_p)
                .expect("member must be found");
            let enc = back.enc_code_at(rank);
            let gamma = evaluate_direct(&server_key, txid).unwrap();
            let got = decrypt_code_v5(&gamma, txid, &block_hash, enc, back.code_bits);
            assert_eq!(got, *code, "decrypted code must match");
        }
    }

    #[test]
    fn test_v4_build_scan_decrypt_roundtrip() {
        use crate::oprf::{evaluate_direct, OprfServerKey};
        use rand::SeedableRng;

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xF117);
        let server_key = OprfServerKey::generate(&mut rng);
        let block_hash = [0x5Au8; 32];
        let golomb_p = 19u8;

        // Three txs with distinct 24-bit tags.
        let mut entries: Vec<([u8; 32], [u8; TAG_CIPHERTEXT_LEN_V4])> = Vec::new();
        for i in 0u8..3 {
            let mut txid = [0u8; 32];
            txid[0] = 0x10 + i;
            txid[31] = 0xAB;
            let tag = [i, 0x00, 0x20]; // arbitrary 3-byte tag
            entries.push((txid, tag));
        }

        let filter =
            build_block_filter_v4(800_000, &block_hash, &entries, &server_key, golomb_p).unwrap();

        // serialize → deserialize roundtrip
        let bytes = filter.serialize();
        let back = BlockFilterV4::deserialize(&bytes).unwrap();
        assert_eq!(back.num_entries, 3);
        assert_eq!(back.golomb_p, golomb_p);
        assert_eq!(back.encrypted_tags.len(), 3 * TAG_CIPHERTEXT_LEN_V4);

        // membership + payload recovery for each tx
        let sorted = back.decode_hashes().unwrap();
        for (txid, tag_plain) in &entries {
            let rank = scan_filter_v4(&sorted, txid, &block_hash, back.num_entries, back.golomb_p)
                .expect("tx should be found");
            let ct = back.tag_at(rank).expect("tag at rank");
            // client recovers γ via OPRF (here directly), then decrypts
            let gamma = evaluate_direct(&server_key, txid).unwrap();
            let pt = decrypt_tag_v4(&gamma, txid, &block_hash, &ct);
            assert_eq!(&pt, tag_plain, "decrypted tag must match plaintext");
        }

        // a non-member txid should not be found
        let missing = [0xFFu8; 32];
        assert!(scan_filter_v4(&sorted, &missing, &block_hash, back.num_entries, back.golomb_p).is_none());
    }

    fn make_test_outpoint(txid_byte: u8, vout: u32) -> TxOutpoint {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        TxOutpoint::new(txid, vout)
    }

    #[test]
    fn test_siphash_deterministic() {
        let outpoint = make_test_outpoint(0xAB, 0);
        let block_hash = [0x42u8; 32];

        let h1 = siphash_txout(&outpoint, &block_hash);
        let h2 = siphash_txout(&outpoint, &block_hash);
        assert_eq!(h1, h2, "SipHash must be deterministic");
    }

    #[test]
    fn test_siphash_different_inputs() {
        let block_hash = [0x42u8; 32];
        let h1 = siphash_txout(&make_test_outpoint(0x01, 0), &block_hash);
        let h2 = siphash_txout(&make_test_outpoint(0x02, 0), &block_hash);
        assert_ne!(h1, h2, "different outpoints should give different hashes");
    }

    #[test]
    fn test_siphash_different_block_hashes() {
        let outpoint = make_test_outpoint(0xAB, 0);
        let h1 = siphash_txout(&outpoint, &[0x01u8; 32]);
        let h2 = siphash_txout(&outpoint, &[0x02u8; 32]);
        assert_ne!(h1, h2, "different block hashes should give different hashes");
    }

    #[test]
    fn test_build_sorted_hash_map() {
        let block_hash = [0x42u8; 32];
        let outpoints = vec![
            make_test_outpoint(0x03, 0),
            make_test_outpoint(0x01, 0),
            make_test_outpoint(0x02, 0),
        ];

        let sorted = build_sorted_hash_map(&outpoints, &block_hash);
        assert_eq!(sorted.len(), 3);

        // Verify sorted order
        for i in 1..sorted.len() {
            assert!(sorted[i].0 >= sorted[i - 1].0, "must be sorted ascending");
        }
    }

    #[test]
    fn test_scan_filter_finds_match() {
        use crate::golomb::GOLOMB_P;

        let block_hash = [0x42u8; 32];
        let target = make_test_outpoint(0xAB, 2);

        let outpoints = vec![
            make_test_outpoint(0x01, 0),
            make_test_outpoint(0x02, 0),
            target,
            make_test_outpoint(0x03, 0),
        ];

        let n = outpoints.len() as u32;
        let sorted_pairs = build_sorted_hash_map(&outpoints, &block_hash);
        // Apply range reduction (same as server-side builder)
        let mut reduced: Vec<(u64, usize)> = sorted_pairs
            .iter()
            .map(|(h, idx)| (reduce_hash(*h, n, GOLOMB_P), *idx))
            .collect();
        reduced.sort_by_key(|(h, _)| *h);
        let sorted_hashes: Vec<u64> = reduced.iter().map(|(h, _)| *h).collect();

        let result = scan_filter_for_match(&sorted_hashes, &target, &block_hash, n);
        assert!(result.is_some(), "should find the target in the filter");
    }

    #[test]
    fn test_scan_filter_no_match() {
        use crate::golomb::GOLOMB_P;

        let block_hash = [0x42u8; 32];
        let outpoints = vec![
            make_test_outpoint(0x01, 0),
            make_test_outpoint(0x02, 0),
        ];

        let n = outpoints.len() as u32;
        let sorted_pairs = build_sorted_hash_map(&outpoints, &block_hash);
        let mut reduced: Vec<(u64, usize)> = sorted_pairs
            .iter()
            .map(|(h, idx)| (reduce_hash(*h, n, GOLOMB_P), *idx))
            .collect();
        reduced.sort_by_key(|(h, _)| *h);
        let sorted_hashes: Vec<u64> = reduced.iter().map(|(h, _)| *h).collect();

        let missing = make_test_outpoint(0xFF, 0);
        let result = scan_filter_for_match(&sorted_hashes, &missing, &block_hash, n);
        assert!(result.is_none(), "should not find a missing outpoint");
    }

    #[test]
    fn test_block_filter_serialization_roundtrip() {
        // Every encrypted tag must be exactly TAG_CIPHERTEXT_LEN bytes in the v2 format.
        let tag_a: Vec<u8> = (0..TAG_CIPHERTEXT_LEN as u8).collect();
        let tag_b: Vec<u8> = (100..100 + TAG_CIPHERTEXT_LEN as u8).collect();

        let filter = BlockFilter {
            height: 800000,
            block_hash: [0xAB; 32],
            num_entries: 2,
            hash_stream: vec![0xDE, 0xAD, 0xBE, 0xEF],
            encrypted_tags: vec![tag_a, tag_b],
        };

        let serialized = filter.serialize();
        let deserialized = BlockFilter::deserialize(&serialized).expect("deserialize should succeed");

        assert_eq!(filter.height, deserialized.height);
        assert_eq!(filter.block_hash, deserialized.block_hash);
        assert_eq!(filter.num_entries, deserialized.num_entries);
        assert_eq!(filter.hash_stream, deserialized.hash_stream);
        assert_eq!(filter.encrypted_tags, deserialized.encrypted_tags);
    }

    #[test]
    fn test_filter_rejects_wrong_magic() {
        let mut bogus = vec![0u8; 64];
        bogus[0..4].copy_from_slice(b"XXXX");
        assert!(BlockFilter::deserialize(&bogus).is_err());
    }

    #[test]
    fn test_filter_rejects_wrong_version() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&FILTER_MAGIC);
        bad.push(FILTER_FORMAT_VERSION.wrapping_add(1));
        bad.extend_from_slice(&[0u8; 44]);
        assert!(BlockFilter::deserialize(&bad).is_err());
    }
}
