//! Golomb-Rice encoding/decoding for BIP-158-style block filters.
//!
//! The Golomb-Rice code compresses a sequence of positive integers that are
//! geometrically distributed (i.e., skewed toward small values). This is exactly
//! what we get from delta-encoding sorted 64-bit hash values.
//!
//! BIP-158 uses parameter P = 20 (i.e., 2^20 as the Rice parameter).
//! Each delta δ is encoded as: quotient q = δ >> P in unary, then remainder r = δ & ((1<<P)-1) in P bits.

use crate::types::PerseverusError;

/// Default Golomb-Rice parameter (BIP-158 uses P=20)
pub const GOLOMB_P: u8 = 20;

/// Golomb-Rice encoder: encodes a list of deltas into a compressed bitstream.
pub struct GolombEncoder {
    /// The P parameter (number of bits for the remainder)
    p: u8,
    /// Output buffer (packed bits)
    bits: Vec<u8>,
    /// Current bit position within the last byte
    bit_pos: u8,
}

impl GolombEncoder {
    pub fn new(p: u8) -> Self {
        Self {
            p,
            bits: Vec::new(),
            bit_pos: 0,
        }
    }

    /// Encode a single delta value.
    pub fn encode(&mut self, delta: u64) {
        let m = 1u64 << self.p;
        let q = delta / m;    // quotient — encoded in unary
        let r = delta % m;    // remainder — encoded in P bits

        // Write quotient in unary: q ones followed by a zero
        for _ in 0..q {
            self.write_bit(1);
        }
        self.write_bit(0);

        // Write remainder in P bits (big-endian)
        for i in (0..self.p).rev() {
            self.write_bit(((r >> i) & 1) as u8);
        }
    }

    /// Encode a sequence of deltas.
    pub fn encode_all(&mut self, deltas: &[u64]) {
        for &d in deltas {
            self.encode(d);
        }
    }

    /// Get the compressed bitstream as bytes.
    pub fn finish(self) -> Vec<u8> {
        self.bits
    }

    pub fn write_bit(&mut self, bit: u8) {
        if self.bit_pos == 0 {
            self.bits.push(0);
        }
        if bit == 1 {
            let byte_idx = self.bits.len() - 1;
            self.bits[byte_idx] |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos = (self.bit_pos + 1) % 8;
    }
}

/// Golomb-Rice decoder: decodes a compressed bitstream back to delta values.
pub struct GolombDecoder<'a> {
    p: u8,
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> GolombDecoder<'a> {
    pub fn new(data: &'a [u8], p: u8) -> Self {
        Self {
            p,
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Decode a single delta value. Returns None if no more data.
    pub fn decode(&mut self) -> Option<u64> {
        // Read unary quotient: count ones until we hit a zero
        let mut q: u64 = 0;
        loop {
            let bit = self.read_bit()?;
            if bit == 0 {
                break;
            }
            q += 1;
        }

        // Read P-bit remainder (big-endian)
        let mut r: u64 = 0;
        for _ in 0..self.p {
            let bit = self.read_bit()?;
            r = (r << 1) | (bit as u64);
        }

        let m = 1u64 << self.p;
        Some(q * m + r)
    }

    /// Decode all deltas from the stream.
    pub fn decode_all(&mut self, count: usize) -> Result<Vec<u64>, PerseverusError> {
        let mut deltas = Vec::with_capacity(count);
        for _ in 0..count {
            match self.decode() {
                Some(d) => deltas.push(d),
                None => return Err(PerseverusError::FilterError(
                    "premature end of Golomb-Rice stream".into(),
                )),
            }
        }
        Ok(deltas)
    }

    pub fn read_bit(&mut self) -> Option<u8> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }
}

/// Helper: Given a sorted list of 64-bit hash values, compute the delta sequence.
pub fn compute_deltas(sorted_hashes: &[u64]) -> Vec<u64> {
    if sorted_hashes.is_empty() {
        return vec![];
    }
    let mut deltas = Vec::with_capacity(sorted_hashes.len());
    deltas.push(sorted_hashes[0]); // first value is stored as-is
    for i in 1..sorted_hashes.len() {
        deltas.push(sorted_hashes[i] - sorted_hashes[i - 1]);
    }
    deltas
}

/// Helper: Reconstruct sorted hash values from a delta sequence.
pub fn reconstruct_from_deltas(deltas: &[u64]) -> Vec<u64> {
    if deltas.is_empty() {
        return vec![];
    }
    let mut values = Vec::with_capacity(deltas.len());
    values.push(deltas[0]);
    for i in 1..deltas.len() {
        values.push(values[i - 1] + deltas[i]);
    }
    values
}

// ─────────────────────────────────────────────────────────────────────────────
// V3 Filter Format: Interleaved Golomb-Rice (delta + raw tag bytes per entry)
// ─────────────────────────────────────────────────────────────────────────────

/// Interleaved encoder: for each entry, writes the Golomb-Rice encoded delta
/// followed by `tag_len` raw bytes of encrypted tag data. The result is a
/// single combined bitstream with no separate tag column.
pub struct InterleavedGolombEncoder {
    inner: GolombEncoder,
    /// Number of raw tag bytes appended after each delta
    tag_len: usize,
}

impl InterleavedGolombEncoder {
    pub fn new(p: u8, tag_len: usize) -> Self {
        Self {
            inner: GolombEncoder::new(p),
            tag_len,
        }
    }

    /// Encode one entry: Golomb-Rice delta followed by raw tag bytes.
    pub fn encode_entry(&mut self, delta: u64, tag_bytes: &[u8]) {
        assert_eq!(tag_bytes.len(), self.tag_len,
            "tag_bytes length must equal configured tag_len");
        // 1. Golomb-Rice encode the delta (variable-length bits)
        self.inner.encode(delta);
        // 2. Append raw tag bytes (byte-aligned would waste bits;
        //    instead we write each bit directly into the bitstream)
        for &byte in tag_bytes {
            for bit_idx in (0..8).rev() {
                self.inner.write_bit((byte >> bit_idx) & 1);
            }
        }
    }

    /// Encode all entries from parallel slices.
    pub fn encode_all(&mut self, deltas: &[u64], tags: &[&[u8]]) {
        assert_eq!(deltas.len(), tags.len());
        for (d, t) in deltas.iter().zip(tags.iter()) {
            self.encode_entry(*d, t);
        }
    }

    /// Finish and return the combined bitstream.
    pub fn finish(self) -> Vec<u8> {
        self.inner.finish()
    }
}

/// Interleaved decoder: reads Golomb-Rice deltas interleaved with raw tag bytes.
pub struct InterleavedGolombDecoder<'a> {
    inner: GolombDecoder<'a>,
    tag_len: usize,
}

impl<'a> InterleavedGolombDecoder<'a> {
    pub fn new(data: &'a [u8], p: u8, tag_len: usize) -> Self {
        Self {
            inner: GolombDecoder::new(data, p),
            tag_len,
        }
    }

    /// Decode one entry: returns (delta, tag_bytes). None if stream exhausted.
    pub fn decode_entry(&mut self) -> Option<(u64, Vec<u8>)> {
        let delta = self.inner.decode()?;
        let mut tag = vec![0u8; self.tag_len];
        for byte in tag.iter_mut() {
            let mut val = 0u8;
            for _ in 0..8 {
                let bit = self.inner.read_bit()?;
                val = (val << 1) | bit;
            }
            *byte = val;
        }
        Some((delta, tag))
    }

    /// Decode `count` entries. Returns (deltas, tags) vectors.
    pub fn decode_all(&mut self, count: usize) -> Result<(Vec<u64>, Vec<Vec<u8>>), crate::types::PerseverusError> {
        let mut deltas = Vec::with_capacity(count);
        let mut tags = Vec::with_capacity(count);
        for _ in 0..count {
            match self.decode_entry() {
                Some((d, t)) => {
                    deltas.push(d);
                    tags.push(t);
                }
                None => return Err(crate::types::PerseverusError::FilterError(
                    "premature end of interleaved Golomb-Rice stream".into(),
                )),
            }
        }
        Ok((deltas, tags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let deltas = vec![1, 0, 5, 1048576, 100, 3, 0, 42];

        let mut encoder = GolombEncoder::new(GOLOMB_P);
        encoder.encode_all(&deltas);
        let compressed = encoder.finish();

        let mut decoder = GolombDecoder::new(&compressed, GOLOMB_P);
        let decoded = decoder.decode_all(deltas.len()).expect("decode should succeed");

        assert_eq!(deltas, decoded, "roundtrip must preserve values");
    }

    #[test]
    fn test_delta_computation_roundtrip() {
        let sorted = vec![100, 350, 351, 1000, 5000, 5001, 999999];

        let deltas = compute_deltas(&sorted);
        assert_eq!(deltas[0], 100);
        assert_eq!(deltas[1], 250);
        assert_eq!(deltas[2], 1);

        let reconstructed = reconstruct_from_deltas(&deltas);
        assert_eq!(sorted, reconstructed, "delta roundtrip must preserve values");
    }

    #[test]
    fn test_full_pipeline() {
        // Simulate: hash some values, sort, delta-encode, compress, decompress, reconstruct
        let mut hashes: Vec<u64> = vec![
            0xDEADBEEF,
            0x12345678,
            0xCAFEBABE,
            0xBAADF00D,
            0x0BADC0DE,
            0xFEEDFACE,
        ];
        hashes.sort();

        let deltas = compute_deltas(&hashes);

        let mut encoder = GolombEncoder::new(GOLOMB_P);
        encoder.encode_all(&deltas);
        let compressed = encoder.finish();

        let mut decoder = GolombDecoder::new(&compressed, GOLOMB_P);
        let decoded_deltas = decoder.decode_all(hashes.len()).unwrap();

        let reconstructed = reconstruct_from_deltas(&decoded_deltas);
        assert_eq!(hashes, reconstructed);

        // Check compression ratio
        let raw_size = hashes.len() * 8; // 8 bytes per u64
        println!(
            "Raw: {} bytes, Compressed: {} bytes, Ratio: {:.1}%",
            raw_size,
            compressed.len(),
            (compressed.len() as f64 / raw_size as f64) * 100.0
        );
    }

    #[test]
    fn test_empty_input() {
        let deltas: Vec<u64> = vec![];
        let mut encoder = GolombEncoder::new(GOLOMB_P);
        encoder.encode_all(&deltas);
        let compressed = encoder.finish();
        assert!(compressed.is_empty());

        assert_eq!(compute_deltas(&[]), vec![]);
        assert_eq!(reconstruct_from_deltas(&[]), vec![]);
    }
}
