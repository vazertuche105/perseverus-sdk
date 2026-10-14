//! Client-side global tag codebook (PSCB format).
//!
//! The v5 filter stores, per tx, an OPRF-encrypted **code** rather than the
//! 24-bit tag itself. The code is an index into a global, public codebook that
//! maps realized 24-bit v3-lean tags to compact `code_bits`-wide indices. After
//! the client decrypts the code (`decrypt_code_v5`), it looks the code up here
//! to recover the 24-bit tag.
//!
//! Wire format (matches `make_codebook.py` / the server's builder):
//! ```text
//! magic "PSCB" (4) | version (1) | code_bits (1) | count (u32 LE) | id (4)
//!   | count * 3-byte tags (LE, sorted; code = array index)
//! ```
//! The 4-byte `id` must equal each v5 filter's `codebook_id`, proving the
//! client holds the matching codebook before it decodes anything.

/// Parsed global codebook: `code -> 24-bit tag`.
#[derive(Debug, Clone)]
pub struct Codebook {
    pub code_bits: u8,
    pub id: [u8; 4],
    /// `code_to_tag[code]` = the realized 24-bit tag for that code.
    code_to_tag: Vec<u32>,
}

impl Codebook {
    /// Parse a PSCB byte buffer.
    pub fn parse(d: &[u8]) -> Result<Self, String> {
        if d.len() < 14 || &d[0..4] != b"PSCB" {
            return Err("bad codebook magic (expected PSCB)".into());
        }
        let code_bits = d[5];
        let count = u32::from_le_bytes(d[6..10].try_into().unwrap()) as usize;
        let mut id = [0u8; 4];
        id.copy_from_slice(&d[10..14]);
        if d.len() < 14 + count * 3 {
            return Err(format!(
                "codebook truncated: need {} bytes for {} tags, have {}",
                14 + count * 3,
                count,
                d.len()
            ));
        }
        let mut code_to_tag = Vec::with_capacity(count);
        for i in 0..count {
            let o = 14 + i * 3;
            let tag = d[o] as u32 | (d[o + 1] as u32) << 8 | (d[o + 2] as u32) << 16;
            code_to_tag.push(tag);
        }
        Ok(Codebook { code_bits, id, code_to_tag })
    }

    /// Recover the 24-bit tag for a decrypted code, or `None` if out of range.
    pub fn tag_for(&self, code: u32) -> Option<u32> {
        self.code_to_tag.get(code as usize).copied()
    }

    /// Number of codes in the book.
    pub fn len(&self) -> usize {
        self.code_to_tag.len()
    }

    pub fn is_empty(&self) -> bool {
        self.code_to_tag.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        // Build a tiny PSCB: 3 tags, code_bits=2, id=DEADBEEF.
        let tags: [u32; 3] = [0x0000f2, 0x000001, 0xabcdef];
        let mut d = Vec::new();
        d.extend_from_slice(b"PSCB");
        d.push(1); // version
        d.push(2); // code_bits
        d.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        d.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        for t in tags {
            d.push((t & 0xff) as u8);
            d.push(((t >> 8) & 0xff) as u8);
            d.push(((t >> 16) & 0xff) as u8);
        }
        let cb = Codebook::parse(&d).unwrap();
        assert_eq!(cb.code_bits, 2);
        assert_eq!(cb.id, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cb.len(), 3);
        assert_eq!(cb.tag_for(0), Some(0x0000f2));
        assert_eq!(cb.tag_for(2), Some(0xabcdef));
        assert_eq!(cb.tag_for(3), None);
    }
}
