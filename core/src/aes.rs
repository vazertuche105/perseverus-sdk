//! AES-256-GCM encryption for KYC tag data in block filters.
//!
//! Implements Section 6.2 of the whitepaper:
//! - Derive symmetric key: κ_t = HMAC(γ_t || ctx)
//! - Derive deterministic nonce from per-block secret
//! - Encrypt/decrypt tags with AES-256-GCM
//! - Optional GCM tag truncation to 8 bytes (2^-64 forgery probability)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ark_ed_on_bn254::EdwardsProjective;
type G1Projective = EdwardsProjective;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use siphasher::sip::SipHasher;
use std::hash::Hasher;

use crate::types::PerseverusError;

type HmacSha256 = Hmac<Sha256>;

/// Context string for KYC tag encryption key derivation
const TAG_CTX: &[u8] = b"kyc-tag";

/// Fixed plaintext width for every KYC tag, in bytes.
///
/// CRITICAL FOR PRIVACY: every encrypted tag in a block filter MUST be the
/// same size. If Coinbase/Unknown/Clean tags (1-byte plaintexts) were stored
/// at a different size than KycExchange tags (3-byte plaintexts), anyone
/// downloading a filter could count ciphertext lengths to learn how many KYC
/// hits the block contained — completely bypassing the encryption.
///
/// 4 bytes holds all current tag types (max = 3-byte KycExchange) plus one
/// byte of headroom for future tag extensions (confidence score, cluster
/// identifier, etc.) without another filter-format migration.
pub const TAG_PLAINTEXT_LEN: usize = 4;

/// Fixed ciphertext length: 4-byte plaintext + 8-byte truncated GCM auth tag.
pub const TAG_CIPHERTEXT_LEN: usize = TAG_PLAINTEXT_LEN + 8;

/// Pad a `KycTag::to_bytes()` payload to the fixed plaintext width with
/// trailing zeros. `KycTag::from_bytes` dispatches on the first byte (the
/// tag discriminator) and reads only the bytes it needs, so trailing zeros
/// are inert on the decode side.
pub fn pad_tag_plaintext(tag_bytes: &[u8]) -> Result<[u8; TAG_PLAINTEXT_LEN], PerseverusError> {
    if tag_bytes.len() > TAG_PLAINTEXT_LEN {
        return Err(PerseverusError::AesError(format!(
            "tag plaintext {} bytes exceeds fixed width {}",
            tag_bytes.len(),
            TAG_PLAINTEXT_LEN
        )));
    }
    let mut padded = [0u8; TAG_PLAINTEXT_LEN];
    padded[..tag_bytes.len()].copy_from_slice(tag_bytes);
    Ok(padded)
}

/// Derive the AES-256 encryption key from an OPRF evaluation point.
///
/// κ_t = HMAC-SHA256(γ_t || ctx)
///
/// where γ_t = k · H2C(txid||index) is the OPRF evaluation.
pub fn derive_tag_key(gamma: &G1Projective) -> [u8; 32] {
    let mut gamma_bytes = Vec::new();
    gamma
        .into_affine()
        .serialize_compressed(&mut gamma_bytes)
        .expect("serialization should not fail");

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&gamma_bytes).expect("HMAC can take any size key");
    mac.update(TAG_CTX);
    let result = mac.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Derive a deterministic 96-bit nonce for a transaction within a block.
///
/// nonce = Trunc96(SipHash(K_h, txid||index))
///
/// K_h is the per-block secret derived from the block hash.
/// This ensures each (block, tx) pair gets a unique nonce without randomness.
pub fn derive_nonce(
    outpoint_bytes: &[u8],
    block_hash: &[u8; 32],
) -> [u8; 12] {
    // Use a different portion of the block hash as the nonce-derivation key
    // (bytes 16..32 to avoid overlap with the SipHash filter key at bytes 0..16)
    let k0 = u64::from_le_bytes(block_hash[16..24].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_hash[24..32].try_into().unwrap());

    let mut hasher = SipHasher::new_with_keys(k0, k1);
    hasher.write(outpoint_bytes);
    let hash = hasher.finish();

    // Second round with slightly different input for 96 bits
    let mut hasher2 = SipHasher::new_with_keys(k0.wrapping_add(1), k1);
    hasher2.write(outpoint_bytes);
    let hash2 = hasher2.finish();

    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&hash.to_le_bytes());
    nonce[8..12].copy_from_slice(&hash2.to_le_bytes()[0..4]);
    nonce
}

/// Encrypt a KYC tag using AES-256-GCM.
///
/// Returns the ciphertext + full 16-byte GCM auth tag.
pub fn encrypt_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PerseverusError::AesError(format!("encryption failed: {}", e)))
}

/// Encrypt a KYC tag with truncated 8-byte GCM auth tag.
///
/// Accepts 2^-64 forgery probability per whitepaper Section 6.
/// This compresses each encrypted tag to (ciphertext_len + 8) bytes.
pub fn encrypt_tag_truncated(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    let full = encrypt_tag(key, nonce, plaintext)?;

    // AES-GCM output = ciphertext || 16-byte tag
    // Truncate the auth tag from 16 bytes to 8 bytes
    let ct_len = plaintext.len();
    let mut truncated = Vec::with_capacity(ct_len + 8);
    truncated.extend_from_slice(&full[..ct_len]); // ciphertext
    truncated.extend_from_slice(&full[ct_len..ct_len + 8]); // first 8 bytes of GCM tag
    Ok(truncated)
}

/// Decrypt a KYC tag using AES-256-GCM (full 16-byte tag).
pub fn decrypt_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| PerseverusError::AesError(format!("decryption failed: {}", e)))
}

/// Decrypt a KYC tag with truncated 8-byte GCM auth tag.
///
/// Strategy: GCM's CTR-mode ciphertext bytes are identical regardless of tag length.
/// So we decrypt with the full 16-byte tag API by padding the truncated tag with zeros.
/// If that fails (expected — the padded tag is wrong), we fall back to XOR-based CTR
/// decryption, then re-encrypt to verify the truncated 8 bytes match.
pub fn decrypt_tag_truncated(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_truncated: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    if ciphertext_truncated.len() < 8 {
        return Err(PerseverusError::AesError("ciphertext too short for truncated tag".into()));
    }

    let ct_len = ciphertext_truncated.len() - 8;
    let ct_body = &ciphertext_truncated[..ct_len];
    let truncated_tag = &ciphertext_truncated[ct_len..];

    // Try full-tag decrypt with zero-padded tag (works if the last 8 bytes happen to be zero)
    let mut padded = Vec::with_capacity(ct_len + 16);
    padded.extend_from_slice(ct_body);
    padded.extend_from_slice(truncated_tag);
    padded.extend_from_slice(&[0u8; 8]);

    if let Ok(plaintext) = decrypt_tag(key, nonce, &padded) {
        return Ok(plaintext);
    }

    // Standard path: XOR the ciphertext with the keystream to get plaintext,
    // then re-encrypt with full GCM to verify the first 8 tag bytes match.
    //
    // GCM = AES-CTR (for confidentiality) + GHASH (for auth tag).
    // The ciphertext bytes are produced by CTR mode alone, so we can
    // recover plaintext by encrypting a zero plaintext of the same length
    // and XOR-ing with the ciphertext body.
    let zero_plaintext = vec![0u8; ct_len];
    let zero_encrypted = encrypt_tag(key, nonce, &zero_plaintext)?;
    // zero_encrypted[..ct_len] is the keystream XOR'd with zeros = keystream itself
    let keystream = &zero_encrypted[..ct_len];

    let plaintext: Vec<u8> = ct_body.iter()
        .zip(keystream.iter())
        .map(|(&c, &k)| c ^ k)
        .collect();

    // Verify: re-encrypt the recovered plaintext and check truncated tag
    let re_encrypted = encrypt_tag(key, nonce, &plaintext)?;
    let re_tag_first_8 = &re_encrypted[ct_len..ct_len + 8];

    if re_tag_first_8 != truncated_tag {
        return Err(PerseverusError::AesError("truncated GCM tag verification failed".into()));
    }

    Ok(plaintext)
}

// ─────────────────────────────────────────────────────────────────────────────
// V3 Filter Format: AES-CTR encryption (no auth tag) with 2-byte tags
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed plaintext width for v3 filter format (2 bytes).
///
/// Byte 0: tag discriminator (0x01–0x05)
/// Byte 1: exchange ID for KycExchange, 0x00 for all other types
///
/// This is intentionally smaller than TAG_PLAINTEXT_LEN (v2) — v3 trades
/// the GCM auth tag for bandwidth savings: 2 bytes per entry vs 12.
pub const TAG_PLAINTEXT_LEN_V3: usize = 2;

/// Fixed ciphertext length for v3: pure CTR XOR, no auth tag.
/// Ciphertext size = plaintext size.
pub const TAG_CIPHERTEXT_LEN_V3: usize = TAG_PLAINTEXT_LEN_V3;

/// Pad a tag to v3's 2-byte format: [discriminator, exchange_id_or_zero].
pub fn pad_tag_plaintext_v3(tag_bytes: &[u8]) -> Result<[u8; TAG_PLAINTEXT_LEN_V3], PerseverusError> {
    if tag_bytes.is_empty() {
        return Err(PerseverusError::AesError("empty tag bytes".into()));
    }
    let mut padded = [0u8; TAG_PLAINTEXT_LEN_V3];
    padded[0] = tag_bytes[0]; // discriminator
    // For KycExchange (0x02), the second byte is the low byte of the exchange ID.
    // For all other types, it stays 0x00.
    if tag_bytes[0] == 0x02 && tag_bytes.len() >= 2 {
        padded[1] = tag_bytes[1]; // low byte of exchange ID (supports 256 exchanges)
    }
    Ok(padded)
}

/// Encrypt a 2-byte KYC tag using pure AES-256-CTR (no authentication tag).
///
/// This is the v3 filter format: we XOR the plaintext with the AES-CTR
/// keystream. The result is exactly 2 bytes — same size as the plaintext.
/// No integrity protection — acceptable because the client verifies tags
/// probabilistically (wrong key → random 2 bytes → invalid discriminator).
pub fn encrypt_tag_ctr(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8; TAG_PLAINTEXT_LEN_V3],
) -> [u8; TAG_CIPHERTEXT_LEN_V3] {
    // AES-GCM's ciphertext bytes are produced by CTR mode. We encrypt
    // a zero-block to get the raw keystream, then XOR with plaintext.
    let zero = [0u8; TAG_PLAINTEXT_LEN_V3];
    let full_encrypted = encrypt_tag(key, nonce, &zero)
        .expect("encrypting zeros should never fail");
    // full_encrypted = keystream XOR zeros || 16-byte GCM tag
    // So full_encrypted[..2] IS the keystream for positions 0..2.
    let mut ct = [0u8; TAG_CIPHERTEXT_LEN_V3];
    ct[0] = plaintext[0] ^ full_encrypted[0];
    ct[1] = plaintext[1] ^ full_encrypted[1];
    ct
}

/// Decrypt a 2-byte AES-CTR ciphertext back to plaintext.
///
/// Symmetric to encrypt_tag_ctr (XOR is its own inverse).
pub fn decrypt_tag_ctr(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8; TAG_CIPHERTEXT_LEN_V3],
) -> [u8; TAG_PLAINTEXT_LEN_V3] {
    // CTR decryption = same XOR with keystream
    let zero = [0u8; TAG_PLAINTEXT_LEN_V3];
    let full_encrypted = encrypt_tag(key, nonce, &zero)
        .expect("encrypting zeros should never fail");
    let mut pt = [0u8; TAG_PLAINTEXT_LEN_V3];
    pt[0] = ciphertext[0] ^ full_encrypted[0];
    pt[1] = ciphertext[1] ^ full_encrypted[1];
    pt
}

// ─────────────────────────────────────────────────────────────────────────────
// V4 Filter Format: per-transaction, 24-bit (3-byte) heuristic tag, pure AES-CTR
// ─────────────────────────────────────────────────────────────────────────────

/// Plaintext width for v4: the 24-bit heuristic tag = 3 bytes.
pub const TAG_PLAINTEXT_LEN_V4: usize = 3;

/// Ciphertext width for v4: pure CTR (no GCM auth tag) → same as plaintext.
///
/// Integrity is NOT per-tag in v4 (that would cost 8 bytes/entry, dwarfing the
/// 3-byte payload). Cover the whole filter with one MAC/signature instead, and
/// rely on the client verifying a hit against the real transaction.
pub const TAG_CIPHERTEXT_LEN_V4: usize = 3;

/// Derive 3 bytes of AES-256-CTR keystream for (key, nonce).
///
/// AES-GCM's ciphertext is produced by CTR mode, so encrypting a 3-byte zero
/// buffer and taking the output bytes yields the raw keystream — exactly the
/// trick `encrypt_tag_ctr` uses for v3, here fixed at the 24-bit tag width.
pub fn ctr_keystream_v4(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; TAG_CIPHERTEXT_LEN_V4] {
    let zero = [0u8; TAG_PLAINTEXT_LEN_V4];
    let full = encrypt_tag(key, nonce, &zero).expect("encrypting zeros should never fail");
    let mut ks = [0u8; TAG_CIPHERTEXT_LEN_V4];
    ks.copy_from_slice(&full[..TAG_CIPHERTEXT_LEN_V4]);
    ks
}

/// Encrypt OR decrypt a 3-byte v4 tag with pure AES-256-CTR (XOR keystream).
/// XOR is its own inverse, so this single function serves both directions.
pub fn ctr_xor_tag_v4(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8; TAG_CIPHERTEXT_LEN_V4],
) -> [u8; TAG_CIPHERTEXT_LEN_V4] {
    let ks = ctr_keystream_v4(key, nonce);
    let mut out = [0u8; TAG_CIPHERTEXT_LEN_V4];
    for i in 0..TAG_CIPHERTEXT_LEN_V4 {
        out[i] = data[i] ^ ks[i];
    }
    out
}

/// 16 bits of AES-256-CTR keystream for (key, nonce) — used by v5 to encrypt a
/// short (<=16-bit) codebook index. Same zero-block trick as the v4 helper.
pub fn ctr_keystream_u16(key: &[u8; 32], nonce: &[u8; 12]) -> u16 {
    let zero = [0u8; 2];
    let full = encrypt_tag(key, nonce, &zero).expect("encrypting zeros should never fail");
    u16::from_le_bytes([full[0], full[1]])
}

// ─────────────────────────────────────────────────────────────────────────────

/// Full pipeline: encrypt a KYC tag for a specific transaction in a block.
///
/// 1. Compute OPRF evaluation γ = k · H2C(outpoint)
/// 2. Derive key κ = HMAC(γ || ctx)
/// 3. Derive nonce from block hash
/// 4. Encrypt with AES-256-GCM
pub fn encrypt_tag_for_outpoint(
    gamma: &G1Projective,
    outpoint_bytes: &[u8],
    block_hash: &[u8; 32],
    tag_plaintext: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    let key = derive_tag_key(gamma);
    let nonce = derive_nonce(outpoint_bytes, block_hash);
    encrypt_tag(&key, &nonce, tag_plaintext)
}

/// Full pipeline: decrypt a KYC tag for a specific transaction.
pub fn decrypt_tag_for_outpoint(
    gamma: &G1Projective,
    outpoint_bytes: &[u8],
    block_hash: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PerseverusError> {
    let key = derive_tag_key(gamma);
    let nonce = derive_nonce(outpoint_bytes, block_hash);
    decrypt_tag(&key, &nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2c::hash_to_curve;
    use crate::types::KycTag;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"KycExchange:Coinbase";

        let ciphertext = encrypt_tag(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_tag(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret-tag";

        let ciphertext = encrypt_tag(&key, &nonce, plaintext).unwrap();
        let result = decrypt_tag(&wrong_key, &nonce, &ciphertext);
        assert!(result.is_err(), "wrong key should fail decryption");
    }

    #[test]
    fn test_full_oprf_based_encryption_pipeline() {
        let mut rng = thread_rng();
        let server_secret = ark_ed_on_bn254::Fr::rand(&mut rng);

        let outpoint_bytes = b"some-txid:0";
        let block_hash = [0xAB; 32];
        let tag = KycTag::KycExchange("Kraken".to_string());

        // Server encrypts during filter construction
        let gamma = hash_to_curve(outpoint_bytes) * server_secret;
        let ciphertext =
            encrypt_tag_for_outpoint(&gamma, outpoint_bytes, &block_hash, &tag.to_bytes())
                .unwrap();

        // Client decrypts after obtaining γ via OPRF
        // (In real flow, client gets γ via blinded OPRF. Here we shortcut.)
        let decrypted_bytes =
            decrypt_tag_for_outpoint(&gamma, outpoint_bytes, &block_hash, &ciphertext)
                .unwrap();

        let decrypted_tag = KycTag::from_bytes(&decrypted_bytes).unwrap();
        assert_eq!(decrypted_tag, KycTag::KycExchange("Kraken".to_string()));
    }

    #[test]
    fn test_derive_nonce_deterministic() {
        let outpoint = b"txid:0";
        let block_hash = [0x42u8; 32];

        let n1 = derive_nonce(outpoint, &block_hash);
        let n2 = derive_nonce(outpoint, &block_hash);
        assert_eq!(n1, n2, "nonce derivation must be deterministic");
    }

    #[test]
    fn test_derive_nonce_different_inputs() {
        let block_hash = [0x42u8; 32];
        let n1 = derive_nonce(b"txid-a:0", &block_hash);
        let n2 = derive_nonce(b"txid-b:0", &block_hash);
        assert_ne!(n1, n2, "different outpoints should give different nonces");
    }

    #[test]
    fn test_truncated_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"\x02\x01\x00"; // KycExchange ID=1 (Coinbase) in new format

        let ciphertext = encrypt_tag_truncated(&key, &nonce, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 8, "truncated tag should be 8 bytes");

        let decrypted = decrypt_tag_truncated(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_truncated_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"\x01"; // Coinbase tag

        let ciphertext = encrypt_tag_truncated(&key, &nonce, plaintext).unwrap();
        let result = decrypt_tag_truncated(&wrong_key, &nonce, &ciphertext);
        assert!(result.is_err(), "wrong key should fail truncated decryption");
    }

    /// End-to-end: server encrypts with evaluate_direct, client decrypts
    /// with blind/evaluate/unblind gamma. Proves OPRF round-trip produces
    /// the same AES key.
    #[test]
    fn test_truncated_oprf_roundtrip_blind_unblind() {
        use crate::oprf::{OprfServerKey, blind, evaluate_batch, verify_batch};
        use ark_ff::Field;
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE);

        let server_key = OprfServerKey::generate(&mut rng);
        let outpoint_bytes = b"deadbeef00000000000000000000000000000000000000000000000000000001\x00\x00\x00\x00";
        let block_hash = [0xABu8; 32];
        let tag = KycTag::KycExchange("Kraken".to_string());
        let padded = pad_tag_plaintext(&tag.to_bytes()).unwrap();

        // ── Server side: encrypt during filter build ──
        let gamma_server = crate::oprf::evaluate_direct(&server_key, outpoint_bytes).unwrap();
        let key_enc = derive_tag_key(&gamma_server);
        let nonce = derive_nonce(outpoint_bytes, &block_hash);
        let ct = encrypt_tag_truncated(&key_enc, &nonce, &padded).unwrap();

        // ── Client side: blind → server evaluate → unblind ──
        let blinded = blind(outpoint_bytes, &mut rng).unwrap();
        let (betas, dleq) = evaluate_batch(&server_key, &[blinded.blinded_point], &mut rng);
        verify_batch(&server_key.pubkey, &[blinded.blinded_point], &betas, &dleq).unwrap();
        let rho_inv = blinded.blinding_factor.inverse().unwrap();
        let gamma_client = betas[0] * rho_inv;

        // ── The gammas must be identical ──
        assert_eq!(gamma_server, gamma_client, "OPRF round-trip gamma mismatch!");

        // ── Client decrypts ──
        let key_dec = derive_tag_key(&gamma_client);
        assert_eq!(key_enc, key_dec, "AES keys must match");

        let decrypted = decrypt_tag_truncated(&key_dec, &nonce, &ct).unwrap();
        let recovered = KycTag::from_bytes(&decrypted).unwrap();
        assert_eq!(recovered, tag);
    }

    #[test]
    fn test_truncated_all_tag_types() {
        let key = [0x55u8; 32];
        let nonce = [0x07u8; 12];

        let tags = vec![
            KycTag::Coinbase,
            KycTag::KycExchange("Coinbase".to_string()),
            KycTag::KycExchange("Kraken".to_string()),
            KycTag::CoinJoin,
            KycTag::Unknown,
            KycTag::Clean,
        ];

        for tag in &tags {
            let plaintext = tag.to_bytes();
            let ct = encrypt_tag_truncated(&key, &nonce, &plaintext).unwrap();
            let decrypted = decrypt_tag_truncated(&key, &nonce, &ct).unwrap();
            let recovered = KycTag::from_bytes(&decrypted).unwrap();
            assert_eq!(&recovered, tag, "roundtrip failed for {:?}", tag);
        }
    }
}
