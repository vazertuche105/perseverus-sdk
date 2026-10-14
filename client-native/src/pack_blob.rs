//! Opaque `IssuedPack` blob format, shared by the Sparrow JNI layer and the
//! Perseverus SDK so a pack issued by either wallet stack can be read by both.

use ark_ed_on_bn254::EdwardsAffine as G1Affine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use perseverus_core::issuance::IssuedPack;
use perseverus_core::poseidon::{poseidon_config, PoseidonField};
use perseverus_core::token_pack::{Token, TokenPack};

// ─────────────────────────────────────────────────────────────────────
// IssuedPack ⇄ bytes (opaque blob handed to Java)
// ─────────────────────────────────────────────────────────────────────
//
// Format v9 (little-endian, all `u*` are LE):
//   u64                pack_id
//   u64                quota
//   u32                expiration_month  (YYYYMM format)
//   u32                start_month       (YYYYMM format, activation epoch)
//   [compressed PF]    token_seed      (ark_serialize compressed)
//   u32                num_tokens
//   repeated num_tokens times:
//     [compressed G1]  base_point      (ark_serialize compressed)
//     [compressed G1]  blinded_sig     (ark_serialize compressed)
//   u32                num_poseidon_proofs
//   repeated num_poseidon_proofs times:
//     [compressed PF]  challenge       (ark_serialize compressed)
//     [compressed PF]  response        (ark_serialize compressed)
//
// `pack_root` is NOT serialized — it's derived on read via
// `TokenPack::build`, which also reconstructs the Merkle levels Sparrow
// never needs to see. Keeping the format minimal protects us from
// round-trip drift and keeps the blob small (~96 B / token + fixed header).

/// Pack blob format version. Bump this whenever the serialization layout
/// changes so the deserializer can reject stale blobs with a clear message
/// instead of silently misreading fields.
pub const PACK_BLOB_VERSION: u8 = 2; // v1 = pre-start_month, v2 = v9 (with start_month)

pub fn serialize_issued_pack(issued: &IssuedPack) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.push(PACK_BLOB_VERSION);
    out.extend_from_slice(&issued.pack_id.to_le_bytes());
    out.extend_from_slice(&issued.quota.to_le_bytes());
    out.extend_from_slice(&issued.expiration_month.to_le_bytes());
    out.extend_from_slice(&issued.start_month.to_le_bytes());
    issued
        .token_seed
        .serialize_compressed(&mut out)
        .map_err(|e| format!("token_seed serialize: {}", e))?;
    let n = issued.pack.tokens.len();
    if n > u32::MAX as usize {
        return Err("pack too large for JNI blob".into());
    }
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for tok in &issued.pack.tokens {
        tok.base_point
            .serialize_compressed(&mut out)
            .map_err(|e| format!("base_point serialize: {}", e))?;
        tok.blinded_sig
            .serialize_compressed(&mut out)
            .map_err(|e| format!("blinded_sig serialize: {}", e))?;
    }
    // Poseidon DLEQ proofs
    let np = issued.poseidon_dleq_proofs.len();
    out.extend_from_slice(&(np as u32).to_le_bytes());
    for (i, proof) in issued.poseidon_dleq_proofs.iter().enumerate() {
        proof.challenge
            .serialize_compressed(&mut out)
            .map_err(|e| format!("poseidon_proof[{}] challenge: {}", i, e))?;
        proof.response
            .serialize_compressed(&mut out)
            .map_err(|e| format!("poseidon_proof[{}] response: {}", i, e))?;
    }
    Ok(out)
}

pub fn deserialize_issued_pack(bytes: &[u8]) -> Result<IssuedPack, String> {
    use std::io::Read;

    if bytes.is_empty() {
        return Err("empty pack blob".into());
    }

    let version = bytes[0];
    if version != PACK_BLOB_VERSION {
        return Err(format!(
            "pack blob version mismatch: found v{}, expected v{}. \
             This pack was issued under an older protocol and must be re-issued.",
            version, PACK_BLOB_VERSION
        ));
    }

    let mut cursor = std::io::Cursor::new(&bytes[1..]); // skip version byte
    let mut u64_buf = [0u8; 8];
    cursor.read_exact(&mut u64_buf).map_err(|e| format!("pack_id read: {}", e))?;
    let pack_id = u64::from_le_bytes(u64_buf);

    cursor.read_exact(&mut u64_buf).map_err(|e| format!("quota read: {}", e))?;
    let quota = u64::from_le_bytes(u64_buf);

    let mut u32_buf = [0u8; 4];
    cursor.read_exact(&mut u32_buf).map_err(|e| format!("expiration_month read: {}", e))?;
    let expiration_month = u32::from_le_bytes(u32_buf);

    let mut u32_sm = [0u8; 4];
    cursor.read_exact(&mut u32_sm).map_err(|e| format!("start_month read: {}", e))?;
    let start_month = u32::from_le_bytes(u32_sm);

    let token_seed = PoseidonField::deserialize_compressed(&mut cursor)
        .map_err(|e| format!("token_seed deserialize: {}", e))?;

    let mut u32_buf2 = [0u8; 4];
    cursor.read_exact(&mut u32_buf2).map_err(|e| format!("num_tokens read: {}", e))?;
    let n = u32::from_le_bytes(u32_buf2) as usize;

    let mut tokens = Vec::with_capacity(n);
    for i in 0..n {
        let base_point = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| format!("token[{}] base_point: {}", i, e))?;
        let blinded_sig = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| format!("token[{}] blinded_sig: {}", i, e))?;
        tokens.push(Token {
            base_point,
            blinded_sig,
        });
    }

    // Poseidon DLEQ proofs
    let mut u32_buf3 = [0u8; 4];
    cursor.read_exact(&mut u32_buf3).map_err(|e| format!("num_poseidon_proofs read: {}", e))?;
    let np = u32::from_le_bytes(u32_buf3) as usize;

    let mut poseidon_dleq_proofs = Vec::with_capacity(np);
    for i in 0..np {
        let challenge = PoseidonField::deserialize_compressed(&mut cursor)
            .map_err(|e| format!("poseidon_proof[{}] challenge: {}", i, e))?;
        let response = PoseidonField::deserialize_compressed(&mut cursor)
            .map_err(|e| format!("poseidon_proof[{}] response: {}", i, e))?;
        poseidon_dleq_proofs.push(perseverus_core::dleq::PoseidonDleqProof { challenge, response });
    }

    let cfg = poseidon_config();
    let pack = TokenPack::build(&cfg, tokens)
        .map_err(|e| format!("TokenPack::build: {}", e))?;
    let pack_root = pack.root;

    Ok(IssuedPack {
        token_seed,
        pack,
        pack_root,
        pack_id,
        quota,
        poseidon_dleq_proofs,
        expiration_month,
        start_month,
    })
}

