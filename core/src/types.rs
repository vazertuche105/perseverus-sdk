//! Core types shared across all modules.

use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BabyJubJub scalar field element (used for blinding factors, secrets, etc.)
pub type Scalar = Fr;

/// BabyJubJub curve point (projective coordinates for arithmetic)
pub type CurvePoint = EdwardsProjective;

/// BabyJubJub curve point (affine coordinates for serialization)
pub type CurveAffine = EdwardsAffine;

/// A 32-byte transaction ID
pub type Txid = [u8; 32];

/// A transaction output identifier (TXID + vout index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxOutpoint {
    pub txid: Txid,
    pub vout_index: u32,
}

impl TxOutpoint {
    pub fn new(txid: Txid, vout_index: u32) -> Self {
        Self { txid, vout_index }
    }

    /// Serialize to bytes: txid || vout_index (little-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.vout_index.to_le_bytes());
        buf
    }
}

/// Known exchange registry — maps numeric IDs to human-readable names.
///
/// Both server and client share this registry so the encrypted filter only
/// needs to store a 2-byte exchange ID instead of a variable-length string.
/// This cuts each KycExchange ciphertext from ~26 bytes to ~11 bytes (with
/// truncated GCM tag).
pub struct ExchangeRegistry;

impl ExchangeRegistry {
    /// Look up an exchange name by its numeric ID.
    pub fn name_for_id(id: u16) -> Option<&'static str> {
        match id {
            1 => Some("Coinbase"),
            2 => Some("Binance"),
            3 => Some("Kraken"),
            4 => Some("Bitfinex"),
            5 => Some("Gemini"),
            6 => Some("Bitstamp"),
            7 => Some("OKX"),
            8 => Some("Bybit"),
            9 => Some("KuCoin"),
            10 => Some("Huobi"),
            11 => Some("Gate.io"),
            12 => Some("Crypto.com"),
            13 => Some("Bittrex"),
            14 => Some("Poloniex"),
            15 => Some("FTX"),
            16 => Some("BlockFi"),
            17 => Some("Celsius"),
            18 => Some("Nexo"),
            19 => Some("SwanBitcoin"),
            20 => Some("River"),
            21 => Some("Cash App"),
            22 => Some("PayPal"),
            23 => Some("Robinhood"),
            24 => Some("eToro"),
            25 => Some("Strike"),
            _ => None,
        }
    }

    /// Look up a numeric ID by exchange name (case-insensitive).
    pub fn id_for_name(name: &str) -> Option<u16> {
        let lower = name.to_lowercase();
        match lower.as_str() {
            "coinbase" => Some(1),
            "binance" => Some(2),
            "kraken" => Some(3),
            "bitfinex" => Some(4),
            "gemini" => Some(5),
            "bitstamp" => Some(6),
            "okx" => Some(7),
            "bybit" => Some(8),
            "kucoin" => Some(9),
            "huobi" => Some(10),
            "gate.io" => Some(11),
            "crypto.com" => Some(12),
            "bittrex" => Some(13),
            "poloniex" => Some(14),
            "ftx" => Some(15),
            "blockfi" => Some(16),
            "celsius" => Some(17),
            "nexo" => Some(18),
            "swanbitcoin" => Some(19),
            "river" => Some(20),
            "cashapp" | "cash app" => Some(21),
            "paypal" => Some(22),
            "robinhood" => Some(23),
            "etoro" => Some(24),
            "strike" => Some(25),
            _ => None,
        }
    }
}

/// KYC tag associated with a transaction output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KycTag {
    /// Coinbase (mining reward) — not KYC
    Coinbase,
    /// Known KYC exchange identified by numeric registry ID.
    /// Use `ExchangeRegistry::name_for_id()` to get the display name.
    KycExchange(String),
    /// CoinJoin transaction — privacy-enhancing
    CoinJoin,
    /// Unknown provenance
    Unknown,
    /// Clean — no KYC association detected
    Clean,
}

impl KycTag {
    /// Encode to a compact byte representation for encryption.
    ///
    /// Format (v2 — numeric exchange IDs):
    ///   0x01         → Coinbase
    ///   0x02 ID_HI ID_LO → KycExchange (2-byte little-endian exchange ID)
    ///   0x03         → CoinJoin
    ///   0x04         → Unknown
    ///   0x05         → Clean
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            KycTag::Coinbase => vec![0x01],
            KycTag::KycExchange(name) => {
                // Look up numeric ID; fall back to 0 (unknown exchange) if not in registry
                let id = ExchangeRegistry::id_for_name(name).unwrap_or(0);
                let mut buf = Vec::with_capacity(3);
                buf.push(0x02);
                buf.extend_from_slice(&id.to_le_bytes());
                buf
            }
            KycTag::CoinJoin => vec![0x03],
            KycTag::Unknown => vec![0x04],
            KycTag::Clean => vec![0x05],
        }
    }

    /// Decode from compact byte representation
    pub fn from_bytes(data: &[u8]) -> Result<Self, PerseverusError> {
        if data.is_empty() {
            return Err(PerseverusError::InvalidTag("empty tag data".into()));
        }
        match data[0] {
            0x01 => Ok(KycTag::Coinbase),
            0x02 => {
                if data.len() < 2 {
                    return Err(PerseverusError::InvalidTag("missing exchange ID bytes".into()));
                }
                // v3 filters store only 1 byte of exchange ID (2 total bytes);
                // v2 filters store 2 bytes of exchange ID (3 total bytes).
                let id = if data.len() >= 3 {
                    u16::from_le_bytes([data[1], data[2]])
                } else {
                    data[1] as u16
                };
                let name = ExchangeRegistry::name_for_id(id)
                    .unwrap_or("UnknownExchange")
                    .to_string();
                Ok(KycTag::KycExchange(name))
            }
            0x03 => Ok(KycTag::CoinJoin),
            0x04 => Ok(KycTag::Unknown),
            0x05 => Ok(KycTag::Clean),
            other => Err(PerseverusError::InvalidTag(format!("unknown tag byte: {:#x}", other))),
        }
    }
}

/// Errors for the Perseverus core library
#[derive(Debug, Error)]
pub enum PerseverusError {
    #[error("DLEQ proof verification failed")]
    DleqVerificationFailed,

    #[error("batched DLEQ proof verification failed")]
    BatchedDleqVerificationFailed,

    #[error("invalid KYC tag: {0}")]
    InvalidTag(String),

    #[error("AES-GCM encryption/decryption error: {0}")]
    AesError(String),

    #[error("filter encoding/decoding error: {0}")]
    FilterError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("invalid curve point")]
    InvalidCurvePoint,
}
