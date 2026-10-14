//! Perseverus Core — Cryptographic primitives for the privacy-preserving KYC query engine.
//!
//! This crate implements:
//! - VOPRF (Verifiable Oblivious Pseudorandom Function) on BabyJubJub
//! - Chaum-Pedersen DLEQ proofs (single + batched)
//! - Sparse Merkle Tree (depth-16) for token pack revocation
//! - Bulletin board (append-only attribution tree with encrypted blobs)
//! - SipHash-based TXID hashing for block filters
//! - Golomb-Rice encoding/decoding (BIP-158 compatible)
//! - AES-256-GCM encryption with truncated tags
//! - Discrete Laplace decoy block selection

pub mod types;
pub mod h2c;
pub mod oprf;
pub mod dleq;
pub mod filter;
pub mod golomb;
pub mod aes;
pub mod laplace;
pub mod poseidon;
pub mod token_pack;
pub mod nullifier;
pub mod issuance;
pub mod smt;
pub mod bulletin_board;

// Re-exports for convenience
pub use types::*;
pub use h2c::hash_to_curve;
