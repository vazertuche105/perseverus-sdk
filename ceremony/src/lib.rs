//! Multi-party Groth16 setup for the Perseverus spend circuit.
//!
//! Phase 1 (circuit-independent) is read from the public Perpetual Powers of
//! Tau ([`ptau`]); phase 2 (this circuit) is run between the participants
//! ([`phase2`]). The result is a `pk.bin` / `vk.bin` pair that is sound unless
//! EVERY phase-2 participant kept their secret, and that anyone can check was
//! built correctly — so proofs made with it cannot leak a wallet's token.
//!
//! See `ceremony/README.md` for the procedure.

pub mod phase2;
pub mod ptau;
