//! Groth16 zk-SNARK circuit for revocation-based token authentication (v10).
//!
//! **BabyJubJub + BN254** — the proof system is Groth16 on BN254. BabyJubJub
//! is a twisted Edwards curve embedded in BN254's scalar field:
//! `Fq(BabyJubJub) = Fr(BN254)`, so in-circuit BabyJubJub point arithmetic
//! is native field arithmetic — no non-native simulation needed.
//!
//! # Statement (v10 — Path-Bound SMT + Activation Epoch, Constant Server Key)
//!
//! A prover holds a token `(P_i, σ_i)` where σ_i = v·P_i (server-signed).
//! The prover demonstrates that:
//! 1. They know the token's secret seed and can derive its base point
//! 2. The token was legitimately signed by the server (DLEQ)
//! 3. The token's nullifier is correctly computed
//! 4. The token has not expired (expiration_month ≥ current_month)
//! 5. The token pack has activated (start_month ≤ current_month)
//! 6. The token pack has NOT been revoked (SMT non-inclusion)
//!
//! ## Public inputs (3 Fr elements)
//! - `nullifier`        — one-shot spend tag
//! - `current_month`    — global epoch (YYYYMM)
//! - `revocation_root`  — root of the depth-16 Sparse Merkle Tree
//!
//! ## Constants (baked into R1CS at setup time)
//! - `pk_server`        — server's public key V = v·G (EdwardsProjective)
//!   Key rotation is handled via FROST threshold secret sharing: the
//!   aggregate public key stays constant while shares are refreshed.
//!   This avoids variable-base scalar multiplication in the DLEQ gadget,
//!   which causes deep LC chains and quadratic memory blowup in
//!   `inline_all_lcs()` during Groth16 trusted setup.
//!
//! ## Witnesses
//! - `token_seed`         — per-pack random scalar (wallet secret)
//! - `pack_id`            — random pack identifier
//! - `token_index`        — which token in the pack
//! - `blinded_sig` σ_i    — server-signed point (2 Fr: x, y)
//! - `dleq_c`             — DLEQ challenge scalar (Poseidon Fiat-Shamir)
//! - `dleq_s`             — DLEQ response scalar
//! - `expiration_month`   — pack expiration (YYYYMM)
//! - `start_month`        — pack activation epoch (YYYYMM)
//! - `smt_siblings[16]`   — SMT authentication path siblings
//! - `smt_path_bits[16]`  — SMT path direction bits
//!
//! ## Derived in-circuit (not passed as inputs)
//! - `P_i` = Poseidon(seed, pack_id, idx) · H_TOKEN
//!
//! ## 6 Constraint Groups
//! 1. **Base-Point Derivation**: derive P_i = Poseidon(seed, pack_id, idx)·H_TOKEN
//! 2. **Nullifier Binding**: nullifier == Poseidon(token_seed, pack_id, token_index)
//! 3. **DLEQ Signature**: σ_i = v·P_i via Chaum-Pedersen + Poseidon Fiat-Shamir
//! 4. **Expiration Check**: expiration_month ≥ current_month
//! 5. **Activation Check**: start_month ≤ current_month
//! 6. **SMT Non-Inclusion**: pack's revocation key is NOT in the revocation tree

use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::EdwardsProjective;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    prelude::*,
};
use ark_r1cs_std::prelude::ToBitsGadget;
use ark_ec::PrimeGroup;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use perseverus_core::poseidon::{poseidon_config, PoseidonField};
use perseverus_core::smt::SMT_DEPTH;

/// Scalar field of BN254 — the SNARK constraint field.
pub type CircuitField = ark_bn254::Fr;

/// Bit width for the expiration month range check.
/// 18 bits supports values up to 262143 (well beyond YYYYMM format).
const EXPIRATION_BITS: usize = 18;

/// The v10 revocation-based token authentication circuit.
///
/// Changes from v9:
/// - **Soundness fix**: SMT gadget now derives `Poseidon(pack_id)` in-circuit
///   and enforces `smt_path_bits == revocation_key_bits[0..16]`. Previously
///   path bits were unconstrained witnesses, allowing a revoked pack to
///   prove non-inclusion at a different (empty) leaf position.
///
/// Changes from v8:
/// - Added: `start_month` witness + activation check (start_month ≤ current_month).
///   Enables yearly prepaid subscriptions where each monthly pack activates
///   only in its designated epoch. Without this, all 12 packs could be
///   spent immediately.
///
/// Changes from v7:
/// - Reverted: pk_server from public input back to circuit constant.
///   Variable-base scalar multiplication on a public-input point creates
///   deep LC chains (~253 levels) that cause `inline_all_lcs()` to use
///   ~47 GB RAM during Groth16 trusted setup. As a constant, the scalar
///   mul is fixed-base (shallow LCs, ~1 GB setup).
///   Key rotation is handled via FROST threshold secret sharing.
/// - Reduced: SMT depth from 32 to 16 (saves ~4K Poseidon constraints).
///
/// Changes from v4:
/// - Removed: Pedersen commitment derivation (constraint ①)
/// - Removed: Board membership proof (constraint ③) — replaced by SMT
/// - Removed: Range check on token_index (constraint ④) — server enforces
/// - Removed: Alpha binding (constraint ⑦) — OPRF blinding handled off-circuit
/// - Removed: board_root, quota, alpha as public inputs
/// - Removed: blinding_factor, board_path, board_path_bits, oprf_blinding as witnesses
/// - Added: revocation_root as public input
/// - Added: smt_siblings[SMT_DEPTH], smt_path_bits[SMT_DEPTH] as witnesses
/// - Added: SMT non-inclusion constraint
/// - Modified: nullifier now uses token_seed (was blinding_factor)
/// - Modified: base point derivation includes pack_id
#[derive(Clone)]
pub struct RevocationSpendCircuit {
    // ── public inputs (3 Fr elements) ─────────────────────────────────────
    /// One-shot nullifier = Poseidon(token_seed, pack_id, token_index).
    pub nullifier: Option<CircuitField>,
    /// Current month for expiration check (YYYYMM, global parameter).
    pub current_month: Option<CircuitField>,
    /// Root of the depth-16 Sparse Merkle Tree (revocation set).
    pub revocation_root: Option<CircuitField>,

    // ── constant (baked into R1CS) ────────────────────────────────────────
    /// Server's public key PK = v·G. Baked into the circuit at setup time.
    /// Key rotation handled via FROST — aggregate key stays constant.
    pub pk_server: EdwardsProjective,

    // ── witnesses ──────────────────────────────────────────────────────────
    /// Per-pack random scalar (wallet secret, replaces blinding_factor).
    pub token_seed: Option<CircuitField>,
    /// Random pack identifier.
    pub pack_id: Option<CircuitField>,
    /// Which token in the pack is being spent.
    pub token_index: Option<CircuitField>,
    /// Server-signed point σ_i = v·P_i.
    pub blinded_sig: Option<EdwardsProjective>,
    /// DLEQ challenge scalar (Poseidon Fiat-Shamir output).
    pub dleq_c: Option<CircuitField>,
    /// DLEQ response scalar.
    pub dleq_s: Option<CircuitField>,
    /// Pack expiration month (YYYYMM format).
    pub expiration_month: Option<CircuitField>,
    /// Pack activation month (YYYYMM format) — the epoch when this pack becomes spendable.
    pub start_month: Option<CircuitField>,
    /// SMT authentication path siblings (SMT_DEPTH field elements).
    pub smt_siblings: Option<Vec<CircuitField>>,
    /// SMT path direction bits (SMT_DEPTH bools).
    pub smt_path_bits: Option<Vec<bool>>,
}

impl RevocationSpendCircuit {
    /// Synthesize an empty circuit for diagnostics.
    pub fn measure_size() -> (usize, usize, usize) {
        use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        Self::empty()
            .generate_constraints(cs.clone())
            .expect("diagnostic synthesis failed");
        (cs.num_constraints(), cs.num_witness_variables(), cs.num_instance_variables())
    }

    /// Construct an empty circuit for trusted-setup / key generation.
    ///
    /// **Important**: `pk_server` is baked into the R1CS as a constant.
    /// The setup binary MUST set `pk_server` to the real server public key
    /// before calling `Groth16::circuit_specific_setup`. The resulting
    /// proving/verifying keys are bound to that specific key.
    pub fn empty() -> Self {
        Self {
            nullifier: None,
            current_month: None,
            revocation_root: None,
            pk_server: EdwardsProjective::generator(), // placeholder — setup must override
            token_seed: None,
            pack_id: None,
            token_index: None,
            blinded_sig: None,
            dleq_c: None,
            dleq_s: None,
            expiration_month: None,
            start_month: None,
            smt_siblings: Some(vec![CircuitField::from(0u64); SMT_DEPTH]),
            smt_path_bits: Some(vec![false; SMT_DEPTH]),
        }
    }
}

impl ConstraintSynthesizer<CircuitField> for RevocationSpendCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        // ── allocate public inputs ─────────────────────────────────────────
        // IMPORTANT: allocation order defines the public-input vector layout.
        // Order: nullifier, current_month, revocation_root
        let nullifier = FpVar::<CircuitField>::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let current_month = FpVar::<CircuitField>::new_input(cs.clone(), || {
            self.current_month.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let revocation_root = FpVar::<CircuitField>::new_input(cs.clone(), || {
            self.revocation_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── allocate witnesses ─────────────────────────────────────────────
        let token_seed = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.token_seed.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pack_id = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.pack_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let token_index = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.token_index.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let blinded_sig = EdwardsVar::new_witness(cs.clone(), || {
            self.blinded_sig.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let dleq_c = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.dleq_c.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let dleq_s = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.dleq_s.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let expiration_month = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.expiration_month.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let start_month = FpVar::<CircuitField>::new_witness(cs.clone(), || {
            self.start_month.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let smt_sibling_vals = self
            .smt_siblings
            .clone()
            .unwrap_or_else(|| vec![CircuitField::from(0u64); SMT_DEPTH]);
        let smt_siblings: Vec<FpVar<CircuitField>> = smt_sibling_vals
            .into_iter()
            .map(|v| FpVar::<CircuitField>::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;

        let smt_bit_vals = self
            .smt_path_bits
            .clone()
            .unwrap_or_else(|| vec![false; SMT_DEPTH]);
        let smt_path_bits: Vec<Boolean<CircuitField>> = smt_bit_vals
            .into_iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── constants baked into R1CS ──────────────────────────────────────
        // pk_server is a constant — fixed-base scalar mul creates shallow
        // LC chains (~1 GB setup), unlike variable-base (~47 GB blowup).
        let pk_server_var = EdwardsVar::new_constant(cs.clone(), self.pk_server)?;

        let g_var = EdwardsVar::new_constant(
            cs.clone(),
            ark_ed_on_bn254::EdwardsProjective::generator(),
        )?;

        // ── dispatch to gadgets ───────────────────────────────────────────

        // ① Base-Point Derivation: P_i = Poseidon(seed, pack_id, idx)·H_TOKEN
        let base_point_derived = gadgets::derive_base_point(
            cs.clone(),
            &token_seed,
            &pack_id,
            &token_index,
        )?;

        // ② Nullifier Binding: nullifier == Poseidon(token_seed, pack_id, token_index)
        gadgets::enforce_nullifier(
            cs.clone(),
            &nullifier,
            &token_seed,
            &pack_id,
            &token_index,
        )?;

        // ③ DLEQ Signature Verification: proves σ_i = v·P_i
        gadgets::enforce_dleq_signature(
            cs.clone(),
            &base_point_derived,
            &blinded_sig,
            &dleq_c,
            &dleq_s,
            &pk_server_var,
            &g_var,
        )?;

        // ④ Expiration Check: expiration_month ≥ current_month
        gadgets::enforce_expiration_check(
            cs.clone(),
            &expiration_month,
            &current_month,
        )?;

        // ⑤ Activation Check: start_month ≤ current_month
        gadgets::enforce_activation_check(
            cs.clone(),
            &start_month,
            &current_month,
        )?;

        // ⑥ SMT Non-Inclusion: pack_id is NOT in the revocation tree
        gadgets::enforce_smt_non_inclusion(
            cs,
            &revocation_root,
            &pack_id,
            &smt_siblings,
            &smt_path_bits,
        )?;

        Ok(())
    }
}

/// Build the Groth16 public-inputs vector for a `RevocationSpendCircuit` proof.
///
/// Allocation order MUST match `RevocationSpendCircuit::generate_constraints`:
///   [nullifier, current_month, revocation_root]
pub fn build_public_inputs(
    nullifier: CircuitField,
    current_month: CircuitField,
    revocation_root: CircuitField,
) -> Result<Vec<CircuitField>, SynthesisError> {
    use ark_relations::r1cs::ConstraintSystem;

    struct PublicInputsOnly {
        nullifier: CircuitField,
        current_month: CircuitField,
        revocation_root: CircuitField,
    }

    impl ConstraintSynthesizer<CircuitField> for PublicInputsOnly {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<CircuitField>,
        ) -> Result<(), SynthesisError> {
            let _ = FpVar::<CircuitField>::new_input(cs.clone(), || Ok(self.nullifier))?;
            let _ = FpVar::<CircuitField>::new_input(cs.clone(), || Ok(self.current_month))?;
            let _ = FpVar::<CircuitField>::new_input(cs, || Ok(self.revocation_root))?;
            Ok(())
        }
    }

    let cs = ConstraintSystem::<CircuitField>::new_ref();
    PublicInputsOnly {
        nullifier,
        current_month,
        revocation_root,
    }
    .generate_constraints(cs.clone())?;
    cs.finalize();
    let snap = cs.borrow().unwrap().instance_assignment.clone();
    Ok(snap[1..].to_vec())
}

/// Gadget helpers — each enforces one constraint group.
pub mod gadgets {
    use super::*;

    /// Constraint ①: Derive the token base point in-circuit (v6).
    ///
    /// Computes P_i = Poseidon(token_seed, pack_id, token_index) · H_TOKEN.
    /// Returns P_i as an EdwardsVar.
    ///
    /// v6 change: now includes pack_id in the hash (v4 was seed+index only).
    pub fn derive_base_point(
        cs: ConstraintSystemRef<CircuitField>,
        token_seed: &FpVar<CircuitField>,
        pack_id: &FpVar<CircuitField>,
        token_index: &FpVar<CircuitField>,
    ) -> Result<EdwardsVar, SynthesisError> {
        let cfg: PoseidonConfig<PoseidonField> = poseidon_config();
        let mut sponge = PoseidonSpongeVar::<CircuitField>::new(cs.clone(), &cfg);
        sponge.absorb(token_seed)?;
        sponge.absorb(pack_id)?;
        sponge.absorb(token_index)?;
        let s = sponge.squeeze_field_elements(1)?.remove(0);

        let h_token_var = EdwardsVar::new_constant(cs, perseverus_core::h2c::h_token())?;
        let s_bits = s.to_bits_le()?;
        let derived = h_token_var.scalar_mul_le(s_bits.iter())?;

        Ok(derived)
    }

    /// Constraint ②: `nullifier == Poseidon(token_seed, pack_id, token_index)`.
    ///
    /// Absorb order must match `perseverus_core::nullifier::compute_nullifier`.
    pub fn enforce_nullifier(
        cs: ConstraintSystemRef<CircuitField>,
        nullifier: &FpVar<CircuitField>,
        token_seed: &FpVar<CircuitField>,
        pack_id: &FpVar<CircuitField>,
        token_index: &FpVar<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let cfg: PoseidonConfig<PoseidonField> = poseidon_config();
        let mut sponge = PoseidonSpongeVar::<CircuitField>::new(cs, &cfg);
        sponge.absorb(token_seed)?;
        sponge.absorb(pack_id)?;
        sponge.absorb(token_index)?;
        let expected = sponge.squeeze_field_elements(1)?.remove(0);
        nullifier.enforce_equal(&expected)?;
        Ok(())
    }

    /// Constraint ③: DLEQ Signature Verification (~6K constraints).
    ///
    /// Proves σ_i = v·P_i using a Chaum-Pedersen proof with Poseidon Fiat-Shamir.
    ///
    /// Verification:
    ///   R1' = s·G - c·PK_server
    ///   R2' = s·P_i - c·σ_i
    ///   c' = Poseidon(PK.x, PK.y, σ.x, σ.y, R1'.x, R1'.y, R2'.x, R2'.y)
    ///   Enforce: c == c'
    pub fn enforce_dleq_signature(
        cs: ConstraintSystemRef<CircuitField>,
        base_point: &EdwardsVar,    // P_i (derived in-circuit)
        blinded_sig: &EdwardsVar,   // σ_i (witness)
        dleq_c: &FpVar<CircuitField>,  // challenge scalar
        dleq_s: &FpVar<CircuitField>,  // response scalar
        pk_server: &EdwardsVar,     // PK_server (constant)
        g: &EdwardsVar,             // G (constant)
    ) -> Result<(), SynthesisError> {
        // s·G
        let s_bits = dleq_s.to_bits_le()?;
        let s_g = g.scalar_mul_le(s_bits.iter())?;

        // c·PK_server
        let c_bits = dleq_c.to_bits_le()?;
        let c_pk = pk_server.scalar_mul_le(c_bits.iter())?;

        // R1' = s·G - c·PK
        let r1_prime = s_g - c_pk;

        // s·P_i
        let s_pi = base_point.scalar_mul_le(s_bits.iter())?;

        // c·σ_i
        let c_sigma = blinded_sig.scalar_mul_le(c_bits.iter())?;

        // R2' = s·P_i - c·σ_i
        let r2_prime = s_pi - c_sigma;

        // c' = Poseidon(PK.x, PK.y, σ.x, σ.y, R1'.x, R1'.y, R2'.x, R2'.y)
        let cfg: PoseidonConfig<PoseidonField> = poseidon_config();
        let mut sponge = PoseidonSpongeVar::<CircuitField>::new(cs, &cfg);
        sponge.absorb(&pk_server.x)?;
        sponge.absorb(&pk_server.y)?;
        sponge.absorb(&blinded_sig.x)?;
        sponge.absorb(&blinded_sig.y)?;
        sponge.absorb(&r1_prime.x)?;
        sponge.absorb(&r1_prime.y)?;
        sponge.absorb(&r2_prime.x)?;
        sponge.absorb(&r2_prime.y)?;
        let c_prime = sponge.squeeze_field_elements(1)?.remove(0);

        // Enforce c == c'
        dleq_c.enforce_equal(&c_prime)?;

        Ok(())
    }

    /// Constraint ④: Expiration Check (~254 constraints).
    ///
    /// Proves expiration_month ≥ current_month by computing
    /// diff = expiration_month - current_month and verifying
    /// it fits in EXPIRATION_BITS bits (i.e. is non-negative and small).
    pub fn enforce_expiration_check(
        cs: ConstraintSystemRef<CircuitField>,
        expiration_month: &FpVar<CircuitField>,
        current_month: &FpVar<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let diff = expiration_month - current_month;

        let diff_bits = diff.to_bits_le()?;
        for bit in diff_bits.iter().skip(EXPIRATION_BITS) {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        let _ = cs;
        Ok(())
    }

    /// Constraint ⑤: Activation Check (~254 constraints).
    ///
    /// Proves current_month ≥ start_month by computing
    /// diff = current_month - start_month and verifying
    /// it fits in EXPIRATION_BITS bits (i.e. is non-negative and small).
    pub fn enforce_activation_check(
        cs: ConstraintSystemRef<CircuitField>,
        start_month: &FpVar<CircuitField>,
        current_month: &FpVar<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let diff = current_month - start_month;

        let diff_bits = diff.to_bits_le()?;
        for bit in diff_bits.iter().skip(EXPIRATION_BITS) {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        let _ = cs;
        Ok(())
    }

    /// Constraint ⑥: SMT Non-Inclusion (~7,700 constraints).
    ///
    /// Proves that `Poseidon(pack_id)` (the revocation key) is NOT in the
    /// depth-16 Sparse Merkle Tree with root `revocation_root`.
    ///
    /// Verification:
    /// 1. Compute revocation_key = Poseidon(pack_id) in-circuit
    /// 2. Decompose to bits and enforce smt_path_bits == key_bits[0..16]
    /// 3. Start with current = 0 (empty leaf)
    /// 4. For each level (from leaf to root):
    ///    - Select (left, right) based on path bit
    ///    - current = Poseidon(left, right) if either is non-zero, else 0
    /// 5. Enforce current == revocation_root
    ///
    /// **v10 soundness fix**: Step 2 binds the authentication path to the
    /// pack's actual revocation key. Without this, a revoked pack could
    /// supply path bits for a different empty leaf and evade revocation.
    ///
    /// The "if either is non-zero" optimization is applied as:
    ///    hash = Poseidon(left, right)
    ///    is_both_zero = (left == 0) AND (right == 0)
    ///    current = is_both_zero ? 0 : hash
    pub fn enforce_smt_non_inclusion(
        cs: ConstraintSystemRef<CircuitField>,
        revocation_root: &FpVar<CircuitField>,
        pack_id: &FpVar<CircuitField>,
        smt_siblings: &[FpVar<CircuitField>],
        smt_path_bits: &[Boolean<CircuitField>],
    ) -> Result<(), SynthesisError> {
        debug_assert_eq!(smt_siblings.len(), SMT_DEPTH);
        debug_assert_eq!(smt_path_bits.len(), SMT_DEPTH);

        let cfg: PoseidonConfig<PoseidonField> = poseidon_config();

        // ── Path binding (v10 fix) ───────────────────────────────────────
        // Compute revocation_key = Poseidon(pack_id) in-circuit, decompose
        // to bits, and enforce that smt_path_bits matches the first
        // SMT_DEPTH bits. Without this, a revoked pack could supply path
        // bits pointing to a *different* empty leaf and bypass revocation.
        {
            let mut key_sponge = PoseidonSpongeVar::<CircuitField>::new(cs.clone(), &cfg);
            key_sponge.absorb(pack_id)?;
            let revocation_key = key_sponge.squeeze_field_elements(1)?.remove(0);
            let key_bits = revocation_key.to_bits_le()?;
            for i in 0..SMT_DEPTH {
                smt_path_bits[i].enforce_equal(&key_bits[i])?;
            }
        }

        // Start from empty leaf (value = 0 means "not present")
        let zero = FpVar::<CircuitField>::new_constant(cs.clone(), CircuitField::from(0u64))?;
        let mut current = zero.clone();

        // Fold from leaf (level 15) to root (level 0)
        // smt_siblings[0] is the sibling at the deepest level (leaf level)
        // smt_path_bits[0] is the direction at the deepest level
        for i in 0..SMT_DEPTH {
            let sibling = &smt_siblings[i];
            let bit = &smt_path_bits[i];

            // Select left/right based on path bit
            let left = FpVar::conditionally_select(bit, sibling, &current)?;
            let right = FpVar::conditionally_select(bit, &current, sibling)?;

            // Compute hash
            let mut sponge = PoseidonSpongeVar::<CircuitField>::new(cs.clone(), &cfg);
            sponge.absorb(&left)?;
            sponge.absorb(&right)?;
            let hash = sponge.squeeze_field_elements(1)?.remove(0);

            // Optimization: if both children are zero, parent is zero.
            // Instead of AND-ing two booleans, we nest conditionally_select:
            // if left == 0 { if right == 0 { zero } else { hash } } else { hash }
            let left_is_zero = left.is_eq(&zero)?;
            let right_is_zero = right.is_eq(&zero)?;
            let inner = FpVar::conditionally_select(&right_is_zero, &zero, &hash)?;
            current = FpVar::conditionally_select(&left_is_zero, &inner, &hash)?;
        }

        // The computed root must match the public revocation_root
        current.enforce_equal(revocation_root)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;
    use perseverus_core::dleq::dleq_prove_poseidon;
    use perseverus_core::h2c::token_base_point;
    use perseverus_core::nullifier::compute_nullifier;
    use perseverus_core::poseidon::poseidon_config as pcfg;
    use perseverus_core::smt::{SparseMerkleTree, revocation_key};

    /// Build a valid v9 circuit with all 6 constraints. Expect `is_satisfied`.
    ///
    /// Slow in debug (depth-16 SMT synthesis). Run with:
    /// `cargo test -p perseverus-circuits --release full_proof_valid -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn full_proof_valid() {
        let mut rng = ark_std::test_rng();

        // Server key
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;

        let cfg = pcfg();
        let seed = CircuitField::from(7u64);
        let pack_id_val: u64 = 12345;
        let pack_id_f = CircuitField::from(pack_id_val);
        let idx: usize = 3;
        let idx_f = CircuitField::from(idx as u64);
        let expiration_month: u32 = 202612;
        let current_month: u64 = 202604;

        // Derive base point (v6: includes pack_id)
        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;

        // Generate DLEQ proof
        let dleq_proof = dleq_prove_poseidon(&v, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);

        // Compute nullifier (v6: uses token_seed)
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        // Build revocation tree (empty — pack is NOT revoked)
        let smt = SparseMerkleTree::new();
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);
        let rev_root = smt.root();

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(current_month)),
            revocation_root: Some(rev_root),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(expiration_month as u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("synthesis failed");
        assert!(cs.is_satisfied().expect("is_satisfied failed"));
        eprintln!(
            "Full v9 circuit: {} constraints, {} witness vars, {} instance vars",
            cs.num_constraints(),
            cs.num_witness_variables(),
            cs.num_instance_variables(),
        );
    }

    /// Valid proof with a non-empty revocation tree (other packs revoked, but not ours).
    #[test]
    #[ignore]
    fn valid_with_other_packs_revoked() {
        let mut rng = ark_std::test_rng();
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;
        let cfg = pcfg();

        let seed = CircuitField::from(42u64);
        let pack_id_f = CircuitField::from(9999u64);
        let idx_f = CircuitField::from(0u64);
        let expiration_month: u32 = 202612;
        let current_month: u64 = 202604;

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;
        let dleq_proof = dleq_prove_poseidon(&v, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        // Insert OTHER packs into revocation tree
        let mut smt = SparseMerkleTree::new();
        for other_id in [100u64, 200, 300, 400, 500] {
            let key = revocation_key(&cfg, CircuitField::from(other_id));
            smt.insert(key);
        }

        // Our pack is NOT revoked
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);
        let rev_root = smt.root();

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(current_month)),
            revocation_root: Some(rev_root),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(expiration_month as u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("synthesis failed");
        assert!(cs.is_satisfied().expect("is_satisfied failed"));
    }

    /// Wrong nullifier → must fail.
    #[test]
    #[ignore]
    fn wrong_nullifier_rejected() {
        let mut rng = ark_std::test_rng();
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;
        let cfg = pcfg();

        let seed = CircuitField::from(1u64);
        let pack_id_f = CircuitField::from(42u64);
        let idx_f = CircuitField::from(0u64);

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;
        let dleq_proof = dleq_prove_poseidon(&v, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);

        let smt = SparseMerkleTree::new();
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);

        let circuit = RevocationSpendCircuit {
            nullifier: Some(CircuitField::from(999u64)), // bogus
            current_month: Some(CircuitField::from(202604u64)),
            revocation_root: Some(smt.root()),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(202612u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Expired token (current_month > expiration_month) → must fail.
    #[test]
    #[ignore]
    fn expired_token_rejected() {
        let mut rng = ark_std::test_rng();
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;
        let cfg = pcfg();

        let seed = CircuitField::from(1u64);
        let pack_id_f = CircuitField::from(42u64);
        let idx_f = CircuitField::from(0u64);
        let expiration_month: u32 = 202603; // expired!
        let current_month: u64 = 202604;    // current is later

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;
        let dleq_proof = dleq_prove_poseidon(&v, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        let smt = SparseMerkleTree::new();
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(current_month)),
            revocation_root: Some(smt.root()),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(expiration_month as u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "expired token must be rejected");
    }

    /// Wrong DLEQ proof (wrong server key) → must fail.
    #[test]
    #[ignore]
    fn wrong_dleq_rejected() {
        let mut rng = ark_std::test_rng();
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let v_wrong = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;
        let cfg = pcfg();

        let seed = CircuitField::from(1u64);
        let pack_id_f = CircuitField::from(42u64);
        let idx_f = CircuitField::from(0u64);

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;
        // Generate DLEQ proof with WRONG key
        let dleq_proof = dleq_prove_poseidon(&v_wrong, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        let smt = SparseMerkleTree::new();
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(202604u64)),
            revocation_root: Some(smt.root()),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(202612u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "wrong DLEQ must be rejected");
    }

    /// v10 soundness test: a revoked pack supplying a *different* pack's
    /// empty-leaf path bits must be rejected. Before v10 this would pass
    /// because path bits were unconstrained witnesses.
    #[test]
    #[ignore]
    fn revoked_pack_wrong_path_rejected() {
        let mut rng = ark_std::test_rng();
        let v = ark_ed_on_bn254::Fr::rand(&mut rng);
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * v;
        let cfg = pcfg();

        // Our pack (pack_id = 42) — this one gets revoked
        let seed = CircuitField::from(7u64);
        let pack_id_f = CircuitField::from(42u64);
        let idx_f = CircuitField::from(0u64);

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * v;
        let dleq_proof = dleq_prove_poseidon(&v, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        // Revoke our pack
        let mut smt = SparseMerkleTree::new();
        let our_key = revocation_key(&cfg, pack_id_f);
        smt.insert(our_key);

        // Get a proof for a DIFFERENT pack's (empty) leaf — this is the attack
        let other_pack_id = CircuitField::from(9999u64);
        let other_key = revocation_key(&cfg, other_pack_id);
        let stolen_proof = smt.prove_non_inclusion(other_key);

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(202604u64)),
            revocation_root: Some(smt.root()),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),       // our revoked pack
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(202612u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(stolen_proof.siblings),   // wrong pack's path!
            smt_path_bits: Some(stolen_proof.path_bits),  // wrong pack's bits!
        };

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "revoked pack using another pack's empty-leaf path must be rejected (v10 fix)"
        );
    }

    /// Quick constraint-count diagnostic.
    #[test]
    fn constraint_count() {
        let (nc, nw, ni) = RevocationSpendCircuit::measure_size();
        println!();
        println!("  ══════════════════════════════════════");
        println!("  RevocationSpendCircuit v9");
        println!("  ──────────────────────────────────────");
        println!("  Constraints:      {}", nc);
        println!("  Witness vars:     {}", nw);
        println!("  Instance vars:    {}", ni);
        println!("  Total vars:       {}", nw + ni);
        println!("  ══════════════════════════════════════");
        println!();
    }

    /// Diagnostic: load PK/VK from keys/ directory, generate a proof locally,
    /// and verify it. If this fails, the keys don't match the local circuit.
    ///
    /// Run with:
    /// ```bash
    /// cargo test -p perseverus-circuits --release prove_verify_with_key_files -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn prove_verify_with_key_files() {
        use ark_bn254::Bn254;
        use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
        use ark_snark::SNARK;
        use ark_serialize::CanonicalDeserialize;

        // Load keys from files (workspace root = parent of circuits/)
        let ws = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let pk_bytes = std::fs::read(ws.join("keys/pk.bin")).expect("keys/pk.bin not found");
        let vk_bytes = std::fs::read(ws.join("keys/vk.bin")).expect("keys/vk.bin not found");
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).expect("pk deserialize");
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).expect("vk deserialize");
        eprintln!("Loaded PK ({} bytes) and VK ({} bytes)", pk_bytes.len(), vk_bytes.len());

        // Load the real OPRF server key
        let key_bytes = std::fs::read(ws.join("keys/oprf_key.bin")).expect("keys/oprf_key.bin not found");
        let secret = ark_ed_on_bn254::Fr::deserialize_compressed(&key_bytes[..]).expect("oprf key deserialize");
        let g_bjj = EdwardsProjective::generator();
        let pk_server = g_bjj * secret;

        // Build a valid circuit with the real server key
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let cfg = pcfg();
        let seed = CircuitField::from(7u64);
        let pack_id_f = CircuitField::from(12345u64);
        let idx_f = CircuitField::from(3u64);

        let p_i = token_base_point(&cfg, seed, pack_id_f, idx_f);
        let sigma_i = p_i * secret;  // sign with real key
        let dleq_proof = dleq_prove_poseidon(&secret, &g_bjj, &pk_server, &p_i, &sigma_i, &mut rng);
        let null = compute_nullifier(&cfg, seed, pack_id_f, idx_f);

        let smt = SparseMerkleTree::new();
        let rev_key = revocation_key(&cfg, pack_id_f);
        let proof = smt.prove_non_inclusion(rev_key);

        let circuit = RevocationSpendCircuit {
            nullifier: Some(null),
            current_month: Some(CircuitField::from(202605u64)),
            revocation_root: Some(smt.root()),
            pk_server,
            token_seed: Some(seed),
            pack_id: Some(pack_id_f),
            token_index: Some(idx_f),
            blinded_sig: Some(sigma_i),
            dleq_c: Some(dleq_proof.challenge),
            dleq_s: Some(dleq_proof.response),
            expiration_month: Some(CircuitField::from(202612u64)),
            start_month: Some(CircuitField::from(202601u64)),
            smt_siblings: Some(proof.siblings),
            smt_path_bits: Some(proof.path_bits),
        };

        // Generate proof with the file PK
        eprintln!("Generating Groth16 proof...");
        let groth_proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
            .expect("Groth16::prove failed");
        eprintln!("Proof generated.");

        // Build public inputs
        let public_inputs = build_public_inputs(null, CircuitField::from(202605u64), CircuitField::from(0u64))
            .expect("public inputs");
        eprintln!("Public inputs: {}", public_inputs.len());

        // Verify with the file VK
        let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &groth_proof)
            .expect("verify call failed");

        if ok {
            eprintln!("✓ PROOF VERIFIED — keys match local circuit");
        } else {
            eprintln!("✗ PROOF REJECTED — keys do NOT match local circuit (cross-platform R1CS mismatch)");
        }
        assert!(ok, "Proof verification failed — PK/VK from key files don't match locally compiled circuit");

        // ── Save proof + public inputs to file for cross-platform verification ──
        use ark_serialize::CanonicalSerialize as CsEnc;
        let mut proof_buf = Vec::new();
        CsEnc::serialize_compressed(&groth_proof, &mut proof_buf).unwrap();

        let mut pi_hexes: Vec<String> = Vec::new();
        for pi in &public_inputs {
            let mut buf = Vec::new();
            CsEnc::serialize_compressed(pi, &mut buf).unwrap();
            let h: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
            pi_hexes.push(h);
        }
        let proof_hex: String = proof_buf.iter().map(|b| format!("{:02x}", b)).collect();

        let cross_plat = format!(
            "proof_hex={}\nnullifier_hex={}\ncurrent_month_hex={}\nrevocation_root_hex={}\n",
            proof_hex, pi_hexes[0], pi_hexes[1], pi_hexes[2],
        );
        let out_path = ws.join("keys/cross_platform_proof.txt");
        std::fs::write(&out_path, &cross_plat).unwrap();
        eprintln!("Saved cross-platform proof to {:?}", out_path);

        // Also verify the serialization round-trip locally
        let proof_rt = ark_groth16::Proof::<Bn254>::deserialize_compressed(&proof_buf[..]).unwrap();
        let ok_rt = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof_rt).unwrap();
        assert!(ok_rt, "Serialization round-trip broke the proof!");
        eprintln!("✓ Serialization round-trip verified OK");
    }

    /// Cross-platform verify: load a proof generated on another platform and verify it.
    ///
    /// Run with:
    /// ```bash
    /// cargo test -p perseverus-circuits --release cross_platform_verify -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn cross_platform_verify() {
        use ark_bn254::Bn254;
        use ark_groth16::{Groth16, VerifyingKey};
        use ark_snark::SNARK;
        use ark_serialize::CanonicalDeserialize;

        fn from_hex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
                .collect()
        }

        let ws = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let vk_bytes = std::fs::read(ws.join("keys/vk.bin")).expect("keys/vk.bin not found");
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).expect("vk deserialize");

        let content = std::fs::read_to_string(ws.join("keys/cross_platform_proof.txt"))
            .expect("keys/cross_platform_proof.txt not found — run prove_verify_with_key_files first");

        let mut proof_hex = String::new();
        let mut null_hex = String::new();
        let mut cm_hex = String::new();
        let mut root_hex = String::new();
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("proof_hex=") { proof_hex = v.to_string(); }
            if let Some(v) = line.strip_prefix("nullifier_hex=") { null_hex = v.to_string(); }
            if let Some(v) = line.strip_prefix("current_month_hex=") { cm_hex = v.to_string(); }
            if let Some(v) = line.strip_prefix("revocation_root_hex=") { root_hex = v.to_string(); }
        }

        let proof_bytes = from_hex(&proof_hex);
        let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]).unwrap();
        eprintln!("Loaded proof: {} bytes", proof_bytes.len());

        let null_bytes = from_hex(&null_hex);
        let nullifier = CircuitField::deserialize_compressed(&null_bytes[..]).unwrap();
        let cm_bytes = from_hex(&cm_hex);
        let current_month = CircuitField::deserialize_compressed(&cm_bytes[..]).unwrap();
        let root_bytes = from_hex(&root_hex);
        let revocation_root = CircuitField::deserialize_compressed(&root_bytes[..]).unwrap();

        let public_inputs = build_public_inputs(nullifier, current_month, revocation_root).unwrap();
        eprintln!("Public inputs: {}", public_inputs.len());

        let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).expect("verify call failed");
        if ok {
            eprintln!("✓ CROSS-PLATFORM PROOF VERIFIED — macOS proof verifies on this platform");
        } else {
            eprintln!("✗ CROSS-PLATFORM PROOF REJECTED — proof from other platform does NOT verify here");
        }
        assert!(ok, "Cross-platform verification failed!");
    }


}
