# Perseverus ZK-SNARK Circuit Specification — v10 (v11 changes below)

## v11 changes (draft, security review F1 + F12)

v11 keeps the three public inputs `(nullifier, current_month, revocation_root)` and changes three things. Both need a new trusted setup; do them in one.

1. **Validity months are signed (F1).** In v10, `expiration_month` and `start_month` were witnesses used only in the range checks, so a prover could claim any months and pass ④⑤. In v11 the server signs the dated point

   `Q_i = P_i + expiration_month·H_EXP + start_month·H_START`

   with months it chooses from the plan that was paid for (`H_EXP`, `H_START` are new NUMS points, `core/src/h2c.rs`). The DLEQ ③ proves `σ_i = v·Q_i`, and the circuit rebuilds `Q_i` from the witness months, each range-checked to 18 bits. A prover claiming other months gets a different `Q_i` and the DLEQ fails.
2. **Nullifier is domain-separated (F12).** In v10, `nullifier = Poseidon(seed, pack_id, idx)` was the same scalar `s` as in `P_i = s·H_TOKEN`, and the server sees `P_i` at issuance, so `nullifier·H_TOKEN == P_i` linked every spend to its purchase. In v11, `nullifier = Poseidon(NULLIFIER_TAG, seed, pack_id, idx)` (`core/src/nullifier.rs`).

3. **DLEQ transcripts bind the whole statement (F9).** The Poseidon challenge is now `Poseidon(TAG, PK, Q_i, σ_i, R1, R2)` (was `Poseidon(PK, σ_i, R1, R2)`), and the SHA-256 DLEQ used for OPRF answers hashes `DST || G || V || α || β || R1 || R2`, with batch coefficients derived from one seed over the whole batch. Clients and server must update together, which the v11 key rotation forces anyway.

Issuance response gains `sigmas` (`σ_i = v·Q_i`), `expiration_month` and `start_month`; the wallet verifies each Poseidon DLEQ against the `Q_i` it rebuilds itself and keeps the server's months (it does not compare them with its own clock, which can differ at a month boundary). The server must also check `current_month` against its own clock at spend time (review F13); that is a server change, not a circuit one.

Measured on a 2-core cloud machine: **23,084 constraints (v10: 20,670), setup 1.1 s, proving key 4.4 MB, one proof 1.0 s** (`cargo run --release -p perseverus-circuits --example setup_bench`).


## Overview

A Groth16 zk-SNARK on BN254 that proves a wallet holds a legitimately-issued, non-revoked, active token — without revealing which token it is. Each proof burns a one-time nullifier, enabling privacy-preserving rate-limited access to encrypted block filters.

**Proving system**: Groth16 (trusted setup, constant-size proofs)
**Pairing curve**: BN254 (alt_bn128)
**In-circuit arithmetic curve**: BabyJubJub (twisted Edwards embedded in BN254's scalar field)
**Hash function**: Poseidon-2 sponge over Fr(BN254)
**Constraint count**: ~22,153 R1CS constraints
**Proof size**: 3 G1 + 1 G2 elements (~128 bytes compressed)
**Verification**: 1 pairing check (constant time, ~2ms)
**Proving time**: ~280ms per proof (Apple M-series, release build)

---

## Algebraic Setting

| Symbol | Definition |
|--------|-----------|
| Fr(BN254) | Scalar field of BN254, ~254-bit prime. This is the R1CS constraint field. |
| Fr(BJJ) | Scalar field of BabyJubJub. |Fr(BJJ)| < |Fr(BN254)|, so BJJ scalars embed losslessly. |
| Fq(BJJ) | Base field of BabyJubJub = Fr(BN254). BJJ point coordinates are native field elements. |
| G | BabyJubJub generator (fixed, well-known) |
| H_TOKEN | Nothing-up-my-sleeve BabyJubJub point, derived via try-and-increment H2C with DST `"perseverus-h-token-v1"` |

**Key property**: Since Fq(BabyJubJub) = Fr(BN254), all BabyJubJub point arithmetic (addition, scalar multiplication) is native field arithmetic in the circuit — no non-native field simulation is needed. This keeps constraint counts low.

---

## Statement

A prover holds a token `(P_i, σ_i)` where `σ_i = v · P_i` (server-signed via OPRF). The circuit proves all of the following without revealing `P_i`, `σ_i`, or any identifying information:

1. **Base-point derivation**: The prover knows `(token_seed, pack_id, token_index)` such that `P_i = Poseidon(seed, pack_id, idx) · H_TOKEN`
2. **DLEQ signature**: `σ_i = v · P_i` — the token was legitimately signed by the server (verified via Chaum-Pedersen with Poseidon Fiat-Shamir)
3. **Nullifier binding**: `nullifier = Poseidon(token_seed, pack_id, token_index)` — correctly computed
4. **Non-expiration**: `expiration_month ≥ current_month`
5. **Activation**: `start_month ≤ current_month`
6. **Non-revocation**: The pack's revocation key is NOT in the depth-16 Sparse Merkle Tree

---

## Inputs and Witnesses

### Public Inputs (3 field elements)

Allocation order defines the Groth16 public-input vector layout. **Order is critical** — must match across circuit, prover, and verifier:

| # | Name | Type | Description |
|---|------|------|-------------|
| 1 | `nullifier` | Fr(BN254) | One-shot spend tag. Burned on use to prevent double-spending. |
| 2 | `current_month` | Fr(BN254) | Global epoch in YYYYMM format (e.g., 202605). Set by server. |
| 3 | `revocation_root` | Fr(BN254) | Root of the depth-16 Sparse Merkle Tree (server-authoritative). |

### Constants (baked into R1CS at trusted setup)

| Name | Type | Description |
|------|------|-------------|
| `pk_server` | EdwardsProjective | Server's OPRF public key V = v·G. Fixed at ceremony time. Key rotation via FROST threshold sharing (aggregate key stays constant, shares refresh). |
| `G` | EdwardsProjective | BabyJubJub generator. |
| `H_TOKEN` | EdwardsProjective | NUMS base point for token derivation. |

**Why pk_server is a constant, not a public input**: Variable-base scalar multiplication on a public-input point creates deep linear-combination chains (~253 levels) that cause arkworks' `inline_all_lcs()` to consume ~47 GB RAM during Groth16 trusted setup. As a constant, the scalar mul is fixed-base (shallow LCs, ~1–2 GB setup). Trade-off: changing the server key requires a new ceremony.

### Witnesses (private inputs)

| Name | Type | Description |
|------|------|-------------|
| `token_seed` | Fr(BN254) | Per-pack random scalar. Wallet secret, never leaves device. |
| `pack_id` | Fr(BN254) | Random pack identifier (u64, cast to field). |
| `token_index` | Fr(BN254) | Which token in the pack (0..pack_size). |
| `blinded_sig` (σ_i) | EdwardsProjective | Server-signed point σ_i = v · P_i (2 field elements: x, y). |
| `dleq_c` | Fr(BN254) | DLEQ challenge scalar (Poseidon Fiat-Shamir output). |
| `dleq_s` | Fr(BN254) | DLEQ response scalar. |
| `expiration_month` | Fr(BN254) | Pack expiration in YYYYMM format. |
| `start_month` | Fr(BN254) | Pack activation epoch in YYYYMM format. |
| `smt_siblings[16]` | [Fr(BN254); 16] | SMT authentication path sibling hashes. |
| `smt_path_bits[16]` | [bool; 16] | SMT path direction bits (left=0, right=1). |

### Derived In-Circuit (not passed as inputs)

| Name | Derivation |
|------|-----------|
| `P_i` | `Poseidon(token_seed, pack_id, token_index) · H_TOKEN` |
| `revocation_key` | Used implicitly — the path bits determine the tree position |

---

## Constraint Groups (6 total, ~22,153 constraints)

### ① Base-Point Derivation (~4,500 constraints)

Derives the token's base point deterministically from the wallet's secrets:

```
s = Poseidon(token_seed, pack_id, token_index)
P_i = s · H_TOKEN
```

- Poseidon sponge: absorb 3 elements, squeeze 1 (~1,200 constraints)
- Fixed-base scalar multiplication of s over H_TOKEN: bit decomposition (254 bits) + conditional adds (~3,300 constraints)

**v6 change**: `pack_id` added to the hash input (v4 only used seed + index). Defense-in-depth against two packs with the same seed producing identical base points.

### ② Nullifier Binding (~1,200 constraints)

Enforces the nullifier is correctly derived:

```
expected = Poseidon(token_seed, pack_id, token_index)
enforce: nullifier == expected
```

- Poseidon sponge: absorb 3 elements, squeeze 1
- 1 equality constraint

The absorb order MUST match the out-of-circuit `compute_nullifier()` function exactly.

### ③ DLEQ Signature Verification (~6,000 constraints)

Proves σ_i = v · P_i using Chaum-Pedersen with Poseidon Fiat-Shamir. This is the most expensive constraint group.

**Verification equation:**
```
R1' = s·G - c·PK_server
R2' = s·P_i - c·σ_i
c'  = Poseidon(PK.x, PK.y, σ.x, σ.y, R1'.x, R1'.y, R2'.x, R2'.y)
enforce: c == c'
```

**Costs:**
- `s·G`: fixed-base scalar mul (~1,200 constraints — G is constant)
- `c·PK_server`: fixed-base scalar mul (~1,200 constraints — PK is constant)
- `s·P_i`: variable-base scalar mul (~1,500 constraints — P_i is a witness)
- `c·σ_i`: variable-base scalar mul (~1,500 constraints — σ_i is a witness)
- 2 point subtractions: ~10 constraints each
- Poseidon(8 elements): ~1,200 constraints
- 1 equality constraint

**Field arithmetic note**: The challenge `c` and response `s` are Fr(BN254) values. The actual scalar multiplication uses these as 254-bit integers over the BabyJubJub group. Since |Fr(BJJ)| < |Fr(BN254)|, the BJJ scalar is embedded losslessly in the BN254 field element via `from_le_bytes_mod_order`.

### ④ Expiration Check (~254 constraints)

Proves the token pack has not expired:

```
diff = expiration_month - current_month
enforce: diff fits in 18 bits (i.e., diff ∈ [0, 2^18))
```

- 1 field subtraction
- Bit decomposition to 254 bits (~254 constraints for Boolean allocation)
- Enforce bits 18..253 are all zero

**18-bit range check**: Supports values up to 262,143. Since months are in YYYYMM format (max ~999912), 18 bits is more than sufficient to prove non-negativity.

### ⑤ Activation Check (~254 constraints)

Proves the token pack has activated (is not being used before its start date):

```
diff = current_month - start_month
enforce: diff fits in 18 bits (i.e., diff ∈ [0, 2^18))
```

Identical structure to the expiration check, with operands swapped. Enables yearly prepaid subscriptions where each monthly pack activates only in its designated epoch.

### ⑥ SMT Non-Inclusion (~7,700 constraints)

Proves the pack has not been revoked by showing its position in the Sparse Merkle Tree is empty.

**Algorithm:**
```
1. Compute revocation_key = Poseidon(pack_id)
2. Decompose revocation_key to bits; enforce path_bits[0..16] == key_bits[0..16]
3. Start with current = 0 (empty leaf — "not present")
4. For each level i in 0..16 (leaf to root):
   a. Select (left, right) based on path_bits[i]:
      - If bit=0: left=current, right=sibling[i]
      - If bit=1: left=sibling[i], right=current
   b. Compute hash = Poseidon(left, right)
   c. Optimization: if both children are zero, parent is zero
      left_is_zero = (left == 0)
      right_is_zero = (right == 0)
      inner = right_is_zero ? 0 : hash
      current = left_is_zero ? inner : hash
5. Enforce: current == revocation_root
```

**v10 soundness fix (step 2):** Without binding the path bits to `Poseidon(pack_id)`, a revoked pack could supply path bits pointing to a *different* empty leaf and bypass revocation. The path bits are witness values — the prover can set them to anything unless explicitly constrained.

**Path binding (~1,200 constraints):**
- 1 Poseidon(1 element) (~1,200 constraints for key derivation)
- Bit decomposition (254 bits, reuses `to_bits_le`)
- 16 equality constraints (one per SMT level)

**Per level (~540 constraints × 16 levels):**
- 2 conditional selects (~4 constraints each)
- 1 Poseidon(2 elements) (~243 constraints)
- 2 equality comparisons with zero (~2 constraints each)
- 2 conditional selects for the optimization (~4 constraints each)

**Total**: ~9,860 constraints (path binding + 16 levels + 1 final equality).

---

## Hash Function: Poseidon-2

All hash operations use identical parameters:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Field | Fr(BN254), ~254-bit prime | Native to BN254 R1CS |
| State width | 3 (rate=2, capacity=1) | Sufficient for 2-to-1 CRH |
| Full rounds | 8 (4 start + 4 end) | Standard security margin |
| Partial rounds | 57 | Grassi et al. for 128-bit security on ~254-bit field |
| S-box (α) | x⁵ | gcd(5, p−1) = 1 for Fr(BN254) |
| Round constants | Deterministic from `find_poseidon_ark_and_mds(254, 2, 8, 57, 0)` | Reproducible across builds |
| MDS matrix | 3×3, from same derivation | Cauchy matrix construction |

---

## Sparse Merkle Tree

| Parameter | Value |
|-----------|-------|
| Depth | 16 |
| Leaf positions | 2^16 = 65,536 |
| Empty hash | 0 (field zero) |
| Internal node | `Poseidon(left, right)` (or 0 if both children are 0) |
| Key derivation | `Poseidon(pack_id)`, truncated to 16 bits for path |
| Collision handling | Server rejects issuance if path collides with existing entry |

**Capacity**: 65,536 leaf positions. At 100 revocations/month, this covers ~54 years.

---

## Trusted Setup

**Type**: Per-circuit Groth16 setup (single ceremony, toxic waste)

**Inputs to ceremony:**
- The full R1CS (circuit structure including baked-in `pk_server`)
- Random toxic waste τ (must be destroyed after ceremony)

**Outputs:**
- `pk.bin`: Compressed ProvingKey<Bn254> (~3.8 MB for v9)
- `vk.bin`: Compressed VerifyingKey<Bn254> (~360 bytes)

**Key binding**: The proving/verifying keys are bound to a specific `pk_server` value. Changing the server's OPRF key requires a new ceremony.

**Key rotation**: Handled via FROST threshold secret sharing. The aggregate public key stays constant (no new ceremony needed) while individual secret shares can be refreshed among threshold participants.

**Resource requirements**: ~800 GB RAM, ~6 hours (observed on large-memory cloud instance).

---

## Wire Format

### Proof submission (client → server)

```json
{
  "blinded_points": ["<hex: compressed G1 affine>"],
  "spend": {
    "nullifier_hex": "<hex: 32-byte compressed Fr>",
    "current_month": 202605,
    "revocation_root_hex": "<hex: 32-byte compressed Fr>",
    "proof_hex": "<hex: ~128-byte compressed Groth16 proof>"
  }
}
```

### Verification (server-side)

1. Decode `nullifier`, `current_month`, `revocation_root` from wire
2. Cross-check `revocation_root` against server's authoritative SMT root (reject if mismatch)
3. Build public inputs vector: `[nullifier, Fr::from(current_month), revocation_root]`
4. Deserialize compressed Groth16 proof
5. `Groth16::verify(vk, &public_inputs, &proof)` → accept/reject
6. If accepted: burn nullifier in persistent ledger (sled DB), proceed with OPRF evaluation

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Anonymity** | ZK proof reveals nothing about which token is being spent |
| **Unlinkability** | Fresh nullifier per spend; no correlation between spends from same pack |
| **Double-spend prevention** | Server stores burned nullifiers persistently; rejects duplicates |
| **Revocation** | Server inserts pack's revocation key into SMT; future proofs fail constraint ⑥ |
| **Expiration** | Constraint ④ rejects tokens past their expiration month |
| **Activation gating** | Constraint ⑤ prevents early use of future-dated packs |
| **Forgery resistance** | DLEQ proof (constraint ③) requires knowledge of a valid server signature |
| **Soundness** | Groth16 knowledge-soundness under q-PKE assumption on BN254 |

---

## Version History

| Version | Changes |
|---------|---------|
| v4 | Initial: Pedersen commitment + board Merkle + DLEQ + expiration + alpha binding |
| v6 | Removed Pedersen/board/alpha. Added SMT non-inclusion. Nullifier uses token_seed. Base point includes pack_id. |
| v7 | Moved pk_server from constant to public input (caused 47 GB setup blowup — reverted in v8) |
| v8 | Reverted pk_server to constant. Reduced SMT depth 256→32→12 (later increased to 16 in v10). FROST for key rotation. |
| v9 | Added start_month witness + activation check. Enables monthly pack scheduling for yearly subscriptions. |
| v10 | **Soundness fix**: SMT path bits now constrained to match `Poseidon(pack_id)` bits. Closes gap where revoked pack could prove non-inclusion at a different empty leaf. SMT depth increased 12→16 (65,536 leaf positions). |
