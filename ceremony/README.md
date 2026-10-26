# perseverus-ceremony

Multi-party setup for the v11 spend circuit. It produces the `pk.bin` (shipped in
every wallet) and `vk.bin` (on the server) that spend proofs use.

## Why

A Groth16 key pair comes from a one-time setup with secret random values. Whoever
knows them can do two things:

1. **Forge spends.** Proofs that verify without a real token: free checks, and a
   way around the per-token limit on how much of the grade database one wallet
   can read.
2. **Ship a backdoored `pk.bin`.** A malformed proving key can make proofs leak or
   link the token secrets, which would tie a user's checks to the purchase of
   their tokens. A normal proof verification does not notice.

With a single-party setup, everyone has to trust that party (us) on both. With
this ceremony:

- **Forging** needs the secrets of *every* participant. If one participant
  discarded theirs, nobody can forge.
- **A backdoor is impossible** for keys that pass `verify`. `verify` rebuilds the
  keys' fixed part from public data and checks every step. Keys that pass are
  honest Groth16 keys for this circuit, so proofs reveal nothing about the token.

What it does not change: the server still holds the OPRF key and issues tokens,
and which coins a wallet checks stays hidden by blinding, decoys and Tor, exactly
as before.

## How it works

| Stage | What | Who |
|---|---|---|
| Phase 1 (any circuit) | Public Powers of Tau file: 54 contributions plus a random beacon, by the Hermez/Polygon ceremony, on top of the Perpetual Powers of Tau | Already done; we only download and check it |
| `init` | Phase 1 + our circuit → `round0.params`. Deterministic, no secrets | Perseverus (anyone can redo it) |
| `contribute` | Multiply δ by a fresh secret k, divide the H and L queries by k, publish a proof of knowing k, wipe k | Perseverus, then BlueWallet, then anyone else |
| `verify` | Redo `init`; check that only δ changed, every proof of knowledge, the chain of δ's, and the H/L division | Everyone, especially each participant |
| `export` | `verify`, then write `pk.bin` and `vk.bin` | Perseverus |

This is the Bowe–Gabizon–Miers scheme used by Zcash Sapling, written for
arkworks so the output is the `ProvingKey<Bn254>` the SDK already loads.

The server's public key is a constant inside the circuit. So the ceremony is for
one server key: rotating the OPRF key again means running a new ceremony.

## Phase 1 file

`powersOfTau28_hez_final_15.ptau` (2^15 rows; the v11 circuit needs 23,084
constraints plus 4 public-input rows, so 2^15 = 32,768).

```
URL      https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
blake2b  982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e
```

The hash is the one published in the snarkjs README (github.com/iden3/snarkjs,
"Prepared (phase2) Ptau files"). `init` and `verify` print the file's blake2b; it
must match. Any `.ptau` with power 15 or more for BN254 works (for example
`_16`), but every participant must use the same file. The params file records a
digest of the exact points used, and `verify` refuses a different phase 1.

## Build

From this repository at the release tag:

```bash
cargo build --release -p perseverus-ceremony
B=target/release/perseverus-ceremony
```

A recent stable Rust (tested with 1.97). The tool is about 1,200 lines (`ceremony/src`), short enough to
read before running.

## Running the ceremony

`SERVER_PUBKEY` is the production server key (`GET /v1/meta` →
`server_pubkey_hex`).

### 1. Perseverus: start, and contribute first

```bash
curl -LO https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
$B init       --ptau powersOfTau28_hez_final_15.ptau --server-pubkey $SERVER_PUBKEY --out round0.params
$B contribute --in round0.params --out round1.params
```

`contribute` prints a **receipt** (64 hex characters). Post it publicly, then send
`round1.params` (about 9 MB) to the next participant.

### 2. Each other participant (BlueWallet first)

```bash
# optional but recommended: confirm you are building on a valid chain (about 2 min)
$B verify --ptau powersOfTau28_hez_final_15.ptau --server-pubkey $SERVER_PUBKEY --params round1.params

# your contribution (seconds)
$B contribute --in round1.params --out round2.params
```

- The secret comes from the operating system's random generator. Add
  `--entropy "anything you like"` to mix in your own as well.
- The secret is only ever in memory and is overwritten before the command exits.
  Nothing secret is written to disk.
- Post your receipt publicly and send `round2.params` back.

### 3. Perseverus: export

```bash
$B export --ptau powersOfTau28_hez_final_15.ptau --server-pubkey $SERVER_PUBKEY \
          --params round2.params --out-dir final
```

Publish `round2.params` (the final one), the list of receipts, and the
`pk.bin` / `vk.bin` hashes it prints.

### 4. Everyone: check the result

```bash
$B verify --ptau powersOfTau28_hez_final_15.ptau --server-pubkey $SERVER_PUBKEY \
          --params round2.params --expect YOUR_RECEIPT
```

It must end with `RESULT: VALID`, list your receipt, and print:

- `pk.bin sha256` equal to the `pk.bin` in the SDK release
  (`assets/circuit-v11/pk.bin.sha256`);
- `vk.bin sha256` equal to `circuit.vk_sha256` at `GET /v1/meta` on the
  production server.

## Rolling out the ceremony keys

Only `pk.bin` and `vk.bin` change. The OPRF key, the filters and every token
already sold stay as they are. Proofs are made at spend time, so old tokens work
with the new key.

1. Server: install the new `vk.bin` and restart. That's about a minute offline.
2. SDK: new release with the new `assets/circuit-v11/pk.bin`.
3. Sparrow and wallets: ship the new `pk.bin`.

Until a wallet updates, its spends fail to verify (it holds the old `pk.bin`), so
do steps 1 and 2 together and before wallets launch publicly.

## Timings

Measured on a 2-core cloud machine:

| Command | Time |
|---|---|
| `init`, `verify`, `export` | about 2 minutes (most of it rebuilding the starting parameters; faster with more cores) |
| `contribute` | about 5 seconds |

The params files are about 9 MB each.

## Tests

```bash
cargo test --release -p perseverus-ceremony
```

- **Matches arkworks.** The starting parameters are byte-for-byte what arkworks'
  own Groth16 setup produces for the same τ, α, β, using a test phase 1 with
  known values.
- **Real spends work.** Proofs made with exported ceremony keys verify, and a
  proof that lies about its expiry does not.
- **Tampering is caught.** `verify` rejects all of these:
  - no contributions yet;
  - a changed A query, public-input query, H query, L query or α;
  - a contribution without a valid proof of knowledge;
  - a contribution removed from the chain;
  - a coordinator who sets δ to a value they know;
  - parameters for a different server key;
  - a phase 1 file with out-of-order powers.
- **Works with real snarkjs files.**
  `PERSEVERUS_TEST_PTAU=file.ptau cargo test --release -p perseverus-ceremony real_ptau -- --ignored`
  runs the whole flow on a real `.ptau`. It passes on a snarkjs-generated file.
