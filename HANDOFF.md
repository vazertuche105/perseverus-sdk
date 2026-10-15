# Handoff: perseverus-sdk

*Written 2026-10-13. Read this, then `docs/blueberry-v1/README.md` and `sdk/README.md`.*

## The project

BTC Medusa tells a wallet how exposed its coins are to chain analysis, using findings from the open-source [am-i-exposed](https://github.com/Copexit/am-i-exposed) engine, **without the server learning which coins were asked about**.

1. The server publishes one encrypted filter per block. Each transaction's findings are compressed to a 24-bit **v3-lean tag**, encrypted under a key that only an **OPRF** evaluation (Baby Jubjub over BN254) can recover.
2. The wallet downloads filters for its real blocks mixed with **Laplace decoys**, and matches its transaction locally.
3. To decrypt a match, the wallet spends one **anonymous token**. Tokens are blind-signed in packs, so a purchase can't be linked to a query, and each one is spent with a **Groth16 proof** carrying a nullifier, so one query can't be linked to another.

**Goal:** an SDK that BlueWallet's privacy wallet **Blueberry** ([Kotlin Multiplatform](https://github.com/BlueWallet/Blueberry.kmp)) can call to check a transaction's inputs before broadcast. Tokens are spent per funding transaction.

## Status

**Done and tested**
- `sdk/` API: `connect`, `buyTokens` (Lightning trial and onetime, card onetime, monthly and yearly), `addPurchase`, `purchaseStatus`, `redeem` (returns a list of packs), `tokenBalance`, `listPacks`, `importPack`, `analyzeInputs`. Kotlin bindings live in package `com.btcmedusa.perseverus`.
- Report text is generated from `docs/blueberry-v1/findings-catalog.v3lean.json`. It matches the reference wallet's renderer exactly; the parity test covers 500 tags.
- The full analysis pipeline has been tested end to end against a real server: decoys, local match, ungraded and not-covered inputs, one token per funding transaction, batched spend, DLEQ verification, and already-spent tokens. That test needs the private server code, so it isn't in this repo.
- `sdk/examples/kotlin-jvm` runs on macOS (Apple silicon, JDK 25, Gradle 9.1): `status` works and `import-sparrow` imports packs.

**Not yet verified:** `analyze` against the live server on a real coin, and the Lightning and card purchase flows through the SDK.

## Things that are easy to get wrong

1. **v5 filters are keyed per transaction (txid), not per outpoint.** The OPRF input is the 32-byte funding txid in internal byte order. The SDK tries both byte orders. One token covers all inputs that come from the same funding transaction.
2. **The server never builds missing filters.** Missing heights become `NOT_COVERED` reports, and no token is spent.
3. **Codebook:** a decrypted value is an index into `GET /codebook` (PSCB format). Check the filter's `codebook_id` before decoding.
4. **OHTTP in `client-native/src/transport.rs` is a stub that connects directly.** The SDK only exposes Tor (fails closed) or Direct (development).
5. **Never add a "tag for txid X" endpoint or call.** It destroys query privacy.
6. **Token accounting:** a token is marked used before its spend request goes out. A per-entry rejection returns it to the pool, unless the server says it's already spent (409), in which case it stays used.

## Next steps, in order

1. ~~Verify `analyze` on a real coin.~~ Done 2026-10-14: real mainnet coin against production, grade D (peel chain), 1 token, 3.3 s.
2. ~~Server `/v1` API, then switch the SDK to `/v1`.~~ Done 2026-10-14. The server serves `/v1` (contract: `docs/blueberry-v1/openapi.yaml`) and the SDK uses only `/v1`. The card yearly plan (13 packs) is supported.
3. **Developer documentation** in `docs/`, written for a wallet developer who has never seen this project:
   - **SDK guide:** every function and type, with what it does, *why* it exists (including the privacy reason), when to call it, a Kotlin example, its errors and how to handle them, and what the server can and can't see.
   - **5-minute quickstart** and walkthroughs: buying tokens, pre-broadcast analysis, showing ungraded / not-covered / error results.
   - **`PrivacyReport` field guide:** every grade, status and finding explained.
   - **HTTP `/v1` reference:** each endpoint's purpose, request and response with real examples, and errors (the server's tests record real exchanges with `V1_EXAMPLES_DIR`).
   - **Privacy and threat model** in plain language, plus troubleshooting.
   - **Build instructions for integrators:** how to compile the SDK for Android (`cargo-ndk`) and iOS (XCFramework via `uniffi-bindgen --language swift`). Integrators build and ship the native library themselves; we don't publish binaries.
4. **SDK features:** BTC silent-payment purchase, a redeem retry that survives an app restart (persist the prepared blinded packs), a progress callback (`#[uniffi::export(with_foreign)]` trait), and async variants.

**Open questions for BlueWallet:** inputs as a PSBT or as outpoints plus heights (the SDK takes outpoints plus heights today); decoy default and bandwidth budget; which block range must have filters; payment methods at launch; how the SDK is licensed and published.

## Rules for contributors

- No secrets in commits. The SDK needs none.
- Don't change the pack blob format (`client-native/src/pack_blob.rs`); it's shared with the reference wallet.
- Report wording comes only from the findings catalog. Don't hard-code strings.
- Server-side changes go through the project owner; the server isn't in this repo.

## Starting a Claude session

> Read `HANDOFF.md`, `docs/blueberry-v1/README.md` and `sdk/README.md`. Run `cargo test --workspace` to confirm the baseline. Our next task is: *[pick from Next steps]*. Never add an API that sends a txid or outpoint to the server.

**Owner:** Valentino Zertuche (`vazertuche105`). **Point of contact:** *[fill in]*
