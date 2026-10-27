# 9. Troubleshooting

Find the message you're seeing. In Kotlin, `e.message` prints as `reason=…` or `status=…, reason=…`; the part after `reason=` is what's listed here.

## Connecting

| You see | Cause | Fix |
|---|---|---|
| `Network`: `… error sending request …`, `connection refused`, `proxy` | Tor isn't running, or isn't at the SOCKS address you gave. | Start Tor or wait until it reports ready. Check `socksProxy`; the default is `socks5h://127.0.0.1:9050`. On desktop, test with `curl --socks5-hostname 127.0.0.1:9050 http://medusayl5…had.onion/v1/meta`. |
| `Network`: `… error connecting to socks proxy: … failed to create underlying connection` | Nothing is listening at the SOCKS address (Tor not running, or on another port such as Tor Browser's 9150), or the SDK was built with `--no-default-features`. | Start Tor (`brew services start tor`) and test it with the `curl` above. Rebuild with default features. |
| `Network`: timeouts, or slow first call | Building a new Tor circuit to an onion service takes a few seconds, sometimes more on mobile. | Retry. The first call after Tor starts is often the slowest. |
| `InvalidArgument`: `Transport.Direct is only allowed for a server on this machine…` | `Transport.Direct` with a remote server (production, or a dev server on another host). | Use `Transport.Tor` with the `.onion` endpoint. `Direct` is only for a server on `localhost`. |
| `Verification`: `server pubkey … does not match pinned …` | You're talking to a different server, or the pinned key has a typo. | Check `endpoint` and the key (`64194625…d695`). **Don't** turn off pinning to make it go away. |
| `Unsupported`: `server API … is not 1.x` / `older than the server's minimum` | The SDK version and server version are incompatible. | Update the SDK to a current commit and rebuild. |
| `Storage`: `create …` / `write …` | `dataDir` isn't writable. | Use app-private storage (`context.filesDir`). |
| `Storage`: `unsupported store version` | The store was written by a newer SDK. | Don't downgrade the SDK over existing data. |

## Buying and redeeming

| You see | Cause | Fix |
|---|---|---|
| `Server` 400 `bad_request: plan "trial" is not available by card…` | Invalid method/plan combination. | See the table in [`buyTokens`](03-sdk-reference.md#buytokens). |
| `Server` 403 `plan_unavailable: the dev plan is only sold by test servers…` | `Plan.DEV` asked of a server that doesn't sell it (production never does). | Use `TRIAL` or `ONETIME`; keep `DEV` out of release builds. |
| `Server` 503 `not_configured: …` | That payment method is turned off on the server. | Hide that option. `GET /v1/meta` → `payment_methods` lists what's enabled. |
| `Server` 503 `upstream_unavailable: BTC price feed unavailable…` | The server couldn't price the Lightning invoice. | Retry in a minute. |
| `Server` 402 `payment_required` on `redeem` | Not paid yet, or the card webhook hasn't arrived. | Keep polling `purchaseStatus` until `PAID`. |
| `InvalidArgument`: `unknown purchase …` on `redeem` | The id isn't in this device's pending list. | `addPurchase(id, plan)` first. |
| `Server` 404 `not_found: unknown or already-redeemed purchase_id` | Already redeemed (card ids vanish after redemption), or a wrong id. | Check `listPacks()`; the packs are probably already there. |
| `Server` 400 `this code's plan (onetime) allows 1 pack(s), 13 requested` | `addPurchase` was called with `YEARLY` for a one-time purchase. | Use the plan that was actually bought. |
| `PurchaseState.EXPIRED` | The Lightning invoice expired unpaid. | Start a new purchase. |

## Analysing

| You see | Cause | Fix |
|---|---|---|
| `InvalidArgument`: `… has no block height (unconfirmed inputs cannot be analysed)` | `blockHeight = 0`. | Leave unconfirmed inputs out of the list. |
| `InvalidArgument`: `txid … is not 32 bytes` / hex error | Not a 64-character hex txid. | Pass the funding txid in explorer order. |
| `InvalidArgument`: `proving key …: No such file` / `is not a valid pk.bin` | `provingKeyPath` is wrong, or the file is corrupt or truncated. | Copy `pk.bin` from assets and check its SHA-256 (`2f59e8…2483`). |
| `Server` 404 `not_found: this server does not serve the proving key…` | `provingKeyPath = null` against production. | Ship `pk.bin` and set `provingKeyPath`. |
| `InsufficientTokens(needed, available)` | Not enough **active** tokens. Packs from a yearly plan that haven't started don't count, and neither do revoked packs (`PackInfo.revoked`, after a card chargeback). | Buy tokens. Nothing was spent. |
| Every input `UNGRADED` | Normal for dust, OP_RETURN, ordinal, runes and Counterparty/Omni transactions. Also if you passed the **spending** txid instead of the **funding** txid, or the wrong height for the funding transaction. | Check that `txid` is the transaction that *created* the coin and `blockHeight` is where *that* transaction confirmed. |
| `NOT_COVERED` | No filter for that block. | `GET /v1/meta` → `filters.covered_ranges`. Try again later. |
| Report `ERROR`, `token_already_spent` | The token was used before, typically because the same pack was imported or restored on two devices. | Run the check again; the SDK uses another token. Stop sharing the store between devices. |
| Report `ERROR`, `spend_rejected` with `revocation_root_mismatch` | The revocation tree changed between fetching the root and spending. | Retry. The token was returned to the balance. |
| Report `ERROR`, `spend_rejected` with `proof_invalid` | The proof didn't verify: usually a `pk.bin` from a different circuit version. | Use the `pk.bin` matching `circuit.version` in `/v1/meta`. |
| Report `ERROR`, `spend_failed` with `network: …` | The connection dropped during the spend. The SDK counts those tokens as spent, because the server may have used them. | Retry the check. |
| `Verification`: `filter … wants codebook …, server codebook is …` | The server is mid-update between codebooks. | Retry shortly. If it persists, report it. |
| `InvalidArgument`: `decoys_per_input must be at least 4…` | `decoysPerInput` below the minimum. | Use 8. Nothing was sent or spent. |
| Very slow analysis | Proving takes about 0.5–1.5 s per matched funding transaction on a phone, plus filter downloads over Tor. | Run it as soon as the user opens the review screen, not when they press Send. Cache graded reports by txid. |

## Building

| You see | Cause | Fix |
|---|---|---|
| `java.lang.UnsatisfiedLinkError: … perseverus_sdk` | The native library isn't packaged for this ABI, or isn't on `jna.library.path` (desktop). | Check `jniLibs/<abi>/libperseverus_sdk.so` is in the APK (Android Studio's APK Analyzer). |
| `UniFFI API checksum mismatch` / contract version error at load | Bindings and native library come from different SDK commits. | Regenerate the bindings from the same build as the library. |
| `cargo ndk` can't find the NDK | `ANDROID_NDK_HOME` isn't set. | Point it at an installed NDK. |
| Kotlin: `Type mismatch: inferred type is Int but UInt was expected` | The API uses unsigned types. | Use `8u`, `.toUInt()`, `.toULong()`. |

## Debug output

The SDK prints nothing by default. Set the environment variable `PERSEVERUS_DEBUG=1` before the SDK loads to get progress and timing lines on stderr: filter downloads, proof times, server response codes, and pass/fail checks run before each proof (whether the token's signature, nullifier and dates are valid). The checks solve the circuit a second time, so analysis is slower in this mode. The output never contains txids, tags, block heights, pack ids or nullifiers, but don't ship release builds with it on.

## Still stuck

Collect the exception class and message, the `rawTag` or `error.code` from the report, the SDK commit, and the output of `GET /v1/meta`. Send them to Perseverus. **Don't include txids, addresses or `purchaseId`s** in bug reports.
