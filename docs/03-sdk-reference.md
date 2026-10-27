# 3. SDK reference

Signatures are shown in **Kotlin** (package `com.btcmedusa.perseverus`), as UniFFI generates them. Swift is the same with Swift naming. The Rust names are the snake_case versions (`analyze_inputs`).

Every method **blocks**: it does network I/O over Tor, and `analyzeInputs` also creates zero-knowledge proofs (about 0.5–1.5 s of CPU per matched funding transaction). Never call one on the UI thread; see [Threading](04-integration-guides.md#threading). Use **one `Perseverus` instance per data directory**. Its methods are safe to call from any thread; two instances on the same directory are not safe.

Contents:
- [`Perseverus.connect`](#perseverusconnect)
- Reading state: [`serverPubkey`](#serverpubkey), [`currentMonth`](#currentmonth), [`tokenBalance`](#tokenbalance), [`listPacks`](#listpacks)
- Buying tokens: [`buyTokens`](#buytokens), [`addPurchase`](#addpurchase), [`pendingPurchases`](#pendingpurchases), [`purchaseStatus`](#purchasestatus), [`redeem`](#redeem)
- [`importPack`](#importpack)
- [`analyzeInputs`](#analyzeinputs), [`forgetCachedGrades`](#forgetcachedgrades)
- [Types](#types)
- [Errors: `PerseverusException`](#errors-perseverusexception)

---

## `Perseverus.connect`

```kotlin
@Throws(PerseverusException::class)
fun Perseverus.Companion.connect(config: Config): Perseverus
```

**What it does.** Sets up the network transport, opens the local token store in `config.dataDir` (creating it if needed), and calls `GET /v1/meta`. It checks that the server speaks API `1.x`, that this SDK isn't older than the server's `min_client_version`, and that the server's public key parses. If you pin a key, it also checks that the server's key matches it.

**Why.** Every later call needs the server's public key: it's used to verify every signature and evaluation the server returns. Pinning that key means a substitute server (for example, a hijacked endpoint) is refused before any token or query reaches it.

**When.** Once, when the wallet starts or when Medusa is first used. Keep the returned object for the lifetime of the app. It's thread-safe, and holding one instance avoids re-reading the store and re-loading the 4 MB proving key. It is `AutoCloseable`; call `close()` when you're done with it.

```kotlin
val medusa = Perseverus.connect(Config(
    endpoint = "http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion",
    dataDir = File(context.filesDir, "medusa").path,
    transport = Transport.Tor(socksProxy = "socks5h://127.0.0.1:9050"),
    expectedServerPubkey = "641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695",
    provingKeyPath = File(context.filesDir, "medusa-pk.bin").path,
))
```

**`Config` fields**

| Field | Type | Meaning |
|---|---|---|
| `endpoint` | `String` | Server base URL, without `/v1`. Production is the `.onion` above. |
| `dataDir` | `String` | Directory for the token store (`perseverus-packs.json`). **Back it up with the wallet.** Tokens are bearer value; the server keeps no copy. |
| `transport` | `Transport` | `Transport.Tor(socksProxy)` routes everything through a Tor SOCKS proxy and **fails closed**: if Tor is down, calls fail, they never fall back to clearnet. `socksProxy = null` means `socks5h://127.0.0.1:9050`. `Transport.Direct` is clearnet and **only allowed for a server on the same machine** (`localhost`, `127.x.x.x`, `::1`), for local development; `connect` refuses it for any other endpoint, because the server would see the user's IP address. Loopback endpoints always go direct. |
| `expectedServerPubkey` | `String?` | Pin the server's OPRF public key (hex). Strongly recommended in production. |
| `provingKeyPath` | `String?` | Path to `pk.bin` (4,394,320 bytes, SHA-256 `2f59e8…2483`). **Ship it inside your app.** The production server does not serve it, so a malicious server can't hand you a different one. If `null`, the SDK tries `GET /v1/circuit/pk` (development servers only) and caches the result. Only `analyzeInputs` needs it. |

**Errors**

| Exception | Cause |
|---|---|
| `InvalidArgument` | Empty endpoint, `Transport.Direct` with a server that isn't on this machine, or a bad SOCKS URL. |
| `Network` | Tor not running, server unreachable, timeout (180 s). Retry later. |
| `Server` | The server answered with an error (rare here). |
| `Unsupported` | The server's API isn't `1.x`, or this SDK is older than `min_client_version`. Update the SDK. |
| `Verification` | The server's key doesn't match `expectedServerPubkey`, or isn't a valid point. **Don't proceed**; this is the "wrong server" alarm. |
| `Storage` | `dataDir` can't be created, or the store file is unreadable or from a newer SDK. |

**What the server sees.** One `GET /v1/meta` over Tor.

---

## `serverPubkey`

```kotlin
fun serverPubkey(): String
```

The server's OPRF public key (64 hex chars). It makes no network call. Use it to pin on first use if you didn't hard-code the key.

## `currentMonth`

```kotlin
@Throws(PerseverusException::class)
fun currentMonth(): UInt
```

The server's epoch month as `YYYYMM` (e.g. `202610`). It decides which packs are active. The server derives it from the blockchain's own clock, not from the device clock, so a wrong phone clock can't make packs look expired. **Network:** one `GET /v1/meta`.

## `tokenBalance`

```kotlin
@Throws(PerseverusException::class)
fun tokenBalance(): UInt
```

**What.** Unspent tokens in currently **active** packs: packs whose `startMonth ≤ currentMonth ≤ expirationMonth`.

**Why.** Show it in the UI, and check it before a pre-broadcast analysis so you can offer to buy tokens first.

**Network.** The balance itself never leaves the device. The call fetches the current month (`GET /v1/meta`) to decide which packs are active, so it needs a connection.

```kotlin
val balance = medusa.tokenBalance()
balanceLabel.text = "$balance checks left"
```

## `listPacks`

```kotlin
@Throws(PerseverusException::class)
fun listPacks(): List<PackInfo>
```

Every pack in the store, including expired and not-yet-active ones (a yearly plan stores 13 packs up front). Use it for a "tokens" screen. Same network note as `tokenBalance`.

```kotlin
for (p in medusa.listPacks()) {
    println("${p.remaining}/${p.size} left, valid ${p.startMonth}–${p.expirationMonth}, active=${p.active}")
}
```

`PackInfo`: `packId: ULong`, `size: UInt`, `remaining: UInt`, `startMonth: UInt`, `expirationMonth: UInt`, `method: String` (`"lightning"`, `"card"`, or whatever label was given to `importPack`), `acquiredAt: ULong` (unix seconds), `active: Boolean`, `revoked: Boolean`.

`revoked` is set when the server's public revocation list shows the pack revoked, which happens if its card payment was charged back. The SDK checks this on the device at each analysis; it never sends the pack id. A revoked pack is never `active`, its tokens don't count toward `tokenBalance`, and the flag is permanent.

---

## `buyTokens`

```kotlin
@Throws(PerseverusException::class)
fun buyTokens(method: PayMethod, plan: Plan): Purchase
```

**What.** Starts a purchase with `POST /v1/tokens/purchase` and returns what to show the user. The purchase is also saved in the store as *pending*, so it survives an app restart.

**Why.** Tokens are what each analysis spends. The server sets the price (Lightning is priced at the live BTC/USD rate; card prices come from the Stripe checkout).

**Valid combinations**

| `method` | `plan` | You get |
|---|---|---|
| `LIGHTNING` | `TRIAL` | 1 token |
| `LIGHTNING` | `ONETIME` | 1 pack of 100 tokens |
| `CARD` | `ONETIME` | 1 pack of 100 tokens |
| `CARD` | `MONTHLY` | Subscription: 1 pack of 100 per month |
| `CARD` | `YEARLY` | Paid once: 13 packs of 100 (the rest of this month plus the next 12 months) |
| `LIGHTNING` | `DEV` | 1 pack of 100 tokens at a token price (e.g. $0.10), for testing your integration. Only servers with the dev plan switched on sell it (`GET /v1/meta` shows `dev_plan`); production refuses it with `Server` 403 `plan_unavailable`. Don't ship a build that offers it to users. |

A single pack is valid for the month it's redeemed and the following month.

**`Purchase` fields**

| Field | Meaning |
|---|---|
| `purchaseId` | `ln_…` or `card_…`. A **bearer credential**: anyone holding it can redeem the paid tokens. The SDK keeps it in `dataDir`; don't log it. |
| `paymentRequest` | Lightning: a BOLT11 invoice; show it as a QR code or hand it to the wallet's own Lightning payer. Card: a Stripe checkout URL; open it in a browser or custom tab. |
| `amountSat` | Invoice amount (Lightning), else `null`. |
| `packs`, `tokens` | What the purchase redeems into. |
| `expiresAt` | Unix seconds after which payment is no longer accepted. |
| `method`, `plan` | Echoed back. |

```kotlin
val p = medusa.buyTokens(PayMethod.LIGHTNING, Plan.ONETIME)
showInvoiceQr(p.paymentRequest, "${p.amountSat} sats for ${p.tokens} checks")
```

**Errors.** `Server` with reason:
- `bad_request: …` for an invalid combination, e.g. `TRIAL` by card.
- `plan_unavailable: …` (403) for `DEV` on a server that doesn't sell it.
- `not_configured: …` when that payment method is turned off on the server.
- `upstream_unavailable: …` when the price feed or payment processor is down (retryable).

`Network` when the server can't be reached.

**What the server sees.** That someone wants to buy this plan. The request carries no wallet data.

## `addPurchase`

```kotlin
@Throws(PerseverusException::class)
fun addPurchase(purchaseId: String, plan: Plan)
```

Tracks a purchase that wasn't started by `buyTokens` on this device: for example, a card checkout completed on the web, or a purchase started on another device. After this you can `purchaseStatus` and `redeem` it here. The `plan` must match what was bought (`YEARLY` redeems 13 packs). It throws `InvalidArgument` if the id doesn't start with `ln_` or `card_`.

## `pendingPurchases`

```kotlin
@Throws(PerseverusException::class)
fun pendingPurchases(): List<String>
```

Purchase ids started but not yet redeemed. **Call it at startup** and resume any that are paid. That covers the user closing the app between paying and redeeming.

## `purchaseStatus`

```kotlin
@Throws(PerseverusException::class)
fun purchaseStatus(purchaseId: String): PurchaseState
```

`GET /v1/tokens/purchase/{id}/status`. Returns:
- `PENDING`: not paid yet. Poll every 2–5 s while the payment screen is open.
- `PAID`: call `redeem` now.
- `REDEEMED`: already claimed (Lightning).
- `EXPIRED`: the invoice timed out; start a new purchase.

Card purchases disappear from the server once redeemed, so after redemption this throws `Server(404, "not_found: …")`.

## `redeem`

```kotlin
@Throws(PerseverusException::class)
fun redeem(purchaseId: String): List<PackInfo>
```

**What.**
1. Generates fresh tokens on the device (100 per pack, or 1 for a trial) and blinds them.
2. Sends them with the `purchaseId` to `POST /v1/tokens/redeem` over a **separate Tor circuit**.
3. Verifies the server's signatures (DLEQ proofs) and unblinds them.
4. Stores the packs in `dataDir`.

It returns one `PackInfo` per pack: 13 for `YEARLY`, otherwise 1.

**Why it's built this way.** This one request is the only point where a payment touches the tokens. Later spends can't be linked back to this purchase (see the [privacy model](07-privacy-model.md#the-rules-that-make-it-hold)).

**Safety.** The request carries a random `Idempotency-Key`. If the connection drops without a response, the SDK resends the identical request up to 4 times, and the server replays its stored answer instead of refusing a "used" purchase. The packs are written to disk before the call returns, and before anything else can fail.

**Card packs** also publish one attribution entry each (`POST /v1/board/publish`, each over its own circuit). That lets a pack be revoked after a chargeback. The server hands out a one-time ticket with each card pack, and the SDK sends it with the publish; you don't handle it. If publishing fails the tokens are still fine: the SDK keeps the ticket with the pack and retries on the next `redeem`. Lightning, dev and on-chain packs publish nothing.

```kotlin
val packs = medusa.redeem(p.purchaseId)
toast("Added ${packs.sumOf { it.size.toInt() }} checks")
```

**Errors**
- `InvalidArgument("unknown purchase …")`: the id isn't in this device's pending list. Call `addPurchase` first.
- `Server(402, "payment_required: …")`: not paid yet. (The `NotPaid` exception is reserved and currently not thrown.)
- `Server(404, "not_found: …")`: unknown or already redeemed.
- `Server(400, "bad_request: …")`: e.g. more packs than the plan allows.
- `Server(503, "not_configured: …")`: that payment method is off.
- `Network`: Tor or server unreachable after retries. The purchase stays pending; try again later.
- `Verification`: the server's signatures didn't verify against its public key. Treat the server as faulty and don't retry blindly.

**What the server sees.** A paid credential and the pack's token points. It can't connect them to any later spend.

---

## `importPack`

```kotlin
@Throws(PerseverusException::class)
fun importPack(blob: ByteArray, method: String, spent: List<Boolean>?): PackInfo
```

Adds a pack in the shared binary format (the same format the BTC Medusa Sparrow wallet uses). Use it to migrate a user's tokens from another Medusa wallet, or to restore from your own backup. `method` is a free-text label shown in `PackInfo.method`. `spent` is the per-token used-bitmap from the source wallet. Pass it whenever you have it: a token spent elsewhere and re-used here is rejected by the server and wasted. Throws `InvalidArgument` if the blob doesn't parse. No network call except `currentMonth`.

---

## `analyzeInputs`

```kotlin
@Throws(PerseverusException::class)
fun analyzeInputs(inputs: List<InputRef>, options: AnalyzeOptions): AnalysisResult
```

**What.** The pre-broadcast privacy check. For each input of the transaction the user is about to sign, it returns a `PrivacyReport` describing how exposed the coin is, based on the transaction that created it.

**How** (details in [How it works](01-how-it-works.md)):
0. Coins already graded on this device are answered from the SDK's cache in `dataDir`: no request, no token, `tokenSpent = false`. Only the rest go on to the steps below.
1. Inputs are grouped by funding transaction; one check covers all inputs from the same earlier transaction.
2. Filters are downloaded for the real block heights mixed with `decoysPerInput` decoys each, shuffled, at most 200 per request, over one Tor circuit.
3. Each funding transaction is matched **on the device**:
   - Not in its block's filter → `UNGRADED` (free).
   - No filter for that block → `NOT_COVERED` (free).
4. If anything matched, the SDK checks the balance. It throws `InsufficientTokens` **before spending anything** if there aren't enough tokens. Otherwise it marks one token per matched funding transaction as used, then sends all the spend proofs in **one** request over a **different** Tor circuit. That request contains no heights, txids or outpoints.
5. It verifies the server's DLEQ proofs, decrypts each tag, and builds the reports.

**When.** After the user has built a transaction and before they sign or broadcast it, typically when they open the review screen. Also useful on demand ("check this coin") from a coin-control screen.

**`InputRef`** (one per transaction input)

| Field | Meaning |
|---|---|
| `txid` | The **funding** transaction's id (the transaction that created the coin being spent), in normal explorer/RPC byte order, 64 hex chars. |
| `vout` | Output index. It doesn't affect the result (analysis is per transaction); it's echoed back so you can match reports to inputs. |
| `blockHeight` | Height of the block that confirmed the funding transaction, from your wallet's own data. Must be > 0: unconfirmed coins can't be analysed (`InvalidArgument`). |
| `valueSats` | Optional, echoed back. |

**`AnalyzeOptions`**

| Field | Meaning |
|---|---|
| `decoysPerInput` | Decoy blocks per real funding block. More decoys mean more privacy and more download. **8** is the reference wallet's value. The minimum is **4** (`minDecoysPerInput()`); with fewer, `analyzeInputs` throws `InvalidArgument` before contacting the server. |
| `chainTip` | Current chain height from your wallet. It's the upper bound for picking decoys, so decoys are never beyond the tip. |

**`AnalysisResult`**

| Field | Meaning |
|---|---|
| `reports` | One `PrivacyReport` per input, **in the same order** as `inputs`. |
| `tokensSpent` | Tokens consumed by this call. This is the authoritative count, including tokens lost to a failed request. |
| `filtersDownloaded`, `bytesDownloaded` | Bandwidth used. Each filter is roughly tens to hundreds of KB. |

```kotlin
val result = medusa.analyzeInputs(
    inputs = psbtInputs.map { InputRef(it.prevTxid, it.prevVout.toUInt(), it.prevHeight.toUInt(), it.valueSat.toULong()) },
    options = AnalyzeOptions(decoysPerInput = 8u, chainTip = wallet.tipHeight.toUInt()),
)
// The lowest score is the input that most needs the user's attention.
val worst = result.reports.filter { it.status == ReportStatus.GRADED }.minByOrNull { it.score ?: 100u }
```

**Errors (thrown for the whole call)**
- `InvalidArgument`: a txid isn't 64 hex chars, `blockHeight` is 0, or `pk.bin` is missing or invalid.
- `InsufficientTokens(needed, available)`: nothing was spent. Offer to buy tokens.
- `Network`: a filter download failed. Nothing was spent; retry.
- `Server`: e.g. `batch_too_large`. Shouldn't happen, because the SDK chunks requests.
- `Verification`: a filter or codebook failed to decode, or the filter references a different codebook than the server serves. Nothing was spent; report it.

**Per-input failures** don't throw. They come back as a report with `status = ERROR` and `error.code`:

| `error.code` | Meaning | Token |
|---|---|---|
| `token_already_spent` | The server says this token was already used. This happens when the same pack was imported into two wallets. `retryable = true`: analysing again uses a different token. | Lost |
| `spend_rejected` | The server rejected the proof before using the token, e.g. after a revocation-root change. | Returned to the balance |
| `spend_failed` | The whole spend request failed (network or verification). The SDK can't know whether the server used the tokens, so it counts them as spent. `retryable = true` for network failures. | Counted as spent |
| `decrypt_failed` | The decrypted value isn't in the codebook. Report it to Perseverus. | Spent |
| `unsupported_filter_version` | The server sent a filter format this SDK doesn't know. Update the SDK. | Free |

**What the server sees.** A shuffled set of block heights on one circuit, and later, on another circuit, *k* blinded points with token proofs. Never a txid, an outpoint, an address or a balance.

## `forgetCachedGrades`

```kotlin
@Throws(PerseverusException::class)
fun forgetCachedGrades()
```

**What.** Clears the grades the SDK has cached on this device. The next `analyzeInputs` of those coins looks them up again and spends tokens.

**Why you normally shouldn't.** Looking the same coin up twice, with fresh decoys each time, lets the server narrow down which block is real. The cache is what prevents that. Use this only for something like a "reset app data" screen.

---

## Types

| Type | Kind | Values / fields |
|---|---|---|
| `Transport` | sealed class | `Tor(socksProxy: String?)`, `Direct` |
| `PayMethod` | enum | `LIGHTNING`, `CARD` |
| `Plan` | enum | `TRIAL`, `ONETIME`, `MONTHLY`, `YEARLY`, `DEV` (test servers only) |
| `PurchaseState` | enum | `PENDING`, `PAID`, `REDEEMED`, `EXPIRED` |
| `ReportStatus` | enum | `GRADED`, `UNGRADED`, `NOT_COVERED`, `ERROR` |
| `Severity` | enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `GOOD` |
| `PrivacyReport`, `Finding`, `Recommendation`, `SeverityCounts`, `ReportError` | data classes | See the [PrivacyReport field guide](05-privacy-report.md). |

Integers are Kotlin unsigned types (`UInt`, `ULong`, `UShort`) because the Rust side is unsigned. Use `8u`, `.toUInt()`, and so on.

## Errors: `PerseverusException`

Every throwing method throws a subclass of the sealed class `PerseverusException`:

| Subclass | Fields | Meaning | Typical handling |
|---|---|---|---|
| `Network` | `reason` | Tor down, server unreachable, timeout. Safe to retry. | "Can't reach Medusa. Is Tor connected?" with a retry button. |
| `Server` | `status: UShort`, `reason` | The server returned an error. `reason` is `"<code>: <message>"`, where `<code>` is a stable [`/v1` error code](06-http-api.md#error-codes). | Branch on `reason.substringBefore(':')`, not on the message text. |
| `Verification` | `reason` | A cryptographic check on a server response failed (key pin, DLEQ, codebook). | Stop, don't retry automatically, and surface it. This may mean the server is faulty or impersonated. |
| `InsufficientTokens` | `needed`, `available` | Not enough active tokens; nothing was spent. | Offer to buy tokens. |
| `NotPaid` | none | Reserved. Unpaid redeems currently surface as `Server(402, "payment_required: …")`. | |
| `InvalidArgument` | `reason` | Bad input from your code (txid, height, ids, paths). | Fix the caller. |
| `Unsupported` | `reason` | Server/SDK version mismatch. | Ship an SDK update. |
| `Storage` | `reason` | `dataDir` unreadable or unwritable. | Check permissions and disk space. |
| `Internal` | `reason` | An unexpected response shape. | Report it. |

```kotlin
try {
    medusa.redeem(id)
} catch (e: PerseverusException.Server) {
    when (e.reason.substringBefore(':')) {
        "payment_required" -> keepPolling()
        "not_found"        -> markRedeemedOrInvalid(id)
        "not_configured", "upstream_unavailable" -> showTryLater()
        else -> showError(e.reason)
    }
} catch (e: PerseverusException.Network) {
    showOfflineRetry()
}
```
