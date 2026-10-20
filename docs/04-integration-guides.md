# 4. Integration guides

Complete flows, in the order you'll build them. Code is Kotlin with coroutines. Your wallet's own types (`Psbt`, `Utxo`, and so on) are placeholders for whatever Blueberry uses.

- [Setup: Tor, `pk.bin` and the instance](#setup)
- [Threading](#threading)
- [Buying tokens](#buying-tokens): Lightning, card, yearly, resuming after a restart
- [The pre-broadcast check](#the-pre-broadcast-check)
- [Low balance and token cost](#low-balance-and-token-cost)
- [Backups, restore and multiple devices](#backups-restore-and-multiple-devices)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Release checklist](#release-checklist)

---

## Setup

### Tor

Production is a Tor onion service, and the SDK needs a **SOCKS5 proxy** to reach it. `Transport.Tor(socksProxy = null)` means `socks5h://127.0.0.1:9050`. On mobile you have two options:
- **Embedded Tor** inside the app (for example a tor-android or Arti build that exposes a local SOCKS port). Pass its address: `Transport.Tor("socks5h://127.0.0.1:$port")`.
- **An external Tor app** (Orbot on Android) on its SOCKS port, default `9050`.

Use the `socks5h://` scheme so hostnames, including the `.onion`, are resolved inside Tor. The SDK fails closed: if the proxy isn't up, calls throw `Network` and never fall back to clearnet. Start Medusa features only once your Tor layer reports it's ready.

The SDK asks Tor for **separate circuits** for filter downloads, token spends and redemptions, using random SOCKS credentials. This needs no setup, but it relies on Tor's default `IsolateSOCKSAuth` behaviour, so don't turn that off in an embedded Tor config.

### `pk.bin`

The spend proof needs the circuit's proving key, [`assets/circuit-v10/pk.bin`](../assets/circuit-v10/) in this repo. Ship it in the app (about 4 MB) and copy it to internal storage on first launch. The SDK needs a file path:

```kotlin
private const val PK_SHA256 = "ca79225709f48f20ab00549d51d6876e91a383047b13083846e85d326f8b909b"

fun provingKeyFile(context: Context): File {
    val f = File(context.filesDir, "medusa-pk-v10.bin")
    if (!f.exists()) {
        context.assets.open("medusa/pk.bin").use { input -> f.outputStream().use { input.copyTo(it) } }
    }
    val digest = MessageDigest.getInstance("SHA-256").digest(f.readBytes())
    check(digest.joinToString("") { "%02x".format(it) } == PK_SHA256) { "corrupt pk.bin" }
    return f
}
```

When the circuit version changes (`GET /v1/meta` → `circuit.version`, currently `v10`), a new `assets/circuit-v<N>/pk.bin` will be added. Version the file name so the old and new keys don't collide.

### One instance

```kotlin
class Medusa(private val context: Context, private val socks: String) {
    @Volatile private var instance: Perseverus? = null

    /** Connects on first use. Call from a background dispatcher. */
    fun get(): Perseverus = instance ?: synchronized(this) {
        instance ?: Perseverus.connect(Config(
            endpoint = "http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion",
            dataDir = File(context.filesDir, "medusa").path,
            transport = Transport.Tor(socks),
            expectedServerPubkey = "dc03c12db41ba08872513309b777f2375e35215ea46ba5efd8c4a4542c13560b",
            provingKeyPath = provingKeyFile(context).path,
        )).also { instance = it }
    }
}
```

If `connect` throws `Network` (Tor not ready yet), `instance` stays `null` and the next `get()` tries again.

---

## Threading

Every SDK call blocks. On Android, wrap calls in `withContext(Dispatchers.IO)`; on iOS, use a background `Task` or `DispatchQueue`.

```kotlin
suspend fun <T> Medusa.io(block: (Perseverus) -> T): T = withContext(Dispatchers.IO) { block(get()) }

// in a ViewModel
viewModelScope.launch {
    val balance = medusa.io { it.tokenBalance() }
    _state.update { it.copy(balance = balance.toInt()) }
}
```

Typical durations over Tor:
- `connect`, `tokenBalance`, `purchaseStatus`: about 1 s.
- `redeem`: 1–3 s for a 100-token pack, longer for a yearly plan (1,300 tokens).
- `analyzeInputs`: a few seconds. Filter download dominates, plus 0.5–1.5 s of proving per matched funding transaction.

Calls can't be cancelled mid-flight. If the user leaves the screen, let the call finish in the background and ignore the result. Don't abandon a `redeem`.

---

## Buying tokens

Every purchase follows the same four steps: **buy → show payment → poll → redeem**.

### Lightning (trial, 100-token pack, or dev)

```kotlin
suspend fun buyWithLightning(plan: Plan): List<PackInfo> {
    val p = medusa.io { it.buyTokens(PayMethod.LIGHTNING, plan) }   // TRIAL, ONETIME (or DEV while testing)
    ui.showInvoice(qr = p.paymentRequest, amountSat = p.amountSat, expiresAt = p.expiresAt)
    // If Blueberry can pay Lightning itself, offer "Pay from this wallet" with p.paymentRequest.

    while (true) {
        when (medusa.io { it.purchaseStatus(p.purchaseId) }) {
            PurchaseState.PAID -> break
            PurchaseState.EXPIRED -> throw InvoiceExpired()
            PurchaseState.REDEEMED -> return medusa.io { it.listPacks() }    // finished elsewhere
            PurchaseState.PENDING -> delay(3_000)
        }
    }
    return medusa.io { it.redeem(p.purchaseId) }
}
```

### Card (one-time, monthly, yearly)

```kotlin
suspend fun buyWithCard(plan: Plan) {                // ONETIME, MONTHLY or YEARLY
    val p = medusa.io { it.buyTokens(PayMethod.CARD, plan) }
    ui.openBrowser(p.paymentRequest)                 // Stripe checkout page (Custom Tab / SFSafariViewController)
    // When the user comes back to the app, poll:
    repeat(60) {
        if (medusa.io { it.purchaseStatus(p.purchaseId) } == PurchaseState.PAID) {
            val packs = medusa.io { it.redeem(p.purchaseId) }    // YEARLY returns 13 packs
            ui.toast("Added ${packs.sumOf { it.size.toInt() }} checks")
            return
        }
        delay(5_000)
    }
    // Still pending: the purchase stays in pendingPurchases() and is resumed at next start.
}
```

Things to know about cards:
- The checkout opens in a browser. **Stripe sees the user's IP and card details**, as with any card payment. The Medusa server sees only that a checkout was paid, and nothing about the tokens (see [Privacy model](07-privacy-model.md)).
- **Yearly** stores 13 packs at once. Only the current one is active; one more becomes active each month, so `tokenBalance` counts only the active pack.
- Card packs can be **revoked** if the payment is charged back. A revoked pack's tokens stop working; `listPacks()` shows it with `revoked = true`. The SDK detects this on the device, from the public revocation list.

### Resume at startup

A user can pay and close the app before redemption, so resume pending purchases on every start:

```kotlin
suspend fun resumePendingPurchases() {
    for (id in medusa.io { it.pendingPurchases() }) {
        val state = runCatching { medusa.io { it.purchaseStatus(id) } }.getOrNull() ?: continue
        if (state == PurchaseState.PAID) runCatching { medusa.io { it.redeem(id) } }
    }
}
```

### A purchase made outside the app

If the user bought on another device, or you run your own web checkout, register it and redeem as usual:

```kotlin
medusa.io { it.addPurchase("card_3f9a…", Plan.YEARLY) }
```

---

## The pre-broadcast check

### When to run it

Run it on the transaction review screen, after the user has chosen inputs and before signing. Only the inputs are analysed: the report describes the history of each coin being spent.

### Building the inputs

You need each input's **funding txid**, **vout** and **confirmation height**. Your wallet already has all three from its UTXO set; nothing is looked up externally.

```kotlin
fun inputsFor(psbt: Psbt, utxos: Map<Outpoint, Utxo>): List<InputRef> =
    psbt.inputs.map { inp ->
        val u = utxos.getValue(inp.outpoint)
        require(u.confirmations > 0) { "unconfirmed input" }   // analyse confirmed coins only
        InputRef(txid = inp.outpoint.txid, vout = inp.outpoint.vout.toUInt(),
                 blockHeight = u.height.toUInt(), valueSats = u.valueSat.toULong())
    }
```

Leave unconfirmed inputs out of the list and show them as "not checked (unconfirmed)". If you include them, the whole call throws `InvalidArgument`.

### Running it

```kotlin
suspend fun checkBeforeBroadcast(inputs: List<InputRef>): CheckResult = try {
    val r = medusa.io {
        it.analyzeInputs(inputs, AnalyzeOptions(decoysPerInput = 8u, chainTip = wallet.tipHeight.toUInt()))
    }
    CheckResult.Done(r.reports, r.tokensSpent.toInt())
} catch (e: PerseverusException.InsufficientTokens) {
    CheckResult.NeedTokens(e.needed.toInt(), e.available.toInt())       // nothing was spent
} catch (e: PerseverusException.Network) {
    CheckResult.Offline                                                 // nothing was spent
}
```

### Showing it

- Show **one summary** for the transaction (the worst graded input), with a per-input breakdown on tap.
- For each graded input, show its `grade`, its `primaryRecommendation.headline`, and its findings sorted by severity. See the [field guide](05-privacy-report.md) for colours and wording.
- `UNGRADED` and `NOT_COVERED` are **neutral**. Don't show them as warnings.
- **Never block the broadcast.** The check is advice. Show the result and let the user continue or change their inputs.

```kotlin
val graded = reports.filter { it.status == ReportStatus.GRADED }
val worst = graded.minByOrNull { it.score ?: 100u }
val summary = when {
    worst == null -> "No privacy grade available for these coins"
    else -> "Privacy ${worst.grade}: ${worst.primaryRecommendation?.headline}"
}
```

### Caching

**The SDK does this for you.** A coin's history doesn't change once its funding transaction is confirmed, so the SDK keeps every graded result in `dataDir` and answers repeat checks of the same coin on the device: no request, no token (`tokenSpent = false` on those reports). This is also a privacy feature: checking the same coin again with new decoys would let the server narrow down which block is real, so don't add your own "re-check" that clears it.

You can call `analyzeInputs` on every send without worrying about cost; only coins never graded before reach the server. `ERROR` reports aren't cached, so retrying works. `NOT_COVERED` isn't cached either and can be checked again later, because coverage grows (see `GET /v1/meta` → `filters.covered_ranges`). `forgetCachedGrades()` clears the cache; you shouldn't normally need it.

---

## Low balance and token cost

A check costs at most one token per **distinct funding txid** among the inputs, and less if some are ungraded or not covered:

```kotlin
val maxCost = inputs.map { it.txid }.distinct().size
val balance = medusa.io { it.tokenBalance() }.toInt()
if (balance < maxCost) ui.offerTopUp(needed = maxCost - balance)
```

`analyzeInputs` checks the balance itself, after matching and before spending, and throws `InsufficientTokens` if it's short. The check above just lets you warn early. Ungraded or not-covered inputs might make the call succeed anyway.

Packs expire: a single pack lasts through the end of the month after it was redeemed. Show `listPacks()` expirations so users aren't surprised.

---

## Backups, restore and multiple devices

- **Back up `dataDir`** (the `perseverus-packs.json` inside it) with the wallet backup, encrypted the same way. It holds the tokens and pending purchase ids, which are bearer value.
- **Restore** by putting the file back before `connect`.
- **Don't run the same store on two devices.** Both would spend the same tokens. The second spend of each is rejected (`token_already_spent`) and that check is wasted. If you sync wallets between devices, give each device its own packs.
- **Migrating from the BTC Medusa Sparrow wallet**: use `importPack(blob, "sparrow-import", spentBitmap)` with each pack and its `spent` array.

---

## Error handling

| Situation | What the user should see |
|---|---|
| `Network` | "Can't reach Medusa (check Tor)" and a retry. Nothing was lost. |
| `InsufficientTokens` | "This check needs N tokens, you have M", with a buy button. |
| `Server`, `upstream_unavailable` / `not_configured` | "Purchases are temporarily unavailable." |
| `Server`, `payment_required` on redeem | Keep polling; the payment hasn't settled. |
| `Verification` | "Medusa server failed a security check." Don't auto-retry, and log it for support. |
| Report `ERROR` + `token_already_spent` | "A token was already used elsewhere; run the check again." |
| Report `ERROR` + `spend_failed` (retryable) | "Check interrupted; run it again." |
| `Unsupported` | "Update the app to keep using privacy checks." |

Branch on the code (`e.reason.substringBefore(':')` for `Server`, `report.error.code` for reports), never on message text.

---

## Testing

- **A full pack for a few cents:** while you're integrating, a test server may sell the Lightning `DEV` plan: 100 tokens at a token price (e.g. $0.10). `GET /v1/meta` shows `dev_plan` when it's on, and the sample's `buy-dev` command buys one. Production doesn't sell it (`Server` 403 `plan_unavailable`), so never offer `DEV` to users in a release build.
- **Against production with real money, cheaply:** a Lightning `TRIAL` is 1 token (about $0.25).
- **Without Tor:** only against a server on your own machine (`Transport.Direct` with a `localhost` endpoint; see the server repository's local-server instructions). The SDK refuses `Transport.Direct` for any other server, production included, so testing with a real wallet can't expose your IP.
- **Known coin:** `728da0f74813fec9c1381ec9e82ab7a096d1b637b845c446f3ac02db14ccb44f`, vout `0`, height `945270` returns grade **D** (peel chain) and raw tag `V3LEAN:b40014`.
- **Ungraded and not-covered:** a txid that isn't in its block (e.g. a random 64-hex string at a covered height) returns `UNGRADED` for free. A height outside `covered_ranges` returns `NOT_COVERED`.
- The `sdk/examples/kotlin-jvm` app exercises every call from the command line.

---

## Release checklist

- [ ] `Transport.Tor` everywhere in release builds (the SDK already refuses `Direct` for anything but localhost).
- [ ] `expectedServerPubkey` pinned to `dc03c12d…560b`.
- [ ] `pk.bin` bundled and its SHA-256 checked.
- [ ] `dataDir` included in the wallet backup and excluded from cloud sync between devices.
- [ ] Pending purchases resumed at startup.
- [ ] All SDK calls off the main thread.
- [ ] `decoysPerInput` 8 (the SDK refuses fewer than 4).
- [ ] No txid, outpoint or address sent to any Medusa endpoint by your own code, and not logged alongside Medusa activity.
- [ ] No wallet-side "re-check" that calls `forgetCachedGrades()`; the SDK's cache answers repeat checks for free. `UNGRADED` and `NOT_COVERED` shown as neutral.
- [ ] The broadcast is never blocked by the check.
