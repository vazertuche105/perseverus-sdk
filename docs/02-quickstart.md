# 2. Quickstart

Goal: in about 15 minutes, analyse a real Bitcoin coin against the production server from your laptop, using the same SDK calls a wallet makes. Most of the time goes to the first build.

## Prerequisites

- **Rust** (stable, via [rustup](https://rustup.rs)).
- **JDK 17 or newer**. Gradle comes with the sample through its wrapper.
- **`pk.bin`**, the spend circuit's proving key, is already in the repo at [`assets/circuit-v10/pk.bin`](../assets/circuit-v10/), and the sample uses it automatically. Its SHA-256 is `ca79225709f48f20ab00549d51d6876e91a383047b13083846e85d326f8b909b`.
- **Tor**, running before you start: `brew install tor && tor` on macOS, or `apt install tor` on Linux. It listens on `127.0.0.1:9050`. (Tor Browser works too while it's open: set `MEDUSA_TOR_SOCKS=socks5h://127.0.0.1:9150`.) The sample sends everything over Tor, including its chain-tip lookup, so it's safe to try with a wallet that holds real funds. The SDK refuses clearnet connections to any server except one on your own machine.
- **Tokens:** either some in a Medusa wallet to import, or a Lightning wallet to pay a 1-token trial invoice (about $0.25).

## Step 1: get the code and build

```bash
git clone https://github.com/vazertuche105/perseverus-sdk
cd perseverus-sdk
cargo test -p perseverus-sdk            # quick sanity check (report parity + schema)
cd sdk/examples/kotlin-jvm
./gradlew run --args="status"                # talks to the production .onion over Tor
```

The first `run` compiles the Rust library, generates the Kotlin bindings (`com.btcmedusa.perseverus`) and compiles the sample. Expected output:

```
server        http://medusayl5…had.onion
oprf pubkey   dc03c12db41ba08872513309b777f2375e35215ea46ba5efd8c4a4542c13560b
epoch month   202610
balance       0 tokens
```

If you see `network: … connection refused`, Tor isn't running. See [Troubleshooting](09-troubleshooting.md).

## Step 2: get a token

Pay a 1-token trial over Lightning:

```bash
./gradlew run --args="buy-trial"
```

The sample prints a BOLT11 invoice. Pay it from any Lightning wallet. The sample polls until the invoice is paid, then redeems it:

```
Redeemed: pack 559256596868823998 with 1 token(s), 202610–202611
Balance: 1
```

## Step 3: analyse a coin

Pick a coin you own (or any confirmed transaction output). You need its **funding txid** (normal explorer order), its **vout**, and the **height of the block** that confirmed it.

```bash
./gradlew run --args="analyze 728da0f74813fec9c1381ec9e82ab7a096d1b637b845c446f3ac02db14ccb44f:0:945270"
```

Output (a real mainnet result; your timing and download size will differ):

```
Analyzing 1 input(s), 8 decoys each, tip 969210, balance 1…
done in 3.3s: 1 token(s) spent, 9 filters (… KB). Balance 0

728da0f74813fec9…:0 @945270  GRADE D (65/100, band D)  V3LEAN:b40014
   [soon] Part of a peel chain
   - high: Peel chain detected (2+ consecutive hops)
   - low: 2 wallet fingerprinting signals
   - low: RBF signaled
   - low: No anti-fee-sniping (nLockTime = 0)
   - low: No anonymity set
```

What happened:
1. The SDK downloaded 9 filters (the real block plus 8 decoys) over one Tor circuit.
2. It found the transaction in its block's filter on your machine.
3. It spent one token with a zero-knowledge proof over a second Tor circuit. That request contained no heights or txids.
4. It decrypted the tag and turned it into findings using the catalog.

The server saw nine block heights, and separately one token spend. It never saw which coin was checked. (In the current release it can tell which purchase the token came from; that's fixed in v11, see the [privacy model](07-privacy-model.md#known-limitations).)

## The same thing in code

This is the core of what you'll put in your wallet. Everything is blocking, so run it off the main thread (see [threading](04-integration-guides.md#threading)).

```kotlin
import com.btcmedusa.perseverus.*

val medusa = Perseverus.connect(Config(
    endpoint = "http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion",
    dataDir = File(context.filesDir, "medusa").path,            // back this up with the wallet
    transport = Transport.Tor(socksProxy = null),               // socks5h://127.0.0.1:9050
    expectedServerPubkey = "dc03c12db41ba08872513309b777f2375e35215ea46ba5efd8c4a4542c13560b",
    provingKeyPath = bundledPkBinPath,                          // pk.bin shipped with the app
))

val inputs = tx.inputs.map { InputRef(txid = it.prevTxid, vout = it.prevVout.toUInt(),
                                      blockHeight = it.prevHeight.toUInt(), valueSats = it.value.toULong()) }
val result = medusa.analyzeInputs(inputs, AnalyzeOptions(decoysPerInput = 8u, chainTip = tipHeight.toUInt()))

for (r in result.reports) when (r.status) {
    ReportStatus.GRADED      -> show(r.grade, r.primaryRecommendation?.headline, r.findings)
    ReportStatus.UNGRADED    -> showNeutral("No privacy grade for this coin")
    ReportStatus.NOT_COVERED -> showNeutral("Not checked yet")
    ReportStatus.ERROR       -> showRetry(r.error?.message)
}
```

## Next

- [SDK reference](03-sdk-reference.md) for every call and its errors.
- [Integration guides](04-integration-guides.md) for the purchase screens and the pre-broadcast check.
- [PrivacyReport field guide](05-privacy-report.md) for how to show results.
