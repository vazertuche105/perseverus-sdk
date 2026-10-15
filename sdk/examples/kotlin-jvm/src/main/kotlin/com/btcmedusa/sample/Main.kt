// Command-line sample for perseverus-sdk. It's what a wallet like Blueberry
// would do, minus the UI.
//
//   ./gradlew run --args="status"
//   ./gradlew run --args="import-sparrow"                      (test with your Sparrow tokens)
//   ./gradlew run --args="buy-trial"                           (pays a real ~$0.25 Lightning invoice)
//   ./gradlew run --args="analyze <txid>:<vout>:<height> ..."  (pre-broadcast analysis)
//
// Everything goes through Tor by default, so it's safe to try with a wallet
// that holds real funds. Start Tor first (`brew install tor && tor`, or keep
// Tor Browser open and set MEDUSA_TOR_SOCKS=socks5h://127.0.0.1:9150).
//
// Environment:
//   MEDUSA_ENDPOINT  server URL (default: the production .onion over Tor; a
//                    localhost URL uses a direct connection, for a local server)
//   MEDUSA_TOR_SOCKS Tor SOCKS proxy (default: socks5h://127.0.0.1:9050)
//   MEDUSA_DATA_DIR  where this sample keeps its tokens (default: ~/.perseverus-sample)
//   MEDUSA_PROVING_KEY  path to the circuit's pk.bin (default: the repo's
//                    assets/circuit-v10/pk.bin; the production server
//                    doesn't serve it)

package com.btcmedusa.sample

import com.btcmedusa.perseverus.AnalyzeOptions
import com.btcmedusa.perseverus.Config
import com.btcmedusa.perseverus.InputRef
import com.btcmedusa.perseverus.PayMethod
import com.btcmedusa.perseverus.Perseverus
import com.btcmedusa.perseverus.PerseverusException
import com.btcmedusa.perseverus.Plan
import com.btcmedusa.perseverus.PrivacyReport
import com.btcmedusa.perseverus.PurchaseState
import com.btcmedusa.perseverus.ReportStatus
import com.btcmedusa.perseverus.Transport
import com.google.gson.JsonParser
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import kotlin.system.exitProcess

private const val DEFAULT_ENDPOINT = "http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion"
private const val DEFAULT_TOR_SOCKS = "socks5h://127.0.0.1:9050"
// mempool.space's own onion service, for the chain tip (see `analyze`).
private const val MEMPOOL_ONION_TIP = "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api/blocks/tip/height"
private const val BUNDLED_PK = "../../../assets/circuit-v10/pk.bin"

fun main(args: Array<String>) {
    val endpoint = System.getenv("MEDUSA_ENDPOINT") ?: DEFAULT_ENDPOINT
    val dataDir = System.getenv("MEDUSA_DATA_DIR") ?: File(System.getProperty("user.home"), ".perseverus-sample").path
    val torSocks = System.getenv("MEDUSA_TOR_SOCKS") ?: DEFAULT_TOR_SOCKS
    // The SDK only allows a direct connection to a server on this machine.
    val transport = if (isLocalhost(endpoint)) Transport.Direct else Transport.Tor(socksProxy = torSocks)
    // Real wallets ship pk.bin inside the app. Gradle runs this from
    // sdk/examples/kotlin-jvm, so ../../../ is the repo root.
    val provingKey = System.getenv("MEDUSA_PROVING_KEY")
        ?: File(BUNDLED_PK).takeIf { it.exists() }?.canonicalPath

    try {
        val medusa = Perseverus.connect(Config(endpoint = endpoint, dataDir = dataDir, transport = transport, expectedServerPubkey = null, provingKeyPath = provingKey))
        when (args.firstOrNull() ?: "status") {
            "status" -> status(medusa, endpoint, dataDir)
            "import-sparrow" -> importSparrow(medusa, args.getOrNull(1))
            "buy-trial" -> buyTrial(medusa)
            "analyze" -> analyze(medusa, args.drop(1))
            else -> usage()
        }
    } catch (e: PerseverusException) {
        System.err.println("error: ${e::class.simpleName}: ${e.message}")
        exitProcess(1)
    } catch (e: IllegalArgumentException) { // includes NumberFormatException
        System.err.println("error: ${e.message}")
        usage()
        exitProcess(2)
    }
}

private fun usage() {
    println(
        """
        commands:
          status
          import-sparrow [path-to-sparrow-config]
          buy-trial
          analyze <txid>:<vout>:<height> [...] [--decoys N] [--tip HEIGHT]

        Connects over Tor (start it first). --decoys is at least 4; 8 by default.
        """.trimIndent(),
    )
}

private fun isLocalhost(endpoint: String): Boolean {
    val host = runCatching { URI(endpoint).host }.getOrNull()?.removeSurrounding("[", "]") ?: return false
    if (host.equals("localhost", ignoreCase = true) || host == "::1") return true
    val parts = host.split(".")
    return parts.size == 4 && parts[0] == "127" && parts.all { it.toIntOrNull() in 0..255 }
}

/** The chain tip over Tor, from mempool.space's onion, so asking reveals
 *  neither your IP nor when you're about to check coins. */
private fun chainTipOverTor(torSocks: String): UInt {
    val hostPort = torSocks.substringAfter("://").split(":")
    val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(hostPort[0], hostPort.getOrNull(1)?.toInt() ?: 9050))
    return try {
        val conn = URI(MEMPOOL_ONION_TIP).toURL().openConnection(proxy)
        conn.connectTimeout = 60_000
        conn.readTimeout = 60_000
        conn.getInputStream().bufferedReader().readText().trim().toUInt()
    } catch (e: Exception) {
        throw IllegalArgumentException("couldn't get the chain tip over Tor ($torSocks): ${e.message}. Is Tor running? Or pass --tip HEIGHT")
    }
}

private fun status(medusa: Perseverus, endpoint: String, dataDir: String) {
    println("server        $endpoint")
    println("oprf pubkey   ${medusa.serverPubkey()}")
    println("epoch month   ${medusa.currentMonth()}")
    println("data dir      $dataDir")
    println("proving key   ${System.getenv("MEDUSA_PROVING_KEY") ?: File(BUNDLED_PK).takeIf { it.exists() }?.canonicalPath ?: "(none: will try the server)"}")
    println("balance       ${medusa.tokenBalance()} tokens")
    for (p in medusa.listPacks()) {
        val state = if (p.active) "active" else "inactive"
        println("  pack ${p.packId}: ${p.remaining}/${p.size} left, ${p.startMonth}–${p.expirationMonth}, ${p.method}, $state")
    }
    val pending = medusa.pendingPurchases()
    if (pending.isNotEmpty()) println("pending purchases: $pending  (finish with buy-trial, or ignore)")
}

/** Copy the token packs from Sparrow's config so analysis can be tried without paying.
 *  Tokens used here are invisible to Sparrow; if Sparrow later picks one, the
 *  server rejects it as already spent. Fine for testing. */
private fun importSparrow(medusa: Perseverus, path: String?) {
    // The Medusa fork keeps its packs in a side file that stock Sparrow never
    // rewrites; older builds kept them in `config` itself.
    val home = System.getProperty("user.home") + "/.sparrow"
    val candidates = if (path != null) listOf(File(path)) else listOf(File("$home/perseverus-config"), File("$home/config"))
    val file = candidates.firstOrNull { f ->
        f.exists() && JsonParser.parseString(f.readText()).asJsonObject.has("perseverusPacks")
    } ?: run {
        println("no perseverusPacks found in ${candidates.joinToString { it.path }}")
        return
    }
    val packs = JsonParser.parseString(file.readText()).asJsonObject.getAsJsonArray("perseverusPacks")
    println("reading ${packs.size()} pack(s) from ${file.path}")
    var imported = 0
    for (el in packs) {
        val o = el.asJsonObject
        val b = o.get("blob")
        // Gson writes byte[] as a number array by default; accept Base64 too.
        val blob = if (b.isJsonArray) b.asJsonArray.map { it.asInt.toByte() }.toByteArray()
                   else java.util.Base64.getDecoder().decode(b.asString)
        val spent = o.getAsJsonArray("spent")?.map { it.asBoolean }
        try {
            val info = medusa.importPack(blob, "sparrow-import", spent)
            println("imported pack ${info.packId}: ${info.remaining}/${info.size} unspent, active=${info.active}")
            imported++
        } catch (e: PerseverusException) {
            println("skipped one pack: ${e.message}")
        }
    }
    println("$imported pack(s) imported; balance is now ${medusa.tokenBalance()}")
}

private fun buyTrial(medusa: Perseverus) {
    val p = medusa.buyTokens(PayMethod.LIGHTNING, Plan.TRIAL)
    println("Pay this Lightning invoice (${p.amountSat} sats) for ${p.tokens} token(s):\n\n${p.paymentRequest}\n")
    println("Waiting for payment… (Ctrl-C to stop; the purchase is saved and can be redeemed later)")
    while (true) {
        when (medusa.purchaseStatus(p.purchaseId)) {
            PurchaseState.PAID -> break
            PurchaseState.EXPIRED -> { println("invoice expired"); return }
            PurchaseState.REDEEMED -> { println("already redeemed"); return }
            PurchaseState.PENDING -> Thread.sleep(3_000)
        }
    }
    // A yearly card plan yields 13 packs; everything else yields one.
    val packs = medusa.redeem(p.purchaseId)
    for (pack in packs) println("Redeemed: pack ${pack.packId} with ${pack.remaining} token(s), ${pack.startMonth}–${pack.expirationMonth}")
    println("Balance: ${medusa.tokenBalance()}")
}

private fun analyze(medusa: Perseverus, args: List<String>) {
    var decoys = 8u
    var tip: UInt? = null
    val inputs = mutableListOf<InputRef>()
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--decoys" -> decoys = args[++i].toUInt()
            "--tip" -> tip = args[++i].toUInt()
            else -> {
                val parts = args[i].split(":")
                val vout = parts.getOrNull(1)?.toUIntOrNull()
                val height = parts.getOrNull(2)?.toUIntOrNull()
                require(parts.size == 3 && parts[0].length == 64 && vout != null && height != null) {
                    "expected <txid>:<vout>:<height> with real values, e.g. 4a5e…f2c1:0:912345 — got `${args[i]}`"
                }
                inputs += InputRef(txid = parts[0], vout = vout, blockHeight = height, valueSats = null)
            }
        }
        i++
    }
    require(inputs.isNotEmpty()) { "give at least one <txid>:<vout>:<height>" }
    // A real wallet knows its chain tip from its own headers. The sample asks
    // mempool.space's onion over Tor.
    val chainTip = tip ?: chainTipOverTor(System.getenv("MEDUSA_TOR_SOCKS") ?: DEFAULT_TOR_SOCKS)

    println("Analyzing ${inputs.size} input(s), $decoys decoys each, tip $chainTip, balance ${medusa.tokenBalance()}…")
    val t0 = System.currentTimeMillis()
    val result = medusa.analyzeInputs(inputs, AnalyzeOptions(decoysPerInput = decoys, chainTip = chainTip))
    val secs = (System.currentTimeMillis() - t0) / 1000.0
    println(
        "done in ${"%.1f".format(secs)}s: ${result.tokensSpent} token(s) spent, " +
            "${result.filtersDownloaded} filters (${result.bytesDownloaded / 1024u} KB). Balance ${medusa.tokenBalance()}\n",
    )
    result.reports.forEach(::printReport)
}

private fun printReport(r: PrivacyReport) {
    val head = "${r.input.txid.take(16)}…:${r.input.vout} @${r.input.blockHeight}"
    when (r.status) {
        ReportStatus.GRADED -> {
            println("$head  GRADE ${r.grade} (${r.score}/100, band ${r.gradeBand})  ${r.rawTag}")
            r.primaryRecommendation?.let { println("   [${it.urgency}] ${it.headline}") }
            r.findings.forEach { println("   - ${it.severity.name.lowercase()}: ${it.title}") }
        }
        ReportStatus.UNGRADED -> println("$head  ungraded (excluded by skip rules, not a flag; no token spent)")
        ReportStatus.NOT_COVERED -> println("$head  not covered (no filter for this block yet; no token spent)")
        ReportStatus.ERROR -> println("$head  error ${r.error?.code}: ${r.error?.message}")
    }
    println()
}
