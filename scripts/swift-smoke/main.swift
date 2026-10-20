// Swift smoke test for the generated bindings: calls into the real library
// through every kind of type that crosses the FFI (records, enums with and
// without fields, errors, lists, optionals, an object) and checks the
// privacy guards. Run by scripts/swift-smoke.sh against a stand-in server
// that serves only GET /v1/meta.
import Foundation

let pub = "dc03c12db41ba08872513309b777f2375e35215ea46ba5efd8c4a4542c13560b"
var failures = 0

func check(_ ok: Bool, _ what: String) {
    print(ok ? "ok   \(what)" : "FAIL \(what)")
    if !ok { failures += 1 }
}

/// Error case name, independent of how UniFFI cases them in Swift.
func kind(_ e: Error) -> String { String(describing: e).lowercased() }

let endpoint = CommandLine.arguments[1]
let dir = NSTemporaryDirectory() + "perseverus-swift-smoke-\(UUID().uuidString)"

check(minDecoysPerInput() == 4, "minDecoysPerInput() == 4")

// Clearnet to anything but this machine is refused before any request.
do {
    _ = try Perseverus.connect(config: Config(
        endpoint: "http://example.com", dataDir: dir, transport: .direct,
        expectedServerPubkey: nil, provingKeyPath: nil))
    check(false, "Direct to a remote server is refused")
} catch {
    check(kind(error).contains("invalidargument") && kind(error).contains("localhost"),
          "Direct to a remote server is refused (\(error))")
}

// A pinned key that doesn't match is refused.
do {
    _ = try Perseverus.connect(config: Config(
        endpoint: endpoint, dataDir: dir, transport: .direct,
        expectedServerPubkey: String(repeating: "00", count: 32), provingKeyPath: nil))
    check(false, "mismatched pinned key is refused")
} catch {
    check(kind(error).contains("verification"), "mismatched pinned key is refused (\(error))")
}

do {
    let sdk = try Perseverus.connect(config: Config(
        endpoint: endpoint, dataDir: dir, transport: .direct,
        expectedServerPubkey: pub, provingKeyPath: nil))
    check(sdk.serverPubkey() == pub, "connect + pinned key")
    check(try sdk.currentMonth() == 202610, "currentMonth()")
    check(try sdk.tokenBalance() == 0, "tokenBalance() on an empty store")
    check(try sdk.listPacks().isEmpty, "listPacks() returns an empty list")
    check(try sdk.pendingPurchases().isEmpty, "pendingPurchases()")
    try sdk.forgetCachedGrades()
    check(true, "forgetCachedGrades()")

    // Fewer than 4 decoys is refused before anything is sent.
    let input = InputRef(txid: String(repeating: "11", count: 32), vout: 0,
                         blockHeight: 800_000, valueSats: nil)
    do {
        _ = try sdk.analyzeInputs(inputs: [input],
                                  options: AnalyzeOptions(decoysPerInput: 3, chainTip: 900_000))
        check(false, "3 decoys refused")
    } catch {
        check(kind(error).contains("invalidargument"), "3 decoys refused (\(error))")
    }
    // No inputs: an empty result, no tokens.
    let empty = try sdk.analyzeInputs(inputs: [],
                                      options: AnalyzeOptions(decoysPerInput: 8, chainTip: 900_000))
    check(empty.reports.isEmpty && empty.tokensSpent == 0, "analyzeInputs([]) is empty and free")
} catch {
    check(false, "connect to the stand-in server: \(error)")
}

try? FileManager.default.removeItem(atPath: dir)
if failures > 0 { print("swift smoke: \(failures) failure(s)"); exit(1) }
print("swift smoke: all ok")
