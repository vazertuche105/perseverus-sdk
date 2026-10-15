# Kotlin/JVM sample

A command-line app that uses `perseverus-sdk` the way a wallet like Blueberry would, without the UI. It needs Rust (`cargo`) and JDK 17 or newer.

```bash
cd sdk/examples/kotlin-jvm
./gradlew run --args="status"
```

The first run builds the Rust library in release mode, generates the Kotlin bindings and compiles the app, which takes a few minutes. Later runs are quick.

| Command | What it does |
|---|---|
| `status` | Server key, epoch month, token balance and packs |
| `import-sparrow` | Copies the Medusa wallet's token packs, from `~/.sparrow/perseverus-config`, so you can try analysis without paying. Tokens you spend here are invisible to Sparrow; if Sparrow later picks one, the server rejects it as already spent. |
| `buy-trial` | Shows a real Lightning invoice (about $0.25, 1 token), waits for payment, then claims the token |
| `analyze <txid>:<vout>:<height> …` | Pre-broadcast analysis. Options: `--decoys N` (default 8, minimum 4) and `--tip HEIGHT` (by default it asks mempool.space's onion over Tor) |

The `txid` is the funding transaction in normal explorer order, and `height` is the block it confirmed in. Sparrow's UTXOs tab shows both.

The app talks to the production `.onion` over Tor, so start Tor first (`brew install tor && tor`; it listens on 127.0.0.1:9050). With Tor Browser instead, set `MEDUSA_TOR_SOCKS=socks5h://127.0.0.1:9150`. The chain tip is also fetched over Tor, from mempool.space's onion, unless you pass `--tip`. Everything is private by default, so it's safe to try with a wallet that holds real funds. `MEDUSA_ENDPOINT` points it elsewhere; only a `localhost` server is reached directly (the SDK refuses clearnet to anything else). Tokens are kept in `~/.perseverus-sample`, which you can change with `MEDUSA_DATA_DIR`.

`analyze` needs the circuit's proving key (`pk.bin`, about 4 MB), which the production server doesn't serve. By default the app uses the repo's copy in `assets/circuit-v10/pk.bin`. To use a different copy, set `MEDUSA_PROVING_KEY=/path/to/pk.bin`.
