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
| `analyze <txid>:<vout>:<height> …` | Pre-broadcast analysis. Options: `--decoys N` (default 8) and `--tip HEIGHT` (by default it asks mempool.space for the chain tip) |

The `txid` is the funding transaction in normal explorer order, and `height` is the block it confirmed in. Sparrow's UTXOs tab shows both.

By default the app talks to the dev server over clearnet. Set `MEDUSA_ENDPOINT` to the `.onion` address to go through Tor; a Tor daemon must be running on 127.0.0.1:9050. Tokens are kept in `~/.perseverus-sample`, which you can change with `MEDUSA_DATA_DIR`.
