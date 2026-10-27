# BTC Medusa developer documentation

BTC Medusa tells a Bitcoin wallet how exposed a coin is to chain analysis **before the user spends it**, without the server ever learning which coin was asked about. This documentation is for wallet developers integrating it, starting with BlueWallet's Blueberry.

You integrate through the **`perseverus-sdk`** library: Rust, with Kotlin bindings for Android and JVM, and Swift bindings for iOS. The library does all the cryptography. You make a handful of calls and show the results.

## Read in this order

| # | Page | What you get from it |
|---|---|---|
| 1 | [How it works](01-how-it-works.md) | The idea in ten minutes: tokens, filters, decoys, and why each exists. Read this first, because the API makes sense once you know why it's shaped this way. |
| 2 | [Quickstart](02-quickstart.md) | Build the SDK, connect to the production server, and analyse a real coin from a small Kotlin program. |
| 3 | [SDK reference](03-sdk-reference.md) | Every function and type: what it does, why it exists, when to call it, examples, errors, and what the server sees. |
| 4 | [Integration guides](04-integration-guides.md) | Complete flows: buying tokens (Lightning, card, yearly), the pre-broadcast check, threading, backups, error handling. |
| 5 | [PrivacyReport field guide](05-privacy-report.md) | Every grade, status, finding and recommendation, and how to show them to users. |
| 6 | [HTTP API reference (`/v1`)](06-http-api.md) | The server endpoints the SDK calls, with real requests and responses. Needed only if you write your own client or debug traffic. |
| 7 | [Privacy and threat model](07-privacy-model.md) | What the server, the network and the payment processors can and cannot learn, and the rules that keep it that way. |
| 8 | [Building for Android, iOS and desktop](08-building.md) | Compiling the native library and bindings into your app. |
| 9 | [Troubleshooting](09-troubleshooting.md) | Error messages, their causes and fixes. |

The machine-readable contract lives in [`blueberry-v1/`](blueberry-v1/):
- `openapi.yaml`: the `/v1` HTTP API
- `privacy-report.schema.json`: the report format
- `findings-catalog.v3lean.json`: all user-facing finding text

## Facts you'll need

| | |
|---|---|
| Production server | `http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion` (Tor only) |
| Server OPRF public key (pin this) | `641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695` |
| API version | `1.x` (`GET /v1/meta` → `api_version`) |
| Spend circuit | `v11`. The proving key file is `pk.bin` (4,394,320 bytes), SHA-256 `2f59e8bde11819b583d117fc75f1be3c7902aba2eb67e6436b3efad392372483`. You ship it inside your app. It's in this repo at [`assets/circuit-v11/`](../assets/circuit-v11/). |
| Kotlin package | `com.btcmedusa.perseverus` |
| Cost of one analysis | 1 token per distinct funding transaction that is graded. Ungraded or uncovered inputs are free. |

## Three rules that matter most

1. **Never send a txid, outpoint or address to the server.** No API in this project does, and none ever will. The whole product depends on it (see [Privacy model](07-privacy-model.md)).
2. **Use Tor.** `Transport.Tor` fails closed. The SDK refuses `Transport.Direct` for any server not on the same machine, so a user's IP never reaches the server.
3. **Back up the SDK's data directory with the wallet.** Tokens are bearer value stored only on the device. If the directory is lost, so are the tokens.

## Getting help

Questions and anything server-side go to Perseverus Privacy Solutions (owner: Valentino Zertuche, GitHub `vazertuche105`).
