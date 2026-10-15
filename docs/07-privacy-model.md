# 7. Privacy and threat model

What each party can and cannot learn when a wallet uses BTC Medusa, stated plainly. If you change how the SDK is used, check your change against this page.

## The promise

**The server never learns which coins a user owns or asked about.** No request contains a txid, an outpoint, an address or a balance. Analysis results are computed and decrypted on the device.

## Testing with a wallet that holds real funds

You can point a development build at production with your own wallet. Here is exactly what the server receives during an analysis, and nothing else:

| Request | What it carries |
|---|---|
| `GET /v1/meta`, `/v1/codebook`, `/v1/revocation/root`, `/v1/revocation/list` | Nothing. The same public data every wallet downloads. |
| `POST /v1/filters/batch` | A shuffled list of block heights: each real one hidden among decoys. |
| `POST /v1/analyze/batch` | Per matched funding transaction: a **blinded** curve point (the txid multiplied by a random secret that never leaves the phone) and a zero-knowledge spend proof (a one-time nullifier, the month, the public revocation root). No heights. |

This is checked, not just stated. An end-to-end test records every byte a wallet sends to the server (URLs, headers and bodies) across real spends, a double-spend and a revoked pack. It fails if any of these appear: the txids in either byte order, their prefixes, the **unblinded** txid points (which is what would leak if blinding were skipped), the pack id, the token seed, or a real block height without at least three decoys. The test is `analyze_inputs_end_to_end` in the server repository; it's run before each release.

**Debug mode doesn't change this.** `PERSEVERUS_DEBUG=1` only prints to the device's own stderr. It sends nothing extra to the server, and even locally it never prints txids, tags, heights, pack ids or nullifiers.

Three things are still up to you when testing with real funds:

- **Use Tor.** With `Transport.Direct`, the server sees your IP address and when you checked. That still says nothing about which coins, but your IP plus timing is information. Use the `.onion` endpoint with `Transport.Tor`.
- **Keep decoys at 8 or more.** `decoysPerInput = 0` sends your coins' real block heights unhidden.
- **Prefer Lightning over card** if you'd rather your identity weren't attached even to the purchase. A card payment tells Stripe and the server who bought tokens, though never what they checked.

## Who sees what

| Party | Can learn | Cannot learn |
|---|---|---|
| **Medusa server** | <ul><li>That some Tor user downloaded filters for a set of block heights (real ones mixed with decoys).</li><li>That some Tor user spent *k* valid tokens at a given time.</li><li>That a payment was made for a plan.</li></ul> | <ul><li>Which heights were real.</li><li>Any txid, outpoint, address, amount or result.</li><li>The user's IP (Tor).</li><li>Which payment or pack a spend came from (blind signatures; revocation proofs are built on the device).</li><li>The user's balance.</li></ul> |
| **Network observer** (ISP, Wi-Fi) | That the device uses Tor. | Anything about Medusa traffic. |
| **Tor exit / relays** | Nothing. The server is an onion service, so traffic never leaves Tor. | |
| **Lightning payment path** | A payment of the invoice amount to the server's node. | What it's for, beyond the invoice description. |
| **Stripe (card payments)** | Card holder identity, IP, amount, and that the purchase was from Perseverus. | Anything about tokens or queries. |
| **Someone with the device's `dataDir`** | The user's unspent tokens. They can spend them. | Past queries; the SDK stores no query history. Reports your app caches are your responsibility. |

## The rules that make it hold

The SDK enforces all of these. Don't work around them.

1. **No transaction identifiers leave the device.** Matching happens locally against downloaded filters. There is no "look up txid X" API, and adding one, even for debugging, would break the product.
2. **Decoys.** Real block heights are mixed with Laplace-distributed decoys and shuffled. Use `decoysPerInput >= 8`. With `0`, the server learns the exact blocks the user's coins came from.
3. **Separate circuits, no heights on spends.** Filter downloads, token spends, redemptions and board publishes each use a different Tor circuit. The spend request carries no heights, so the server can't join a spend to the filter download that preceded it.
4. **Blind issuance.** Tokens are generated and blinded on the device; the server signs without seeing them. A spend can't be traced to the purchase that paid for it.
5. **Verified server answers.** Every signature and OPRF evaluation comes with a DLEQ proof checked against the pinned server key, so the server can't give a targeted user different results to tag them.
6. **Fail closed.** `Transport.Tor` never falls back to clearnet.
7. **Proving key in the app.** `pk.bin` ships with the wallet, so a malicious server can't substitute a key.

## What tokens protect against

Tokens make the service paid, and stop anyone from decrypting a whole block's tags by asking about every transaction. Each token works once, enforced by its nullifier, and packs expire. Card packs can be revoked if the payment is reversed. Revocation is proven in zero knowledge. The wallet downloads the public revocation list, which is the same for everyone, and builds its proof on the device, so the server never learns which pack a spend came from.

## Known limitations

These are honest edges of the current version, in rough order of importance.

1. **Card purchases are linkable by timing.** Stripe knows who paid. Card packs publish an attribution entry (needed for chargebacks) shortly after redemption. A server that correlates times could connect a card holder to a `pack_id`. It can't follow that pack into later checks: spends never reveal `pack_id`, and revocation proofs are built on the device from the public list. It never learns which coins were checked. Users who care should pay over Lightning.
2. **Decoys are probabilistic.** With 8 decoys per real block, the server's best guess at the real block is about 1 in 9 per check. The guess can sharpen if the same user's checks can be linked (by network timing, for instance) and their real blocks recur. More decoys cost more bandwidth.
3. **A dishonest server could try to tag a wallet with a fake revocation list.** Every spend proof names the revocation root it was built against. A server that served one wallet a doctored list (with an extra, made-up key) would see that unique root in that wallet's spends and could link them. Done passively this is impossible: an honest server serves everyone the same list. Done actively it's detectable, because anyone can fetch the list and compare roots, and the server must also accept the doctored root at spend time. A future SDK may cross-check the root over a second circuit.
4. **Timing.** A check happens shortly before a broadcast. A server that also watches the mempool could try to correlate the time of a spend with transactions appearing soon after. This leaks little, because there are thousands of transactions per block, but don't add patterns that help it, such as running the check only immediately before broadcast with no other traffic. Checking coins at other times, for example from coin control, blurs this.
5. **Filter coverage.** Coins in blocks without filters are `NOT_COVERED`. Nothing leaks, but they aren't assessed.

## Integrator checklist

- Never log txids next to Medusa activity, and never send them to analytics or crash reporting together.
- Keep `decoysPerInput >= 8`.
- Pin `expectedServerPubkey`.
- Bundle `pk.bin` and verify its hash.
- Don't set `PERSEVERUS_DEBUG` in release builds. The SDK prints nothing by default; with it set, it prints progress and timing to stderr (never txids, tags, heights, pack ids or nullifiers), which on a phone lands in the system log.
- Store `dataDir` like the wallet's own secrets.
- Don't share one token store across devices.
