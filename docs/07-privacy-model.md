# 7. Privacy and threat model

What each party can and cannot learn when a wallet uses BTC Medusa, stated plainly. If you change how the SDK is used, check your change against this page.

## The promise

**The server never learns which coins a user owns or asked about.** No request contains a txid, an outpoint, an address or a balance. Analysis results are computed and decrypted on the device.

> **Since circuit v11 (live 26 October 2026)** the server also can't connect a token spend to the purchase that paid for it. Before v11 it could; see [Changes in v11](#changes-in-v11).

## Testing with a wallet that holds real funds

You can point a development build at production with your own wallet. Here is exactly what the server receives during an analysis, and nothing else:

| Request | What it carries |
|---|---|
| `GET /v1/meta`, `/v1/codebook`, `/v1/revocation/root`, `/v1/revocation/list` | Nothing. The same public data every wallet downloads. |
| `POST /v1/filters/batch` | A shuffled list of block heights: each real one hidden among decoys. |
| `POST /v1/analyze/batch` | Per matched funding transaction: a **blinded** curve point (the txid multiplied by a random secret that never leaves the phone) and a zero-knowledge spend proof (a one-time nullifier, the month, the public revocation root). No heights. |

This is checked, not just stated. An end-to-end test records every byte a wallet sends to the server (URLs, headers and bodies) across real spends, a double-spend and a revoked pack. It fails if any of these appear: the txids in either byte order, their prefixes, the **unblinded** txid points (which is what would leak if blinding were skipped), the pack id, the token seed, or a real block height without at least three decoys. The test is `analyze_inputs_end_to_end` in the server repository; it's run before each release.

**Debug mode doesn't change this.** `PERSEVERUS_DEBUG=1` only prints to the device's own stderr. It sends nothing extra to the server, and even locally it never prints txids, tags, heights, pack ids or nullifiers.

The SDK also enforces the two settings that could weaken this:

- **Tor only.** `connect` refuses `Transport.Direct` for any server not on your own machine, so the server never sees your IP address.
- **At least 4 decoys** per real block (8 recommended). Fewer is refused before anything is sent.

One choice is still yours: **prefer Lightning over card** if you'd rather your identity weren't attached even to the purchase. A card payment tells Stripe and the server who bought tokens, though never what they checked.

## Who sees what

| Party | Can learn | Cannot learn |
|---|---|---|
| **Medusa server** | <ul><li>That some Tor user downloaded filters for a set of block heights (real ones mixed with decoys).</li><li>That some Tor user spent *k* valid tokens at a given time.</li><li>That a payment was made for a plan.</li></ul> | <ul><li>Which heights were real (beyond the decoy limits in Known limitations, item 3).</li><li>Any txid, outpoint, address, amount or result.</li><li>The user's IP (Tor).</li><li>The user's balance.</li><li>Which payment or pack a spend came from (given an honestly built `pk.bin`; see Known limitations, item 1).</li></ul> |
| **Network observer** (ISP, Wi-Fi) | That the device uses Tor. | Anything about Medusa traffic. |
| **Tor exit / relays** | Nothing. The server is an onion service, so traffic never leaves Tor. | |
| **Lightning payment path** | A payment of the invoice amount to the server's node. | What it's for, beyond the invoice description. |
| **Stripe (card payments)** | Card holder identity, IP, amount, and that the purchase was from Perseverus. | Anything about tokens or queries. |
| **Someone with the device's `dataDir`** | The user's unspent tokens. They can spend them. | Past queries; the SDK stores no query history. Reports your app caches are your responsibility. |

## The rules that make it hold

The SDK enforces all of these. Don't work around them.

1. **No transaction identifiers leave the device.** Matching happens locally against downloaded filters. There is no "look up txid X" API, and adding one, even for debugging, would break the product.
2. **Decoys.** Real block heights are mixed with decoys drawn around them (see Known limitations) and shuffled. Use `decoysPerInput = 8`; the SDK refuses fewer than 4.
3. **Separate circuits, no heights on spends.** Filter downloads, token spends, redemptions and board publishes each use a different Tor circuit. The spend request carries no heights, so the server can't join a spend to the filter download that preceded it.
4. **Unlinkable spends.** Tokens are generated on the device, and nothing a spend reveals (the nullifier, the month, the public revocation root) can be computed from what the server saw at purchase: the nullifier is derived under its own domain tag, separate from the token points the server signs.
5. **Verified server answers.** Every signature and OPRF evaluation comes with a DLEQ proof checked against the pinned server key, so the server can't give a targeted user different results to tag them.
6. **Fail closed.** `Transport.Tor` never falls back to clearnet, and `Transport.Direct` is refused for any server not on the same machine.
7. **Proving key in the app.** `pk.bin` ships with the wallet, so a malicious server can't substitute a key.

## What tokens protect against

Tokens make the service paid, and stop anyone from decrypting a whole block's tags by asking about every transaction. Each token works once, enforced by its nullifier. Packs carry a validity window, signed into every token by the server and enforced inside the proof, so a wallet can't stretch a pack past its months. Card packs can be revoked if the payment is reversed. Revocation is proven in zero knowledge. The wallet downloads the public revocation list, which is the same for everyone, and builds its proof on the device, so the server never learns which pack a spend came from.

## Known limitations

These are honest edges of the current version, in rough order of importance.

1. **The proving key comes from a one-party setup (until the ceremony).** `pk.bin` was generated by Perseverus alone. Proofs made with a correctly built key reveal nothing about the token, but a deliberately malformed key could make them link a spend to its purchase, and a normal proof check would not notice. A multi-party setup with independent participants (BlueWallet first) will replace it before public launch; its `verify` tool lets anyone confirm the published `pk.bin` was built correctly. Until then, this guarantee rests on trusting Perseverus. Which coins were checked is protected either way, by blinding and decoys, not by the proof.
2. **Card purchases are tied to their pack.** Stripe knows who paid. So that a chargeback can revoke the right pack, each card pack publishes an attribution entry, and the publish carries a one-time ticket handed out with that card redemption (this stops strangers filling the board). So the server knows which `pack_id` a card purchase received. It can't follow that pack into later checks: spends never reveal `pack_id`, and revocation proofs are built on the device from the public list. It never learns which coins were checked. Lightning and on-chain packs publish nothing. Users who care should pay over Lightning.
3. **Decoys are probabilistic.** Each real block's decoys are drawn uniformly from a window placed at a random offset around it, so for most coins the real block is no more likely than any decoy. Measured with 8 decoys, the best simple attack (guess the middle or the highest height) picks the real block **about 1 time in 9** (11%) for coins older than a few hours. For coins confirmed in the last ~30 blocks it's 13–16%, because a window can't extend past the chain tip; and a coin in the very block at the tip is always the highest height in its set. (Earlier SDK versions centred the decoys on the real block, which gave it away about 1 time in 3.) Repeated checks of the same coin would let the server intersect decoy sets, so the SDK caches each coin's grade on the device and never looks the same coin up twice (`forgetCachedGrades()` resets that).
4. **A dishonest server could try to tag a wallet with a fake revocation list.** Every spend proof names the revocation root it was built against. A server that served one wallet a doctored list (with an extra, made-up key) would see that unique root in that wallet's spends and could link them. Done passively this is impossible: an honest server serves everyone the same list. Done actively it's detectable, because anyone can fetch the list and compare roots, and the server must also accept the doctored root at spend time. A future SDK may cross-check the root over a second circuit.
5. **Timing.** A check happens shortly before a broadcast. A server that also watches the mempool could try to correlate the time of a spend with transactions appearing soon after. This leaks little, because there are thousands of transactions per block, but don't add patterns that help it, such as running the check only immediately before broadcast with no other traffic. Checking coins at other times, for example from coin control, blurs this.
6. **Filter coverage.** Coins in blocks without filters are `NOT_COVERED`. Nothing leaks, but they aren't assessed.

## Changes in v11

Circuit v11 went live on 26 October 2026, with a one-time key rotation:

- **Spends are unlinkable from purchases.** Before v11, the spend's nullifier was the same value the token points shown at purchase were built from, so the server could match each spend to its purchase (and, for a card purchase, to the card holder). v11 derives the nullifier under its own domain tag.
- **Validity window in the proof.** The server signs each token's months; the proof enforces them.
- **Every DLEQ proof binds its whole statement.**
- **New server key.** `expectedServerPubkey` is now `641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695` and the bundled key is `assets/circuit-v11/pk.bin`. Packs signed by the old key (`dc03c12d…560b`) no longer work. An app that still pins the old key is refused at `connect` (`Verification`), and its spends, made with the v10 `pk.bin`, would not verify anyway. From v11 on, the SDK also checks `circuit.version` at `connect` and refuses a server on a different circuit (`Unsupported`), so a future circuit change fails clearly up front.
- **No API changes.** The SDK calls stay the same; the issuance and spend formats changed inside the SDK.

## Integrator checklist

- Never log txids next to Medusa activity, and never send them to analytics or crash reporting together.
- Keep `decoysPerInput` at 8 (4 is the enforced minimum).
- Pin `expectedServerPubkey`.
- Bundle `pk.bin` and verify its hash.
- Don't set `PERSEVERUS_DEBUG` in release builds. The SDK prints nothing by default; with it set, it prints progress and timing to stderr (never txids, tags, heights, pack ids or nullifiers), which on a phone lands in the system log.
- Store `dataDir` like the wallet's own secrets.
- Don't share one token store across devices.
