# 7. Privacy and threat model

What each party can and cannot learn when a wallet uses BTC Medusa, stated plainly. If you change how the SDK is used, check your change against this page.

## The promise

**The server never learns which coins a user owns or asked about.** No request contains a txid, an outpoint, an address or a balance. Analysis results are computed and decrypted on the device.

> **Current version: one known gap, fix in progress.** In this release the server *can* connect a token spend to the purchase that paid for it (see [Known limitations](#known-limitations), item 1). It still can't see which coins were checked. The fix is a new spend circuit (v11), already implemented and tested; it ships with a one-time key rotation, described in [Upcoming: v11](#upcoming-v11).

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
| **Medusa server** | <ul><li>That some Tor user downloaded filters for a set of block heights (real ones mixed with decoys).</li><li>That some Tor user spent *k* valid tokens at a given time.</li><li>That a payment was made for a plan.</li><li>**Until v11:** which purchase each spend came from (Known limitations, item 1).</li></ul> | <ul><li>Which heights were real (beyond the decoy limits in item 2).</li><li>Any txid, outpoint, address, amount or result.</li><li>The user's IP (Tor).</li><li>The user's balance.</li><li>**From v11:** which payment or pack a spend came from.</li></ul> |
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
4. **Unlinkable spends (v11).** Tokens are generated on the device, and nothing a spend reveals (the nullifier, the month, the public revocation root) can be computed from what the server saw at purchase. In the current release this does not yet hold; see Known limitations, item 1.
5. **Verified server answers.** Every signature and OPRF evaluation comes with a DLEQ proof checked against the pinned server key, so the server can't give a targeted user different results to tag them.
6. **Fail closed.** `Transport.Tor` never falls back to clearnet, and `Transport.Direct` is refused for any server not on the same machine.
7. **Proving key in the app.** `pk.bin` ships with the wallet, so a malicious server can't substitute a key.

## What tokens protect against

Tokens make the service paid, and stop anyone from decrypting a whole block's tags by asking about every transaction. Each token works once, enforced by its nullifier. Packs carry a validity window; from v11 the window is signed into every token and enforced in the proof (in the current release the server checks the month, but the window itself isn't yet bound to the token). Card packs can be revoked if the payment is reversed. Revocation is proven in zero knowledge. The wallet downloads the public revocation list, which is the same for everyone, and builds its proof on the device, so the server never learns which pack a spend came from.

## Known limitations

These are honest edges of the current version, in rough order of importance.

1. **Spends can be linked to the purchase (fixed in v11).** At purchase the wallet sends the unblinded token base points, and the spend's nullifier is the same value those points are built from. So the server can match each spend to the purchase, and therefore to the pack and the other spends from it; for a card purchase, to the card holder. It still can't learn which coins were checked: the lookup is blinded and the heights are mixed with decoys on a separate circuit. v11 derives the nullifier under its own domain tag, so it can't be computed from anything seen at purchase.
2. **Card purchases are linkable by timing.** Stripe knows who paid. Card packs publish an attribution entry (needed for chargebacks) shortly after redemption. A server that correlates times could connect a card holder to a `pack_id`. It can't follow that pack into later checks: spends never reveal `pack_id`, and revocation proofs are built on the device from the public list. It never learns which coins were checked. Users who care should pay over Lightning.
3. **Decoys are probabilistic.** Each real block's decoys are drawn uniformly from a window placed at a random offset around it, so for most coins the real block is no more likely than any decoy. Measured with 8 decoys, the best simple attack (guess the middle or the highest height) picks the real block **about 1 time in 9** (11%) for coins older than a few hours. For coins confirmed in the last ~30 blocks it's 13–16%, because a window can't extend past the chain tip; and a coin in the very block at the tip is always the highest height in its set. (Earlier SDK versions centred the decoys on the real block, which gave it away about 1 time in 3.) Repeated checks of the same coin would let the server intersect decoy sets, so the SDK caches each coin's grade on the device and never looks the same coin up twice (`forgetCachedGrades()` resets that).
4. **A dishonest server could try to tag a wallet with a fake revocation list.** Every spend proof names the revocation root it was built against. A server that served one wallet a doctored list (with an extra, made-up key) would see that unique root in that wallet's spends and could link them. Done passively this is impossible: an honest server serves everyone the same list. Done actively it's detectable, because anyone can fetch the list and compare roots, and the server must also accept the doctored root at spend time. A future SDK may cross-check the root over a second circuit.
5. **Timing.** A check happens shortly before a broadcast. A server that also watches the mempool could try to correlate the time of a spend with transactions appearing soon after. This leaks little, because there are thousands of transactions per block, but don't add patterns that help it, such as running the check only immediately before broadcast with no other traffic. Checking coins at other times, for example from coin control, blurs this.
6. **Filter coverage.** Coins in blocks without filters are `NOT_COVERED`. Nothing leaks, but they aren't assessed.

## Upcoming: v11

v11 is implemented and tested, and ships as one coordinated release:

- **New spend circuit and keys.** The nullifier gets its own domain tag (fixes item 1), the validity window is signed into each token and checked in the proof, and every DLEQ proof binds its whole statement.
- **One-time key rotation.** The server gets a new key, so integrators update the SDK, the bundled `pk.bin` and the pinned `expectedServerPubkey` together. Packs signed by the old key stop working at the switch.
- **No API changes.** The SDK calls you use stay the same; the issuance and spend formats change inside the SDK.

We'll announce the date in advance.

## Integrator checklist

- Never log txids next to Medusa activity, and never send them to analytics or crash reporting together.
- Keep `decoysPerInput` at 8 (4 is the enforced minimum).
- Pin `expectedServerPubkey`.
- Bundle `pk.bin` and verify its hash.
- Don't set `PERSEVERUS_DEBUG` in release builds. The SDK prints nothing by default; with it set, it prints progress and timing to stderr (never txids, tags, heights, pack ids or nullifiers), which on a phone lands in the system log.
- Store `dataDir` like the wallet's own secrets.
- Don't share one token store across devices.
