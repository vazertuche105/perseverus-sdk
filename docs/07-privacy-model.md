# 7. Privacy and threat model

What each party can and cannot learn when a wallet uses BTC Medusa, stated plainly. If you change how the SDK is used, check your change against this page.

## The promise

**The server never learns which coins a user owns or asked about.** No request contains a txid, an outpoint, an address or a balance. Analysis results are computed and decrypted on the device.

## Who sees what

| Party | Can learn | Cannot learn |
|---|---|---|
| **Medusa server** | <ul><li>That some Tor user downloaded filters for a set of block heights (real ones mixed with decoys).</li><li>That some Tor user spent *k* valid tokens at a given time.</li><li>That a payment was made for a plan.</li><li>Which pack a spend draws from (see [known limitations](#known-limitations)).</li></ul> | <ul><li>Which heights were real.</li><li>Any txid, outpoint, address, amount or result.</li><li>The user's IP (Tor).</li><li>Which payment a spend came from, beyond timing (blind signatures).</li><li>The user's balance.</li></ul> |
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

Tokens make the service paid, and stop anyone from decrypting a whole block's tags by asking about every transaction. Each token works once, enforced by its nullifier, and packs expire. Card packs can be revoked if the payment is reversed. Revocation is proven in zero knowledge, without revealing which pack is being checked inside the proof itself.

## Known limitations

These are honest edges of the current version, in rough order of importance.

1. **Spends from the same pack are linkable to each other.** To build a spend proof, the SDK fetches the pack's revocation proof (`GET /v1/revocation/proof/{pack_id}`) over the same circuit as the spend. The server can therefore tell that two checks used tokens from the same pack: it learns "the same anonymous user ran these N checks at these times". It still learns nothing about *what* was checked. **Planned fix:** compute revocation proofs on the device from the public revocation list, or fetch them on separate circuits ahead of time, so `pack_id` never travels near a spend.
2. **Card purchases are linkable by timing.** Stripe knows who paid. Card packs publish an attribution entry (needed for chargebacks) shortly after redemption. A server that correlates times could connect a card holder to a `pack_id`, and through limitation 1, to the *number and timing* of that pack's checks. It still never learns which coins were checked. Users who care should pay over Lightning.
3. **Decoys are probabilistic.** With 8 decoys per real block, the server's best guess at the real block is about 1 in 9 per check. The guess can sharpen if the same user's checks can be linked (limitation 1) and their real blocks recur. More decoys cost more bandwidth.
4. **Timing.** A check happens shortly before a broadcast. A server that also watches the mempool could try to correlate the time of a spend with transactions appearing soon after. This leaks little, because there are thousands of transactions per block, but don't add patterns that help it, such as running the check only immediately before broadcast with no other traffic. Checking coins at other times, for example from coin control, blurs this.
5. **Filter coverage.** Coins in blocks without filters are `NOT_COVERED`. Nothing leaks, but they aren't assessed.

## Integrator checklist

- Never log txids next to Medusa activity, and never send them to analytics or crash reporting together.
- Keep `decoysPerInput >= 8`.
- Pin `expectedServerPubkey`.
- Bundle `pk.bin` and verify its hash.
- Store `dataDir` like the wallet's own secrets.
- Don't share one token store across devices.
