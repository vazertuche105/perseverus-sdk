# 6. HTTP API reference (`/v1`)

**Most integrators don't need this page.** The SDK makes all of these calls and does the cryptography around them. Read it if you're debugging traffic, building a client in another language, or want to know exactly what goes over the wire. The formal contract is [`blueberry-v1/openapi.yaml`](blueberry-v1/openapi.yaml).

Responses on this page come from the server's own test suite, which records real exchanges, plus `GET /v1/meta` from production. Long hex values are shortened with `…`. Requests marked *illustrative* have the right shape with made-up values.

## Basics

| | |
|---|---|
| Base URL | `http://medusayl5rrmgnekpabcduw7onhvdowmfart2mulq3b64chgzng52had.onion` over Tor (`socks5h`). Always connect over Tor: anything else shows the server your IP address. |
| Format | JSON, `snake_case`. Binary values are lowercase hex. Curve points are compressed Baby Jubjub (32 bytes). Field elements are BN254 Fr, little-endian (32 bytes). Months are `YYYYMM` integers. |
| Auth | None. Tokens and purchase ids are the only credentials, and they travel in request bodies. |
| Idempotency | `Idempotency-Key` header (1–128 chars) on `tokens/purchase`, `tokens/redeem` and `analyze/batch`. The same key and body within 24 h replays the stored response with header `Idempotent-Replayed: true`. The same key with a different body is refused with `422 idempotency_key_reused`. 5xx responses aren't stored. Keys are held in memory, so a server restart forgets them. |
| Caching | `codebook`, `circuit/pk` and `circuit/vk` send `ETag`. Send `If-None-Match` to get `304`. |
| Privacy rule | **No endpoint takes a txid, outpoint or address, and none ever will.** `filters/batch` and `analyze/batch` must go over different Tor circuits, and the analyze request carries no heights. |

## The error envelope

Every error, including bad JSON and unknown routes, has the same shape:

```json
{ "error": { "code": "not_found", "message": "no such /v1 endpoint", "retryable": false } }
```

Branch on `code`. `message` is for logs and may change. `retryable: true` means the same request may succeed later.

### Error codes

| `code` | HTTP | Meaning | Retryable |
|---|---|---|---|
| `bad_request` | 400 | Malformed JSON, missing or invalid field, or an invalid plan/method combination. | no |
| `batch_too_large` | 400 | More than the limit in `/v1/meta` `limits` (200 heights, 64 spends, 13 packs). | no |
| `payment_required` | 402 | The purchase isn't paid yet. | no (poll status, then retry) |
| `underpaid` | 402 | The Lightning amount is below the plan's price. | no |
| `plan_unavailable` | 403 | The `dev` plan was asked for on a server that doesn't sell it. | no |
| `credential_invalid` | 403 | The redemption credential isn't valid. | no |
| `credential_expired` | 403 | The redemption credential has expired. | no |
| `proof_invalid` | 403 | The spend proof didn't verify (analyze). | no |
| `revocation_root_mismatch` | 403 | The proof used an old revocation root; refetch it and re-prove. | no |
| `ticket_invalid` | 403 | Board publish without a valid one-time ticket from the card redemption. | no |
| `forbidden` | 403 | Other refusal. | no |
| `not_found` | 404 | Unknown route, purchase (or card purchase already redeemed), codebook or key. | no |
| `nullifier_spent` | 409 | This token was already spent (analyze). | no |
| `credential_used` | 409 | The purchase was already redeemed. | no |
| `slot_taken` | 409 | The revocation slot for this `pack_id` is in use; pick another id (board). | no |
| `conflict` | 409 | Other conflict. | no |
| `idempotency_key_reused` | 422 | Same `Idempotency-Key`, different body. | no |
| `not_implemented` | 501 | Not offered through this endpoint (e.g. `method: btc` purchases). | no |
| `upstream_unavailable` | 502/503/504 | The price feed or payment processor is unreachable. | **yes** |
| `not_configured` | 503 | That payment method is disabled on this server. | no |
| `internal` | 500 | A server bug. | **yes** |

New codes may be added; treat unknown ones like `internal`.

---

## Endpoints at a glance

| Method | Path | Purpose | SDK call |
|---|---|---|---|
| GET | [`/v1/meta`](#get-v1meta) | Server key, month, limits, coverage | `connect`, `currentMonth`, `tokenBalance` |
| POST | [`/v1/tokens/purchase`](#post-v1tokenspurchase) | Start a purchase | `buyTokens` |
| GET | [`/v1/tokens/purchase/{id}/status`](#get-v1tokenspurchaseidstatus) | Poll payment | `purchaseStatus` |
| POST | [`/v1/tokens/redeem`](#post-v1tokensredeem) | Blind-sign token packs | `redeem` |
| GET | [`/v1/board/slots`](#get-v1boardslots) | Occupied revocation slots | `redeem` |
| POST | [`/v1/board/publish`](#post-v1boardpublish) | Card pack attribution entry | `redeem` (card) |
| POST | [`/v1/filters/batch`](#post-v1filtersbatch) | Encrypted filters for heights | `analyzeInputs` |
| GET | [`/v1/codebook`](#get-v1codebook) | Tag codebook | `analyzeInputs` |
| GET | [`/v1/revocation/root`](#get-v1revocationroot) | Current revocation root | `analyzeInputs` |
| GET | [`/v1/revocation/list`](#get-v1revocationlist) | Every revoked key (proofs are built on the device) | `analyzeInputs` |
| GET | [`/v1/revocation/proof/{pack_id}`](#get-v1revocationproofpack_id) | Deprecated: server-built proof | none |
| POST | [`/v1/analyze/batch`](#post-v1analyzebatch) | Spend tokens, get OPRF evaluations | `analyzeInputs` |
| GET | [`/v1/circuit/pk`](#get-v1circuitpk-and-v1circuitvk), `/v1/circuit/vk` | Groth16 keys | (fallback only) |

---

## `GET /v1/meta`

**Why:** the first call a client makes. It returns the key to pin, the month to prove against, the limits and the filter coverage.

```bash
curl --socks5-hostname 127.0.0.1:9050 http://medusayl5…had.onion/v1/meta
```

Production response (2026-10-15):

```json
{
  "api_version": "1.0.0",
  "min_client_version": "0.1.0",
  "server_pubkey_hex": "641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695",
  "current_month": 202610,
  "test_clock": false,
  "circuit": { "version": "v11", "pk_sha256": null,
               "vk_sha256": "c2ed4f41c8bdffb1a9bccb5e9aaca9c7bda263d06f2b39b82ffadc3312a6db06" },
  "filters": { "format_version": 5, "tag_format": "v3-lean", "codebook_id": "00a19be3",
               "covered_ranges": [ {"from": 485486, "to": 485486}, {"from": 485488, "to": 485488},
                                   {"from": 485490, "to": 501725}, {"from": 501727, "to": 969210} ] },
  "limits": { "max_filters_per_batch": 200, "max_spends_per_batch": 64,
              "max_tokens_per_pack": 1024, "max_packs_per_redeem": 13 },
  "payment_methods": [ "…" ]
}
```

Test servers that sell the [`dev` plan](#post-v1tokenspurchase) also include:

```json
  "dev_plan": { "usd": 0.10, "tokens": 100 }
```

| Field | Use |
|---|---|
| `api_version` | Refuse anything that isn't `1.x`. |
| `min_client_version` | If your client is older, it must update. |
| `server_pubkey_hex` | Pin it. Every signature and evaluation is verified against it. |
| `current_month` | The epoch month. It goes into every spend proof, and it decides pack validity. It follows the blockchain's clock. |
| `test_clock` | `true` only on test servers with a simulated clock. Production is always `false`. |
| `circuit.pk_sha256` | `null` because production doesn't serve the proving key; apps ship `pk.bin`. |
| `filters.covered_ranges` | Block heights that have filters. Heights outside these are *not covered*. |
| `payment_methods` | Which of `lightning`, `card` and `btc` are enabled right now. |
| `dev_plan` | Only on servers that sell the testing plan: `{ "usd": 0.10, "tokens": 100 }`. Absent in production. |

## `POST /v1/tokens/purchase`

**Why:** starts a payment. **Request:**

```json
{ "method": "lightning", "plan": "onetime" }
```

`method`: `lightning` | `card` | `btc`. `plan`: `trial` (Lightning, 1 token), `onetime` (100), `monthly` (card), `yearly` (card, 13 packs), `dev` (Lightning, 100 tokens at a token price; test servers only, see `dev_plan` in `/v1/meta`). Card requests may add `success_url` and `cancel_url`.

**`201` response** (illustrative values):

```json
{
  "purchase_id": "ln_9c1e7a4b2f…",
  "method": "lightning",
  "plan": "onetime",
  "packs": 1,
  "tokens": 100,
  "expires_at": 1792051200,
  "payment": { "kind": "lightning", "bolt11": "lnbc128460n1p…", "amount_sat": 12846 }
}
```

For cards, `payment` is `{ "kind": "card", "checkout_url": "https://checkout.stripe.com/…" }` and the id starts with `card_`. **`purchase_id` is a bearer credential**: whoever holds it can redeem the paid tokens.

Recorded errors:

```json
{ "error": { "code": "bad_request", "message": "plan \"trial\" is not available by card; use onetime, monthly or yearly", "retryable": false } }
{ "error": { "code": "bad_request", "message": "monthly and yearly plans are card-only; use plan \"onetime\" or \"trial\"", "retryable": false } }
{ "error": { "code": "bad_request", "message": "unknown method \"paypal\"; use lightning or card", "retryable": false } }
{ "error": { "code": "plan_unavailable", "message": "the dev plan is only sold by test servers; use plan \"trial\" or \"onetime\"", "retryable": false } }
{ "error": { "code": "not_configured", "message": "Stripe not configured", "retryable": false } }
{ "error": { "code": "not_implemented", "message": "on-chain (silent payment) purchases are issued by the separate payment scanner; redeem its psbtc1 code with POST /v1/tokens/redeem {\"btc_code\": ...}", "retryable": false } }
```

## `GET /v1/tokens/purchase/{id}/status`

**Why:** poll while the user pays.

```json
{ "purchase_id": "card_pend", "state": "pending" }
{ "purchase_id": "card_paid1", "state": "paid" }
```

`state`: `pending` | `paid` | `redeemed` | `expired`. Lightning responses also include `expires_at`. Card purchases return `404 not_found` once redeemed.

## `POST /v1/tokens/redeem`

**Why:** turns a paid purchase into tokens the server has signed without seeing them. This one request is the only link between a payment and its tokens.

**Request** (illustrative). One entry in `packs` per pack: 1, or up to 13 for card `yearly`. Each pack carries the client's blinded points:

```json
{
  "purchase_id": "card_3f9a…",
  "packs": [
    { "alphas":      ["5e0c…(64 hex)", "a17b…", "…"],
      "base_points": ["0d93…(64 hex)", "44f1…", "…"] }
  ]
}
```

Send exactly one of `purchase_id` or `btc_code` (a `psbtc1…` code from the silent-payment scanner). `alphas[i] = r_i · base_points[i]`, where `r_i` is the client's secret blinding factor. `base_points[i]` is derived from the client's secret seed, the `pack_id` and `i`. The server validates the whole request **before** using up the credential, so a malformed request never burns a paid purchase. Always send an `Idempotency-Key`, so a dropped connection can be retried safely.

**`200` response** (recorded). There is one signed pack per requested pack, in order:

```json
{
  "packs": [{
    "betas": ["ac9a5592d7509507a23b6d6344207d976df88cb0cf9214da378597c4d5755d97",
              "bc56604c6c867b6012e031b83234661dc4e0427d5a57425250bd87a24643b9ae",
              "160790a19ef87f8dcd3ef98f523bb69ce288f710492e7ea5ae244d572346ac2b"],
    "proof_challenge": "581e347e98bd88fd24aa987f64ea6df2638ee46c7ce2ee129fbe36cc160a5601",
    "proof_response":  "3a11965af8bf06ced2b1df39292c019699948296d07968691d3568e47cfd7e02",
    "poseidon_proofs": [["6e8dced1…08613", "01cd9840…11a01"],
                        ["d0727b40…e3311", "132afa33…53900"],
                        ["bb3dcf3f…d7e00", "4677473e…21205"]]
  }]
}
```

- `betas[i]` is `alphas[i]` multiplied by the server key.
- `proof_challenge` and `proof_response` form a batched DLEQ proof that the same, published key was used for every token. The client **must** verify it.
- `poseidon_proofs` are per-token proofs used later inside the spend circuit.
- `board_ticket` (card packs only): a one-time ticket for this pack's [`POST /v1/board/publish`](#post-v1boardpublish). Lightning and on-chain packs don't get one and don't publish.

Recorded errors:

```json
{ "error": { "code": "payment_required", "message": "card payment not confirmed yet", "retryable": false } }
{ "error": { "code": "not_found", "message": "unknown or already-redeemed purchase_id", "retryable": false } }
{ "error": { "code": "bad_request", "message": "this code's plan (onetime) allows 1 pack(s), 2 requested", "retryable": false } }
{ "error": { "code": "bad_request", "message": "send exactly one of purchase_id or btc_code", "retryable": false } }
{ "error": { "code": "idempotency_key_reused", "message": "this Idempotency-Key was already used with a different request body", "retryable": false } }
```

## `GET /v1/board/slots`

**Why:** each pack id maps to a 16-bit slot in the revocation tree. Before choosing `pack_id`s, the client reads the taken slots and re-rolls any id that collides.

```json
{ "slots": [] }
```

## `POST /v1/board/publish`

**Why:** card packs only. It publishes an attribution entry so the pack can be revoked after a chargeback. Send it over a Tor circuit isolated from the redeem call.

```json
{ "pack_id": 12873466129870023, "tag_hex": "1f0c…(64 hex)", "expiration_month": 202611,
  "ticket": "9b41…(64 hex)" }
```

`ticket` is the pack's `board_ticket` from the redeem response. A new entry needs one; each ticket works once and lasts 30 days. Without tickets anyone could fill the board's 65,536 slots and block every future purchase. Republishing an entry that's already on the board (same `pack_id`, tag and month) succeeds without a ticket and changes nothing. The board is kept on disk, so there's no need to republish after a server restart.

The response is `{ "board_size": 42, "board_root_hex": "…" }`. Errors: `403 ticket_invalid` (missing, made up, expired or already used), `409 slot_taken`, `400 bad_request`.

## `POST /v1/filters/batch`

**Why:** fetch the encrypted filters for real heights mixed with decoys. The server can't tell which heights are real.

```json
{ "heights": [800000, 800001] }
```

Recorded response:

```json
{ "filters": [ { "height": 800000, "num_entries": 0, "filter_hex": "505356520500350c00" } ],
  "missing": [800001] }
```

- `filter_hex` is a v5 block filter (`PSVR` magic, format byte `05`). Real filters are tens to hundreds of KB. Its layout is in `core/src/filter.rs`.
- `missing` heights have no filter. They are never built on demand; treat those inputs as *not covered*.
- At most 200 heights per request:
  `{ "error": { "code": "batch_too_large", "message": "too many heights (201), max 200", "retryable": false } }`

## `GET /v1/codebook`

**Why:** a decrypted filter value is an index into this public table, which maps it to a 24-bit tag. Download it once per `codebook_id`, and check that every filter's `codebook_id` matches it.

```json
{ "codebook_hex": "50534342010201000000c0deb00caabbcc", "codebook_id": "c0deb00c", "len": 17 }
```

The `ETag` / `If-None-Match` pair returns `304` when unchanged. A server with no codebook returns `404 not_found`.

## `GET /v1/revocation/root`

**Why:** every spend proof proves "my pack isn't revoked" against this root. Proofs against an old root are refused with `revocation_root_mismatch`.

```json
{ "revocation_root_hex": "0000000000000000000000000000000000000000000000000000000000000000" }
```

## `GET /v1/revocation/list`

**Why:** every spend proof includes "my pack isn't revoked". Rather than asking the server for that proof (which would reveal the pack), the client downloads the whole list, which is the same for everyone, and builds the proof itself.

```json
{ "revocation_root_hex": "4f1a…(64 hex)",
  "revoked_keys_hex": ["9c27…(64 hex)", "d013…(64 hex)"] }
```

Each key is `Poseidon(pack_id)` as a compressed field element. To use it, rebuild the tree in the given order (`SparseMerkleTree::from_keys` in `perseverus-core`), check its root equals `revocation_root_hex`, and take your pack's non-inclusion proof from it. If your pack's slot is occupied, the pack is revoked. The list is empty (and the root all zeros) until the first revocation; it stays small, since only charged-back card packs are revoked.

## `GET /v1/revocation/proof/{pack_id}`

**Deprecated.** It puts `pack_id` on the wire, which lets the server link spends from the same pack. Use [`/v1/revocation/list`](#get-v1revocationlist) instead. The endpoint stays for SDKs released before 2026-10-15.

```json
{ "is_included": false,
  "path_bits": [true, false, true, false, false, false, false, true, false, false, true, true, false, false, true, true],
  "siblings_hex": ["0000…0000", "0000…0000", "… 16 entries"] }
```

`is_included: true` means the pack **is revoked** and its tokens can't be spent. A `pack_id` that isn't a u64 gets `400 bad_request: pack_id must be an unsigned 64-bit integer`.

## `POST /v1/analyze/batch`

**Why:** spend one token per matched funding transaction and get the blind OPRF evaluation that decrypts its tag.

**Request** (illustrative). There is one entry per matched funding transaction, at most 64:

```json
{
  "requests": [{
    "blinded_point": "9b41…(64 hex)",
    "spend": {
      "nullifier_hex": "3d07…(64 hex)",
      "revocation_root_hex": "0000…0000",
      "current_month": 202610,
      "proof_hex": "a8f2…(Groth16 proof)"
    }
  }]
}
```

- `blinded_point` is the funding txid hashed to the curve and multiplied by a secret random factor, so the server can't recover the txid.
- `spend` is a Groth16 proof (public inputs: `nullifier`, `current_month`, `revocation_root`). It proves that the client holds an unspent, unrevoked token signed by this server, without revealing which one. The server requires `current_month` to equal its own month, and the token's validity window, signed by the server at issuance, is checked inside the proof.
- The request contains **no heights, txids or outpoints**, and must go over a different Tor circuit from `filters/batch`.

**`200` response** (illustrative). There is one entry per request, in order, and each succeeds or fails independently:

```json
{
  "responses": [
    { "ok": true, "evaluated_point": "c0a3…(64 hex)", "proof_challenge": "…", "proof_response": "…" },
    { "ok": false, "error": { "code": "nullifier_spent", "message": "nullifier already spent", "retryable": false } }
  ]
}
```

The client verifies the DLEQ proof (`proof_challenge`, `proof_response`) against the server key, unblinds `evaluated_point`, and decrypts the tag. A failed entry's token was **not** used, except for `nullifier_spent` (that token had already been spent).

Recorded errors for the whole request:

```json
{ "error": { "code": "bad_request", "message": "requests must not be empty", "retryable": false } }
{ "error": { "code": "bad_request", "message": "invalid JSON body: missing field `spend` at line 1 column 35", "retryable": false } }
```

## `GET /v1/circuit/pk` and `/v1/circuit/vk`

The Groth16 proving and verifying keys, in compressed arkworks format, with ETags. **Production does not serve the proving key**, so a malicious server can't swap it; apps ship `pk.bin`:

```json
{ "error": { "code": "not_found", "message": "this server does not serve the proving key; ship pk.bin with the app (see /v1/meta circuit.pk_sha256)", "retryable": false } }
```

## Unknown routes

```json
{ "error": { "code": "not_found", "message": "no such /v1 endpoint", "retryable": false } }
```
