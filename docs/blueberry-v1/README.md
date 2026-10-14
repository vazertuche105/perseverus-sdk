# Blueberry integration — M0 contract (draft 1)

Step 2 of the handoff plan (B.12): a draft `/v1` contract for the Blueberry SDK, written against the **local working tree** of `perseverus` and `sparrow-fork`, not GitHub. GitHub is ~5 months and about 4.4k lines behind.

| File | What it is |
|---|---|
| `openapi.yaml` | The `/v1` façade (OpenAPI 3.1, passes validation). Each operation says which existing handler it wraps. |
| `privacy-report.schema.json` | JSON Schema (2020-12) for the `PrivacyReport` the SDK returns per input. It mirrors `PrivacyReport.java` and adds `status`, `token_spent` and `include_in_wallet_average`. |
| `findings-catalog.v3lean.json` | A data-only port of `V3LeanTag` + `V3LeanReportBuilder`: bit layout, enums, 22 finding templates with trigger rules, the primary-recommendation cascade and the synthetic scores. The Rust SDK should build reports from this file so Sparrow and Blueberry render the same text. |
| `catalog_ref.py` | A ~40-line reference decoder that uses only the catalog. Checked against the Java builder on 20,000 tags with 0 mismatches. |

## Where the handoff doc is out of date

The local code has moved past what `PERSEVERUS_HANDOFF_AND_BLUEBERRY_INTEGRATION.md` describes. The contract follows the code:

1. **Filters are v5, keyed per transaction, not per outpoint.** The OPRF input is the funding **txid**. The payload is a codebook code that maps through `/codebook` to a 24-bit v3-lean tag. So the token unit is **one token per distinct funding txid that matches locally**, not one per input. Five inputs from two funding txs cost two tokens.
2. **The client scans the filter before spending a token.** An input whose txid isn't in a present filter is `ungraded` (skip rule). An input whose height is in `missing` is `not_covered`. Neither costs a token. The schema has a separate status for each.
3. **No on-demand filter building.** `/filters/*` now serve pre-built filters only, and a miss returns 404 or lands in `missing`. Filter coverage for deep-history inputs (B.7) is therefore an M0 decision, not a latency tweak. `/v1/meta.filters.covered_ranges` exposes it.
4. **Heights must not travel with spends.** B.5 sketched `/v1/analyze/batch` as "(filterHeight, decoys) + spend proofs". That would let the server join the decoy set to the spend batch. In this contract the analyze request carries no heights, and it must go over a different Tor circuit from the filter download.
5. **Pack ids need `/board/slots`.** The wallet re-rolls any `pack_id` whose 16-bit revocation slot is taken, and publish returns 409 on a collision.
6. **The yearly card plan is 13 packs**, through `/stripe/redeem-batch`.

## Open questions for Blueberry (from B.11, narrowed)

1. **Request shape:** outpoints + funding heights (recommended, because their SPV already has heights) or PSBT. The SDK needs the funding txid and height. Value, input count, output count and fee are optional and only feed the report footer.
2. **BTC silent-payment purchase:** codes come from the separate SP scanner (`POST /subscribe`). Either proxy it behind `/v1/tokens/purchase` or document it as a second service. The spec returns 501 for now.
3. **Coverage guarantee:** which height window gets pre-built filters at launch.
4. **Decoy default / padding bucket** for `/v1/filters/batch` (max 200 heights per request ⇒ at most ~200/(1+D) real heights per call).

## Not done yet (next steps per B.12)

- Step 3: `perseverus-sdk` crate + UniFFI (`connect`, `buy_tokens`, `redeem`, `token_balance`, `analyze_inputs`), with a Rust port of the catalog decoder.
- Step 4: the `/v1` router in the server, including the error-envelope mapping and `/v1/meta`.
