# 5. PrivacyReport field guide

`analyzeInputs` returns one `PrivacyReport` per input. This page explains every field and every value, and how to show them. The report is built **on the device** from a decrypted 24-bit tag; the server never sees it. Its JSON form follows [`blueberry-v1/privacy-report.schema.json`](blueberry-v1/privacy-report.schema.json), and all wording comes from [`blueberry-v1/findings-catalog.v3lean.json`](blueberry-v1/findings-catalog.v3lean.json), compiled into the SDK. Every wallet using Medusa shows the same text for the same coin.

**What a report describes.** The *funding transaction*: the transaction that created the coin being spent. It answers "what does chain analysis already know about where this coin came from?" Every input from the same funding transaction gets the same report.

## Start with `status`

| `status` | Meaning | Token spent | How to show it |
|---|---|---|---|
| `GRADED` | The tag was decrypted. `grade`, `score`, `findings` and `primaryRecommendation` are filled in. | Yes (one per funding transaction) | The full report. |
| `UNGRADED` | The funding transaction is deliberately not graded (tiny-value, dust-only, OP_RETURN, ordinals, runes, Counterparty/Omni). **This is not a warning.** | No | Neutral: "No privacy grade for this coin". |
| `NOT_COVERED` | The server has no filter for that block yet. | No | Neutral: "Not checked yet". Try again later. |
| `ERROR` | This input's check failed; see `error`. | See `error.code` | "Couldn't check this coin", with a retry if `error.retryable`. |

## Fields

| Field (Kotlin) | Type | When set | Meaning |
|---|---|---|---|
| `schemaVersion` | `UInt` | always | `1`. |
| `status` | `ReportStatus` | always | See above. |
| `input` | `InputRef` | always | The input you passed in, echoed back, so you can match reports to inputs. Reports are also in input order. |
| `grade` | `String?` | graded | Display letter: `B`, `C`, `D` or `F`. Today's tags carry a 4-level band, so the best band (A+/A/B) displays as `B`. A future, richer tag format may emit `A+` or `A`, so handle those too. |
| `gradeBand` | `String?` | graded | The raw band: `A+/A/B`, `C`, `D` or `F`. |
| `score` | `UInt?` | graded | 0–100, **synthesised** from the band so the number never contradicts the letter: 85 (B), 75 (C), 65 (D), 45 (F), or 30 for F with a *deterministic* failure. |
| `scoreIsExact` | `Boolean` | always | `false` today. If false, show the score as approximate (e.g. "~65") or show only the letter. |
| `profile` | `String` | always | `transaction`, `peel-chain` or `coinjoin` when graded; `ungraded`, `not-covered` or `error` otherwise. |
| `primaryRecommendation` | `Recommendation?` | graded, ungraded | The single most important thing to tell the user (see [the cascade](#the-primary-recommendation)). |
| `findings` | `List<Finding>` | always | Individual detections, most severe first. Empty for not-covered and error. For ungraded it lists the possible exclusion reasons. |
| `severityCounts` | `SeverityCounts` | always | Count of findings per severity, handy for badges. |
| `includeInWalletAverage` | `Boolean` | always | `true` only for graded reports. Use it if you compute a wallet-wide privacy score, so ungraded or uncovered coins don't drag the average down. |
| `rawTag` | `String?` | graded | `V3LEAN:` plus 6 hex digits. For support and debugging only; don't show it to users. |
| `tokenSpent` | `Boolean` | always | `true` when a token was spent to produce this report. For the call's total, use `AnalysisResult.tokensSpent`. |
| `error` | `ReportError?` | error | `code` (stable), `message` (for logs), `retryable`. Codes are listed in the [SDK reference](03-sdk-reference.md#analyzeinputs). |

`Finding`: `id` (stable; use it for icons or analytics), `title`, `severity`, `confidence` (display text: `deterministic confidence`, `high confidence`, `medium confidence`, `low confidence`, `good`, or `rule` for ungraded reasons), `description`, `recommendation`.

`Recommendation`: `urgency`, `headline`, `detail`. Urgency is one of `immediate`, `soon`, `when-convenient`, `positive` or `neutral`.

## Grades

| Grade | Score | What it means for the user |
|---|---|---|
| **B** (band A+/A/B) | 85 | No significant issues found. |
| **C** | 75 | Some weaker signals, such as fingerprinting or low entropy. |
| **D** | 65 | A strong heuristic links this coin, for example a peel chain or common-input ownership. |
| **F** | 45 | Serious exposure. |
| **F** (deterministic) | 30 | A certain, not probabilistic, leak, e.g. change sent back to an input address. |

A suggested colour scale: B green, C yellow, D orange, F red. Use `severity` for finding colours: `critical` red, `high` orange, `medium` yellow, `low` grey, `info` blue, `good` green.

## The primary recommendation

The SDK picks **one** headline per graded report by walking this list top to bottom and taking the first condition that's true for the tag. Lead with this in the UI.

| Order | Condition | Urgency | Headline | Detail |
|---|---|---|---|---|
| 1 | `deterministic_cap || address_reuse_io` | immediate | Your wallet sends change back to the input address | Switch to a wallet that generates fresh change addresses for every transaction. This is a critical privacy failure - the change output is 100% identifiable. |
| 2 | `entity_class == 3` | immediate | Sanctioned-entity exposure | These coins carry strong forensic association. Avoid linking them to any KYC identity. |
| 3 | `entity_class == 2` | immediate | Darknet-market-linked entity | These coins carry strong forensic association. Avoid linking them to any KYC identity. |
| 4 | `dust_class >= 2` | immediate | Dust attack or dust co-spend detected | Mark the dust UTXOs as do-not-spend in coin control and never co-spend them with real funds. |
| 5 | `consolidation_class != 0` | soon | UTXO consolidation links your history | Pre-mix through CoinJoin before consolidating, or avoid consolidation. |
| 6 | `chain_taint` | soon | Cluster / taint signals in ancestry | Investigate this UTXO's history on your own node before spending. |
| 7 | `is_peel_chain` | soon | Part of a peel chain | Insert a CoinJoin between spends or rotate to a fresh wallet. |
| 8 | `cioh` | soon | Common-input-ownership clustering | Avoid combining UTXOs from different sources in one transaction. |
| 9 | `entity_class == 1` | when-convenient | Known entity involved in this transaction | Assume this counterparty can link the transaction to your KYC identity. |
| 10 | `multisig_escrow` | when-convenient | Multisig / escrow product detected | This product is identifiable on-chain. |
| 11 | `is_coinjoin` | positive | CoinJoin participation - privacy protected | Good - this transaction breaks deterministic links. |
| 12 | `true` | when-convenient | No significant privacy issues | No critical or high-severity findings for this transaction. |

(The conditions refer to fields of the decoded tag; you don't need to evaluate them, because the SDK does.)

## All findings

Findings appear in this order (most severe first). Text is exactly what the SDK returns. `{consolidation_class}` is filled with `fan-in`, `fan-out` or `cross-or-other`, and `{count} wallet fingerprinting signal(s)` becomes e.g. "2 wallet fingerprinting signals".

| `id` | Severity | Title | Description | Recommendation |
|---|---|---|---|---|
| `compound-deterministic-cap` | critical | Deterministic privacy failure - score capped | A 100% certain privacy leak was detected. The score is capped at F because no amount of positive signals can offset a deterministic identification. | Fix the deterministic issue before addressing other findings. |
| `h2-same-address-io` | critical | Same address in input and output - change revealed | One of the spendable outputs goes back to an address that was also an input. This is a 100% deterministic link - that output is certainly change, revealing which other outputs are payments and the exact payment amount. | Use a wallet that generates a new change address for every transaction (HD wallets). Never send change back to the same address. |
| `alarm-toxic-merge` | critical | Chain taint / toxic merge in ancestry | This transaction's ancestry includes a privacy-fatal merge or cross-cluster link. The damage is on-chain and irreversible. | Avoid spending these UTXOs in ways that further extend the linkage. Run a backward trace on your own node for detail. |
| `entity-ofac-match` | critical | Sanctions / OFAC entity match | An address in this transaction matches a sanctions / OFAC list. | Treat these coins as toxic; consult compliance guidance before transacting. |
| `entity-behavior-darknet` | critical | Darknet-market-linked entity detected | An address in this transaction is associated with a darknet market or compromised mixer. | These coins carry strong forensic association; avoid linking them to KYC identities. |
| `dust-attack` | critical | Dust attack or dust co-spend detected | This transaction co-spends dust with other coins, which confirms common ownership to an attacker who planted the dust. | Mark dust UTXOs as do-not-spend in coin control; never co-spend them with real funds. |
| `consolidation` | critical | Consolidation pattern ({consolidation_class}) | Multiple UTXOs were combined, collapsing separate histories into one cluster that chain analysis treats as a single wallet. | Pre-mix through CoinJoin before consolidating, or avoid consolidation entirely. |
| `h3-cioh` | high | Common input ownership heuristic fires | Multiple inputs were spent together; standard chain analysis treats them all as one wallet. | Use CoinJoin or avoid combining UTXOs from different sources in one transaction. |
| `peel-chain` | high | Peel chain detected (2+ consecutive hops) | This transaction is part of a peel chain - a sequence of transactions each with one input and two outputs, where one output feeds the next. The pattern is highly identifiable and links every downstream UTXO into one wallet's spending behaviour. | Insert a CoinJoin between spends, or rotate to a fresh wallet. |
| `h17-multisig` | high | Multisig / escrow product detected | The script structure reveals participation in a known escrow / multisig product. | Be aware that this product is identifiable on-chain. |
| `dust-outputs` | high | Dust outputs present | This transaction has outputs below the dust threshold, which can act as tracking beacons. | Mark dust UTXOs as do-not-spend in coin control. |
| `entity-behavior-exchange` | high | Known entity involved | An exchange, gambling site, or other identified service is involved in this transaction. | Assume this counterparty can link the transaction to any KYC identity it holds for you. |
| `h5-low-entropy` | medium | Very low transaction entropy | The transaction has near-zero entropy: there is essentially one valid interpretation of which inputs fund which outputs. | Use transactions with more balanced amounts / multiple participants (CoinJoin). |
| `h5-low-entropy` | medium | Low transaction entropy | The input/output mapping is largely determinable from the amounts. | Prefer amounts that don't trivially reveal the change output. |
| `h7-op-return` | medium | OP_RETURN metadata present | This transaction embeds OP_RETURN data, which can carry protocol metadata that aids identification. | Avoid attaching data payments to private spends. |
| `h11-wallet-fingerprint` | low | {count} wallet fingerprinting signal(s) | Wallet-specific transaction construction signals (nSequence / nLockTime / nVersion) narrow down which wallet software created this transaction. | Different wallet software exposes different fingerprints; this is informational. |
| `h6-rbf` | low | RBF signaled | nSequence indicates this transaction opted into Replace-By-Fee. | Informational - common and not directly de-anonymising. |
| `h11-no-locktime` | low | No anti-fee-sniping (nLockTime = 0) | nLockTime is 0, so the transaction does not use anti-fee-sniping. Some wallets always set a recent locktime. | Informational - reveals wallet construction style. |
| `h11-legacy-version` | low | Legacy transaction version (< 2) | The transaction version is below 2, a wallet-fingerprinting signal. | Informational. |
| `anon-set-none` | low | No anonymity set | All output amounts are unique, so there is no ambiguity set hiding the payment among equal-value outputs. | Equal-value outputs (as in CoinJoin) provide an anonymity set. |
| `script-uniform` | good | Uniform script types | All inputs and outputs use the same script type, avoiding the script-type change fingerprint. | Good - keep using a single address type per transaction where possible. |
| `h4-coinjoin` | good | CoinJoin participation | This transaction participates in a CoinJoin, breaking deterministic input-output links. | Good - CoinJoin is privacy-positive. |

`h5-low-entropy` appears with two titles because it has two strength levels; only one ever fires at a time.

## Ungraded: why a coin has no grade

For `UNGRADED` reports, `primaryRecommendation` is *"No privacy grade for this UTXO"* (urgency `neutral`), and `findings` lists **all** the exclusion rules below as `info`. The filter tells the SDK only that the transaction was excluded, not which rule applied. Present them as "possible reasons".

| `id` | Title | Description |
|---|---|---|
| `skip-dust-total` | Transaction value under 2,000 sats | The whole transaction that created this output sends less than 2,000 satoshis in total. Very-low-value transactions are not assessed. |
| `skip-dust-output` | Dust outputs only | Every output in the transaction is below the 546-sat network dust limit. |
| `skip-op-return` | Data carrier (OP_RETURN only) | The transaction carries only embedded data and no spendable payment output. |
| `skip-ordinal` | Ordinal inscription | The transaction is an ordinal inscription (witness-embedded content), not a standard payment. |
| `skip-runes` | Runes transfer | The transaction is a Runes protocol message rather than a standard payment. |
| `skip-asset` | Counterparty / Omni asset transfer | The transaction is a Counterparty or Omni Layer asset transfer rather than a standard bitcoin payment. |

## Example JSON

The graded report for the quickstart coin (in snake_case, as in the schema; the Kotlin object has the same data):

```json
{
  "schema_version": 1,
  "status": "graded",
  "input": { "txid": "728da0f74813fec9c1381ec9e82ab7a096d1b637b845c446f3ac02db14ccb44f", "vout": 0, "block_height": 945270 },
  "grade": "D",
  "grade_band": "D",
  "score": 65,
  "score_is_exact": false,
  "profile": "peel-chain",
  "primary_recommendation": { "urgency": "soon", "headline": "Part of a peel chain",
                              "detail": "Insert a CoinJoin between spends or rotate to a fresh wallet." },
  "findings": [ { "id": "peel-chain", "severity": "high", "title": "Peel chain detected (2+ consecutive hops)", "...": "..." },
               { "id": "h11-wallet-fingerprint", "severity": "low", "title": "2 wallet fingerprinting signals", "...": "..." },
               { "id": "h6-rbf", "severity": "low", "...": "..." },
               { "id": "h11-no-locktime", "severity": "low", "...": "..." },
               { "id": "anon-set-none", "severity": "low", "...": "..." } ],
  "severity_counts": { "critical": 0, "high": 1, "medium": 0, "low": 4, "info": 0, "good": 0 },
  "include_in_wallet_average": true,
  "raw_tag": "V3LEAN:b40014",
  "token_spent": true
}
```

## The whole transaction: `TransactionAssessment`

A `PrivacyReport` describes one coin. But a transaction that spends several coins also shows the world that they share an owner, so a clean coin spent next to an exposed one takes on its history. `TransactionAssessment` answers the question a per-coin report can't: **is it a problem to spend these inputs together, and if so, which ones should come out?**

You get it two ways, and both give the same result:

- `analyzeInputs(...)` returns it as `result.transaction`, for exactly the inputs you passed.
- `assessTransaction(reports)` works it out from any list of reports you already hold. Call it again whenever the user adds or removes a coin on the review screen: it answers instantly.

**It runs on the device.** It only reads reports the wallet already has, so it sends no request and costs no token. That's deliberate, and it's why there is no server endpoint for it: the server never learns any coin's result, and it must never learn which coins are about to be spent together.

**Example.** A user builds a transaction from four coins. Coin #1 is grade B; coins #2–#4 are D, F and D:

```kotlin
val result = medusa.analyzeInputs(inputs, options)     // 4 tokens, as before
val tx = result.transaction                            // free
if (tx.verdict == CombineVerdict.AVOID) {
    showWarning(tx.primaryRecommendation!!.headline,    // "Mixes clean coins with badly exposed ones"
                tx.primaryRecommendation!!.detail)      // "Spend the cleaner coin(s) in a separate transaction…"
    highlight(tx.findings.first().inputs)               // [0] → coin #1 is the one to take out
}

// The user removes coin #1. No new request, no token:
val again = assessTransaction(result.reports.drop(1))   // verdict OK
```

### Fields

| Field | Type | Meaning |
|---|---|---|
| `verdict` | `CombineVerdict` | `OK`: none of the risky combinations fired. `CAUTION`: worth a second look (most severe finding is medium). `AVOID`: combining these inputs does real damage (a high or critical finding). **Warn before sending on `AVOID`.** |
| `complete` | `Boolean` | `false` when some input has no grade (ungraded, not covered, or error), so the verdict covers only the others. |
| `inputsTotal`, `inputsGraded` | `UInt` | How many inputs were looked at, and how many of them have a grade. |
| `fundingTransactions` | `UInt` | Distinct earlier transactions the inputs come from. Inputs from the same one are already linked on-chain, so combining them reveals nothing new. |
| `bestGrade`, `worstGrade` | `String?` | Best and worst grade among the graded inputs. |
| `primaryRecommendation` | `Recommendation?` | The one thing to show first: the most severe finding, or the good news when there's no problem. `null` only for an empty list. |
| `findings` | `List<TransactionFinding>` | Everything that fired, most severe first. Each has `id`, `title`, `severity`, `description`, `recommendation` and `inputs`. |
| `groups` | `List<InputGroup>` | The inputs sorted into groups that are fine to spend with each other. More than one group means "spend these separately". |

**Input positions.** `findings[].inputs` and `groups[].inputs` are positions in the list of reports that was assessed, starting at 0 (so `0` is the first input you passed). For a "would link X to your other coins" finding, `inputs` are the X: taking them out of the transaction clears the finding.

### Findings

A finding about mixing only fires when **some but not all** inputs have the property. If every input already has it, spending them together adds nothing new.

| `id` | Severity | Fires when | `inputs` |
|---|---|---|---|
| `mix-sanctioned-or-darknet` | critical | Some inputs come from a transaction tied to a sanctioned or darknet-market entity, others don't. | The flagged inputs |
| `mix-dust-attack` | critical | Some inputs show a dust-attack or dust-spending pattern. Spending dust next to real coins is what a dust attack waits for. | The dust inputs |
| `mix-taint` | critical | Some inputs carry chain-taint signals, others don't. | The tainted inputs |
| `mix-coinjoin-with-other` | high | Some inputs are CoinJoin outputs, others aren't. Spending them together undoes the CoinJoin. | The CoinJoin outputs |
| `mix-grade-spread-severe` | high | Clean coins (grade B or C) are combined with lower-grade ones, and the worst is F. | The clean inputs |
| `mix-grade-spread` | medium | Clean coins (B or C) are combined with grade-D ones. | The clean inputs |
| `mix-known-entity` | medium | Some inputs come from a known entity such as an exchange, others don't. | The known-entity inputs |
| `merge-coinjoin-outputs` | medium | Two or more CoinJoin outputs are spent together. | The CoinJoin outputs |
| `incomplete` | low | Some inputs have no grade. | The unassessed inputs |
| `links-inputs` | info | Always, when the inputs come from two or more earlier transactions: any multi-input transaction links its inputs. | (none) |
| `consistent` | good | Two or more earlier transactions, every input graded, and nothing above fired. | (none) |
| `same-origin` | good | All inputs come from the same earlier transaction. | (none) |
| `single-input` | good | Only one input. | (none) |
| `none-assessed` | info | No input has a grade. | All inputs |

The grade-spread findings only compare coins that have no special flag. A flagged coin (sanctioned, tainted, dust, CoinJoin, known entity) is reported by its own finding, not twice.

### Groups

Each input lands in exactly one group. The first match wins:

| `id` | Inputs in it |
|---|---|
| `exposed` | Sanctioned or darknet link, chain taint, or a dust pattern |
| `coinjoin` | CoinJoin outputs |
| `known-entity` | From a known entity such as an exchange |
| `clean` | Grade B or C, no flag above |
| `lower-grade` | Grade D or F, no flag above |
| `unassessed` | No grade |

Only groups with at least one input are returned. In the example above: `clean: [0]` and `lower-grade: [1, 2, 3]`.

### Example JSON

`transactionAssessmentJson(assessment)` gives the snake_case form ([schema](blueberry-v1/transaction-assessment.schema.json)). For the four-coin example:

```json
{
  "schema_version": 1,
  "verdict": "avoid",
  "complete": true,
  "inputs_total": 4,
  "inputs_graded": 4,
  "funding_transactions": 4,
  "best_grade": "B",
  "worst_grade": "F",
  "primary_recommendation": { "urgency": "immediate", "headline": "Mixes clean coins with badly exposed ones",
                              "detail": "Spend the cleaner coin(s) in a separate transaction from the lower-graded ones." },
  "findings": [
    { "id": "mix-grade-spread-severe", "severity": "high", "title": "Mixes clean coins with badly exposed ones",
      "description": "These inputs have very different privacy grades: the best is B, the worst is F. One transaction ties them together, so the cleaner coin(s) take on the history of the exposed one(s).",
      "recommendation": "Spend the cleaner coin(s) in a separate transaction from the lower-graded ones.", "inputs": [0] },
    { "id": "links-inputs", "severity": "info", "title": "Links 4 coins on-chain", "...": "...", "inputs": [] }
  ],
  "groups": [
    { "id": "clean", "title": "Clean (grade B or C)", "inputs": [0] },
    { "id": "lower-grade", "title": "Lower grade (D or F)", "inputs": [1, 2, 3] }
  ]
}
```

### What it can't tell you

- **It knows where each coin came from, not where this transaction is going.** A report describes the transaction that created the coin. The assessment doesn't see this transaction's outputs, amounts or change, so it can't judge those.
- **`OK` means none of the known risky combinations fired, not that the transaction is private.** Every multi-input transaction still links its inputs (`links-inputs`).
- **It's only as complete as the reports.** Check `complete`. An unassessed input is unknown, not clean.
- **Storing reports.** To assess later without re-analyzing, keep the reports you got back. The assessment only reads each report's `status`, `input.txid` and `rawTag`.

## UI guidance

- **Lead with the grade and `primaryRecommendation.headline`**, with `detail` and the findings one tap away.
- **Explain, don't alarm.** The report describes the coin's past. Most findings can't be undone; the recommendations are about what to do *next*, such as not merging this coin with others or using a fresh wallet.
- **Never call ungraded or not-covered coins risky**, and don't count them in averages (`includeInWalletAverage`).
- **Several inputs:** lead with the transaction's `verdict` and its `primaryRecommendation` ([above](#the-whole-transaction-transactionassessment)), then list each coin's own grade. On `AVOID`, warn before the user can send, and mark the inputs named in the top finding. On `CAUTION`, show the note without blocking. Offer the fix the `groups` suggest: "send coin #1 separately".
- **Re-assess as the selection changes.** When the user adds or removes a coin, call `assessTransaction` with the reports of the coins now selected. It's instant and free. Only coins without a report yet need `analyzeInputs`.
- **Accessibility:** don't rely on colour alone; always show the letter and the text.
