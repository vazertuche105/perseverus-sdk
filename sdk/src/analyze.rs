//! Pre-broadcast input analysis: the privacy-preserving pipeline behind
//! `Perseverus::analyze_inputs`.
//!
//! ```text
//!  inputs ─► group by funding tx ─► filters for real + Laplace-decoy heights
//!        ─► local match (txid absent → ungraded, height missing → not covered)
//!        ─► reserve 1 token per MATCHED funding tx (local store)
//!        ─► Groth16 spend proofs + ONE batched OPRF request (isolated circuit)
//!        ─► decrypt codebook code → 24-bit tag → PrivacyReport per input
//! ```
//!
//! What the server sees: a shuffled set of block heights (real ∪ decoys) on
//! one circuit, and later, on a different circuit, k blinded points with spend
//! proofs. It never sees a txid, an outpoint, or which heights were real.

use std::collections::{HashMap, HashSet};

use perseverus_client_native::codebook::Codebook;
use perseverus_client_native::{QueryClient, SpendClient};
use perseverus_core::filter::{decrypt_code_v5, scan_filter_v5, BlockFilterV5, FILTER_FORMAT_VERSION_V5};
use perseverus_core::issuance::IssuedPack;
use perseverus_core::laplace::select_decoy_blocks;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::error::PerseverusError;
use crate::report::{self, InputRef, PrivacyReport};
use crate::store::Store;

/// Server limits (see `/filters/batch` and `/oprf/evaluate/batch`).
const MAX_FILTERS_PER_REQUEST: usize = 200;
const MAX_SPENDS_PER_REQUEST: usize = 64;
const DEFAULT_LAPLACE_SCALE: f64 = 5.0;

#[derive(Debug, Clone, uniffi::Record)]
pub struct AnalyzeOptions {
    /// Decoy blocks fetched per real funding block. Higher = more privacy,
    /// more bandwidth (each filter is tens to hundreds of KB). Sparrow uses 8.
    pub decoys_per_input: u32,
    /// Current chain tip height (upper bound for decoy selection).
    pub chain_tip: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AnalysisResult {
    /// One report per input, in the same order as the request.
    pub reports: Vec<PrivacyReport>,
    /// Tokens consumed by this call (one per matched funding transaction).
    pub tokens_spent: u32,
    /// Filters downloaded (real + decoy).
    pub filters_downloaded: u32,
    pub bytes_downloaded: u64,
}

/// Everything the pipeline needs from the SDK instance.
pub(crate) struct Ctx<'a> {
    pub query: &'a QueryClient,
    pub spend: &'a dyn Fn() -> Result<SpendClient, PerseverusError>,
    pub store: &'a Store,
    pub current_month: u32,
}

struct Funding {
    /// txid in internal byte order as given (display hex reversed).
    txid_internal: [u8; 32],
    height: u32,
}

struct Matched {
    txid_used: [u8; 32],
    block_hash: [u8; 32],
    enc_code: u32,
    code_bits: u8,
}

enum Outcome {
    Pending,
    Matched(Matched),
    Done(Box<dyn Fn(InputRef) -> PrivacyReport>),
}

pub(crate) fn parse_txid_display(hex_str: &str) -> Result<[u8; 32], PerseverusError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| PerseverusError::InvalidArgument { reason: format!("txid `{hex_str}`: {e}") })?;
    let mut out: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PerseverusError::InvalidArgument { reason: format!("txid `{hex_str}` is not 32 bytes") })?;
    out.reverse(); // display order → internal order
    Ok(out)
}

/// Pick `real ∪ decoys` heights, exactly `real × (1 + d)` unique heights when
/// the chain allows it, mirroring Sparrow's `prefetchFiltersWithDecoys`.
pub(crate) fn heights_with_decoys(real: &HashSet<u32>, d: usize, tip: u32) -> Vec<u32> {
    let mut all: HashSet<u32> = real.clone();
    if d > 0 && !real.is_empty() {
        let target = real.len() * (1 + d);
        let reals: Vec<u32> = real.iter().copied().collect();
        let mut rng = OsRng;
        let mut i = 0usize;
        while all.len() < target && i < target * 200 {
            let h = reals[i % reals.len()];
            for c in select_decoy_blocks(h, 1, DEFAULT_LAPLACE_SCALE, 1, tip.max(h), &mut rng) {
                all.insert(c);
            }
            i += 1;
        }
    }
    let mut v: Vec<u32> = all.into_iter().collect();
    v.shuffle(&mut OsRng);
    v
}

pub(crate) fn analyze(ctx: &Ctx, inputs: Vec<InputRef>, opts: &AnalyzeOptions) -> Result<AnalysisResult, PerseverusError> {
    if inputs.is_empty() {
        return Ok(AnalysisResult { reports: vec![], tokens_spent: 0, filters_downloaded: 0, bytes_downloaded: 0 });
    }

    // ── 1. Group inputs by funding tx (v5 filters are keyed per transaction) ──
    let mut fundings: Vec<Funding> = Vec::new();
    let mut key_to_idx: HashMap<([u8; 32], u32), usize> = HashMap::new();
    let mut input_funding: Vec<usize> = Vec::with_capacity(inputs.len());
    for inp in &inputs {
        if inp.block_height == 0 {
            return Err(PerseverusError::InvalidArgument {
                reason: format!("input {}:{} has no block height (unconfirmed inputs cannot be analysed)", inp.txid, inp.vout),
            });
        }
        let txid = parse_txid_display(&inp.txid)?;
        let idx = *key_to_idx.entry((txid, inp.block_height)).or_insert_with(|| {
            fundings.push(Funding { txid_internal: txid, height: inp.block_height });
            fundings.len() - 1
        });
        input_funding.push(idx);
    }

    // ── 2. Download filters for real + decoy heights (shuffled, chunked) ──
    let real: HashSet<u32> = fundings.iter().map(|f| f.height).collect();
    let tip = opts.chain_tip.max(*real.iter().max().unwrap());
    let heights = heights_with_decoys(&real, opts.decoys_per_input as usize, tip);
    let mut filters: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut bytes = 0u64;
    for chunk in heights.chunks(MAX_FILTERS_PER_REQUEST) {
        let batch = ctx.query.download_filters_batch(chunk)?;
        for (h, data) in batch.filters {
            bytes += data.len() as u64;
            filters.insert(h, data);
        }
    }
    let filters_downloaded = filters.len() as u32;

    // ── 3. Local match ──
    let mut codebook: Option<Codebook> = None;
    let mut decoded: HashMap<u32, (BlockFilterV5, Vec<u64>)> = HashMap::new();
    let mut outcomes: Vec<Outcome> = fundings.iter().map(|_| Outcome::Pending).collect();

    for (fi, f) in fundings.iter().enumerate() {
        let Some(data) = filters.get(&f.height) else {
            outcomes[fi] = Outcome::Done(Box::new(report::not_covered));
            continue;
        };
        if data.get(4).copied() != Some(FILTER_FORMAT_VERSION_V5) {
            let v = data.get(4).copied().unwrap_or(0);
            outcomes[fi] = Outcome::Done(Box::new(move |i| {
                report::failed(i, "unsupported_filter_version", format!("filter format v{v} is not supported by this SDK"), false)
            }));
            continue;
        }
        if !decoded.contains_key(&f.height) {
            let filt = BlockFilterV5::deserialize(data)
                .map_err(|e| PerseverusError::Verification { reason: format!("filter {}: {e}", f.height) })?;
            if codebook.is_none() {
                let cb = Codebook::parse(&ctx.query.download_codebook()?)
                    .map_err(|m| PerseverusError::Verification { reason: m })?;
                codebook = Some(cb);
            }
            if codebook.as_ref().unwrap().id != filt.codebook_id {
                return Err(PerseverusError::Verification {
                    reason: format!("filter {} wants codebook {:02x?}, server codebook is {:02x?}", f.height, filt.codebook_id, codebook.as_ref().unwrap().id),
                });
            }
            let hashes = filt
                .decode_hashes()
                .map_err(|e| PerseverusError::Verification { reason: format!("filter {} decode: {e}", f.height) })?;
            decoded.insert(f.height, (filt, hashes));
        }
        let (filt, hashes) = &decoded[&f.height];
        // Filters are keyed on internal byte order; accept either orientation
        // like the Sparrow client does, and use whichever matched for the OPRF.
        let mut rev = f.txid_internal;
        rev.reverse();
        let hit = [f.txid_internal, rev].into_iter().find_map(|t| {
            scan_filter_v5(hashes, &t, &filt.block_hash, filt.num_entries, filt.golomb_p).map(|r| (t, r))
        });
        outcomes[fi] = match hit {
            None => Outcome::Done(Box::new(report::ungraded)),
            Some((txid_used, rank)) => Outcome::Matched(Matched {
                txid_used,
                block_hash: filt.block_hash,
                enc_code: filt.enc_code_at(rank),
                code_bits: filt.code_bits,
            }),
        };
    }

    // ── 4. Spend one token per matched funding tx ──
    let matched: Vec<usize> = (0..fundings.len()).filter(|&i| matches!(outcomes[i], Outcome::Matched(_))).collect();
    let mut tags: HashMap<usize, Result<u32, (String, String, bool)>> = HashMap::new();
    let mut tokens_spent = 0u32;
    if !matched.is_empty() {
        // Set up the prover BEFORE reserving tokens: if this fails (bad or
        // missing proving key, network), no token has been marked used.
        let spend = (ctx.spend)()?;
        // Download the public revocation list (the same for every wallet)
        // and check our own packs against it on the device, so revoked
        // packs are never reserved and no pack_id is ever sent.
        let revocation = spend.fetch_revocation_tree().map_err(PerseverusError::from)?;
        let newly_revoked: Vec<u64> = ctx
            .store
            .packs(ctx.current_month)?
            .iter()
            .filter(|p| !p.revoked && spend.is_pack_revoked(&revocation.0, p.pack_id))
            .map(|p| p.pack_id)
            .collect();
        ctx.store.mark_revoked(&newly_revoked)?;
        let reservations = ctx.store.reserve(matched.len(), ctx.current_month)?;
        let cb = codebook.as_ref().expect("codebook loaded when anything matched");
        let mut released: Vec<(u64, usize)> = Vec::new();

        for (chunk_f, chunk_r) in matched.chunks(MAX_SPENDS_PER_REQUEST).zip(reservations.chunks(MAX_SPENDS_PER_REQUEST)) {
            let inputs_bytes: Vec<[u8; 32]> = chunk_f
                .iter()
                .map(|&fi| match &outcomes[fi] {
                    Outcome::Matched(m) => m.txid_used,
                    _ => unreachable!(),
                })
                .collect();
            let items: Vec<(&IssuedPack, usize, &[u8])> = chunk_r
                .iter()
                .zip(inputs_bytes.iter())
                .map(|(r, t)| (&r.pack, r.index, &t[..]))
                .collect();

            match spend.spend_batch_with_revocation(&items, ctx.current_month, &revocation, &mut OsRng) {
                Err(e) => {
                    // Whole request failed: we cannot know whether the server
                    // burned the nullifiers, so the tokens stay marked used.
                    let e: PerseverusError = e.into();
                    let retryable = matches!(e, PerseverusError::Network { .. });
                    for &fi in chunk_f {
                        tags.insert(fi, Err(("spend_failed".into(), e.to_string(), retryable)));
                    }
                    tokens_spent += chunk_f.len() as u32;
                }
                Ok(results) => {
                    for ((&fi, r), res) in chunk_f.iter().zip(chunk_r).zip(results) {
                        let Outcome::Matched(m) = &outcomes[fi] else { unreachable!() };
                        match res {
                            Ok(gamma) => {
                                tokens_spent += 1;
                                let code = decrypt_code_v5(&gamma, &m.txid_used, &m.block_hash, m.enc_code, m.code_bits);
                                tags.insert(
                                    fi,
                                    cb.tag_for(code).ok_or_else(|| {
                                        ("decrypt_failed".into(), format!("code {code} outside codebook (len {})", cb.len()), false)
                                    }),
                                );
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                // A 409 means this token's nullifier was already
                                // burned (e.g. spent by another wallet holding the
                                // same pack): it stays used. Any other per-entry
                                // rejection happens before the burn, so the token
                                // is still good and goes back to the pool.
                                let burned = msg.contains("nullifier_spent") || msg.contains("409") || msg.contains("already spent");
                                if !burned {
                                    released.push((r.pack.pack_id, r.index));
                                }
                                let code = if burned { "token_already_spent" } else { "spend_rejected" };
                                tags.insert(fi, Err((code.into(), msg, burned)));
                            }
                        }
                    }
                }
            }
        }
        ctx.store.release(&released)?;
    }

    // ── 5. Reports, in input order ──
    let reports = inputs
        .into_iter()
        .zip(input_funding)
        .map(|(inp, fi)| match &outcomes[fi] {
            Outcome::Done(make) => make(inp),
            Outcome::Matched(_) => match &tags[&fi] {
                Ok(tag) => report::graded(inp, *tag, true),
                Err((code, msg, retry)) => report::failed(inp, code, msg.clone(), *retry),
            },
            Outcome::Pending => unreachable!(),
        })
        .collect();

    Ok(AnalysisResult { reports, tokens_spent, filters_downloaded, bytes_downloaded: bytes })
}
