//! Pre-broadcast input analysis: the privacy-preserving pipeline behind
//! `Perseverus::analyze_inputs`.
//!
//! ```text
//!  inputs ─► group by funding tx
//!        ─► per real block: its height + decoys, ONE request on its own circuit
//!        ─► local match (txid absent → ungraded, height missing → not covered)
//!        ─► revocation list (own circuit); reserve 1 token per MATCHED funding tx
//!        ─► per matched funding tx: Groth16 proof + OPRF request on its own circuit
//!        ─► decrypt codebook code → 24-bit tag → PrivacyReport per input
//! ```
//!
//! Every coin travels alone. If all of a transaction's coins went in one
//! filter request, the server could later find the broadcast transaction as
//! the one whose inputs all come from blocks in that set (decoys hide one
//! block well, but no stranger's multi-input transaction fits a whole set);
//! and a shared circuit would let it group coins checked in the same session.
//! So each real block gets its own filter request and each token its own
//! spend request, each on a fresh circuit, sent in parallel after a random
//! delay so they don't arrive as one obvious burst. The shared query circuit
//! only carries `/v1/meta` and the codebook, which are the same for everyone.
//!
//! What the server sees per coin: a shuffled set of block heights (real ∪
//! decoys) on one circuit, and, on another, one blinded point with a spend
//! proof. It never sees a txid, an outpoint, or which heights were real.
//!
//! A funding transaction already graded on this device is answered from the
//! local cache and never requested again: repeated decoy sets around the same
//! block let the server intersect them (security review F11).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use perseverus_client_native::codebook::Codebook;
use perseverus_client_native::{QueryClient, SpendClient};
use perseverus_core::filter::{decrypt_code_v5, scan_filter_v5, BlockFilterV5, FILTER_FORMAT_VERSION_V5};
use perseverus_core::laplace::{cover_heights_for, window_for_scale};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::error::PerseverusError;
use crate::report::{self, InputRef, PrivacyReport};
use crate::store::{grade_key, Store};

const DEFAULT_LAPLACE_SCALE: f64 = 5.0;
/// Per-coin requests in flight at once (filter downloads, then spends).
const MAX_PARALLEL: usize = 6;
/// Each per-coin request waits a random 0..JITTER_MS first, so a wallet's
/// coins don't reach the server as one burst.
const JITTER_MS: u64 = 1000;
/// Fewest decoy blocks allowed per real funding block. Below this the real
/// heights stand out too much; 8 is the recommended value.
pub const MIN_DECOYS_PER_INPUT: u32 = 4;

#[derive(Debug, Clone, uniffi::Record)]
pub struct AnalyzeOptions {
    /// Decoy blocks fetched per real funding block. Higher = more privacy,
    /// more bandwidth (each filter is tens to hundreds of KB). Minimum 4
    /// (`analyze_inputs` refuses less); 8 is recommended, as Sparrow uses.
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
    /// The shared query circuit: only the codebook (the same for everyone).
    pub query: &'a QueryClient,
    /// A query client on a fresh circuit, for one block's filter request.
    pub filters: &'a (dyn Fn() -> Result<QueryClient, PerseverusError> + Sync),
    /// A spend client on a fresh circuit tagged `purpose` ("spend",
    /// "revocation").
    pub spend: &'a (dyn Fn(&'static str) -> Result<SpendClient, PerseverusError> + Sync),
    pub store: &'a Store,
    pub current_month: u32,
}

/// `f` over `items`, up to MAX_PARALLEL at a time, each after a random delay
/// of up to JITTER_MS. Results in input order.
fn per_coin<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let mut out: Vec<Option<R>> = (0..items.len()).map(|_| None).collect();
    let slots: Vec<std::sync::Mutex<&mut Option<R>>> = out.iter_mut().map(std::sync::Mutex::new).collect();
    std::thread::scope(|s| {
        for _ in 0..MAX_PARALLEL.min(items.len()) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                if JITTER_MS > 0 {
                    std::thread::sleep(Duration::from_millis(OsRng.gen_range(0..=JITTER_MS)));
                }
                let r = f(&items[i]);
                **slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            });
        }
    });
    drop(slots);
    out.into_iter().map(|r| r.expect("every item processed")).collect()
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
    Done(Box<dyn Fn(InputRef) -> PrivacyReport + Send + Sync>),
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

/// One real height plus `d` decoys drawn uniformly from a window placed at a
/// random offset around it, so the real block is no more likely than any
/// decoy (security review F11; the old centred Laplace draw let the server
/// pick the real block ~1 time in 3). Shuffled before sending.
pub(crate) fn heights_with_decoys(real: u32, d: usize, tip: u32) -> Vec<u32> {
    let window = window_for_scale(DEFAULT_LAPLACE_SCALE, d);
    let mut v = cover_heights_for(&[real], d, window, tip.max(real), &mut OsRng);
    v.shuffle(&mut OsRng);
    v
}

/// Reject options that would weaken privacy. Called before any network use.
pub(crate) fn validate_options(opts: &AnalyzeOptions) -> Result<(), PerseverusError> {
    if opts.decoys_per_input < MIN_DECOYS_PER_INPUT {
        return Err(PerseverusError::InvalidArgument {
            reason: format!(
                "decoys_per_input must be at least {MIN_DECOYS_PER_INPUT} (8 recommended); \
                 fewer would let the server see which blocks your coins are in"
            ),
        });
    }
    Ok(())
}

pub(crate) fn analyze(ctx: &Ctx, inputs: Vec<InputRef>, opts: &AnalyzeOptions) -> Result<AnalysisResult, PerseverusError> {
    validate_options(opts)?;
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

    // ── 1b. Answer already-graded funding txs from the local cache ──
    let mut outcomes: Vec<Outcome> = fundings.iter().map(|_| Outcome::Pending).collect();
    let cached = ctx.store.cached_grades()?;
    for (fi, f) in fundings.iter().enumerate() {
        if let Some(&tag) = cached.get(&grade_key(&f.txid_internal, f.height)) {
            outcomes[fi] = Outcome::Done(Box::new(move |i| report::graded(i, tag, false)));
        }
    }

    // ── 2. Filters: one request per real block (its height + decoys), each
    //       on its own circuit. Coins in the same block share a request: two
    //       sets that both contain the same height would give it away. ──
    let real: Vec<u32> = {
        let set: HashSet<u32> =
            fundings.iter().zip(&outcomes).filter(|(_, o)| matches!(o, Outcome::Pending)).map(|(f, _)| f.height).collect();
        let mut v: Vec<u32> = set.into_iter().collect();
        v.shuffle(&mut OsRng);
        v
    };
    let downloads = per_coin(&real, |&h| -> Result<Vec<(u32, Vec<u8>)>, PerseverusError> {
        let heights = heights_with_decoys(h, opts.decoys_per_input as usize, opts.chain_tip);
        Ok((ctx.filters)()?.download_filters_batch(&heights)?.filters)
    });
    let mut filters: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut bytes = 0u64;
    let mut filters_downloaded = 0u32;
    for d in downloads {
        for (h, data) in d? {
            bytes += data.len() as u64;
            filters_downloaded += 1;
            filters.insert(h, data);
        }
    }

    // ── 3. Local match ──
    let mut codebook: Option<Codebook> = None;
    let mut decoded: HashMap<u32, (BlockFilterV5, Vec<u64>)> = HashMap::new();

    for (fi, f) in fundings.iter().enumerate() {
        if !matches!(outcomes[fi], Outcome::Pending) {
            continue; // answered from the cache
        }
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

    // ── 4. Spend one token per matched funding tx, each on its own circuit ──
    let matched: Vec<usize> = (0..fundings.len()).filter(|&i| matches!(outcomes[i], Outcome::Matched(_))).collect();
    let mut tags: HashMap<usize, Result<u32, (String, String, bool)>> = HashMap::new();
    let mut tokens_spent = 0u32;
    if !matched.is_empty() {
        // Set up the prover BEFORE reserving tokens: if this fails (bad or
        // missing proving key, network), no token has been marked used.
        let fetcher = (ctx.spend)("revocation")?;
        // Download the public revocation list (the same for every wallet)
        // and check our own packs against it on the device, so revoked
        // packs are never reserved and no pack_id is ever sent.
        let revocation = fetcher.fetch_revocation_tree().map_err(PerseverusError::from)?;
        let newly_revoked: Vec<u64> = ctx
            .store
            .packs(ctx.current_month)?
            .iter()
            .filter(|p| !p.revoked && fetcher.is_pack_revoked(&revocation.0, p.pack_id))
            .map(|p| p.pack_id)
            .collect();
        ctx.store.mark_revoked(&newly_revoked)?;
        let reservations = ctx.store.reserve(matched.len(), ctx.current_month)?;
        let cb = codebook.as_ref().expect("codebook loaded when anything matched");
        let mut released: Vec<(u64, usize)> = Vec::new();

        let jobs: Vec<(usize, &crate::store::Reservation)> = matched.iter().copied().zip(reservations.iter()).collect();
        let results = per_coin(&jobs, |&(fi, r)| {
            let Outcome::Matched(m) = &outcomes[fi] else { unreachable!() };
            let spend = (ctx.spend)("spend")?;
            spend
                .spend_batch_with_revocation(&[(&r.pack, r.index, &m.txid_used[..])], ctx.current_month, &revocation, &mut OsRng)
                .map_err(PerseverusError::from)
                .map(|mut v| v.pop().expect("one result per spend"))
        });

        for ((fi, r), res) in jobs.into_iter().zip(results) {
            let Outcome::Matched(m) = &outcomes[fi] else { unreachable!() };
            match res {
                // The request failed as a whole: we cannot know whether the
                // server burned the nullifier, so the token stays marked used.
                Err(e) => {
                    let retryable = matches!(e, PerseverusError::Network { .. });
                    tags.insert(fi, Err(("spend_failed".into(), e.to_string(), retryable)));
                    tokens_spent += 1;
                }
                Ok(Ok(gamma)) => {
                    tokens_spent += 1;
                    let code = decrypt_code_v5(&gamma, &m.txid_used, &m.block_hash, m.enc_code, m.code_bits);
                    tags.insert(
                        fi,
                        cb.tag_for(code)
                            .ok_or_else(|| ("decrypt_failed".into(), format!("code {code} outside codebook (len {})", cb.len()), false)),
                    );
                }
                Ok(Err(e)) => {
                    let msg = e.to_string();
                    // A 409 means this token's nullifier was already burned
                    // (e.g. spent by another wallet holding the same pack): it
                    // stays used. Any other per-entry rejection happens before
                    // the burn, so the token is still good and goes back.
                    let burned = msg.contains("nullifier_spent") || msg.contains("409") || msg.contains("already spent");
                    if !burned {
                        released.push((r.pack.pack_id, r.index));
                    }
                    let code = if burned { "token_already_spent" } else { "spend_rejected" };
                    tags.insert(fi, Err((code.into(), msg, burned)));
                }
            }
        }
        ctx.store.release(&released)?;

        // Remember every grade we just paid for, so these coins are never
        // looked up again.
        let learned: Vec<(String, u32)> = tags
            .iter()
            .filter_map(|(&fi, t)| t.as_ref().ok().map(|&tag| (grade_key(&fundings[fi].txid_internal, fundings[fi].height), tag)))
            .collect();
        ctx.store.save_grades(&learned)?;
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

#[cfg(test)]
mod per_coin_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn every_item_once_in_order_and_bounded() {
        let items: Vec<u32> = (0..13).collect();
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let out = per_coin(&items, |&i| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            running.fetch_sub(1, Ordering::SeqCst);
            i * 10
        });
        assert_eq!(out, items.iter().map(|i| i * 10).collect::<Vec<_>>());
        let p = peak.load(Ordering::SeqCst);
        assert!((1..=MAX_PARALLEL).contains(&p), "peak {p}");
    }

    #[test]
    fn one_real_height_per_set() {
        let h = heights_with_decoys(900_000, 8, 975_000);
        assert_eq!(h.len(), 9);
        assert!(h.contains(&900_000));
        assert_eq!(h.iter().collect::<HashSet<_>>().len(), 9);
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    /// F11: a coin graded before is answered from the device, with no request
    /// at all (the query client points at a closed port, so any request would
    /// fail the call) and no token spent.
    #[test]
    fn cached_grade_needs_no_request() {
        let dir = std::env::temp_dir().join(format!("perseverus-grade-cache-{}", rand::random::<u64>()));
        let store = Store::open(&dir).unwrap();
        let txid_display = "11".repeat(32);
        let txid_internal = parse_txid_display(&txid_display).unwrap();
        store.save_grades(&[(grade_key(&txid_internal, 800_000), 0x00_12_34_56)]).unwrap();

        let query = QueryClient::new("http://127.0.0.1:9");
        let no_spend = |_: &'static str| -> Result<SpendClient, PerseverusError> { panic!("must not spend") };
        let filters = || Ok(QueryClient::new("http://127.0.0.1:9"));
        let ctx = Ctx { query: &query, filters: &filters, spend: &no_spend, store: &store, current_month: 202610 };
        let inputs = vec![InputRef { txid: txid_display, vout: 0, block_height: 800_000, value_sats: None }];
        let opts = AnalyzeOptions { decoys_per_input: 8, chain_tip: 900_000 };

        let res = analyze(&ctx, inputs, &opts).expect("answered from cache");
        assert_eq!(res.tokens_spent, 0);
        assert_eq!(res.filters_downloaded, 0);
        assert_eq!(res.reports.len(), 1);
        assert_eq!(res.reports[0].input.block_height, 800_000);
        assert_eq!(res.reports[0].status, crate::report::ReportStatus::Graded);
        assert!(!res.reports[0].token_spent);

        // After forgetting, the same call has to go to the network (and fails here).
        store.forget_grades().unwrap();
        let inputs = vec![InputRef { txid: "11".repeat(32), vout: 0, block_height: 800_000, value_sats: None }];
        assert!(analyze(&ctx, inputs, &opts).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
