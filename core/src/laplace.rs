//! Discrete Laplace decoy block selection.
//!
//! Implements Section 9 of the whitepaper: anonymizing block filter selection.
//!
//! When the wallet needs to query a specific block, it downloads m+1 filters
//! (1 real + m decoys) to prevent the server from knowing which block is the target.
//! Decoy block heights were chosen from a discrete Laplace distribution centred
//! on the target ([`select_decoy_blocks`]). That leaves the target in the middle
//! of its own set, so wallets now use [`select_cover_blocks`]: a window placed
//! at a uniformly random offset around the target, filled uniformly.

use rand::Rng;
use std::collections::HashSet;

/// Default number of camouflage (decoy) blocks
pub const DEFAULT_NUM_DECOYS: usize = 8;

/// Default scale parameter (s=5 → 95% of decoys within ±15 blocks)
pub const DEFAULT_SCALE: f64 = 5.0;

/// Select decoy block heights using the discrete Laplace distribution.
///
/// Returns a sorted set of m+1 block heights including the target.
/// An observer cannot distinguish the real target from the decoys.
///
/// Parameters:
/// - `target_height`: the block the wallet actually needs (h_0)
/// - `num_decoys`: number of camouflage blocks (m)
/// - `scale`: controls dispersion (s). Larger = wider spread
/// - `min_height`: lowest block height the server will serve (H_min)
/// - `max_height`: current chain tip (to avoid requesting future blocks)
pub fn select_decoy_blocks<R: Rng>(
    target_height: u32,
    num_decoys: usize,
    scale: f64,
    min_height: u32,
    max_height: u32,
    rng: &mut R,
) -> Vec<u32> {
    let mut selected: HashSet<u32> = HashSet::new();
    selected.insert(target_height);

    // q = exp(-1/s), the discrete Laplace parameter
    let q = (-1.0_f64 / scale).exp();

    let mut attempts = 0;
    let max_attempts = num_decoys * 100; // prevent infinite loops

    while selected.len() < num_decoys + 1 && attempts < max_attempts {
        attempts += 1;

        // Step 1: Draw magnitude k ≥ 0 from geometric distribution
        // Pr[K = k] = (1 - q) · q^k
        let magnitude = sample_geometric(q, rng);

        // Step 2: Draw sign uniformly from {-1, +1}
        let sign: i64 = if rng.gen_bool(0.5) { 1 } else { -1 };

        // Step 3: Compute offset
        let offset = sign * (magnitude as i64);
        let candidate = target_height as i64 + offset;

        // Step 4: Validate
        if candidate < min_height as i64 || candidate > max_height as i64 {
            continue; // out of range
        }
        let candidate = candidate as u32;

        if candidate == target_height {
            continue; // don't duplicate the target
        }

        selected.insert(candidate);
    }

    // Sort canonically before transmission
    let mut heights: Vec<u32> = selected.into_iter().collect();
    heights.sort();
    heights
}

/// Window width used for a given Laplace `scale`: about the span that held
/// ~99% of the old Laplace decoys (±3·scale), and never narrower than the
/// number of heights requested.
pub fn window_for_scale(scale: f64, num_decoys: usize) -> u32 {
    let w = (6.0 * scale.max(1.0)).ceil() as u32 + 1;
    w.max(num_decoys as u32 + 1)
}

/// Pick `num_decoys` cover heights for `target_height` so that, from the
/// server's side, every height in the set is equally likely to be the real
/// one (security review F11).
///
/// [`select_decoy_blocks`] centres its Laplace cloud on the target, so the
/// real block sits in the middle of its own set and "guess the most central
/// height" wins about 1 time in 3 with 8 decoys. Here a window of `window`
/// consecutive heights is placed so that the target falls at a **uniformly
/// random position** inside it, and the decoys are drawn **uniformly** from
/// the rest of the window. Away from the ends of the chain the target is then
/// indistinguishable from the decoys: the best guess wins 1 in (num_decoys+1).
///
/// Within ~2·scale blocks of the tip it uses the centred Laplace cloud (see the
/// body). Above that, near the tip the window is **not** clamped. Clamping it to end at
/// the tip would leave a tip block inside fewer possible windows than an older
/// block, which makes recent blocks (the ones wallets check most) easy to
/// pick out. Instead the window start is always uniform over the `window`
/// positions that contain the target, even if part of the window lies past
/// the tip, and decoys come only from the heights that exist. If that leaves
/// fewer than `num_decoys` candidates, the start is drawn again. That redraw
/// is the only remaining edge bias, and it is mild: for 8 decoys in a 31-block
/// window, the tip block is ~1.3x as likely as a block 30 below it.
///
/// Returns the sorted set, target included.
pub fn select_cover_blocks<R: Rng>(
    target_height: u32,
    num_decoys: usize,
    window: u32,
    min_height: u32,
    max_height: u32,
    rng: &mut R,
) -> Vec<u32> {
    let max_height = max_height.max(target_height);
    let min_height = min_height.min(target_height);

    // Right at the tip a window can't extend upward, so a block within the
    // last ~2·scale blocks would tend to be the highest in its set. There the
    // centred Laplace cloud, which also puts decoys above the target, does
    // better; measured with 8 decoys at scale 5 (best of the median and
    // maximum guesses), coins in the last 10 blocks: 16% either way, last 30:
    // 13% vs 28%, last 100: 12% vs 32%, older: 11% vs 34%.
    let scale = (window.saturating_sub(1) as f64 / 6.0).max(1.0);
    if ((max_height - target_height) as f64) < 2.0 * scale {
        return select_decoy_blocks(target_height, num_decoys, scale, min_height, max_height, rng);
    }

    let available = (max_height - min_height) as u64 + 1;
    let w = window.max(num_decoys as u32 + 1) as i64;
    let t = target_height as i64;
    let (lo_h, hi_h) = (min_height as i64, max_height as i64);

    // Draw the window start uniformly from [t - w + 1, t]; keep it only if the
    // real heights inside the window leave room for every decoy.
    let need = (num_decoys as u64).min(available - 1) as i64;
    let mut range = (t, t);
    for _ in 0..1000 {
        let s = rng.gen_range(t - w + 1..=t);
        let (a, b) = (s.max(lo_h), (s + w - 1).min(hi_h));
        if b - a >= need {
            range = (a, b);
            break;
        }
    }
    if range == (t, t) && need > 0 {
        // Pathological (tiny chain): fall back to the heights nearest the target.
        let a = (t - w + 1).max(lo_h);
        range = (a, (a + w - 1).min(hi_h));
    }

    let others: Vec<u32> = (range.0..=range.1).filter(|&h| h != t).map(|h| h as u32).collect();
    let k = num_decoys.min(others.len());
    let mut out: Vec<u32> = rand::seq::index::sample(rng, others.len(), k)
        .into_iter()
        .map(|i| others[i])
        .collect();
    out.push(target_height);
    out.sort_unstable();
    out
}

/// Cover heights for several real blocks: the union of one
/// [`select_cover_blocks`] set per real height, sorted. Used by every wallet
/// path (SDK analysis, native lookups, Sparrow's prefetch) so they all hide
/// real blocks the same way.
pub fn cover_heights_for<R: Rng>(
    real_heights: &[u32],
    num_decoys: usize,
    window: u32,
    max_height: u32,
    rng: &mut R,
) -> Vec<u32> {
    let mut all: HashSet<u32> = HashSet::new();
    for &h in real_heights {
        all.extend(select_cover_blocks(h, num_decoys, window, 1, max_height.max(h), rng));
    }
    // Real heights close together get overlapping windows, so the union can
    // hold fewer than reals × (1 + decoys) heights. Top it up with more draws
    // from the same windows so every real block keeps its full share of cover.
    let reals: HashSet<u32> = real_heights.iter().copied().collect();
    let want = reals.len() * (num_decoys + 1);
    let mut attempts = 0;
    while all.len() < want && attempts < 64 * want {
        attempts += 1;
        let h = real_heights[attempts % real_heights.len()];
        let extra = select_cover_blocks(h, num_decoys, window, 1, max_height.max(h), rng);
        let fresh: Vec<u32> = extra.into_iter().filter(|x| !all.contains(x)).collect();
        if !fresh.is_empty() {
            all.insert(fresh[rng.gen_range(0..fresh.len())]);
        }
    }
    let mut v: Vec<u32> = all.into_iter().collect();
    v.sort_unstable();
    v
}

/// Sample from a geometric distribution: Pr[K = k] = (1-q) · q^k for k ≥ 0
fn sample_geometric(q: f64, rng: &mut impl Rng) -> u32 {
    // Inverse CDF method: K = floor(ln(U) / ln(q)) where U ~ Uniform(0,1)
    let u: f64 = rng.gen_range(0.0_f64..1.0_f64);
    // Avoid log(0)
    let u = u.max(1e-15);
    (u.ln() / q.ln()).floor() as u32
}

/// Compute the 95% range for a given scale parameter.
/// 95% of decoys will fall within ±range blocks of the target.
pub fn decoy_range_95(scale: f64) -> f64 {
    // From whitepaper: 95% of samples lie in [-⌈s·ln(20)⌉, ⌈s·ln(20)⌉]
    scale * 20.0_f64.ln()
}

/// Compute the anonymity entropy in bits for a given decoy count.
/// With m decoys, entropy = log2(m + 1) bits.
pub fn anonymity_entropy_bits(num_decoys: usize) -> f64 {
    ((num_decoys + 1) as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    /// Hit rate of the maximum-likelihood attack on a centred Laplace cloud:
    /// the decoys' log-likelihood around a candidate c is -Σ|h - c|/s, which is
    /// largest at the MEDIAN of the set. Over `n` interior targets.
    fn central_guess_rate(cover: impl Fn(u32, &mut rand::rngs::ThreadRng) -> Vec<u32>, n: usize) -> f64 {
        let mut rng = thread_rng();
        let mut hits = 0;
        for i in 0..n {
            let target = 500_000 + (i as u32 % 1000) * 37;
            let set = cover(target, &mut rng);
            if set[set.len() / 2] == target { hits += 1; }
        }
        hits as f64 / n as f64
    }

    /// F11: the centred Laplace cloud gives the real block away far more often
    /// than 1 in 9; the uniform window brings it down to about 1 in 9.
    #[test]
    fn cover_window_hides_the_target_among_its_decoys() {
        let n = 20_000;
        let old = central_guess_rate(|t, r| select_decoy_blocks(t, 8, 5.0, 1, 900_000, r), n);
        let new = central_guess_rate(|t, r| select_cover_blocks(t, 8, window_for_scale(5.0, 8), 1, 900_000, r), n);
        eprintln!("median-guess hit rate: centred Laplace {:.3}, uniform window {:.3}", old, new);
        assert!(old > 0.25, "centred cloud should leak (got {old})");
        assert!(new < 0.15, "uniform window should be near 1/9 (got {new})");
    }

    /// Every position inside the window is equally likely for the target.
    #[test]
    fn target_position_in_window_is_uniform() {
        let mut rng = thread_rng();
        let w = window_for_scale(5.0, 8);
        let mut first = 0usize;
        let n = 20_000;
        for _ in 0..n {
            let set = select_cover_blocks(600_000, 8, w, 1, 900_000, &mut rng);
            if set[0] == 600_000 { first += 1; }
        }
        // The target is the lowest of 9 heights about 1/9 of the time.
        let rate = first as f64 / n as f64;
        assert!((rate - 1.0 / 9.0).abs() < 0.02, "target-is-lowest rate {rate}");
    }

    #[test]
    fn cover_blocks_count_bounds_and_edges() {
        let mut rng = thread_rng();
        for &(t, tip) in &[(1u32, 900_000u32), (900_000, 900_000), (899_990, 900_000), (450_000, 900_000)] {
            let set = select_cover_blocks(t, 8, 31, 1, tip, &mut rng);
            assert_eq!(set.len(), 9, "t={t}");
            assert!(set.contains(&t));
            assert!(set.windows(2).all(|p| p[0] < p[1]));
            assert!(set.iter().all(|&h| (1..=tip).contains(&h)));
        }
        // A chain shorter than the request: everything there is, no panic.
        let set = select_cover_blocks(3, 8, 31, 1, 5, &mut rng);
        assert_eq!(set, vec![1, 2, 3, 4, 5]);
    }

    /// Nearby real blocks share windows; the set still carries a full
    /// (1 + decoys) heights per real block.
    #[test]
    fn nearby_reals_keep_full_cover() {
        let mut rng = thread_rng();
        for _ in 0..500 {
            let v = cover_heights_for(&[900_000, 900_005], 4, window_for_scale(5.0, 4), 900_010, &mut rng);
            assert!(v.len() >= 10, "{v:?}");
            assert!(v.contains(&900_000) && v.contains(&900_005));
            assert!(v.iter().all(|&h| h >= 1 && h <= 900_010));
        }
    }

    /// At the tip, the tip block must no longer be identified every time.
    #[test]
    fn tip_block_is_no_longer_always_the_maximum_giveaway() {
        let mut rng = thread_rng();
        let tip = 900_000;
        let w = window_for_scale(5.0, 8);
        let n = 5_000;
        let mut max_is_target = 0;
        for i in 0..n {
            // real blocks spread over the last w blocks
            let t = tip - (i as u32 % w);
            let set = select_cover_blocks(t, 8, w, 1, tip, &mut rng);
            if *set.last().unwrap() == t { max_is_target += 1; }
        }
        let rate = max_is_target as f64 / n as f64;
        eprintln!("near-tip, guess-the-maximum hit rate: {rate:.3}");
        assert!(rate < 0.2, "guessing the maximum near the tip wins {rate}");
        // And for coins in the last 10 blocks, no worse than the old sampler.
        // Best single strategy (median or maximum) over all trials, per sampler.
        let (mut o_med, mut o_max, mut n_med, mut n_max) = (0, 0, 0, 0);
        for i in 0..n {
            let t = tip - (i as u32 % 10);
            let o = select_decoy_blocks(t, 8, 5.0, 1, tip, &mut rng);
            let nw = select_cover_blocks(t, 8, w, 1, tip, &mut rng);
            o_med += (o[o.len() / 2] == t) as u32;
            o_max += (*o.last().unwrap() == t) as u32;
            n_med += (nw[nw.len() / 2] == t) as u32;
            n_max += (*nw.last().unwrap() == t) as u32;
        }
        let (old_best, new_best) = (o_med.max(o_max), n_med.max(n_max));
        assert!(new_best as f64 <= old_best as f64 * 1.15 + 50.0, "last-10 blocks: new {new_best} vs old {old_best}");
    }

    #[test]
    fn test_select_decoy_blocks_count() {
        let mut rng = thread_rng();
        let heights = select_decoy_blocks(800000, 8, 5.0, 0, 850000, &mut rng);

        // Should have exactly 9 heights (1 target + 8 decoys)
        assert_eq!(heights.len(), 9, "should have m+1 = 9 heights");

        // Target must be included
        assert!(heights.contains(&800000), "target must be in the set");
    }

    #[test]
    fn test_select_decoy_blocks_sorted() {
        let mut rng = thread_rng();
        let heights = select_decoy_blocks(800000, 8, 5.0, 0, 850000, &mut rng);

        for i in 1..heights.len() {
            assert!(heights[i] > heights[i - 1], "must be strictly sorted");
        }
    }

    #[test]
    fn test_select_decoy_blocks_within_range() {
        let mut rng = thread_rng();
        let min_h = 799000;
        let max_h = 801000;
        let heights = select_decoy_blocks(800000, 8, 5.0, min_h, max_h, &mut rng);

        for &h in &heights {
            assert!(h >= min_h, "all heights must be >= min_height");
            assert!(h <= max_h, "all heights must be <= max_height");
        }
    }

    #[test]
    fn test_decoy_blocks_no_duplicates() {
        let mut rng = thread_rng();
        let heights = select_decoy_blocks(800000, 8, 5.0, 0, 850000, &mut rng);

        let unique: HashSet<u32> = heights.iter().copied().collect();
        assert_eq!(heights.len(), unique.len(), "no duplicate heights");
    }

    #[test]
    fn test_scale_affects_spread() {
        let mut rng = thread_rng();
        let target = 800000u32;

        // Small scale: tight clustering
        let tight: Vec<u32> = (0..100)
            .flat_map(|_| select_decoy_blocks(target, 8, 2.0, 0, 900000, &mut rng))
            .filter(|&h| h != target)
            .collect();

        // Large scale: wide spread
        let wide: Vec<u32> = (0..100)
            .flat_map(|_| select_decoy_blocks(target, 8, 20.0, 0, 900000, &mut rng))
            .filter(|&h| h != target)
            .collect();

        let tight_var = variance(&tight, target);
        let wide_var = variance(&wide, target);

        assert!(
            wide_var > tight_var,
            "larger scale should produce wider spread: tight={:.0}, wide={:.0}",
            tight_var,
            wide_var
        );
    }

    #[test]
    fn test_95_range() {
        let range = decoy_range_95(5.0);
        // s=5 → ⌈5·ln(20)⌉ ≈ 15
        assert!((range - 14.98).abs() < 1.0, "95% range for s=5 should be ~15");
    }

    #[test]
    fn test_anonymity_entropy() {
        let bits = anonymity_entropy_bits(8);
        assert!((bits - 3.17).abs() < 0.1, "log2(9) ≈ 3.17 bits");
    }

    fn variance(values: &[u32], center: u32) -> f64 {
        let n = values.len() as f64;
        if n == 0.0 {
            return 0.0;
        }
        let sum_sq: f64 = values
            .iter()
            .map(|&v| {
                let diff = v as f64 - center as f64;
                diff * diff
            })
            .sum();
        sum_sq / n
    }
}
