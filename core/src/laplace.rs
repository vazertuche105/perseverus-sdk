//! Discrete Laplace decoy block selection.
//!
//! Implements Section 9 of the whitepaper: anonymizing block filter selection.
//!
//! When the wallet needs to query a specific block, it downloads m+1 filters
//! (1 real + m decoys) to prevent the server from knowing which block is the target.
//! Decoy block heights are chosen using a discrete Laplace distribution centered
//! on the target block, providing plausible deniability.

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
