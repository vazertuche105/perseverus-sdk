//! Reading the phase-1 file (Powers of Tau, snarkjs `.ptau` format).
//!
//! Phase 1 is the circuit-independent half of a Groth16 setup. We do not run
//! our own: we read the public Perpetual Powers of Tau, which many independent
//! people contributed to. We use five sections of the file:
//!
//! | section | contents                         | points we read |
//! |---------|----------------------------------|----------------|
//! | 2       | [τ^i]₁                           | 2n − 1         |
//! | 3       | [τ^i]₂                           | n              |
//! | 4       | [α·τ^i]₁                         | n              |
//! | 5       | [β·τ^i]₁                         | n              |
//! | 6       | [β]₂                             | 1              |
//!
//! where n is the circuit's evaluation-domain size (2^15 for the v11 circuit).
//!
//! Points are stored uncompressed, each coordinate 32 bytes little-endian in
//! Montgomery form (snarkjs "LEM"), Fq2 as (c0, c1). Every point is checked to
//! be on the curve and in the prime-order subgroup, and [`Phase1::check`]
//! checks that the sections really are powers of one τ with the same α and β.
//! A file that passes cannot make the proving key leak anything, whoever made
//! it; whether τ is *secret* is what the phase-1 ceremony's own transcript is for.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, PrimeField, UniformRand, Zero};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const N8: usize = 32;

/// The phase-1 points one circuit needs.
pub struct Phase1 {
    /// log2 of the domain size these points were read for.
    pub power: u32,
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub alpha_tau_g1: Vec<G1Affine>,
    pub beta_tau_g1: Vec<G1Affine>,
    pub beta_g2: G2Affine,
    /// sha256 over the raw bytes of exactly the points read, section by section.
    /// Recorded in every params file; `verify` refuses a different phase 1.
    pub digest: [u8; 32],
}

/// The file's own `power` (the largest circuit it supports is 2^power rows).
pub fn file_power(path: &Path) -> Result<u32> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let sections = read_section_table(&mut f)?;
    let (off, _) = find(&sections, 1)?;
    f.seek(SeekFrom::Start(off))?;
    let n8 = read_u32(&mut f)? as usize;
    ensure!(
        n8 == N8,
        "ptau field size is {n8} bytes; only BN254 (32) is supported"
    );
    let mut q = vec![0u8; n8];
    f.read_exact(&mut q)?;
    ensure!(
        q == Fq::MODULUS.to_bytes_le(),
        "ptau file is not for BN254 (alt_bn128 / bn128)"
    );
    read_u32(&mut f)
}

/// Read the points for a domain of size 2^`power` and check every one of them.
pub fn read(path: &Path, power: u32) -> Result<Phase1> {
    let have = file_power(path)?;
    ensure!(
        have >= power,
        "{} supports circuits up to 2^{have} rows; this circuit needs 2^{power}",
        path.display()
    );
    let n = 1usize << power;
    let mut f = File::open(path)?;
    let sections = read_section_table(&mut f)?;
    let full = 1usize << have;

    let mut digest = Sha256::new();
    digest.update(b"perseverus-ceremony phase1 v1");
    digest.update((power as u64).to_le_bytes());

    let tau_g1 = read_g1(&mut f, &sections, 2, 2 * full - 1, 2 * n - 1, &mut digest)?;
    let tau_g2 = read_g2(&mut f, &sections, 3, full, n, &mut digest)?;
    let alpha_tau_g1 = read_g1(&mut f, &sections, 4, full, n, &mut digest)?;
    let beta_tau_g1 = read_g1(&mut f, &sections, 5, full, n, &mut digest)?;
    let beta_g2 = read_g2(&mut f, &sections, 6, 1, 1, &mut digest)?[0];

    Ok(Phase1 {
        power,
        tau_g1,
        tau_g2,
        alpha_tau_g1,
        beta_tau_g1,
        beta_g2,
        digest: digest.finalize().into(),
    })
}

/// blake2b-512 of the whole file, the hash the Powers of Tau projects publish.
pub fn blake2b_file(path: &Path) -> Result<String> {
    use blake2::Blake2b512;
    let mut f = File::open(path)?;
    let mut h = Blake2b512::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
    }
    Ok(hex::encode(h.finalize()))
}

impl Phase1 {
    /// Check the points form a valid phase 1: they start at the standard
    /// generators, every section is a run of powers of the same τ, and the α
    /// and β sections use the same τ. Random linear combinations make this a
    /// handful of pairings instead of one per point.
    pub fn check(&self) -> Result<()> {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        ensure!(
            self.tau_g1[0] == g1,
            "phase 1: [τ^0]₁ is not the BN254 G1 generator"
        );
        ensure!(
            self.tau_g2[0] == g2,
            "phase 1: [τ^0]₂ is not the BN254 G2 generator"
        );
        ensure!(!self.tau_g2[1].is_zero(), "phase 1: [τ]₂ is the identity");
        ensure!(
            !self.alpha_tau_g1[0].is_zero(),
            "phase 1: [α]₁ is the identity"
        );
        ensure!(!self.beta_g2.is_zero(), "phase 1: [β]₂ is the identity");
        let tau2 = self.tau_g2[1];

        // [τ^(i+1)]₁ = τ·[τ^i]₁  ⇔  e(Σρ[τ^i], [τ]₂) = e(Σρ[τ^(i+1)], g₂)
        let (a, b) = consecutive_g1(&self.tau_g1);
        ensure!(
            same_ratio((a, b), (g2, tau2)),
            "phase 1: [τ^i]₁ are not powers of one τ"
        );
        let (a, b) = consecutive_g2(&self.tau_g2);
        ensure!(
            same_ratio((g1, self.tau_g1[1]), (a, b)),
            "phase 1: [τ^i]₂ do not match [τ^i]₁"
        );
        let (a, b) = consecutive_g1(&self.alpha_tau_g1);
        ensure!(
            same_ratio((a, b), (g2, tau2)),
            "phase 1: [ατ^i]₁ are not powers of τ"
        );
        let (a, b) = consecutive_g1(&self.beta_tau_g1);
        ensure!(
            same_ratio((a, b), (g2, tau2)),
            "phase 1: [βτ^i]₁ are not powers of τ"
        );
        ensure!(
            same_ratio((g1, self.beta_tau_g1[0]), (g2, self.beta_g2)),
            "phase 1: [β]₁ and [β]₂ differ"
        );
        Ok(())
    }
}

/// e(a.0, b.1) == e(a.1, b.0): "a.1 / a.0 equals b.1 / b.0" in the exponent.
pub fn same_ratio(a: (G1Affine, G1Affine), b: (G2Affine, G2Affine)) -> bool {
    if a.0.is_zero() || a.1.is_zero() || b.0.is_zero() || b.1.is_zero() {
        return false;
    }
    let lhs = Bn254::multi_pairing([a.0, (-a.1.into_group()).into_affine()], [b.1, b.0]);
    lhs.is_zero()
}

fn rhos(n: usize) -> Vec<Fr> {
    let mut rng = rand::rngs::OsRng;
    (0..n).map(|_| Fr::rand(&mut rng)).collect()
}

/// (Σρᵢ·vᵢ, Σρᵢ·vᵢ₊₁) for random ρ.
fn consecutive_g1(v: &[G1Affine]) -> (G1Affine, G1Affine) {
    let r = rhos(v.len() - 1);
    let a = G1Projective::msm_unchecked(&v[..v.len() - 1], &r).into_affine();
    let b = G1Projective::msm_unchecked(&v[1..], &r).into_affine();
    (a, b)
}

fn consecutive_g2(v: &[G2Affine]) -> (G2Affine, G2Affine) {
    let r = rhos(v.len() - 1);
    let a = G2Projective::msm_unchecked(&v[..v.len() - 1], &r).into_affine();
    let b = G2Projective::msm_unchecked(&v[1..], &r).into_affine();
    (a, b)
}

// ── file layout ─────────────────────────────────────────────────────────────

fn read_u32(f: &mut impl Read) -> Result<u32> {
    let mut b = [0u8; 4];
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(f: &mut impl Read) -> Result<u64> {
    let mut b = [0u8; 8];
    f.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// (section type, data offset, data size)
fn read_section_table(f: &mut File) -> Result<Vec<(u32, u64, u64)>> {
    let len = f.metadata()?.len();
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    ensure!(&magic == b"ptau", "not a .ptau file (bad magic)");
    let _version = read_u32(f)?;
    let n = read_u32(f)?;
    let mut out = Vec::new();
    let mut pos = 12u64;
    for _ in 0..n {
        f.seek(SeekFrom::Start(pos))?;
        let t = read_u32(f)?;
        let size = read_u64(f)?;
        let off = pos + 12;
        ensure!(off + size <= len, "ptau file is truncated (section {t})");
        out.push((t, off, size));
        pos = off + size;
    }
    Ok(out)
}

fn find(sections: &[(u32, u64, u64)], t: u32) -> Result<(u64, u64)> {
    let mut it = sections.iter().filter(|s| s.0 == t);
    let s = it
        .next()
        .with_context(|| format!("ptau file has no section {t}"))?;
    ensure!(it.next().is_none(), "ptau file has section {t} twice");
    Ok((s.1, s.2))
}

fn read_raw(
    f: &mut File,
    sections: &[(u32, u64, u64)],
    t: u32,
    total: usize,
    take: usize,
    width: usize,
    digest: &mut Sha256,
) -> Result<Vec<u8>> {
    let (off, size) = find(sections, t)?;
    ensure!(
        size as usize == total * width,
        "ptau section {t} is {size} bytes; expected {} points of {width} bytes",
        total
    );
    let mut buf = vec![0u8; take * width];
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(&mut buf)?;
    digest.update((t as u64).to_le_bytes());
    digest.update((take as u64).to_le_bytes());
    digest.update(&buf);
    Ok(buf)
}

fn fq(b: &[u8]) -> Result<Fq> {
    let mut limbs = [0u64; 4];
    for (i, l) in limbs.iter_mut().enumerate() {
        *l = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let big = BigInt::new(limbs);
    ensure!(big < Fq::MODULUS, "ptau coordinate is not reduced mod q");
    Ok(Fq::new_unchecked(big)) // the bytes are already in Montgomery form
}

fn g1(b: &[u8]) -> Result<G1Affine> {
    if b.iter().all(|&x| x == 0) {
        return Ok(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(fq(&b[..N8])?, fq(&b[N8..])?);
    ensure!(p.is_on_curve(), "ptau G1 point is not on the curve");
    ensure!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "ptau G1 point is outside the subgroup"
    );
    Ok(p)
}

fn g2(b: &[u8]) -> Result<G2Affine> {
    if b.iter().all(|&x| x == 0) {
        return Ok(G2Affine::zero());
    }
    let x = Fq2::new(fq(&b[..N8])?, fq(&b[N8..2 * N8])?);
    let y = Fq2::new(fq(&b[2 * N8..3 * N8])?, fq(&b[3 * N8..])?);
    let p = G2Affine::new_unchecked(x, y);
    ensure!(p.is_on_curve(), "ptau G2 point is not on the curve");
    ensure!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "ptau G2 point is outside the subgroup"
    );
    Ok(p)
}

fn read_g1(
    f: &mut File,
    s: &[(u32, u64, u64)],
    t: u32,
    total: usize,
    take: usize,
    d: &mut Sha256,
) -> Result<Vec<G1Affine>> {
    let raw = read_raw(f, s, t, total, take, 2 * N8, d)?;
    raw.par_chunks(2 * N8).map(g1).collect()
}

fn read_g2(
    f: &mut File,
    s: &[(u32, u64, u64)],
    t: u32,
    total: usize,
    take: usize,
    d: &mut Sha256,
) -> Result<Vec<G2Affine>> {
    let raw = read_raw(f, s, t, total, take, 4 * N8, d)?;
    raw.par_chunks(4 * N8).map(g2).collect()
}

// ── writing (tests and the self-test only) ──────────────────────────────────

/// Write a `.ptau` file from KNOWN τ, α, β. Anyone holding these values can
/// forge proofs, so this is for tests only — the real ceremony reads the
/// public Perpetual Powers of Tau.
pub fn write_insecure_for_tests(
    path: &Path,
    power: u32,
    tau: Fr,
    alpha: Fr,
    beta: Fr,
) -> Result<()> {
    use std::io::Write;
    let n = 1usize << power;
    let mut pows = Vec::with_capacity(2 * n - 1);
    let mut acc = Fr::from(1u64);
    for _ in 0..2 * n - 1 {
        pows.push(acc);
        acc *= tau;
    }
    let g1 = G1Projective::from(G1Affine::generator());
    let g2 = G2Projective::from(G2Affine::generator());
    let tg1: Vec<G1Affine> =
        G1Projective::normalize_batch(&pows.par_iter().map(|p| g1 * p).collect::<Vec<_>>());
    let tg2: Vec<G2Affine> =
        G2Projective::normalize_batch(&pows[..n].par_iter().map(|p| g2 * p).collect::<Vec<_>>());
    let ag1: Vec<G1Affine> = G1Projective::normalize_batch(
        &pows[..n]
            .par_iter()
            .map(|p| g1 * (*p * alpha))
            .collect::<Vec<_>>(),
    );
    let bg1: Vec<G1Affine> = G1Projective::normalize_batch(
        &pows[..n]
            .par_iter()
            .map(|p| g1 * (*p * beta))
            .collect::<Vec<_>>(),
    );
    let bg2 = (g2 * beta).into_affine();

    fn lem(x: &Fq, out: &mut Vec<u8>) {
        for l in x.0 .0.iter() {
            out.extend_from_slice(&l.to_le_bytes()); // Montgomery limbs, as snarkjs stores them
        }
    }
    fn p1(p: &G1Affine, out: &mut Vec<u8>) {
        lem(&p.x, out);
        lem(&p.y, out);
    }
    fn p2(p: &G2Affine, out: &mut Vec<u8>) {
        lem(&p.x.c0, out);
        lem(&p.x.c1, out);
        lem(&p.y.c0, out);
        lem(&p.y.c1, out);
    }
    let mut sections: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut h = Vec::new();
    h.extend_from_slice(&(N8 as u32).to_le_bytes());
    h.extend_from_slice(&Fq::MODULUS.to_bytes_le());
    h.extend_from_slice(&power.to_le_bytes());
    h.extend_from_slice(&power.to_le_bytes());
    sections.push((1, h));
    let mut s = Vec::new();
    tg1.iter().for_each(|p| p1(p, &mut s));
    sections.push((2, s));
    let mut s = Vec::new();
    tg2.iter().for_each(|p| p2(p, &mut s));
    sections.push((3, s));
    let mut s = Vec::new();
    ag1.iter().for_each(|p| p1(p, &mut s));
    sections.push((4, s));
    let mut s = Vec::new();
    bg1.iter().for_each(|p| p1(p, &mut s));
    sections.push((5, s));
    let mut s = Vec::new();
    p2(&bg2, &mut s);
    sections.push((6, s));
    sections.push((7, 0u32.to_le_bytes().to_vec())); // no contributions recorded

    let mut f = File::create(path)?;
    f.write_all(b"ptau")?;
    f.write_all(&1u32.to_le_bytes())?;
    f.write_all(&(sections.len() as u32).to_le_bytes())?;
    for (t, data) in sections {
        f.write_all(&t.to_le_bytes())?;
        f.write_all(&(data.len() as u64).to_le_bytes())?;
        f.write_all(&data)?;
    }
    if tau.is_zero() {
        bail!("tau must be non-zero");
    }
    Ok(())
}
