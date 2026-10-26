//! Phase 2: the part of the Groth16 setup that is specific to our circuit.
//!
//! `initial` turns a checked phase 1 plus the circuit into the starting
//! parameters. It is deterministic and uses no secrets, so anyone can redo it.
//! At that point δ = 1, which is NOT safe to use. Each `contribute` multiplies
//! δ by a fresh secret k and immediately forgets k:
//!
//!   [δ]₁, [δ]₂      ← ·k
//!   H-query, L-query ← ·k⁻¹      (these are the only places δ appears)
//!
//! and publishes a proof that it knew k (`s`, `s·k`, `r·k`, with `r` a point
//! derived by hashing the whole transcript so far). After every participant,
//! δ = k₁·k₂·…·kₘ, which nobody knows unless every participant kept their k.
//!
//! `verify` redoes `initial`, checks that nothing but δ changed, checks every
//! contribution's proof of knowledge and that the chain of δ's is unbroken,
//! and checks the final H and L queries were divided by exactly that δ.
//! Parameters that pass are the honest Groth16 keys for this circuit for
//! SOME δ — so proofs made with them reveal nothing — and δ is secret as long
//! as one participant was honest.
//!
//! This is the scheme of Bowe, Gabizon and Miers (2017), the one used by
//! Zcash Sapling and by `phase2-bn254`, written for arkworks so the output is
//! the `ProvingKey<Bn254>` the SDK already loads.

use std::io::{Read, Write};

use anyhow::{bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::ptau::{same_ratio, Phase1};

const MAGIC: &[u8; 20] = b"PERSEVERUS-PHASE2\0\0\0";
const FORMAT: u32 = 1;

// ── the circuit ─────────────────────────────────────────────────────────────

/// The circuit's constraint matrices, as arkworks' own Groth16 setup sees them.
pub struct Shape {
    pub matrices: ConstraintMatrices<Fr>,
    pub num_instance: usize,
    pub num_witness: usize,
    pub num_constraints: usize,
    /// log2 of the evaluation domain size.
    pub power: u32,
    /// sha256 of the matrices. Two parties with the same circuit source and
    /// the same server key get the same hash.
    pub cs_hash: [u8; 32],
}

/// Synthesize exactly as `Groth16::generate_parameters_with_qap` does.
pub fn synthesize<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<Shape> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .context("circuit synthesis")?;
    cs.finalize();
    let matrices = cs.to_matrices().context("constraint matrices")?;
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();
    let num_constraints = cs.num_constraints();
    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .context("circuit too large for BN254's FFT domain")?;
    let power = domain.size().trailing_zeros();

    let mut h = Sha256::new();
    h.update(b"perseverus-ceremony r1cs v1");
    for x in [num_instance, num_witness, num_constraints] {
        h.update((x as u64).to_le_bytes());
    }
    for m in [&matrices.a, &matrices.b, &matrices.c] {
        h.update((m.len() as u64).to_le_bytes());
        for row in m.iter() {
            h.update((row.len() as u64).to_le_bytes());
            for (coeff, idx) in row {
                h.update(coeff.into_bigint().to_bytes_le());
                h.update((*idx as u64).to_le_bytes());
            }
        }
    }
    Ok(Shape {
        matrices,
        num_instance,
        num_witness,
        num_constraints,
        power,
        cs_hash: h.finalize().into(),
    })
}

/// The v11 spend circuit with the server's public key baked in (the key is a
/// circuit constant, so each server key needs its own ceremony).
pub fn spend_circuit(
    server_pubkey_hex: &str,
) -> Result<perseverus_circuits::RevocationSpendCircuit> {
    let bytes = hex::decode(server_pubkey_hex.trim()).context("server public key is not hex")?;
    let p = ark_ed_on_bn254::EdwardsAffine::deserialize_compressed(&bytes[..])
        .context("server public key is not a valid BabyJubJub point")?;
    ensure!(!p.is_zero(), "server public key is the identity point");
    let mut c = perseverus_circuits::RevocationSpendCircuit::empty();
    c.pk_server = p.into();
    Ok(c)
}

// ── the starting parameters ─────────────────────────────────────────────────

/// Groth16 parameters from a phase 1, with γ = δ = 1. Equal, point for point,
/// to what `Groth16::generate_parameters_with_qap` produces for the same τ, α,
/// β with γ = δ = 1 and the standard generators (see the tests).
pub fn initial(ph1: &Phase1, shape: &Shape) -> Result<ProvingKey<Bn254>> {
    ensure!(
        ph1.power == shape.power,
        "phase 1 was read for 2^{} rows; the circuit needs 2^{}",
        ph1.power,
        shape.power
    );
    let domain = GeneralEvaluationDomain::<Fr>::new(1 << shape.power).unwrap();
    let n = domain.size();
    ensure!(
        ph1.tau_g1.len() >= 2 * n - 1 && ph1.tau_g2.len() >= n,
        "phase 1 too short"
    );

    // Lagrange basis in the exponent: [L_j(τ)] = (1/n)·Σ_k ω^(−jk)·[τ^k],
    // i.e. an inverse FFT of the powers.
    let ifft1 = |v: &[G1Affine]| -> Vec<G1Affine> {
        let p: Vec<G1Projective> = v[..n].iter().map(|x| x.into_group()).collect();
        G1Projective::normalize_batch(&domain.ifft(&p))
    };
    let lag_g1 = ifft1(&ph1.tau_g1);
    let lag_alpha = ifft1(&ph1.alpha_tau_g1);
    let lag_beta = ifft1(&ph1.beta_tau_g1);
    let lag_g2 = {
        let p: Vec<G2Projective> = ph1.tau_g2[..n].iter().map(|x| x.into_group()).collect();
        G2Projective::normalize_batch(&domain.ifft(&p))
    };

    // Columns of A, B, C: for each variable, the (row, coefficient) pairs.
    let nvars = shape.num_instance + shape.num_witness;
    let nc = shape.num_constraints;
    let columns = |m: &Vec<Vec<(Fr, usize)>>| {
        let mut cols: Vec<Vec<(usize, Fr)>> = vec![Vec::new(); nvars];
        for (row, terms) in m.iter().enumerate() {
            for (coeff, var) in terms {
                cols[*var].push((row, *coeff));
            }
        }
        cols
    };
    let mut col_a = columns(&shape.matrices.a);
    // arkworks (libsnark reduction) adds one extra row per public input:
    // A gets L_{nc+i}(τ) for instance variable i.
    for (i, col) in col_a.iter_mut().enumerate().take(shape.num_instance) {
        col.push((nc + i, Fr::one()));
    }
    let col_b = columns(&shape.matrices.b);
    let col_c = columns(&shape.matrices.c);

    fn msm1(bases: &[G1Affine], col: &[(usize, Fr)]) -> G1Projective {
        let b: Vec<G1Affine> = col.iter().map(|(j, _)| bases[*j]).collect();
        let s: Vec<Fr> = col.iter().map(|(_, c)| *c).collect();
        G1Projective::msm_unchecked(&b, &s)
    }
    fn msm2(bases: &[G2Affine], col: &[(usize, Fr)]) -> G2Projective {
        let b: Vec<G2Affine> = col.iter().map(|(j, _)| bases[*j]).collect();
        let s: Vec<Fr> = col.iter().map(|(_, c)| *c).collect();
        G2Projective::msm_unchecked(&b, &s)
    }

    let a_query = G1Projective::normalize_batch(
        &(0..nvars)
            .into_par_iter()
            .map(|v| msm1(&lag_g1, &col_a[v]))
            .collect::<Vec<_>>(),
    );
    let b_g1_query = G1Projective::normalize_batch(
        &(0..nvars)
            .into_par_iter()
            .map(|v| msm1(&lag_g1, &col_b[v]))
            .collect::<Vec<_>>(),
    );
    let b_g2_query = G2Projective::normalize_batch(
        &(0..nvars)
            .into_par_iter()
            .map(|v| msm2(&lag_g2, &col_b[v]))
            .collect::<Vec<_>>(),
    );
    // [β·A_v(τ) + α·B_v(τ) + C_v(τ)]₁
    let abc = G1Projective::normalize_batch(
        &(0..nvars)
            .into_par_iter()
            .map(|v| {
                msm1(&lag_beta, &col_a[v]) + msm1(&lag_alpha, &col_b[v]) + msm1(&lag_g1, &col_c[v])
            })
            .collect::<Vec<_>>(),
    );
    let gamma_abc_g1 = abc[..shape.num_instance].to_vec();
    let l_query = abc[shape.num_instance..].to_vec();

    // [τ^i·Z(τ)]₁ with Z(x) = x^n − 1, for i = 0..n−2
    let h_query = G1Projective::normalize_batch(
        &(0..n - 1)
            .into_par_iter()
            .map(|i| ph1.tau_g1[i + n].into_group() - ph1.tau_g1[i])
            .collect::<Vec<_>>(),
    );

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    Ok(ProvingKey {
        vk: VerifyingKey {
            alpha_g1: ph1.alpha_tau_g1[0],
            beta_g2: ph1.beta_g2,
            gamma_g2: g2,
            delta_g2: g2,
            gamma_abc_g1,
        },
        beta_g1: ph1.beta_tau_g1[0],
        delta_g1: g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    })
}

// ── parameters file ─────────────────────────────────────────────────────────

/// One participant's public record. Says nothing about k beyond the proof
/// that whoever made it knew k.
#[derive(Clone, PartialEq, Debug)]
pub struct Contribution {
    /// [δ]₁ after this contribution.
    pub delta_after: G1Affine,
    /// random s and s·k: proof of knowledge of k, part 1
    pub s: G1Affine,
    pub s_delta: G1Affine,
    /// r·k, with r = hash_to_g2(transcript): proof of knowledge of k, part 2
    pub r_delta: G2Affine,
    /// sha256 of everything before this contribution, plus s and s·k
    pub transcript: [u8; 32],
}

impl Contribution {
    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.delta_after.serialize_uncompressed(&mut b).unwrap();
        self.s.serialize_uncompressed(&mut b).unwrap();
        self.s_delta.serialize_uncompressed(&mut b).unwrap();
        self.r_delta.serialize_uncompressed(&mut b).unwrap();
        b.extend_from_slice(&self.transcript);
        b
    }

    /// The public receipt for this contribution: what a participant posts so
    /// they can later find it in `verify`'s output.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"perseverus-ceremony contribution v1");
        h.update(self.bytes());
        h.finalize().into()
    }
}

pub struct Params {
    pub cs_hash: [u8; 32],
    pub phase1_digest: [u8; 32],
    pub power: u32,
    pub pk: ProvingKey<Bn254>,
    pub contributions: Vec<Contribution>,
}

impl Params {
    pub fn new(shape: &Shape, ph1: &Phase1, pk: ProvingKey<Bn254>) -> Self {
        Params {
            cs_hash: shape.cs_hash,
            phase1_digest: ph1.digest,
            power: shape.power,
            pk,
            contributions: Vec::new(),
        }
    }

    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&FORMAT.to_le_bytes())?;
        w.write_all(&self.cs_hash)?;
        w.write_all(&self.phase1_digest)?;
        w.write_all(&self.power.to_le_bytes())?;
        self.pk.serialize_uncompressed(&mut *w)?;
        w.write_all(&(self.contributions.len() as u32).to_le_bytes())?;
        for c in &self.contributions {
            w.write_all(&c.bytes())?;
        }
        Ok(())
    }

    /// Reads and fully validates every point (on curve, in the subgroup).
    pub fn read(r: &mut impl Read) -> Result<Self> {
        let mut magic = [0u8; 20];
        r.read_exact(&mut magic)?;
        ensure!(&magic == MAGIC, "not a Perseverus ceremony parameters file");
        let mut b4 = [0u8; 4];
        r.read_exact(&mut b4)?;
        ensure!(
            u32::from_le_bytes(b4) == FORMAT,
            "unsupported parameters file version"
        );
        let mut cs_hash = [0u8; 32];
        r.read_exact(&mut cs_hash)?;
        let mut phase1_digest = [0u8; 32];
        r.read_exact(&mut phase1_digest)?;
        r.read_exact(&mut b4)?;
        let power = u32::from_le_bytes(b4);
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&mut *r)
            .context("proving key in parameters file")?;
        r.read_exact(&mut b4)?;
        let n = u32::from_le_bytes(b4) as usize;
        ensure!(n < 1000, "implausible contribution count {n}");
        let mut contributions = Vec::with_capacity(n);
        for _ in 0..n {
            let delta_after = G1Affine::deserialize_uncompressed(&mut *r)?;
            let s = G1Affine::deserialize_uncompressed(&mut *r)?;
            let s_delta = G1Affine::deserialize_uncompressed(&mut *r)?;
            let r_delta = G2Affine::deserialize_uncompressed(&mut *r)?;
            let mut transcript = [0u8; 32];
            r.read_exact(&mut transcript)?;
            contributions.push(Contribution {
                delta_after,
                s,
                s_delta,
                r_delta,
                transcript,
            });
        }
        let mut rest = [0u8; 1];
        ensure!(r.read(&mut rest)? == 0, "trailing bytes after parameters");
        Ok(Params {
            cs_hash,
            phase1_digest,
            power,
            pk,
            contributions,
        })
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::read(&mut std::io::BufReader::new(f))
            .with_context(|| format!("reading {}", path.display()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let tmp = path.with_extension("partial");
        {
            let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            self.write(&mut w)?;
            w.flush()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Transcript hasher primed with the circuit, the phase 1 and every
    /// contribution in `prior`.
    fn transcript_base(&self, prior: &[Contribution]) -> Sha256 {
        let mut h = Sha256::new();
        h.update(b"perseverus-ceremony transcript v1");
        h.update(self.cs_hash);
        h.update(self.phase1_digest);
        for c in prior {
            h.update(c.bytes());
        }
        h
    }
}

/// A G2 point nobody knows the discrete log of, derived from `digest`.
/// (arkworks samples a random x and solves for y, then clears the cofactor.)
pub fn hash_to_g2(digest: &[u8; 32]) -> G2Affine {
    let mut rng = ChaCha20Rng::from_seed(*digest);
    G2Projective::rand(&mut rng).into_affine()
}

// ── contributing ────────────────────────────────────────────────────────────

/// Add one contribution. The secret k comes from the OS random generator
/// (mixed with `extra_entropy` if given), lives only in memory and is
/// overwritten before returning. Returns the receipt hash.
pub fn contribute(params: &mut Params, extra_entropy: &[u8]) -> Result<[u8; 32]> {
    // k = (512 bits of OS randomness, mixed with the participant's own) mod r.
    // No generator state is kept that could rederive k.
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut sh = Sha512::new();
    sh.update(b"perseverus-ceremony secret v1");
    sh.update(seed);
    sh.update(extra_entropy);
    let mut wide: [u8; 64] = sh.finalize().into();
    let mut k = Fr::from_le_bytes_mod_order(&wide);
    seed.zeroize();
    wide.zeroize();
    ensure!(!k.is_zero(), "random generator returned zero; try again");
    let mut k_inv = k.inverse().unwrap();

    let s = G1Projective::rand(&mut rand::rngs::OsRng).into_affine();
    let s_delta = (s * k).into_affine();
    let mut t = params.transcript_base(&params.contributions);
    t.update(s.serialize_uncompressed_vec());
    t.update(s_delta.serialize_uncompressed_vec());
    let transcript: [u8; 32] = t.finalize().into();
    let r = hash_to_g2(&transcript);
    let r_delta = (r * k).into_affine();

    let pk = &mut params.pk;
    pk.delta_g1 = (pk.delta_g1 * k).into_affine();
    pk.vk.delta_g2 = (pk.vk.delta_g2 * k).into_affine();
    let scale = |v: &[G1Affine]| -> Vec<G1Affine> {
        G1Projective::normalize_batch(&v.par_iter().map(|p| *p * k_inv).collect::<Vec<_>>())
    };
    pk.h_query = scale(&pk.h_query);
    pk.l_query = scale(&pk.l_query);

    k.zeroize();
    k_inv.zeroize();

    let c = Contribution {
        delta_after: pk.delta_g1,
        s,
        s_delta,
        r_delta,
        transcript,
    };
    let receipt = c.hash();
    params.contributions.push(c);
    Ok(receipt)
}

trait SerVec {
    fn serialize_uncompressed_vec(&self) -> Vec<u8>;
}
impl<T: CanonicalSerialize> SerVec for T {
    fn serialize_uncompressed_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.serialize_uncompressed(&mut v).unwrap();
        v
    }
}

// ── verifying ───────────────────────────────────────────────────────────────

pub struct Report {
    /// Receipt hash of every contribution, in order.
    pub contributions: Vec<[u8; 32]>,
    /// sha256 of pk.bin / vk.bin as `export` writes them (compressed), the
    /// values the server reports at /v1/meta as circuit.pk_sha256 / vk_sha256.
    pub pk_sha256: String,
    pub vk_sha256: String,
}

/// Check `params` against parameters recomputed by `initial` from the same
/// phase 1 and circuit.
pub fn verify(
    params: &Params,
    initial_pk: &ProvingKey<Bn254>,
    shape: &Shape,
    ph1: &Phase1,
) -> Result<Report> {
    ensure!(
        params.cs_hash == shape.cs_hash,
        "parameters are for a different circuit or server key"
    );
    ensure!(
        params.phase1_digest == ph1.digest,
        "parameters were made from a different phase 1 (ptau) file"
    );
    ensure!(
        params.power == shape.power,
        "parameters have the wrong domain size"
    );

    let (p, i) = (&params.pk, initial_pk);
    // Everything but δ must be exactly what anyone recomputes from phase 1.
    ensure!(p.vk.alpha_g1 == i.vk.alpha_g1, "α changed");
    ensure!(
        p.vk.beta_g2 == i.vk.beta_g2 && p.beta_g1 == i.beta_g1,
        "β changed"
    );
    ensure!(p.vk.gamma_g2 == i.vk.gamma_g2, "γ changed");
    ensure!(
        p.vk.gamma_abc_g1 == i.vk.gamma_abc_g1,
        "public-input query changed"
    );
    ensure!(p.a_query == i.a_query, "A query changed");
    ensure!(p.b_g1_query == i.b_g1_query, "B query (G1) changed");
    ensure!(p.b_g2_query == i.b_g2_query, "B query (G2) changed");
    ensure!(
        p.h_query.len() == i.h_query.len(),
        "H query has the wrong length"
    );
    ensure!(
        p.l_query.len() == i.l_query.len(),
        "L query has the wrong length"
    );

    ensure!(
        !params.contributions.is_empty(),
        "no contributions yet: δ = 1 is not safe to use"
    );

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let mut current = g1;
    let mut receipts = Vec::new();
    for (idx, c) in params.contributions.iter().enumerate() {
        let n = idx + 1;
        ensure!(
            !c.s.is_zero() && !c.s_delta.is_zero() && !c.delta_after.is_zero(),
            "contribution {n}: degenerate (identity) point"
        );
        let mut t = params.transcript_base(&params.contributions[..idx]);
        t.update(c.s.serialize_uncompressed_vec());
        t.update(c.s_delta.serialize_uncompressed_vec());
        let expect: [u8; 32] = t.finalize().into();
        ensure!(
            c.transcript == expect,
            "contribution {n}: transcript does not match the ones before it"
        );
        let r = hash_to_g2(&c.transcript);
        // knew k: s·k / s  ==  r·k / r
        ensure!(
            same_ratio((c.s, c.s_delta), (r, c.r_delta)),
            "contribution {n}: proof of knowledge fails"
        );
        // and applied that same k: δ_after / δ_before  ==  r·k / r
        ensure!(
            same_ratio((current, c.delta_after), (r, c.r_delta)),
            "contribution {n}: δ was not updated by the proven k"
        );
        current = c.delta_after;
        receipts.push(c.hash());
    }
    ensure!(
        p.delta_g1 == current,
        "[δ]₁ does not match the last contribution"
    );
    ensure!(
        same_ratio((g1, p.delta_g1), (g2, p.vk.delta_g2)),
        "[δ]₁ and [δ]₂ differ"
    );

    // H and L were divided by exactly δ: e(Σρ·new, [δ]₂) == e(Σρ·initial, g₂)
    let mut rng = rand::rngs::OsRng;
    for (name, new, old) in [("H", &p.h_query, &i.h_query), ("L", &p.l_query, &i.l_query)] {
        let rho: Vec<Fr> = (0..new.len()).map(|_| Fr::rand(&mut rng)).collect();
        let a = G1Projective::msm_unchecked(new, &rho).into_affine();
        let b = G1Projective::msm_unchecked(old, &rho).into_affine();
        ensure!(
            same_ratio((a, b), (g2, p.vk.delta_g2)),
            "{name} query was not divided by δ"
        );
    }

    let (pk_bytes, vk_bytes) = export_bytes(params)?;
    Ok(Report {
        contributions: receipts,
        pk_sha256: hex::encode(Sha256::digest(&pk_bytes)),
        vk_sha256: hex::encode(Sha256::digest(&vk_bytes)),
    })
}

/// pk.bin and vk.bin exactly as the SDK and server load them (compressed).
pub fn export_bytes(params: &Params) -> Result<(Vec<u8>, Vec<u8>)> {
    if params.contributions.is_empty() {
        bail!("refusing to export: no contributions (δ = 1)");
    }
    let mut pk = Vec::new();
    params.pk.serialize_compressed(&mut pk)?;
    let mut vk = Vec::new();
    params.pk.vk.serialize_compressed(&mut vk)?;
    Ok((pk, vk))
}
