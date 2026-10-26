//! The ceremony produces exactly arkworks' Groth16 keys, real spends verify
//! with its output, and `verify` catches every kind of tampering we can think of.
//!
//! These tests use a phase 1 made from KNOWN τ, α, β (insecure on purpose, so
//! the result can be compared with arkworks' own setup). The real ceremony
//! reads the public Perpetual Powers of Tau.
//!
//!   cargo test --release -p perseverus-ceremony

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use perseverus_ceremony::{phase2, ptau};
use perseverus_circuits::{build_public_inputs, CircuitField, RevocationSpendCircuit};
use perseverus_core::issuance::{finalize_pack, prepare_pack_request, sign_pack_batch};
use perseverus_core::nullifier::compute_nullifier;
use perseverus_core::oprf::OprfServerKey;
use perseverus_core::poseidon::{poseidon_config, PoseidonField};
use perseverus_core::smt::{revocation_key, SparseMerkleTree};

const SEED: u64 = 20261026;

struct Fixture {
    _dir: tempfile::TempDir,
    ptau_path: std::path::PathBuf,
    server: OprfServerKey,
    server_hex: String,
    shape: phase2::Shape,
    ph1: ptau::Phase1,
    pk0: ProvingKey<Bn254>,
    alpha: Fr,
    beta: Fr,
}

fn pubkey_hex(k: &OprfServerKey) -> String {
    let mut b = Vec::new();
    k.pubkey.into_affine().serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}

fn fx() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let ptau_path = dir.path().join("test.ptau");
        // arkworks draws τ as the first field element from its rng; use the
        // same seed so its setup lands on the same τ (see the first test).
        let tau = Fr::rand(&mut StdRng::seed_from_u64(SEED));
        let mut r = StdRng::seed_from_u64(7);
        let (alpha, beta) = (Fr::rand(&mut r), Fr::rand(&mut r));
        let server = OprfServerKey::generate(&mut r);
        let server_hex = pubkey_hex(&server);
        let shape = phase2::synthesize(phase2::spend_circuit(&server_hex).unwrap()).unwrap();
        ptau::write_insecure_for_tests(&ptau_path, shape.power, tau, alpha, beta).unwrap();
        let ph1 = ptau::read(&ptau_path, shape.power).unwrap();
        ph1.check().unwrap();
        let pk0 = phase2::initial(&ph1, &shape).unwrap();
        Fixture {
            _dir: dir,
            ptau_path,
            server,
            server_hex,
            shape,
            ph1,
            pk0,
            alpha,
            beta,
        }
    })
}

fn bytes<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut v = Vec::new();
    x.serialize_uncompressed(&mut v).unwrap();
    v
}

fn contributed(n: usize) -> phase2::Params {
    let f = fx();
    let mut p = phase2::Params::new(&f.shape, &f.ph1, f.pk0.clone());
    for i in 0..n {
        phase2::contribute(&mut p, format!("participant {i}").as_bytes()).unwrap();
    }
    p
}

fn verify_err(p: &phase2::Params) -> String {
    let f = fx();
    match phase2::verify(p, &f.pk0, &f.shape, &f.ph1) {
        Ok(_) => panic!("tampered parameters verified"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn starting_parameters_equal_arkworks_setup() {
    let f = fx();
    let mut circuit = RevocationSpendCircuit::empty();
    circuit.pk_server = f.server.pubkey;
    let ark = Groth16::<Bn254>::generate_parameters_with_qap(
        circuit,
        f.alpha,
        f.beta,
        Fr::one(), // γ
        Fr::one(), // δ
        G1Projective::from(G1Affine::generator()),
        G2Projective::from(G2Affine::generator()),
        &mut StdRng::seed_from_u64(SEED),
    )
    .unwrap();
    assert_eq!(
        bytes(&f.pk0),
        bytes(&ark),
        "ceremony start differs from arkworks' setup"
    );
}

#[test]
fn params_file_round_trips() {
    let p = contributed(2);
    let mut buf = Vec::new();
    p.write(&mut buf).unwrap();
    let q = phase2::Params::read(&mut &buf[..]).unwrap();
    assert_eq!(bytes(&p.pk), bytes(&q.pk));
    assert_eq!(p.contributions, q.contributions);
    let mut extra = buf.clone();
    extra.push(0);
    assert!(
        phase2::Params::read(&mut &extra[..]).is_err(),
        "trailing bytes accepted"
    );
}

#[test]
fn real_spends_verify_with_ceremony_keys() {
    let f = fx();
    let p = contributed(3);
    let report = phase2::verify(&p, &f.pk0, &f.shape, &f.ph1).unwrap();
    assert_eq!(report.contributions.len(), 3);
    for (c, r) in p.contributions.iter().zip(&report.contributions) {
        assert_eq!(&c.hash(), r);
    }

    // through the files, exactly as the SDK and server load them
    let (pk_b, vk_b) = phase2::export_bytes(&p).unwrap();
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_b[..]).unwrap();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_b[..]).unwrap();
    assert_ne!(pk.delta_g1, G1Affine::generator(), "δ still 1");

    check_spends(&f.server, &pk, &vk);
}

#[test]
fn rejects_zero_contributions() {
    let p = contributed(0);
    assert!(verify_err(&p).contains("no contributions"));
    assert!(phase2::export_bytes(&p).is_err());
}

#[test]
fn rejects_changed_queries() {
    let base = contributed(2);
    let double = |x: G1Affine| (x.into_group() + x).into_affine();

    let mut p = contributed(2);
    p.pk.a_query[5] = double(p.pk.a_query[5]);
    assert!(verify_err(&p).contains("A query changed"));

    let mut p = contributed(2);
    p.pk.vk.gamma_abc_g1[1] = double(p.pk.vk.gamma_abc_g1[1]);
    assert!(verify_err(&p).contains("public-input query changed"));

    let mut p = contributed(2);
    let k = p.pk.l_query.len() / 2;
    p.pk.l_query[k] = double(p.pk.l_query[k]);
    assert!(verify_err(&p).contains("L query"));

    let mut p = contributed(2);
    p.pk.h_query[3] = double(p.pk.h_query[3]);
    assert!(verify_err(&p).contains("H query"));

    let mut p = contributed(2);
    p.pk.vk.alpha_g1 = double(p.pk.vk.alpha_g1);
    assert!(verify_err(&p).contains("α changed"));

    let f = fx();
    phase2::verify(&base, &f.pk0, &f.shape, &f.ph1).expect("untouched parameters verify");
}

#[test]
fn rejects_broken_contribution_chains() {
    // a contribution without a valid proof of knowledge
    let mut p = contributed(2);
    let r = p.contributions[1].r_delta;
    p.contributions[1].r_delta = (r.into_group() + r).into_affine();
    assert!(verify_err(&p).contains("contribution 2"));

    // a contribution removed from the middle
    let mut p = contributed(3);
    p.contributions.remove(1);
    assert!(verify_err(&p).contains("transcript"));

    // a coordinator who sets δ to a value THEY know, skipping the contributions:
    // scale δ, H and L by a known d, keep the old receipts
    let mut p = contributed(2);
    let d = Fr::from(12345u64);
    let d_inv = ark_ff::Field::inverse(&d).unwrap();
    p.pk.delta_g1 = (p.pk.delta_g1 * d).into_affine();
    p.pk.vk.delta_g2 = (p.pk.vk.delta_g2 * d).into_affine();
    p.pk.h_query =
        p.pk.h_query
            .iter()
            .map(|x| (*x * d_inv).into_affine())
            .collect();
    p.pk.l_query =
        p.pk.l_query
            .iter()
            .map(|x| (*x * d_inv).into_affine())
            .collect();
    assert!(verify_err(&p).contains("[δ]₁ does not match the last contribution"));
}

#[test]
fn rejects_other_circuit_or_phase1() {
    let f = fx();
    let p = contributed(1);

    // same parameters checked against a different server key's circuit
    let other = OprfServerKey::generate(&mut StdRng::seed_from_u64(99));
    let shape = phase2::synthesize(phase2::spend_circuit(&pubkey_hex(&other)).unwrap()).unwrap();
    let e = match phase2::verify(&p, &f.pk0, &shape, &f.ph1) {
        Ok(_) => panic!("verified against another circuit"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("different circuit"));

    // a phase-1 file with one bad power fails its own check
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.ptau");
    std::fs::copy(&f.ptau_path, &bad).unwrap();
    let mut raw = std::fs::read(&bad).unwrap();
    // section 2 starts after the 12-byte file header, section 1 (12 + 4+32+4+4 bytes)
    // and section 2's own 12-byte header; swap points 10 and 11
    let s2 = 12 + 12 + 44 + 12;
    let (a, b) = (s2 + 10 * 64, s2 + 11 * 64);
    let tmp = raw[a..a + 64].to_vec();
    raw.copy_within(b..b + 64, a);
    raw[b..b + 64].copy_from_slice(&tmp);
    std::fs::write(&bad, raw).unwrap();
    let ph = ptau::read(&bad, f.shape.power).unwrap();
    assert!(ph.check().is_err(), "a phase 1 with swapped powers passed");
    assert_ne!(ph.digest, f.ph1.digest);
}

#[test]
fn server_key_hex_matches_fixture() {
    // keeps pubkey_hex honest: the circuit built from the hex is the fixture's
    let f = fx();
    let c = phase2::spend_circuit(&f.server_hex).unwrap();
    assert_eq!(c.pk_server, f.server.pubkey);
}

/// An honest spend verifies with these keys; one lying about its expiry does not.
fn check_spends(server: &OprfServerKey, pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) {
    let mut rng = ark_std::rand::rngs::OsRng;
    let cfg = poseidon_config();
    let (req, secrets) = prepare_pack_request(&cfg, 4, &mut rng).unwrap();
    let resp = sign_pack_batch(
        server,
        &req.alphas,
        &secrets.base_points,
        202605,
        202605,
        &mut rng,
    );
    let issued = finalize_pack(&cfg, &req, &secrets, &resp, &server.pubkey, &mut rng).unwrap();
    let smt = SparseMerkleTree::new();
    let pack_id = PoseidonField::from(issued.pack_id);
    let idx = 1usize;
    let nullifier = compute_nullifier(
        &cfg,
        issued.token_seed,
        pack_id,
        PoseidonField::from(idx as u64),
    );

    let spend = |current: u64, claimed_exp: u64| -> bool {
        let mut rng = ark_std::rand::rngs::OsRng;
        let non_incl = smt.prove_non_inclusion(revocation_key(&cfg, pack_id));
        let dleq = &issued.poseidon_dleq_proofs[idx];
        let circuit = RevocationSpendCircuit {
            nullifier: Some(nullifier),
            current_month: Some(CircuitField::from(current)),
            revocation_root: Some(smt.root()),
            pk_server: server.pubkey,
            token_seed: Some(issued.token_seed),
            pack_id: Some(pack_id),
            token_index: Some(CircuitField::from(idx as u64)),
            blinded_sig: Some(issued.pack.tokens[idx].blinded_sig.into()),
            dleq_c: Some(dleq.challenge),
            dleq_s: Some(dleq.response),
            expiration_month: Some(CircuitField::from(claimed_exp)),
            start_month: Some(CircuitField::from(issued.start_month as u64)),
            smt_siblings: Some(non_incl.siblings),
            smt_path_bits: Some(non_incl.path_bits),
        };
        let Ok(proof) = Groth16::<Bn254>::prove(pk, circuit, &mut rng) else {
            return false;
        };
        let inputs =
            build_public_inputs(nullifier, CircuitField::from(current), smt.root()).unwrap();
        Groth16::<Bn254>::verify(vk, &inputs, &proof).unwrap()
    };
    assert!(
        spend(202605, 202605),
        "honest spend must verify with ceremony keys"
    );
    assert!(
        !spend(202610, 202612),
        "a spend lying about its expiry must not verify"
    );
}

/// Against a real snarkjs-format Powers of Tau file:
///   PERSEVERUS_TEST_PTAU=/path/to/file.ptau cargo test --release -p perseverus-ceremony real_ptau -- --ignored
#[test]
#[ignore]
fn real_ptau_file() {
    let path = std::env::var("PERSEVERUS_TEST_PTAU").expect("set PERSEVERUS_TEST_PTAU");
    let server = OprfServerKey::generate(&mut ark_std::rand::rngs::OsRng);
    let shape = phase2::synthesize(phase2::spend_circuit(&pubkey_hex(&server)).unwrap()).unwrap();
    let ph1 = ptau::read(std::path::Path::new(&path), shape.power).unwrap();
    ph1.check().unwrap();
    let pk0 = phase2::initial(&ph1, &shape).unwrap();
    let mut p = phase2::Params::new(&shape, &ph1, pk0.clone());
    phase2::contribute(&mut p, b"").unwrap();
    phase2::contribute(&mut p, b"").unwrap();
    phase2::verify(&p, &pk0, &shape, &ph1).unwrap();
    let (pk_b, vk_b) = phase2::export_bytes(&p).unwrap();
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_b[..]).unwrap();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_b[..]).unwrap();
    check_spends(&server, &pk, &vk);
}
