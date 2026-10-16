//! Measure what a Groth16 trusted setup for the spend circuit costs on this
//! machine, then run one full v11 round trip against the fresh keys:
//! issue a pack (server picks the months), prove a spend, verify it, and
//! confirm that a proof claiming a later expiry does not verify.
//!
//! Uses a throwaway random server key. The keys are NOT for production and
//! are not written anywhere.
//!
//!   cargo run --release -p perseverus-circuits --example setup_bench
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use perseverus_circuits::{build_public_inputs, CircuitField, RevocationSpendCircuit};
use perseverus_core::issuance::{finalize_pack, prepare_pack_request, sign_pack_batch};
use perseverus_core::nullifier::compute_nullifier;
use perseverus_core::oprf::OprfServerKey;
use perseverus_core::poseidon::{poseidon_config, PoseidonField};
use perseverus_core::smt::{revocation_key, SparseMerkleTree};
use std::time::Instant;

fn main() {
    let mut rng = ark_std::rand::rngs::OsRng;
    let (nc, nw, ni) = RevocationSpendCircuit::measure_size();
    println!("constraints={nc} witnesses={nw} instances={ni}");

    let server_key = OprfServerKey::generate(&mut rng);
    let mut empty = RevocationSpendCircuit::empty();
    empty.pk_server = server_key.pubkey;

    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(empty, &mut rng).expect("setup");
    println!(
        "setup_seconds={:.1} pk_bytes={} vk_bytes={}",
        t.elapsed().as_secs_f64(),
        pk.compressed_size(),
        vk.compressed_size()
    );

    // ── Issuance: the server signs a pack valid for May 2026 only. ──
    let cfg = poseidon_config();
    let (req, secrets) = prepare_pack_request(&cfg, 4, &mut rng).unwrap();
    let resp = sign_pack_batch(&server_key, &req.alphas, &secrets.base_points, 202605, 202605, &mut rng);
    let issued = finalize_pack(&cfg, &req, &secrets, &resp, &server_key.pubkey, 202605, 202605, &mut rng)
        .expect("finalize");

    let smt = SparseMerkleTree::new();
    let pack_id_f = PoseidonField::from(issued.pack_id);
    let idx = 2usize;
    let nullifier = compute_nullifier(&cfg, issued.token_seed, pack_id_f, PoseidonField::from(idx as u64));

    let spend = |current: u64, claimed_exp: u64, rng: &mut ark_std::rand::rngs::OsRng| -> bool {
        let non_incl = smt.prove_non_inclusion(revocation_key(&cfg, pack_id_f));
        let dleq = &issued.poseidon_dleq_proofs[idx];
        let circuit = RevocationSpendCircuit {
            nullifier: Some(nullifier),
            current_month: Some(CircuitField::from(current)),
            revocation_root: Some(smt.root()),
            pk_server: server_key.pubkey,
            token_seed: Some(issued.token_seed),
            pack_id: Some(pack_id_f),
            token_index: Some(CircuitField::from(idx as u64)),
            blinded_sig: Some(issued.pack.tokens[idx].blinded_sig.into()),
            dleq_c: Some(dleq.challenge),
            dleq_s: Some(dleq.response),
            expiration_month: Some(CircuitField::from(claimed_exp)),
            start_month: Some(CircuitField::from(issued.start_month as u64)),
            smt_siblings: Some(non_incl.siblings),
            smt_path_bits: Some(non_incl.path_bits),
        };
        let t = Instant::now();
        let proof = match Groth16::<Bn254>::prove(&pk, circuit, rng) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let prove_s = t.elapsed().as_secs_f64();
        let inputs = build_public_inputs(nullifier, CircuitField::from(current), smt.root()).unwrap();
        let ok = Groth16::<Bn254>::verify(&vk, &inputs, &proof).unwrap();
        println!("  spend current={current} claimed_exp={claimed_exp}: prove {prove_s:.1}s, verified={ok}");
        ok
    };

    let honest = spend(202605, 202605, &mut rng);
    let lying = spend(202610, 202612, &mut rng);
    println!("honest_in_window_verifies={honest} lying_expiry_verifies={lying}");
    assert!(honest, "an honest in-window spend must verify");
    assert!(!lying, "a spend that lies about its expiry must not verify");
    println!("OK");
}
