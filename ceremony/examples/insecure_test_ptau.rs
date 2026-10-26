//! Write a phase-1 file from KNOWN random τ, α, β for trying the commands out.
//! INSECURE: anything set up from it can be forged. Never use it for real keys.
//!
//!   cargo run --release -p perseverus-ceremony --example insecure_test_ptau -- OUT.ptau [POWER]
use ark_bn254::Fr;
use ark_ff::UniformRand;
fn main() {
    let mut a = std::env::args().skip(1);
    let out = a
        .next()
        .expect("usage: insecure_test_ptau OUT.ptau [POWER]");
    let power: u32 = a.next().map(|p| p.parse().unwrap()).unwrap_or(15);
    let mut r = rand::rngs::OsRng;
    perseverus_ceremony::ptau::write_insecure_for_tests(
        std::path::Path::new(&out),
        power,
        Fr::rand(&mut r),
        Fr::rand(&mut r),
        Fr::rand(&mut r),
    )
    .unwrap();
    eprintln!("wrote {out} (INSECURE test phase 1, power {power})");
}
