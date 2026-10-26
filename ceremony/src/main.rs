//! perseverus-ceremony — run or check the multi-party setup for the v11 spend circuit.
//!
//!   perseverus-ceremony init       --ptau F --server-pubkey HEX --out round0.params
//!   perseverus-ceremony contribute --in roundN.params --out roundN+1.params [--entropy TEXT]
//!   perseverus-ceremony verify     --ptau F --server-pubkey HEX --params P [--expect HASH]...
//!   perseverus-ceremony export     --ptau F --server-pubkey HEX --params P --out-dir DIR
//!
//! See ceremony/README.md.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use perseverus_ceremony::{phase2, ptau};

const USAGE: &str = "\
perseverus-ceremony — multi-party setup for the Perseverus v11 spend circuit

  init       --ptau FILE --server-pubkey HEX --out round0.params
             Starting parameters from the public Powers of Tau file. No secrets;
             anyone running it gets the same result. NOT usable until contributed to.

  contribute --in roundN.params --out roundN+1.params [--entropy TEXT]
             Add your secret randomness (OS random generator, plus TEXT if given).
             The secret stays in memory and is wiped before exit. Prints your receipt.

  verify     --ptau FILE --server-pubkey HEX --params FILE [--expect RECEIPT]...
             Rebuild the starting parameters yourself and check every contribution.
             Prints every receipt and the sha256 of the final pk.bin / vk.bin.
             --expect fails unless that receipt is in the chain (use it for your own).

  export     --ptau FILE --server-pubkey HEX --params FILE --out-dir DIR
             verify, then write DIR/pk.bin and DIR/vk.bin.
";

struct Args {
    cmd: String,
    ptau: Option<PathBuf>,
    server_pubkey: Option<String>,
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    params: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    entropy: Option<String>,
    expect: Vec<String>,
}

fn parse() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut a = Args {
        cmd,
        ptau: None,
        server_pubkey: None,
        input: None,
        out: None,
        params: None,
        out_dir: None,
        entropy: None,
        expect: Vec::new(),
    };
    while let Some(flag) = it.next() {
        let mut val = || it.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--ptau" => a.ptau = Some(val()?.into()),
            "--server-pubkey" => a.server_pubkey = Some(val()?),
            "--in" => a.input = Some(val()?.into()),
            "--out" => a.out = Some(val()?.into()),
            "--params" => a.params = Some(val()?.into()),
            "--out-dir" => a.out_dir = Some(val()?.into()),
            "--entropy" => a.entropy = Some(val()?),
            "--expect" => a.expect.push(val()?.to_lowercase()),
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}\n\n{USAGE}"),
        }
    }
    Ok(a)
}

fn need<T: Clone>(v: &Option<T>, name: &str) -> Result<T> {
    v.clone()
        .with_context(|| format!("missing {name}\n\n{USAGE}"))
}

/// Phase 1 + circuit → (shape, phase 1, starting parameters).
fn start(
    a: &Args,
) -> Result<(
    phase2::Shape,
    ptau::Phase1,
    ark_groth16::ProvingKey<ark_bn254::Bn254>,
)> {
    let ptau_path = need(&a.ptau, "--ptau")?;
    let key = need(&a.server_pubkey, "--server-pubkey")?;
    let t = Instant::now();
    let shape = phase2::synthesize(phase2::spend_circuit(&key)?)?;
    println!(
        "circuit: {} constraints, {} public inputs, domain 2^{}  (r1cs sha256 {})",
        shape.num_constraints,
        shape.num_instance - 1,
        shape.power,
        hex::encode(shape.cs_hash)
    );
    println!("server public key: {}", key.trim());
    println!("ptau file: {}", ptau_path.display());
    println!("  blake2b-512 {}", ptau::blake2b_file(&ptau_path)?);
    println!("  (compare with the hash the Powers of Tau project publishes for this file)");
    let ph1 = ptau::read(&ptau_path, shape.power)?;
    ph1.check()
        .context("phase 1 file failed its consistency checks")?;
    println!("  phase 1 points valid and consistent");
    let pk0 = phase2::initial(&ph1, &shape)?;
    println!(
        "starting parameters rebuilt in {:.1}s",
        t.elapsed().as_secs_f64()
    );
    Ok((shape, ph1, pk0))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let a = parse()?;
    match a.cmd.as_str() {
        "init" => {
            let out = need(&a.out, "--out")?;
            ensure!(!out.exists(), "{} already exists", out.display());
            let (shape, ph1, pk0) = start(&a)?;
            phase2::Params::new(&shape, &ph1, pk0).save(&out)?;
            println!(
                "wrote {} (no contributions yet — not usable on its own)",
                out.display()
            );
        }
        "contribute" => {
            let input = need(&a.input, "--in")?;
            let out = need(&a.out, "--out")?;
            ensure!(!out.exists(), "{} already exists", out.display());
            let mut p = phase2::Params::load(&input)?;
            let before = p.contributions.len();
            let t = Instant::now();
            let receipt =
                phase2::contribute(&mut p, a.entropy.as_deref().unwrap_or("").as_bytes())?;
            p.save(&out)?;
            println!(
                "contribution #{} added in {:.1}s; your secret has been wiped from memory",
                before + 1,
                t.elapsed().as_secs_f64()
            );
            println!("wrote {}", out.display());
            println!();
            println!("YOUR RECEIPT (post it publicly, and check it with `verify --expect`):");
            println!("  {}", hex::encode(receipt));
        }
        "verify" | "export" => {
            let params_path = need(&a.params, "--params")?;
            let (shape, ph1, pk0) = start(&a)?;
            let p = phase2::Params::load(&params_path)?;
            let report = phase2::verify(&p, &pk0, &shape, &ph1)?;
            println!(
                "{}: {} contribution(s), all valid:",
                params_path.display(),
                report.contributions.len()
            );
            for (i, r) in report.contributions.iter().enumerate() {
                println!("  #{} {}", i + 1, hex::encode(r));
            }
            for e in &a.expect {
                ensure!(
                    report.contributions.iter().any(|r| hex::encode(r) == *e),
                    "receipt {e} is NOT in this chain"
                );
                println!("  found expected receipt {e}");
            }
            println!("pk.bin sha256 {}", report.pk_sha256);
            println!("vk.bin sha256 {}", report.vk_sha256);
            println!("RESULT: VALID");
            if a.cmd == "export" {
                let dir = need(&a.out_dir, "--out-dir")?;
                std::fs::create_dir_all(&dir)?;
                let (pk, vk) = phase2::export_bytes(&p)?;
                std::fs::write(dir.join("pk.bin"), pk)?;
                std::fs::write(dir.join("vk.bin"), vk)?;
                println!("wrote {}/pk.bin and vk.bin", dir.display());
            }
        }
        "" | "help" => print!("{USAGE}"),
        other => bail!("unknown command {other}\n\n{USAGE}"),
    }
    Ok(())
}
