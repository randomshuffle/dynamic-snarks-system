//! Matched, verified baseline / full initialization / independent first updates.

use std::error::Error;
use std::time::Instant;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic, static_snark};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::current_num_threads;

fn main() -> Result<(), Box<dyn Error>> {
    let log = env_usize("DYNAMIC_SNARK_TRACE_LOG", 16)?;
    let samples = env_usize("DYNAMIC_SNARK_FIRST_SAMPLES", 5)?;
    let gates = 1usize
        .checked_shl(log.try_into()?)
        .ok_or("trace too large")?;
    if gates < 512 || samples == 0 {
        return Err("need at least 512 gates and one sample".into());
    }
    let circuit = Circuit::new(gates / 2, 256, (0..3 * gates + 256).collect())?;
    let mut assignment = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..gates / 2 {
        let a = Field::from_usize(pair + 1);
        let m = Field::from_usize(pair + 2);
        let b = Field::from_u64(2);
        assignment.extend([a, b, a + b, m, b, m * b]);
    }
    let mut public = vec![Field::from_u64(9); 256];
    assignment.extend_from_slice(&public);
    let (pk, vk) = dynamic::index(circuit.clone())?;
    let mut next_assignment = assignment.clone();
    public[128] = Field::from_u64(10);
    next_assignment[3 * gates + 128] = public[128];
    let program = dynamic::regular_hyperplonk_program(&circuit, &next_assignment)?;
    let (baseline_pk, baseline_vk) = static_snark::setup(&program)?;
    println!(
        "config,gates={gates},threads={},parallel={},initial_folding={},samples={samples}",
        current_num_threads(),
        cfg!(feature = "parallel"),
        static_snark::WHIR_INITIAL_FOLDING_FACTOR
    );
    println!("phase,sample,prove_ms,verify_ms,proof_hash");

    eprintln!("comparison,initial,0,begin");
    let started = Instant::now();
    let base = dynamic::initialize(&pk, assignment)?;
    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
    eprintln!("comparison,initial,0,end");
    let started = Instant::now();
    dynamic::verify(&vk, &vec![Field::from_u64(9); 256], base.proof())?;
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "initial,0,{prove_ms:.6},{verify_ms:.6},{}",
        fingerprint(base.proof())?
    );

    // One verified warmup of each path; subsequent samples start from the same
    // fully proved, empty base. Keys, state cloning and verification are untimed.
    for sample in 0..=samples {
        for phase in if sample % 2 == 0 {
            ["baseline", "update"]
        } else {
            ["update", "baseline"]
        } {
            eprintln!("comparison,{phase},{sample},begin");
            let (prove_ms, verify_ms, hash) = if phase == "baseline" {
                let started = Instant::now();
                let proof = static_snark::prove(&baseline_pk, &program, &public)?;
                let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                eprintln!("comparison,{phase},{sample},end");
                let started = Instant::now();
                static_snark::verify(&baseline_vk, &public, &proof)?;
                let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
                (prove_ms, verify_ms, fingerprint(&proof)?)
            } else {
                let mut state = base.clone();
                let started = Instant::now();
                dynamic::update(&pk, &mut state, &[(3 * gates + 128, public[128])])?;
                let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                eprintln!("comparison,{phase},{sample},end");
                let started = Instant::now();
                dynamic::verify(&vk, &public, state.proof())?;
                let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
                (prove_ms, verify_ms, fingerprint(state.proof())?)
            };
            if sample > 0 {
                println!("{phase},{},{prove_ms:.6},{verify_ms:.6},{hash}", sample - 1);
            }
        }
    }
    Ok(())
}

fn fingerprint(proof: &impl serde::Serialize) -> Result<String, serde_json::Error> {
    Ok(blake3::hash(&serde_json::to_vec(proof)?)
        .to_hex()
        .to_string())
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(std::env::var(name).map_or(Ok(default), |value| value.parse())?)
}
