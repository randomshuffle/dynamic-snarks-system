//! Compare baseline proving and independent first-leaf updates in one Rayon pool.

use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic, static_snark};
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::current_num_threads;

fn main() -> Result<(), Box<dyn Error>> {
    let trace_log = env_usize("DYNAMIC_SNARK_TRACE_LOG", 16)?;
    let samples = env_usize("DYNAMIC_SNARK_FIRST_SAMPLES", 6)?;
    let gates = 1usize
        .checked_shl(trace_log.try_into()?)
        .ok_or("trace too large")?;
    if gates < 512 || samples == 0 {
        return Err("need trace log >= 9 and positive samples".into());
    }
    let pairs = gates / 2;
    let circuit = Circuit::new(pairs, 256, (0..6 * pairs + 256).collect())?;
    let mut assignment = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..pairs {
        let add_left = Field::from_usize(pair + 1);
        let mul_left = Field::from_usize(pair + 2);
        let right = Field::from_u64(2);
        assignment.extend([
            add_left,
            right,
            add_left + right,
            mul_left,
            right,
            mul_left * right,
        ]);
    }
    let mut public = vec![Field::from_u64(9); 256];
    assignment.extend_from_slice(&public);
    let (pk, vk) = dynamic::index(circuit.clone())?;
    let base = dynamic::initialize_transition_benchmark(&pk, assignment.clone())?;
    dynamic::verify_transition_benchmark(&vk, &public, &base)?;
    public[128] = Field::from_u64(10);
    assignment[6 * pairs + 128] = public[128];
    let updates = [(6 * pairs + 128, public[128])];
    let program = dynamic::regular_hyperplonk_program(&circuit, &assignment)?;
    let (baseline_pk, baseline_vk) = static_snark::setup(&program)?;
    println!(
        "config,gates={gates},positions=1,threads={},parallel={},initial_folding={}",
        current_num_threads(),
        cfg!(feature = "parallel"),
        static_snark::WHIR_INITIAL_FOLDING_FACTOR
    );
    println!("phase,sample,threads,prove_ms,verify_ms");

    // One verified warmup of each path; all measured updates still start empty.
    for sample in 0..=samples {
        for phase in if sample % 2 == 0 {
            ["baseline", "update"]
        } else {
            ["update", "baseline"]
        } {
            eprintln!("parallel-scaling,{phase},{sample},begin");
            let (prove_ms, verify_ms) = if phase == "baseline" {
                let started = Instant::now();
                let proof = static_snark::prove(&baseline_pk, &program, &public)?;
                let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                eprintln!("parallel-scaling,{phase},{sample},end");
                let started = Instant::now();
                static_snark::verify(&baseline_vk, &public, &proof)?;
                let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
                black_box(&proof);
                (prove_ms, verify_ms)
            } else {
                let mut state = base.clone();
                let started = Instant::now();
                dynamic::update_transition_benchmark(&pk, &mut state, &updates)?;
                let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                eprintln!("parallel-scaling,{phase},{sample},end");
                let started = Instant::now();
                dynamic::verify_transition_benchmark(&vk, &public, &state)?;
                let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
                black_box(&state);
                (prove_ms, verify_ms)
            };
            if sample > 0 {
                println!(
                    "{phase},{},{},{prove_ms:.6},{verify_ms:.6}",
                    sample - 1,
                    current_num_threads()
                );
            }
        }
    }
    Ok(())
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(std::env::var(name).map_or(Ok(default), |value| value.parse())?)
}
