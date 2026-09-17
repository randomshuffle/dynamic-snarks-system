//! Repeated first-update latency from an empty hierarchy (no accumulated updates).

use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic};
use p3_field::PrimeCharacteristicRing;

fn main() -> Result<(), Box<dyn Error>> {
    let trace_log = env_usize("DYNAMIC_SNARK_TRACE_LOG", 16)?;
    let samples = env_usize("DYNAMIC_SNARK_FIRST_SAMPLES", 20)?;
    let kind = std::env::var("DYNAMIC_SNARK_FIRST_KIND").unwrap_or_else(|_| "gate".into());
    let gates = 1usize
        .checked_shl(trace_log.try_into()?)
        .ok_or("trace too large")?;
    if gates < 512 || samples == 0 || !matches!(kind.as_str(), "gate" | "leaf") {
        return Err("need trace log >= 9, positive samples, and kind gate or leaf".into());
    }
    let n = gates / 2;
    let public_count = 256;
    let circuit = Circuit::new(n, public_count, (0..6 * n + public_count).collect())?;
    let mut assignment = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..n {
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
    let mut public_inputs = vec![Field::from_u64(9); public_count];
    assignment.extend_from_slice(&public_inputs);
    let updates = if kind == "leaf" {
        public_inputs[128] = Field::from_u64(10);
        vec![(6 * n + 128, public_inputs[128])]
    } else {
        let start = 3 * (gates / 2); // An addition gate away from the public-input slots.
        let left = assignment[start] + Field::ONE;
        let right = assignment[start + 1];
        vec![(start, left), (start + 1, right), (start + 2, left + right)]
    };
    let indices = updates.iter().map(|&(index, _)| index).collect::<Vec<_>>();
    let resources = dynamic::transition_resource_estimate(&circuit, &indices)?;
    println!(
        "config,kind={kind},gates={gates},positions={},leaves={},path_depth={},sparse_rows={},main_width={},main_fields={},poseidon_hashes={},parallel={},rayon_threads={}",
        updates.len(),
        4 * gates,
        trace_log + 2,
        resources.row_count,
        resources.row_width,
        resources.master_fields,
        resources.poseidon_hashes,
        cfg!(feature = "parallel"),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
    );
    println!(
        "timing: trusted base; indexing, base construction, cloning, verification, and destruction excluded; every sample starts with empty update tables"
    );
    let (pk, vk) = dynamic::index(circuit)?;
    let base = dynamic::initialize_transition_benchmark(&pk, assignment)?;
    dynamic::verify_transition_benchmark(&vk, &vec![Field::from_u64(9); public_count], &base)?;
    eprintln!("first-update profile ready: pid={}", std::process::id());
    println!("sample,kind,update_ms,verify_ms");
    for sample in 0..samples {
        let mut state = base.clone();
        eprintln!("first-update sample {sample} begin");
        let started = Instant::now();
        dynamic::update_transition_benchmark(&pk, &mut state, &updates)?;
        let update_ms = started.elapsed().as_secs_f64() * 1000.0;
        eprintln!("first-update sample {sample} end");
        let started = Instant::now();
        dynamic::verify_transition_benchmark(&vk, &public_inputs, &state)?;
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
        black_box(&state);
        println!("{sample},{kind},{update_ms:.6},{verify_ms:.6}");
    }
    Ok(())
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(std::env::var(name).map_or(Ok(default), |value| value.parse())?)
}
