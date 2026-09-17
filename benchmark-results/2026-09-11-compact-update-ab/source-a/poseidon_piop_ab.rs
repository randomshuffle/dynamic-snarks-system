//! One identical random gate-set update per binary, for the endpoint PIOP A/B.
//! Compare `--no-default-features --features parallel` with `--features parallel`.
//! `DYNAMIC_SNARK_CHANGED_GATES` defaults to 1; `DYNAMIC_SNARK_PREFLIGHT`
//! prints the workload and memory estimate without indexing or proving.

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic};
use p3_field::PrimeCharacteristicRing;
use std::error::Error;
use std::time::Instant;

#[allow(dead_code)]
#[path = "../benches/support/proof_size.rs"]
mod proof_size;
#[allow(dead_code)]
#[path = "../benches/support/update_workload.rs"]
mod update_workload;

fn main() -> Result<(), Box<dyn Error>> {
    if !cfg!(feature = "parallel") {
        return Err("this comparison requires --features parallel".into());
    }
    if cfg!(feature = "whir-initial-64") {
        return Err("this comparison uses the original WHIR parameters".into());
    }
    let threads = std::thread::available_parallelism()?.get();
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let log =
        std::env::var("DYNAMIC_SNARK_TRACE_LOG").map_or(Ok(16), |value| value.parse::<u32>())?;
    let gates = 1usize.checked_shl(log).ok_or("invalid circuit size")?;
    if gates < 512 {
        return Err("use at least 512 gates".into());
    }
    let changed_gates = std::env::var("DYNAMIC_SNARK_CHANGED_GATES")
        .map_or(Ok(1), |value| value.parse::<usize>())?;
    if changed_gates == 0 || changed_gates > gates {
        return Err("changed gate count must be in 1..=circuit gate count".into());
    }
    let pairs = gates / 2;
    let circuit = Circuit::new(pairs, 256, (0..6 * pairs + 256).collect())?;
    let mut assignment = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..pairs {
        let a = Field::from_usize(pair + 1);
        let m = Field::from_usize(pair + 2);
        let b = Field::from_u64(2);
        assignment.extend([a, b, a + b, m, b, m * b]);
    }
    let public = vec![Field::from_u64(9); 256];
    assignment.extend_from_slice(&public);
    let seed = 20260909;
    let revisions = update_workload::revisions(
        gates,
        changed_gates,
        1,
        seed,
        update_workload::Pattern::Random,
    );
    let update = &revisions[0];
    let indices = update.iter().map(|&(index, _)| index).collect::<Vec<_>>();
    let resources = dynamic::transition_resource_estimate(&circuit, &indices)?;
    let variant = if cfg!(feature = "poseidon-gkr") {
        "endpoint-gkr"
    } else {
        "scalar-trace"
    };
    let r = resources.row_count;
    let product_width = (14 + 2 * r.ilog2() as usize).next_power_of_two();
    let sumcheck_rounds = 2 * r.ilog2()
        + if cfg!(feature = "poseidon-gkr") {
            64
        } else {
            5
        } * (r.ilog2() + 1);
    println!(
        "config,variant={variant},gates={gates},seed={seed},changed_gates={changed_gates},first_gate_index={},positions={},samples=1,threads={threads},parallel=true,rows={r},main_width={},main_fields={},product_fields={},hash_slots={},active_hashes={},outer_sumcheck_rounds={sumcheck_rounds},conservative_transition_peak_bytes={},workload_fingerprint={}",
        indices[0] / 3,
        indices.len(),
        resources.row_width,
        resources.master_fields,
        r * product_width,
        2 * r,
        resources.poseidon_hashes,
        resources.conservative_peak_bytes,
        update_workload::fingerprint(&revisions)
    );
    println!(
        "selected_gate_indices={}",
        indices
            .chunks_exact(3)
            .map(|tuple| (tuple[0] / 3).to_string())
            .collect::<Vec<_>>()
            .join(":")
    );
    println!(
        "timing_scope=update_including_tree_maintenance_and_public_opening; excludes_indexing_trusted_base_cloning_serialization_destruction; WHIR=fixed_half_rate_factor4_security127_pow0"
    );
    if std::env::var_os("DYNAMIC_SNARK_PREFLIGHT").is_some() {
        return Ok(());
    }
    let (pk, vk) = dynamic::index(circuit)?;
    let mut state = dynamic::initialize_transition_benchmark(&pk, assignment)?;
    dynamic::verify_transition_benchmark(&vk, &public, &state)?;
    let start = Instant::now();
    dynamic::update_transition_benchmark(&pk, &mut state, update)?;
    let update_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    dynamic::verify_transition_benchmark(&vk, &public, &state)?;
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let encoded = proof_size::encode(&state.proof_payload())?;
    println!(
        "variant,update_ms,verify_ms,serialized_bytes,field_elements,blake3_hashes,payload_bytes"
    );
    println!(
        "{variant},{update_ms:.6},{verify_ms:.6},{},{},{},{}",
        encoded.metrics.serialized_bytes,
        encoded.metrics.field_elements,
        encoded.metrics.blake3_hashes,
        encoded.metrics.payload_bytes()
    );
    for (component, metrics) in encoded.components {
        println!(
            "component,{component},serialized_bytes={},field_elements={},blake3_hashes={}",
            metrics.serialized_bytes, metrics.field_elements, metrics.blake3_hashes
        );
    }
    std::hint::black_box(&state);
    Ok(())
}
