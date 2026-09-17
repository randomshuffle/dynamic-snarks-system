//! Matched full-initialization comparison: scalar trace versus digest-only GKR.
//! Enable `parallel` for both binaries; use `--no-default-features` only for A.

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic};
use p3_field::PrimeCharacteristicRing;
use std::error::Error;
use std::time::Instant;

#[allow(dead_code)]
#[path = "../benches/support/proof_size.rs"]
mod proof_size;

fn main() -> Result<(), Box<dyn Error>> {
    if !cfg!(feature = "parallel") || cfg!(feature = "whir-initial-64") {
        return Err("use parallel and the original WHIR parameters".into());
    }
    let threads = std::thread::available_parallelism()?.get();
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let log = std::env::var("DYNAMIC_SNARK_TRACE_LOG").map_or(Ok(16), |s| s.parse::<u32>())?;
    let gates = 1usize.checked_shl(log).ok_or("invalid circuit size")?;
    if gates < 512 {
        return Err("use at least 512 gates".into());
    }
    let circuit = Circuit::new(gates / 2, 256, (0..3 * gates + 256).collect())?;
    // This driver uses power-of-two gate counts and four physical slots per gate.
    let k = gates.checked_mul(4).ok_or("invalid assignment size")?;
    let rows = 2 * k;
    let endpoint = cfg!(feature = "poseidon-gkr");
    let width = if endpoint { 1 } else { 64 };
    let variant = if endpoint {
        "digest-gkr"
    } else {
        "scalar-trace"
    };
    println!(
        "config,variant={variant},gates={gates},public_inputs=256,logical_assignment_len={},physical_assignment_len={k},hash_slots={rows},merkle_oracle_fields={},merkle_oracle_bytes={},transient_poseidon_fields={},outer_merkle_sumcheck_rounds={},merkle_opening_queries={},samples=1,threads={threads},parallel=true,WHIR=fixed_half_rate_factor4_security127_pow0",
        circuit.assignment_len(),
        rows * width,
        rows * width * 32,
        rows * if endpoint { 195 } else { 95 },
        rows.ilog2() as usize * if endpoint { 64 } else { 6 },
        if endpoint { 5 } else { 15 }
    );
    println!(
        "timing_scope=complete_dynamic_initialization; excludes_indexing_input_construction_serialization_destruction; verification_timed_separately"
    );
    if std::env::var_os("DYNAMIC_SNARK_PREFLIGHT").is_some() {
        return Ok(());
    }
    let mut assignment = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..gates / 2 {
        let a = Field::from_usize(pair + 1);
        let m = Field::from_usize(pair + 2);
        let b = Field::from_u64(2);
        assignment.extend([a, b, a + b, m, b, m * b]);
    }
    let public = vec![Field::from_u64(9); 256];
    assignment.extend_from_slice(&public);
    let mut assignment_bytes = Vec::new();
    ciborium::ser::into_writer(&assignment, &mut assignment_bytes)?;
    println!(
        "assignment_fingerprint={}",
        blake3::hash(&assignment_bytes).to_hex()
    );
    drop(assignment_bytes);
    let (pk, vk) = dynamic::index(circuit)?;
    eprintln!("initial A/B: {variant}, full proof begin");
    let started = Instant::now();
    let state = dynamic::initialize(&pk, assignment)?;
    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
    eprintln!("initial A/B: {variant}, full proof complete");
    let started = Instant::now();
    dynamic::verify(&vk, &public, state.proof())?;
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
    let encoded = proof_size::encode(state.proof())?;
    let decoded: dynamic::Proof = proof_size::decode(&encoded.bytes)?;
    dynamic::verify(&vk, &public, &decoded)?;
    println!(
        "variant,prove_ms,verify_ms,serialized_bytes,field_elements,blake3_hashes,payload_bytes"
    );
    println!(
        "{variant},{prove_ms:.6},{verify_ms:.6},{},{},{},{}",
        encoded.metrics.serialized_bytes,
        encoded.metrics.field_elements,
        encoded.metrics.blake3_hashes,
        encoded.metrics.payload_bytes()
    );
    for (component, metrics) in encoded.components {
        println!(
            "component,{component},serialized_bytes={},field_elements={},blake3_hashes={},payload_bytes={}",
            metrics.serialized_bytes,
            metrics.field_elements,
            metrics.blake3_hashes,
            metrics.payload_bytes()
        );
    }
    println!(
        "commitment_fingerprint={}",
        blake3::hash(&serde_json::to_vec(&state.current_commitment())?).to_hex()
    );
    println!("verified=true,cbor_roundtrip_verified=true");
    std::hint::black_box(&state);
    Ok(())
}
