//! Reproducible BN254 experiment: one initial proof and independent update sequences.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic, static_snark};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_maybe_rayon::prelude::current_num_threads;

#[path = "support/proof_size.rs"]
mod proof_size;
#[path = "support/update_workload.rs"]
mod update_workload;
use update_workload::{Pattern, fingerprint, maximal_composed_supports, revisions};

const PUBLIC_INPUTS: usize = 256;
const PUBLIC_VALUE: u64 = 9;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Config {
    trace_log: usize,
    update_logs: Vec<usize>,
    sequence_len: usize,
    seed: u64,
    output: PathBuf,
    preflight_only: bool,
    memory_bytes: u128,
    rss_limit_bytes: u128,
    shared_baseline: bool,
}

struct Case {
    gates: usize,
    workload: Vec<Vec<(usize, Field)>>,
}

fn main() -> Result<()> {
    let config = Config::from_env()?;
    fs::create_dir_all(&config.output)?;
    let gates = 1usize << config.trace_log;
    let threads = current_num_threads();
    let baseline_mode = if config.shared_baseline {
        "shared"
    } else {
        "paired"
    };
    let baseline_reference_gates = 1usize << config.update_logs[0];
    let public = vec![Field::from_u64(PUBLIC_VALUE); PUBLIC_INPUTS];
    let circuit = Circuit::new(
        gates / 2,
        PUBLIC_INPUTS,
        (0..3 * gates + PUBLIC_INPUTS).collect(),
    )?;
    let endpoint = cfg!(feature = "poseidon-gkr");
    let piop = if cfg!(feature = "compact-merkle") {
        "compact-merkle"
    } else if endpoint {
        "endpoint-gkr"
    } else {
        "scalar-trace"
    };
    let merkle_width: usize = if endpoint { 1 } else { 64 };
    let cair_variables = config.trace_log + 3 + merkle_width.ilog2() as usize;
    let whir = static_snark::whir_configuration(cair_variables)?;
    let initial_folding = static_snark::WHIR_INITIAL_FOLDING_FACTOR;
    let initial_interleaving = 1usize << initial_folding;
    assert!(matches!(initial_folding, 4 | 6));
    assert_eq!(static_snark::WHIR_SUBSEQUENT_FOLDING_FACTOR, 4);
    write_file(
        &config.output.join("experiment.json"),
        &format!(
            "{{\"schema_version\":3,\"merkle_piop\":\"{piop}\",\"field\":\"BN254\",\"trace_log\":{},\"gate_rows\":{},\"public_inputs\":256,\"permutation\":\"identity\",\"update_pattern\":\"random_without_replacement_within_revision\",\"update_logs\":{:?},\"sequence_len\":{},\"seed\":{},\"rayon_threads\":{},\"parallel\":true,\"initial_interleaving\":{initial_interleaving},\"subsequent_interleaving\":16,\"inverse_rate\":2,\"security_bits\":127,\"pow_bits\":0,\"initializations\":1,\"independent_cases\":true,\"warmups\":0,\"verify_every_proof\":true,\"cair_folding_schedule\":{:?},\"cair_fft_domains\":{:?}}}\n",
            config.trace_log,
            gates,
            config.update_logs,
            config.sequence_len,
            config.seed,
            threads,
            whir.folding_schedule,
            whir.fft_domain_sizes,
        ),
    )?;
    println!(
        "BN254 experiment: 2^{} gates; Rayon workers={threads}; WHIR={initial_folding} then 4 variables; full initial proof once",
        config.trace_log
    );
    // Record which baseline samples the comparison summary must use.
    write_file(
        &config.output.join("baseline.json"),
        &format!(
            "{{\"mode\":\"{baseline_mode}\",\"reference_gates\":{baseline_reference_gates}}}\n"
        ),
    )?;
    println!("Baseline mode: {baseline_mode}; reference update size={baseline_reference_gates}");
    println!(
        "Merkle PIOP: {piop}; initial FFT heights: {:?}",
        whir.fft_domain_sizes
    );
    write_file(
        &config.output.join("proof-size-format.json"),
        concat!(
            "{\"version\":1,\"encoding\":\"CBOR via ciborium 0.2.2, uncompressed\",",
            "\"field_bytes\":32,\"blake3_hash_bytes\":32,",
            "\"field_representation\":\"p3-bn254 Montgomery bytes\",",
            "\"payload\":\"32 * (field_elements + blake3_hashes); includes Poseidon digests as field elements\",",
            "\"serialized\":\"entire proof, including shapes, indices, tags, lengths and field names\",",
            "\"scope\":\"full verifier proof; excludes separately supplied public inputs, verification key and prover state\",",
            "\"checkpoints\":\"initial and final revision of each measured baseline/update case\",",
            "\"serialization_outside_prover_and_verifier_timers\":true}\n"
        ),
    )?;

    let mut preflight = csv(
        &config.output.join("preflight.csv"),
        "update_gates,max_composed_positions,max_sparse_rows,main_width,master_fields,transition_estimate_bytes,dense_envelope_bytes,initial_estimate_bytes,required_peak_bytes",
    )?;
    let mut workload_file = csv(
        &config.output.join("workload.csv"),
        "update_gates,revision,logical_position,new_value",
    )?;
    let mut fingerprints = csv(
        &config.output.join("workload-fingerprints.csv"),
        "update_gates,fingerprint",
    )?;
    let mut cases = Vec::new();
    // Covers retained keys, trees, assignments and baseline proving work. This
    // is a planning envelope, not an RSS measurement or a formal upper bound.
    let dense_envelope = gates as u128 * 256 * 32;
    let (transient_state_fields, input_fields) = if endpoint { (195, 3) } else { (95, 64) };
    let initial_peak =
        gates as u128 * 8 * (4 * merkle_width + transient_state_fields + input_fields) as u128 * 32
            + dense_envelope;
    let mut required_peak = initial_peak;
    for &log in &config.update_logs {
        let changed = 1usize << log;
        let workload = revisions(
            gates,
            changed,
            config.sequence_len,
            config.seed,
            Pattern::Random,
        );
        let supports = maximal_composed_supports(&workload);
        let mut estimates = supports
            .iter()
            .map(|support| {
                dynamic::transition_resource_estimate(&circuit, support)
                    .map(|estimate| (support.len(), estimate))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        estimates.sort_by_key(|(_, estimate)| estimate.conservative_peak_bytes);
        let (positions, estimate) = estimates.last().ok_or("empty workload")?;
        let transition_peak = dense_envelope + estimate.conservative_peak_bytes;
        let case_peak = initial_peak.max(transition_peak);
        required_peak = required_peak.max(case_peak);
        writeln!(
            preflight,
            "{changed},{positions},{},{},{},{},{dense_envelope},{initial_peak},{case_peak}",
            estimate.row_count,
            estimate.row_width,
            estimate.master_fields,
            estimate.conservative_peak_bytes
        )?;
        writeln!(fingerprints, "{changed},{}", fingerprint(&workload))?;
        for (revision, updates) in workload.iter().enumerate() {
            for &(position, value) in updates {
                writeln!(
                    workload_file,
                    "{changed},{},{position},{}",
                    revision + 1,
                    value.as_canonical_biguint()
                )?;
            }
        }
        println!(
            "preflight: {changed} updated gates; max composed positions={positions}; rows={}; main width={}; projected peak={:.2} GiB",
            estimate.row_count,
            estimate.row_width,
            gib(case_peak)
        );
        cases.push(Case {
            gates: changed,
            workload,
        });
    }
    preflight.flush()?;
    workload_file.flush()?;
    fingerprints.flush()?;
    println!(
        "Projected run peak={:.2} GiB; available memory={:.2} GiB; 70% allowance={:.2} GiB",
        gib(required_peak),
        gib(config.memory_bytes),
        gib(config.memory_bytes * 7 / 10)
    );
    if config.preflight_only {
        println!("PREFLIGHT_COMPLETE (no proofs generated)");
        return Ok(());
    }
    if required_peak > config.memory_bytes * 7 / 10 && config.rss_limit_bytes == 0 {
        return Err(format!("memory guard: projected {:.2} GiB exceeds 70% of {:.2} GiB; use a larger host or a smaller rehearsal (no cases were silently skipped)", gib(required_peak), gib(config.memory_bytes)).into());
    }
    if config.rss_limit_bytes != 0 {
        println!(
            "MONITORED_MEMORY_TRIAL: launcher enforces an RSS cutoff of {} bytes; projected allocation is {:.2} GiB; resident memory and allocation are different metrics",
            config.rss_limit_bytes,
            gib(required_peak),
        );
    }

    let mut samples = csv(
        &config.output.join("samples.csv"),
        "phase,update_gates,revision,prove_seconds,verify_seconds,verified,cumulative_distinct_gates,proof_field_elements,proof_blake3_hashes,proof_poseidon_hashes,proof_payload_bytes,proof_serialized_bytes,proof_overhead_bytes,proof_file",
    )?;
    fs::create_dir(config.output.join("proofs"))?;
    let mut components = csv(
        &config.output.join("proof-components.csv"),
        "phase,update_gates,revision,component,field_elements,blake3_hashes,poseidon_hashes,payload_bytes,serialized_bytes",
    )?;
    let mut setup = csv(&config.output.join("setup.csv"), "phase,seconds")?;
    let assignment = initial_assignment(&circuit);
    let started = Instant::now();
    let template = dynamic::regular_hyperplonk_program(&circuit, &assignment)?;
    let (baseline_pk, baseline_vk) = static_snark::setup(&template)?;
    drop(template);
    writeln!(
        setup,
        "baseline_index,{:.9}",
        started.elapsed().as_secs_f64()
    )?;
    setup.flush()?;
    println!("Baseline indexing complete");
    let started = Instant::now();
    let (pk, vk) = dynamic::index(circuit.clone())?;
    writeln!(
        setup,
        "dynamic_index,{:.9}",
        started.elapsed().as_secs_f64()
    )?;
    setup.flush()?;
    println!("Dynamic indexing complete");

    // Cloning the caller's input is outside the prover timing, as in the
    // baseline/update sequence. All actual initial prover work is timed.
    let initial_input = assignment.clone();
    println!("SAMPLE_BEGIN phase=initial gates=0 revision=0");
    let started = Instant::now();
    let base = dynamic::initialize(&pk, initial_input)?;
    let prove_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    dynamic::verify(&vk, &public, base.proof())?;
    let verify_seconds = started.elapsed().as_secs_f64();
    let encoded = proof_size::encode(base.proof())?;
    let decoded: dynamic::Proof = proof_size::decode(&encoded.bytes)?;
    dynamic::verify(&vk, &public, &decoded)?;
    drop(decoded);
    let proof_file = persist_proof(&config, &mut components, "initial", 0, 0, &encoded)?;
    sample(
        &mut samples,
        "initial",
        0,
        0,
        prove_seconds,
        verify_seconds,
        0,
        encoded.metrics,
        &proof_file,
    )?;
    drop(encoded);
    println!(
        "Full initial proof generated and verified in {prove_seconds:.3}s (verification separate)"
    );

    for case in cases {
        // Trees share immutable storage. Each case owns its assignment and
        // update hierarchy and starts from the same fully proved base.
        let mut state = base.clone();
        let mut scratch_assignment = assignment.clone();
        let mut visited = BTreeSet::new();
        println!("CASE_BEGIN update_gates={}", case.gates);
        for (index, updates) in case.workload.iter().enumerate() {
            let revision = index + 1;
            for &(position, value) in updates {
                scratch_assignment[position] = value;
                visited.insert(position / 3);
            }
            // Alternate order to avoid giving one prover a consistent cache
            // or temperature advantage. Neither timer includes the other.
            let order = if revision % 2 == 1 {
                ["update", "baseline"]
            } else {
                ["baseline", "update"]
            };
            for phase in order {
                if phase == "baseline"
                    && config.shared_baseline
                    && case.gates != baseline_reference_gates
                {
                    continue;
                }
                println!(
                    "SAMPLE_BEGIN phase={phase} gates={} revision={revision}",
                    case.gates
                );
                let started = Instant::now();
                let (prove_seconds, verify_seconds, encoded) = if phase == "update" {
                    dynamic::update(&pk, &mut state, updates)?;
                    let elapsed = started.elapsed().as_secs_f64();
                    let verify_started = Instant::now();
                    dynamic::verify(&vk, &public, state.proof())?;
                    let verification = verify_started.elapsed().as_secs_f64();
                    let encoded = proof_size::encode(state.proof())?;
                    if revision == config.sequence_len {
                        let decoded: dynamic::Proof = proof_size::decode(&encoded.bytes)?;
                        dynamic::verify(&vk, &public, &decoded)?;
                    }
                    (elapsed, verification, encoded)
                } else {
                    let program =
                        dynamic::regular_hyperplonk_program(&circuit, &scratch_assignment)?;
                    let proof = static_snark::prove(&baseline_pk, &program, &public)?;
                    let elapsed = started.elapsed().as_secs_f64();
                    let verify_started = Instant::now();
                    static_snark::verify(&baseline_vk, &public, &proof)?;
                    let verification = verify_started.elapsed().as_secs_f64();
                    let encoded = proof_size::encode(&proof)?;
                    if revision == config.sequence_len {
                        let decoded: static_snark::Proof = proof_size::decode(&encoded.bytes)?;
                        static_snark::verify(&baseline_vk, &public, &decoded)?;
                    }
                    black_box(proof);
                    (elapsed, verification, encoded)
                };
                let proof_file = if revision == config.sequence_len {
                    persist_proof(
                        &config,
                        &mut components,
                        phase,
                        case.gates,
                        revision,
                        &encoded,
                    )?
                } else {
                    String::new()
                };
                sample(
                    &mut samples,
                    phase,
                    case.gates,
                    revision,
                    prove_seconds,
                    verify_seconds,
                    visited.len(),
                    encoded.metrics,
                    &proof_file,
                )?;
                println!(
                    "SAMPLE_COMPLETE phase={phase} gates={} revision={revision} prove_seconds={prove_seconds:.6} verify_seconds={verify_seconds:.6}",
                    case.gates
                );
            }
            // Check that the dynamic and ordinary proof used the same witness.
            if state.current_assignment() != scratch_assignment {
                return Err("dynamic/baseline assignment mismatch".into());
            }
        }
        black_box(&state);
        println!("CASE_COMPLETE update_gates={}", case.gates);
    }
    println!("EXPERIMENT_COMPLETE");
    Ok(())
}

impl Config {
    fn from_env() -> Result<Self> {
        let trace_log = env_usize("EXPERIMENT_TRACE_LOG", 24)?;
        if !(9..=24).contains(&trace_log) {
            return Err("EXPERIMENT_TRACE_LOG must be in 9..=24".into());
        }
        let update_logs = std::env::var("EXPERIMENT_UPDATE_LOGS")
            .unwrap_or_else(|_| "0,1,2,3,4,5,6,7,8,9,10".into())
            .split(',')
            .map(str::parse)
            .collect::<std::result::Result<Vec<usize>, _>>()?;
        if update_logs.is_empty()
            || update_logs.iter().any(|&log| log > trace_log)
            || update_logs.iter().copied().collect::<BTreeSet<_>>().len() != update_logs.len()
        {
            return Err(
                "update logs must be distinct, nonempty, and no greater than the trace log".into(),
            );
        }
        let sequence_len = env_usize("EXPERIMENT_SEQUENCE_LEN", 40)?;
        if sequence_len == 0 {
            return Err("sequence length must be positive".into());
        }
        // The launcher detects host/cgroup limits and passes their minimum.
        let memory_bytes: u128 = std::env::var("EXPERIMENT_MEMORY_BYTES")?.parse()?;
        let rss_limit_bytes = std::env::var("EXPERIMENT_RSS_LIMIT_BYTES")
            .unwrap_or_else(|_| "0".into())
            .parse::<u128>()?;
        if rss_limit_bytes > memory_bytes * 7 / 10 {
            return Err("RSS trial cutoff exceeds 70% of host memory".into());
        }
        let shared_baseline = match std::env::var("EXPERIMENT_BASELINE_MODE")
            .as_deref()
            .unwrap_or("shared")
        {
            "paired" => false,
            "shared" => true,
            _ => return Err("EXPERIMENT_BASELINE_MODE must be paired or shared".into()),
        };
        Ok(Self {
            trace_log,
            update_logs,
            sequence_len,
            seed: std::env::var("EXPERIMENT_SEED")
                .unwrap_or_else(|_| "20260909".into())
                .parse()?,
            output: PathBuf::from(std::env::var("EXPERIMENT_OUTPUT")?),
            preflight_only: std::env::var("EXPERIMENT_PREFLIGHT_ONLY").as_deref() == Ok("1"),
            memory_bytes,
            rss_limit_bytes,
            shared_baseline,
        })
    }
}

fn initial_assignment(circuit: &Circuit) -> Vec<Field> {
    let mut values = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..circuit.n {
        let left = Field::from_usize(pair + 1);
        let mul = Field::from_usize(pair + 2);
        let right = Field::from_u64(2);
        values.extend([left, right, left + right, mul, right, mul * right]);
    }
    values.extend(std::iter::repeat_n(
        Field::from_u64(PUBLIC_VALUE),
        PUBLIC_INPUTS,
    ));
    values
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    Ok(std::env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn gib(bytes: u128) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

fn write_file(path: &std::path::Path, text: &str) -> Result<()> {
    let mut file = File::create_new(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn csv(path: &std::path::Path, header: &str) -> Result<BufWriter<File>> {
    let mut file = BufWriter::new(File::create_new(path)?);
    writeln!(file, "{header}")?;
    file.flush()?;
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
fn sample(
    file: &mut BufWriter<File>,
    phase: &str,
    gates: usize,
    revision: usize,
    prove: f64,
    verify: f64,
    distinct: usize,
    size: proof_size::Metrics,
    proof_file: &str,
) -> Result<()> {
    writeln!(
        file,
        "{phase},{gates},{revision},{prove:.9},{verify:.9},true,{distinct},{},{},{},{},{},{},{proof_file}",
        size.field_elements,
        size.blake3_hashes,
        size.poseidon_hashes,
        size.payload_bytes(),
        size.serialized_bytes,
        size.overhead_bytes(),
    )?;
    file.flush()?;
    file.get_ref().sync_data()?;
    Ok(())
}

fn persist_proof(
    config: &Config,
    components: &mut BufWriter<File>,
    phase: &str,
    gates: usize,
    revision: usize,
    proof: &proof_size::EncodedProof,
) -> Result<String> {
    let name = format!("proofs/{phase}-g{gates}-r{revision}.cbor");
    let mut file = File::create_new(config.output.join(&name))?;
    file.write_all(&proof.bytes)?;
    file.sync_all()?;
    for (component, size) in &proof.components {
        writeln!(
            components,
            "{phase},{gates},{revision},{component},{},{},{},{},{}",
            size.field_elements,
            size.blake3_hashes,
            size.poseidon_hashes,
            size.payload_bytes(),
            size.serialized_bytes
        )?;
    }
    components.flush()?;
    components.get_ref().sync_data()?;
    Ok(name)
}
