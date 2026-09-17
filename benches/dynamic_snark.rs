//! End-to-end dynamic-update versus prove-from-scratch benchmark.

use std::collections::BTreeSet;
use std::error::Error;
use std::hint::black_box;
use std::mem::size_of;
use std::process::Command;
use std::time::{Duration, Instant};

use dynamic_snarks_system::Field;
use dynamic_snarks_system::circuit::Circuit;
use dynamic_snarks_system::dynamic::{
    self, index, initialize, initialize_transition_benchmark, regular_hyperplonk_program, update,
    update_transition_benchmark, verify as verify_dynamic, verify_transition_benchmark,
};
use dynamic_snarks_system::static_snark::{
    prove as prove_hyperplonk, setup as setup_hyperplonk, verify as verify_hyperplonk,
};
use p3_field::PrimeCharacteristicRing;

#[path = "support/update_workload.rs"]
mod update_workload;
use update_workload::Pattern;

const DEFAULT_TRACE_LOG: usize = 14;
const DEFAULT_UPDATE_LOGS: &[usize] = &[4];
const DEFAULT_SEQUENCE_LEN: usize = 10;
const PUBLIC_INPUTS: usize = 1 << 8;
const PUBLIC_VALUE: u64 = 9;
const DEFAULT_SEED: u64 = 20_260_909;

struct Case {
    changed_gates: usize,
    revisions: Vec<Vec<(usize, Field)>>,
    first_transition_hashes: usize,
    time_full_initial: bool,
    include_baseline: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let trace_log = env_usize("DYNAMIC_SNARK_TRACE_LOG", DEFAULT_TRACE_LOG)?;
    let update_logs = env_usize_list("DYNAMIC_SNARK_UPDATE_LOGS", DEFAULT_UPDATE_LOGS)?;
    let sequence_len = env_usize("DYNAMIC_SNARK_SEQUENCE_LEN", DEFAULT_SEQUENCE_LEN)?;
    if sequence_len == 0 {
        return Err("DYNAMIC_SNARK_SEQUENCE_LEN must be positive".into());
    }
    let force = env_bool("DYNAMIC_SNARK_FORCE");
    let preflight_only = env_bool("DYNAMIC_SNARK_PREFLIGHT_ONLY");
    let include_baseline = !env_bool("DYNAMIC_SNARK_UPDATE_ONLY");
    let time_full_initial = include_baseline && env_bool("DYNAMIC_SNARK_TIME_FULL_INITIAL");
    let pattern = Pattern::parse(
        &std::env::var("DYNAMIC_SNARK_UPDATE_PATTERN").unwrap_or_else(|_| "random".to_owned()),
    )?;
    let seed = std::env::var("DYNAMIC_SNARK_SEED")
        .map_or(Ok(DEFAULT_SEED), |value| value.parse::<u64>())?;
    let source_trace_len = 1usize
        .checked_shl(trace_log as u32)
        .ok_or("DYNAMIC_SNARK_TRACE_LOG does not fit usize")?;
    if source_trace_len < 2 || source_trace_len % 2 != 0 {
        return Err("the source HyperPlonk trace must have a positive even number of gates".into());
    }
    let circuit = identity_circuit(source_trace_len / 2)?;
    let initial_relation_trace = dynamic::initial_trace_len(&circuit);
    let gate_count = 2 * circuit.n;
    let physical_memory = physical_memory_bytes();

    println!("dynamic SNARK benchmark");
    println!("  original HyperPlonk trace: 2^{trace_log} = {source_trace_len} gate rows");
    println!("  source arithmetic gates: {gate_count}");
    println!("  assignment positions: {}", circuit.assignment_len());
    println!(
        "  assignment Merkle leaves: {} (aligned four-column layout)",
        4 * initial_relation_trace
    );
    println!("  WHIR: fixed rate 1/2, folding factor 4, 127-bit target, zero PoW");
    println!("  public inputs: {}", circuit.num_public_inputs);
    println!("  composed initial-relation trace: {initial_relation_trace} rows");
    println!("  sequential updates per average: {sequence_len}");
    println!("  preprocessing/indexing: excluded from all reported timings");
    if time_full_initial {
        println!("  initial relation proof: fully materialized, timed separately, and verified");
    } else {
        println!(
            "  initial relation proof: excluded and not materialized (trusted base commitment harness)"
        );
    }
    println!("  wiring: identity");
    println!("  update pattern: {}", pattern.label());
    println!("  workload seed: {seed} (StdRng; use the checked-in Cargo.lock)");
    println!("  baseline proving enabled: {include_baseline}");
    if let Some(bytes) = physical_memory {
        println!("  physical memory: {}", gib(bytes));
    }
    println!();

    println!(
        "update_gates,update_positions,first_transition_poseidon_hashes,first_dynamic_ms,\
         first_scratch_ms,first_speedup,sequence_dynamic_total_ms,\
         sequence_dynamic_avg_ms,sequence_scratch_total_ms,sequence_scratch_avg_ms,\
         sequence_speedup"
    );

    for update_log in update_logs {
        let changed_gates = 1usize
            .checked_shl(update_log as u32)
            .ok_or("an update log does not fit usize")?;
        if changed_gates > gate_count {
            eprintln!(
                "skipping 2^{update_log} gates: the 2^{trace_log}-row source trace has only {gate_count} arithmetic gates"
            );
            continue;
        }
        let revisions =
            update_workload::revisions(gate_count, changed_gates, sequence_len, seed, pattern);
        println!(
            "workload_fingerprint,{changed_gates},{}",
            update_workload::fingerprint(&revisions)
        );
        let update_indices = revisions[0]
            .iter()
            .map(|&(index, _)| index)
            .collect::<Vec<_>>();
        let all_indices = revisions
            .iter()
            .flatten()
            .map(|&(index, _)| index)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let transition_resources =
            dynamic::transition_resource_estimate(&circuit, &update_indices)?;
        // Every historical transition support is contained in one of the
        // final composed tables. Bound those separately: the entire sequence
        // union can cross a padding threshold that no actual proof reaches.
        let mut sequence_resources = transition_resources;
        let mut max_composed_positions = update_indices.len();
        for support in update_workload::maximal_composed_supports(&revisions) {
            let estimate = dynamic::transition_resource_estimate(&circuit, &support)?;
            max_composed_positions = max_composed_positions.max(support.len());
            if estimate.conservative_peak_bytes > sequence_resources.conservative_peak_bytes {
                sequence_resources = estimate;
            }
        }
        let transition_hashes = transition_resources.poseidon_hashes;
        let initialization_peak =
            initialization_memory_peak(initial_relation_trace, 4 * initial_relation_trace);
        let transition_floor = dense_initial_key_floor(initial_relation_trace)
            + sequence_resources.conservative_peak_bytes;
        let initial_note = if time_full_initial {
            "materialized in this run"
        } else {
            "not materialized"
        };
        eprintln!(
            "2^{update_log} preflight: transition rows={}, Poseidon hashes={}, row width={}, master={}, transition+key peak <= {}, full initial CAIR RAM peak <= {} ({initial_note})",
            transition_resources.row_count,
            transition_resources.poseidon_hashes,
            transition_resources.row_width,
            mib(transition_resources.master_fields as u128 * size_of::<Field>() as u128),
            gib(transition_floor),
            gib(initialization_peak),
        );
        eprintln!(
            "sequence preflight: unique positions={}, max composed positions={max_composed_positions}, max composed rows={}, row width={}, master={}, transition+key peak <= {}",
            all_indices.len(),
            sequence_resources.row_count,
            sequence_resources.row_width,
            mib(sequence_resources.master_fields as u128 * size_of::<Field>() as u128),
            gib(transition_floor),
        );
        let unsafe_memory = physical_memory.is_some_and(|memory| {
            transition_floor > memory.saturating_mul(7) / 10
                || time_full_initial && initialization_peak > memory.saturating_mul(7) / 10
        });
        if !force && unsafe_memory {
            eprintln!(
                "skipping 2^{update_log} gates: RAM exceeds the 70% guard; set DYNAMIC_SNARK_FORCE=1 to override"
            );
            continue;
        }
        if preflight_only {
            continue;
        }
        run_case(
            circuit.clone(),
            initial_relation_trace,
            Case {
                changed_gates,
                revisions,
                first_transition_hashes: transition_hashes,
                time_full_initial,
                include_baseline,
            },
        )?;
    }
    Ok(())
}

fn run_case(circuit: Circuit, trace_len: usize, case: Case) -> Result<(), Box<dyn Error>> {
    let Case {
        changed_gates,
        revisions,
        first_transition_hashes: transition_hashes,
        time_full_initial,
        include_baseline,
    } = case;
    let sequence_len = revisions.len();
    let changed_positions = 3 * changed_gates;
    let assignment = assignment(&circuit, 0);
    let public_inputs = vec![Field::from_u64(PUBLIC_VALUE); circuit.num_public_inputs];

    let setup_started = Instant::now();
    let baseline = if include_baseline {
        let template = regular_hyperplonk_program(&circuit, &assignment)?;
        let (pk, vk) = setup_hyperplonk(&template)?;
        assert_eq!(pk.preprocessed_width(), 4);
        assert_eq!(pk.trace_len(), trace_len);
        Some((pk, vk))
    } else {
        None
    };
    let (pk, vk) = index(circuit.clone())?;
    assert_eq!(pk.initial_trace_len(), trace_len);
    assert_eq!(pk.initial_preprocessed_width(), 4);
    eprintln!(
        "preprocessing: dynamic initial {} columns; trace rows={trace_len}",
        pk.initial_preprocessed_width()
    );
    let setup_elapsed = setup_started.elapsed();
    eprintln!(
        "indexed source circuit for the {}-updated-gate case in {} (excluded; transitions need no preprocessing)",
        changed_gates,
        human_duration(setup_elapsed)
    );

    let initial_state = if time_full_initial {
        eprintln!("starting full initial dynamic SNARK proof");
        let started = Instant::now();
        let state = initialize(&pk, assignment.clone())?;
        let elapsed = started.elapsed();
        verify_dynamic(&vk, &public_inputs, state.proof())?;
        eprintln!(
            "full initial dynamic SNARK proof complete in {} (verification excluded)",
            human_duration(elapsed)
        );
        println!("initial_dynamic_ms,{:.3}", milliseconds(elapsed));
        BenchmarkState::Full(state)
    } else {
        eprintln!(
            "preparing trusted base commitment for the {}-updated-gate transition benchmark (excluded)",
            changed_gates
        );
        let state = initialize_transition_benchmark(&pk, assignment.clone())?;
        verify_transition_benchmark(&vk, &public_inputs, &state)?;
        BenchmarkState::Trusted(state)
    };

    let mut first_dynamic_state = initial_state.clone();
    eprintln!("starting first dynamic update");
    let started = Instant::now();
    first_dynamic_state.apply_update(&pk, &revisions[0])?;
    let first_dynamic = started.elapsed();
    first_dynamic_state.verify(&vk, &public_inputs)?;
    eprintln!(
        "first dynamic update complete in {} (verification excluded)",
        human_duration(first_dynamic)
    );
    black_box(&first_dynamic_state);

    let first_scratch = if let Some((baseline_pk, baseline_vk)) = &baseline {
        let first_assignment = apply_updates(assignment.clone(), &revisions[0]);
        eprintln!("starting first regular HyperPlonk from-scratch proof");
        let started = Instant::now();
        let program = regular_hyperplonk_program(&circuit, &first_assignment)?;
        let proof = prove_hyperplonk(baseline_pk, &program, &public_inputs)?;
        let elapsed = started.elapsed();
        verify_hyperplonk(baseline_vk, &public_inputs, &proof)?;
        eprintln!(
            "first regular HyperPlonk proof complete in {} (verification excluded)",
            human_duration(elapsed)
        );
        black_box(proof);
        Some(elapsed)
    } else {
        None
    };
    drop(first_dynamic_state);

    let mut sequential_dynamic_state = initial_state;
    let mut dynamic_total = Duration::ZERO;
    let mut seen_positions = BTreeSet::new();
    for (revision_index, revision) in revisions.iter().enumerate() {
        eprintln!(
            "starting sequential dynamic update {}/{}",
            revision_index + 1,
            sequence_len
        );
        let started = Instant::now();
        sequential_dynamic_state.apply_update(&pk, revision)?;
        let elapsed = started.elapsed();
        dynamic_total += elapsed;
        sequential_dynamic_state.verify(&vk, &public_inputs)?;
        seen_positions.extend(revision.iter().map(|&(index, _)| index));
        println!(
            "update_sample,{},{:.3},{}",
            revision_index + 1,
            milliseconds(elapsed),
            seen_positions.len()
        );
        eprintln!(
            "sequential dynamic update {}/{} complete and verified in {} (verification excluded)",
            revision_index + 1,
            sequence_len,
            human_duration(elapsed),
        );
    }
    black_box(&sequential_dynamic_state);

    let scratch_total = if let Some((baseline_pk, baseline_vk)) = &baseline {
        let mut scratch_assignment = assignment;
        let mut total = Duration::ZERO;
        for (revision_index, revision) in revisions.iter().enumerate() {
            scratch_assignment = apply_updates(scratch_assignment, revision);
            eprintln!(
                "starting sequential regular HyperPlonk proof {}/{}",
                revision_index + 1,
                sequence_len
            );
            let started = Instant::now();
            let program = regular_hyperplonk_program(&circuit, &scratch_assignment)?;
            let proof = prove_hyperplonk(baseline_pk, &program, &public_inputs)?;
            total += started.elapsed();
            verify_hyperplonk(baseline_vk, &public_inputs, &proof)?;
            eprintln!(
                "sequential regular HyperPlonk proof {}/{} complete",
                revision_index + 1,
                sequence_len
            );
            black_box(proof);
        }
        Some(total)
    } else {
        None
    };

    let count = sequence_len as f64;
    println!(
        "{changed_gates},{changed_positions},{transition_hashes},{:.3},{},{},{:.3},{:.3},{},{},{}",
        milliseconds(first_dynamic),
        optional_number(first_scratch.map(milliseconds)),
        optional_number(first_scratch.map(|elapsed| ratio(elapsed, first_dynamic))),
        milliseconds(dynamic_total),
        milliseconds(dynamic_total) / count,
        optional_number(scratch_total.map(milliseconds)),
        optional_number(scratch_total.map(|elapsed| milliseconds(elapsed) / count)),
        optional_number(scratch_total.map(|elapsed| ratio(elapsed, dynamic_total))),
    );
    Ok(())
}

#[derive(Clone)]
enum BenchmarkState {
    Full(dynamic::State),
    Trusted(dynamic::TransitionBenchmarkState),
}

impl BenchmarkState {
    fn apply_update(
        &mut self,
        key: &dynamic::ProvingKey,
        updates: &[(usize, Field)],
    ) -> Result<(), dynamic::Error> {
        match self {
            Self::Full(state) => update(key, state, updates),
            Self::Trusted(state) => update_transition_benchmark(key, state, updates),
        }
    }

    fn verify(
        &self,
        key: &dynamic::VerifyingKey,
        public_inputs: &[Field],
    ) -> Result<(), dynamic::Error> {
        match self {
            Self::Full(state) => verify_dynamic(key, public_inputs, state.proof()),
            Self::Trusted(state) => verify_transition_benchmark(key, public_inputs, state),
        }
    }
}

fn identity_circuit(gate_pairs: usize) -> Result<Circuit, Box<dyn Error>> {
    let assignment_len = 6 * gate_pairs + PUBLIC_INPUTS;
    Ok(Circuit::new(
        gate_pairs,
        PUBLIC_INPUTS,
        (0..assignment_len).collect(),
    )?)
}

fn assignment(circuit: &Circuit, revision: usize) -> Vec<Field> {
    let mut values = Vec::with_capacity(circuit.assignment_len());
    for pair in 0..circuit.n {
        let add_left = Field::from_usize(pair + revision + 1);
        let add_right = Field::from_u64(2);
        values.extend([add_left, add_right, add_left + add_right]);

        let mul_left = Field::from_usize(pair + revision + 2);
        let mul_right = Field::from_u64(2);
        values.extend([mul_left, mul_right, mul_left * mul_right]);
    }
    values.extend(std::iter::repeat_n(
        Field::from_u64(PUBLIC_VALUE),
        circuit.num_public_inputs,
    ));
    values
}

fn apply_updates(mut assignment: Vec<Field>, updates: &[(usize, Field)]) -> Vec<Field> {
    for &(position, value) in updates {
        assignment[position] = value;
    }
    assignment
}

fn dense_initial_key_floor(initial_trace: usize) -> u128 {
    // The initial key retains only its four permutation columns. Allow a
    // second copy for packing; selectors and identity labels are derived.
    initial_trace as u128 * (2 * 4) as u128 * size_of::<Field>() as u128
}

fn initialization_memory_peak(initial_trace: usize, padded_assignment: usize) -> u128 {
    let rows = initial_trace.max(2 * padded_assignment);
    let table_width = 64usize;
    // Four table-sized buffers cover the packed table and WHIR work. The
    // transient scalar trace retains 64 committed columns, 30 full-cap layer
    // columns, and the derived third input; the partial sumcheck owns one
    // additional 64-column fold table.
    let cair_fields = rows as u128 * (4 * table_width + 95 + table_width) as u128;
    // Static multilinear/WHIR tables remain live while its callback constructs
    // CAIR. Keep the existing conservative allowance until it is profiled.
    let static_envelope_fields = initial_trace as u128 * 200;
    (cair_fields + static_envelope_fields) * size_of::<Field>() as u128
}

fn physical_memory_bytes() -> Option<u128> {
    if cfg!(target_os = "macos") {
        let sysctl = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        if let Ok(bytes) = String::from_utf8(sysctl.stdout).ok()?.trim().parse() {
            return Some(bytes);
        }
        let pressure = Command::new("/usr/bin/memory_pressure").output().ok()?;
        let output = String::from_utf8(pressure.stdout).ok()?;
        return output.lines().find_map(|line| {
            line.strip_prefix("The system has ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        });
    }
    if cfg!(target_os = "linux") {
        let memory = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kib = memory
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))?
            .split_whitespace()
            .next()?
            .parse::<u128>()
            .ok()?;
        return Some(kib * 1024);
    }
    None
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(std::env::var(name).map_or_else(|_| Ok(default), |value| value.parse())?)
}

fn env_usize_list(name: &str, default: &[usize]) -> Result<Vec<usize>, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => value
            .split(',')
            .map(|item| Ok(item.trim().parse()?))
            .collect(),
        Err(_) => Ok(default.to_vec()),
    }
}

fn env_bool(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn optional_number(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.3}")).unwrap_or_default()
}

fn ratio(numerator: Duration, denominator: Duration) -> f64 {
    numerator.as_secs_f64() / denominator.as_secs_f64()
}

fn gib(bytes: u128) -> String {
    format!("{:.1} GiB", bytes as f64 / 1024.0_f64.powi(3))
}

fn mib(bytes: u128) -> String {
    format!("{:.1} MiB", bytes as f64 / 1024.0_f64.powi(2))
}

fn human_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!("{:.2} min", duration.as_secs_f64() / 60.0)
    } else {
        format!("{:.2} s", duration.as_secs_f64())
    }
}
