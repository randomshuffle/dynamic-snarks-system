//! Commit-all-intermediate-rounds proof for the initial Merkle computation.
//!
//! CAIR commits every width-three Poseidon2 round state. A single degree-six
//! sumcheck checks all 64 nonlinear transitions, and a degree-three sumcheck
//! checks the heap routing, leaf inputs, domains, and indices. The assignment
//! is linked directly to the static SNARK's Boolean-hypercube main-column MLE,
//! so no inverse-Mobius/FFT bridge is needed.

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

use crate::hash::poseidon2_constants;
use crate::poseidon_sumcheck;
use crate::static_snark::{MleOpeningProof, commit_mle, commitment_seed, verify_mle_opening};
use crate::transcript::RawTranscript;

const STATE_WIDTH: usize = 3;
const POSEIDON_TRANSITIONS: usize = 64;
const POSEIDON_STATES: usize = POSEIDON_TRANSITIONS + 1;
const POSEIDON_COLUMNS: usize = POSEIDON_STATES * STATE_WIDTH;
const POSEIDON_DEGREE: usize = 6;
const COMPOSED_DEGREE: usize = 3;
const TRANSCRIPT_DOMAIN: u64 = 0x4341_4952_4d4c_4532;
const ROUTING_ROUND_TAG: u64 = 0x4341_4952_5254_4e44;
const POSEIDON_ROUND_TAG: u64 = 0x4341_4952_5053_4e44;

/// One CAIR proof and a shared WHIR opening of all terminal claims.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    table_rows: usize,
    table_width: usize,
    routing: SumcheckProof,
    poseidon: SumcheckProof,
    table_opening: MleOpeningProof,
}

/// The one opening requested from the static main-column commitment.
pub(crate) struct StaticLink {
    pub(crate) point: Vec<Bn254>,
    pub(crate) transcript_binding: Vec<Bn254>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SumcheckProof {
    rounds: Vec<Vec<Bn254>>,
}

struct PoseidonParameters {
    initial: Vec<[Bn254; 3]>,
    internal: Vec<Bn254>,
    terminal: Vec<[Bn254; 3]>,
}

impl PoseidonParameters {
    fn new() -> Self {
        let (external, internal) = poseidon2_constants();
        Self {
            initial: external.get_initial_constants().clone(),
            internal,
            terminal: external.get_terminal_constants().clone(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("CAIR assignment must be nonempty")]
    EmptyAssignment,
    #[error("CAIR trace length is invalid")]
    TraceLength,
    #[error("CAIR table shape is malformed")]
    TableShape,
    #[error("CAIR Merkle root does not match the public root")]
    RootMismatch,
    #[error("CAIR sumcheck is malformed or inconsistent")]
    Sumcheck,
    #[error("CAIR terminal identity failed")]
    Terminal,
    #[error("CAIR static-link evaluation failed")]
    StaticLink,
    #[error("CAIR WHIR: {0}")]
    Whir(String),
}

/// Commit the full CAIR trace and prove the initial Merkle computation.
pub(crate) fn prove(
    assignment: &[Bn254],
    root: Bn254,
    static_commitment_seed: &[Bn254],
    trace_len: usize,
    committed_main_column: Vec<Bn254>,
) -> Result<(Proof, StaticLink), Error> {
    if assignment.is_empty() {
        return Err(Error::EmptyAssignment);
    }
    if trace_len < 2 || !trace_len.is_power_of_two() || committed_main_column.len() != trace_len {
        return Err(Error::TraceLength);
    }
    if committed_main_column
        .iter()
        .take(assignment.len())
        .ne(assignment.iter())
    {
        return Err(Error::StaticLink);
    }

    let padded_len = assignment.len().next_power_of_two();
    let heap_rows = padded_len << 1;
    let table_rows = trace_len.max(heap_rows);
    let (hash_columns, computed_root) = poseidon_trace(assignment, table_rows);
    if computed_root != root {
        return Err(Error::RootMismatch);
    }
    let table_width = POSEIDON_COLUMNS.next_power_of_two();
    let mut table = vec![Bn254::ZERO; table_rows * table_width];
    for (column, values) in hash_columns.iter().enumerate() {
        for (row, &value) in values.iter().enumerate() {
            table[row * table_width + column] = value;
        }
    }
    let commitment_started = Instant::now();
    let committed = commit_mle(table).map_err(|error| Error::Whir(error.to_string()))?;
    eprintln!(
        "CAIR checkpoint: commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );
    let cair_commitment_seed = commitment_seed(committed.commitment());
    let mut transcript = statement_transcript(
        assignment.len(),
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
    );

    let routing_weights = challenges(&transcript, 0x2000, 6);
    let routing_target = challenges(&transcript, 0x2100, table_rows.trailing_zeros() as usize);
    let routing_work = routing_work(
        &hash_columns,
        &committed_main_column,
        assignment.len(),
        padded_len,
        table_rows,
    );
    let (routing, routing_point) = prove_routing_sumcheck(
        routing_work,
        &routing_weights,
        &routing_target,
        padded_len,
        &mut transcript,
    )?;

    let poseidon_weights = challenges(&transcript, 0x3000, POSEIDON_TRANSITIONS * STATE_WIDTH);
    let poseidon_target = challenges(&transcript, 0x3100, table_rows.trailing_zeros() as usize);
    let (poseidon, poseidon_point) = prove_poseidon_sumcheck(
        hash_columns,
        &poseidon_weights,
        &poseidon_target,
        &mut transcript,
    )?;

    let mut link_point = routing_point[..padded_len.trailing_zeros() as usize].to_vec();
    link_point.resize(trace_len.trailing_zeros() as usize, Bn254::ZERO);
    let opening_points = opening_points(
        table_rows,
        table_width,
        padded_len,
        &poseidon_point,
        &routing_point,
    );
    let opening_seed = raw_opening_seed(
        assignment.len(),
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
        &routing,
        &poseidon,
    );
    let point_refs = opening_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let table_opening =
        committed.open_with_checkpoints(&point_refs, &opening_seed, "CAIR checkpoint");

    Ok((
        Proof {
            table_rows,
            table_width,
            routing,
            poseidon,
            table_opening,
        },
        StaticLink {
            point: link_point,
            transcript_binding: opening_seed,
        },
    ))
}

/// Verify CAIR and its equality to one static main-column MLE evaluation.
pub(crate) fn verify(
    assignment_len: usize,
    root: Bn254,
    static_commitment_seed: &[Bn254],
    trace_len: usize,
    proof: &Proof,
    static_evaluations: &[Bn254],
) -> Result<StaticLink, Error> {
    if assignment_len == 0 || trace_len < 2 || !trace_len.is_power_of_two() {
        return Err(Error::TraceLength);
    }
    let padded_len = assignment_len.next_power_of_two();
    let heap_rows = padded_len << 1;
    let table_rows = trace_len.max(heap_rows);
    let table_width = POSEIDON_COLUMNS.next_power_of_two();
    if proof.table_rows != table_rows || proof.table_width != table_width {
        return Err(Error::TableShape);
    }
    let cair_commitment_seed = commitment_seed(&proof.table_opening.commitment);
    let mut transcript = statement_transcript(
        assignment_len,
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
    );

    let routing_weights = challenges(&transcript, 0x2000, 6);
    let routing_target = challenges(&transcript, 0x2100, table_rows.trailing_zeros() as usize);
    let (routing_claim, routing_point) = verify_sumcheck(
        &proof.routing,
        COMPOSED_DEGREE,
        interpolate,
        table_rows.trailing_zeros() as usize,
        ROUTING_ROUND_TAG,
        0x2200,
        &mut transcript,
    )?;

    let poseidon_weights = challenges(&transcript, 0x3000, POSEIDON_TRANSITIONS * STATE_WIDTH);
    let poseidon_target = challenges(&transcript, 0x3100, table_rows.trailing_zeros() as usize);
    let (poseidon_claim, poseidon_point) = verify_sumcheck(
        &proof.poseidon,
        POSEIDON_DEGREE,
        poseidon_sumcheck::interpolate,
        table_rows.trailing_zeros() as usize,
        POSEIDON_ROUND_TAG,
        0x3200,
        &mut transcript,
    )?;
    let mut link_point = routing_point[..padded_len.trailing_zeros() as usize].to_vec();
    link_point.resize(trace_len.trailing_zeros() as usize, Bn254::ZERO);

    let points = opening_points(
        table_rows,
        table_width,
        padded_len,
        &poseidon_point,
        &routing_point,
    );
    let opening_seed = raw_opening_seed(
        assignment_len,
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
        &proof.routing,
        &proof.poseidon,
    );
    let point_refs = points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    verify_mle_opening(
        table_rows * table_width,
        &point_refs,
        &proof.table_opening,
        &opening_seed,
    )
    .map_err(|error| Error::Whir(error.to_string()))?;
    let values = &proof.table_opening.opening.evaluations;
    let expected_values = POSEIDON_COLUMNS + 6;
    if values.len() != expected_values {
        return Err(Error::TableShape);
    }
    let mut cursor = 0;
    let poseidon_values = &values[cursor..cursor + POSEIDON_COLUMNS];
    cursor += POSEIDON_COLUMNS;
    let poseidon_terminal = eq_eval(&poseidon_target, &poseidon_point)
        * combined_poseidon_residual(
            poseidon_values,
            &poseidon_weights,
            &PoseidonParameters::new(),
        );
    if poseidon_terminal != poseidon_claim {
        return Err(Error::Terminal);
    }

    let route_values = &values[cursor..cursor + 6];
    if route_values[5] != root {
        return Err(Error::RootMismatch);
    }
    if static_evaluations.len() != 1 {
        return Err(Error::StaticLink);
    }
    let routing_terminal = routing_terminal(
        &routing_point,
        assignment_len,
        padded_len,
        table_rows,
        &routing_weights,
        route_values,
        static_evaluations[0],
    );
    if eq_eval(&routing_target, &routing_point) * routing_terminal != routing_claim {
        return Err(Error::Terminal);
    }
    Ok(StaticLink {
        point: link_point,
        transcript_binding: opening_seed,
    })
}

fn statement_transcript(
    assignment_len: usize,
    trace_len: usize,
    root: Bn254,
    static_seed: &[Bn254],
    cair_seed: &[Bn254],
    rows: usize,
    width: usize,
) -> RawTranscript {
    let mut transcript = RawTranscript::new(TRANSCRIPT_DOMAIN);
    transcript.absorb_message(
        1,
        &[
            Bn254::from_usize(assignment_len),
            Bn254::from_usize(trace_len),
            root,
            Bn254::from_usize(rows),
            Bn254::from_usize(width),
        ],
    );
    transcript.absorb_message(2, static_seed);
    transcript.absorb_message(3, cair_seed);
    transcript
}

fn challenges(transcript: &RawTranscript, base: u64, count: usize) -> Vec<Bn254> {
    (0..count)
        .map(|index| transcript.challenge(base + index as u64))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn raw_opening_seed(
    assignment_len: usize,
    trace_len: usize,
    root: Bn254,
    static_seed: &[Bn254],
    cair_seed: &[Bn254],
    rows: usize,
    width: usize,
    routing: &SumcheckProof,
    poseidon: &SumcheckProof,
) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(TRANSCRIPT_DOMAIN),
        Bn254::from_usize(assignment_len),
        Bn254::from_usize(trace_len),
        root,
        Bn254::from_usize(rows),
        Bn254::from_usize(width),
        Bn254::from_usize(static_seed.len()),
    ];
    seed.extend_from_slice(static_seed);
    seed.push(Bn254::from_usize(cair_seed.len()));
    seed.extend_from_slice(cair_seed);
    for proof in [routing, poseidon] {
        seed.push(Bn254::from_usize(proof.rounds.len()));
        for round in &proof.rounds {
            seed.push(Bn254::from_usize(round.len()));
            seed.extend_from_slice(round);
        }
    }
    seed
}

fn poseidon_trace(assignment: &[Bn254], rows: usize) -> (Vec<Vec<Bn254>>, Bn254) {
    let padded = assignment.len().next_power_of_two();
    let heap_rows = padded << 1;
    let mut columns = vec![vec![Bn254::ZERO; rows]; POSEIDON_COLUMNS];
    let mut digests = vec![Bn254::ZERO; heap_rows];
    let parameters = PoseidonParameters::new();
    for index in 0..padded {
        let value = assignment.get(index).copied().unwrap_or(Bn254::ZERO);
        let state = [value, Bn254::from_usize(index), Bn254::ONE];
        let digest = fill_poseidon_row(&mut columns, padded + index, state, &parameters);
        digests[padded + index] = digest;
    }
    let height = padded.trailing_zeros() as usize;
    for node in (1..padded).rev() {
        let depth = (usize::BITS - 1 - node.leading_zeros()) as usize;
        let level = height - 1 - depth;
        let state = [
            digests[node << 1],
            digests[(node << 1) | 1],
            Bn254::from_usize(2 + level),
        ];
        digests[node] = fill_poseidon_row(&mut columns, node, state, &parameters);
    }
    // Dummy and any table padding still carry valid Poseidon traces.
    digests[0] = fill_poseidon_row(&mut columns, 0, [Bn254::ZERO; 3], &parameters);
    for row in heap_rows..rows {
        let _ = fill_poseidon_row(&mut columns, row, [Bn254::ZERO; 3], &parameters);
    }
    (columns, digests[1])
}

fn fill_poseidon_row(
    columns: &mut [Vec<Bn254>],
    row: usize,
    input: [Bn254; 3],
    parameters: &PoseidonParameters,
) -> Bn254 {
    for word in 0..3 {
        columns[word][row] = input[word];
    }
    let mut state = input;
    for round in 0..POSEIDON_TRANSITIONS {
        state = poseidon_round(round, state, parameters);
        for word in 0..3 {
            columns[3 * (round + 1) + word][row] = state[word];
        }
    }
    state[0]
}

fn poseidon_round(
    round: usize,
    mut state: [Bn254; 3],
    parameters: &PoseidonParameters,
) -> [Bn254; 3] {
    if round == 0 {
        state = external_linear(state);
    }
    if round < 4 {
        full_round(state, parameters.initial[round])
    } else if round < 60 {
        partial_round(state, parameters.internal[round - 4])
    } else {
        full_round(state, parameters.terminal[round - 60])
    }
}

fn external_linear(state: [Bn254; 3]) -> [Bn254; 3] {
    let sum = state[0] + state[1] + state[2];
    [sum + state[0], sum + state[1], sum + state[2]]
}

fn full_round(state: [Bn254; 3], constants: [Bn254; 3]) -> [Bn254; 3] {
    let powered = core::array::from_fn(|i| fifth(state[i] + constants[i]));
    external_linear(powered)
}

fn partial_round(state: [Bn254; 3], constant: Bn254) -> [Bn254; 3] {
    let first = fifth(state[0] + constant);
    [
        first.double() + state[1] + state[2],
        first + state[1].double() + state[2],
        first + state[1] + Bn254::from_u64(3) * state[2],
    ]
}

fn fifth(value: Bn254) -> Bn254 {
    let square = value * value;
    square * square * value
}

struct RoutingWork {
    input: [Vec<Bn254>; 3],
    left: Vec<Bn254>,
    right: Vec<Bn254>,
    assignment: Vec<Bn254>,
    active: Vec<Bn254>,
    domain: Vec<Bn254>,
    index: Vec<Bn254>,
    internal: Vec<Bn254>,
    leaf: Vec<Bn254>,
    eq: Vec<Bn254>,
}

fn routing_work(
    hash: &[Vec<Bn254>],
    assignment: &[Bn254],
    assignment_len: usize,
    padded: usize,
    rows: usize,
) -> RoutingWork {
    let height = padded.trailing_zeros() as usize;
    let mut left = vec![Bn254::ZERO; rows];
    let mut right = vec![Bn254::ZERO; rows];
    let mut assignment_table = vec![Bn254::ZERO; rows];
    let mut active = vec![Bn254::ZERO; rows];
    let mut domain = vec![Bn254::ZERO; rows];
    let mut index = vec![Bn254::ZERO; rows];
    let mut internal = vec![Bn254::ZERO; rows];
    let mut leaf = vec![Bn254::ZERO; rows];
    let digest = &hash[3 * POSEIDON_TRANSITIONS];
    for row in 0..rows {
        let parent = row & (padded - 1);
        left[row] = digest[parent << 1];
        right[row] = digest[(parent << 1) | 1];
        assignment_table[row] = assignment[parent];
        active[row] = Bn254::from_bool(parent < assignment_len);
    }
    for node in 1..padded {
        internal[node] = Bn254::ONE;
        let depth = (usize::BITS - 1 - node.leading_zeros()) as usize;
        domain[node] = Bn254::from_usize(2 + height - 1 - depth);
    }
    for offset in 0..padded {
        let node = padded + offset;
        leaf[node] = Bn254::ONE;
        domain[node] = Bn254::ONE;
        index[node] = Bn254::from_usize(offset);
    }
    RoutingWork {
        input: [hash[0].clone(), hash[1].clone(), hash[2].clone()],
        left,
        right,
        assignment: assignment_table,
        active,
        domain,
        index,
        internal,
        leaf,
        eq: Vec::new(),
    }
}

fn prove_routing_sumcheck(
    mut work: RoutingWork,
    weights: &[Bn254],
    target: &[Bn254],
    _padded: usize,
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let phase_started = Instant::now();
    work.eq = eq_evaluations(target);
    let variables = target.len();
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    for round in 0..variables {
        let mut evaluations = vec![Bn254::ZERO; COMPOSED_DEGREE + 1];
        for (evaluation_index, evaluation) in evaluations.iter_mut().enumerate() {
            let t = Bn254::from_usize(evaluation_index);
            for pair in 0..work.eq.len() / 2 {
                let get = |values: &[Bn254]| lerp(values[2 * pair], values[2 * pair + 1], t);
                let input: [Bn254; 3] = core::array::from_fn(|word| get(&work.input[word]));
                let internal = get(&work.internal);
                let leaf = get(&work.leaf);
                let internal_residual = weights[0] * (input[0] - get(&work.left))
                    + weights[1] * (input[1] - get(&work.right))
                    + weights[2] * (input[2] - get(&work.domain));
                let leaf_residual = weights[3]
                    * (input[0] - get(&work.active) * get(&work.assignment))
                    + weights[4] * (input[1] - get(&work.index))
                    + weights[5] * (input[2] - get(&work.domain));
                *evaluation +=
                    get(&work.eq) * (internal * internal_residual + leaf * leaf_residual);
            }
        }
        if evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(ROUTING_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge(0x2200 + round as u64);
        claim = interpolate(&evaluations, challenge);
        point.push(challenge);
        for values in work.input.iter_mut().chain([
            &mut work.left,
            &mut work.right,
            &mut work.assignment,
            &mut work.active,
            &mut work.domain,
            &mut work.index,
            &mut work.internal,
            &mut work.leaf,
            &mut work.eq,
        ]) {
            fold(values, challenge);
        }
        rounds.push(evaluations);
        eprintln!(
            "CAIR checkpoint: routing sumcheck round {}/{} complete ({:.3}s phase elapsed)",
            round + 1,
            variables,
            phase_started.elapsed().as_secs_f64(),
        );
    }
    Ok((SumcheckProof { rounds }, point))
}

fn prove_poseidon_sumcheck(
    mut columns: Vec<Vec<Bn254>>,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let phase_started = Instant::now();
    let mut eq = eq_evaluations(target);
    let variables = target.len();
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let parameters = PoseidonParameters::new();
    let partial_weights = poseidon_sumcheck::partial_round_weights(weights);
    for round in 0..variables {
        let evaluations = poseidon_sumcheck::sum_pairs(eq.len() / 2, |pair| {
            poseidon_pair_evaluations(&columns, &eq, pair, weights, &partial_weights, &parameters)
        });
        if evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(POSEIDON_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge(0x3200 + round as u64);
        claim = poseidon_sumcheck::interpolate(&evaluations, challenge);
        point.push(challenge);
        fold(&mut eq, challenge);
        for column in &mut columns {
            fold(column, challenge);
        }
        rounds.push(evaluations.to_vec());
        eprintln!(
            "CAIR checkpoint: Poseidon sumcheck round {}/{} complete ({:.3}s phase elapsed)",
            round + 1,
            variables,
            phase_started.elapsed().as_secs_f64(),
        );
    }
    Ok((SumcheckProof { rounds }, point))
}

fn poseidon_pair_evaluations(
    columns: &[Vec<Bn254>],
    eq: &[Bn254],
    pair: usize,
    weights: &[Bn254],
    partial_weights: &[[Bn254; STATE_WIDTH]; poseidon_sumcheck::PARTIAL_ROUNDS],
    parameters: &PoseidonParameters,
) -> [Bn254; poseidon_sumcheck::EVALUATIONS] {
    let left = pair << 1;
    let right = left | 1;
    let eq_values = poseidon_sumcheck::line_evaluations(eq[left], eq[right]);
    let mut residuals = [Bn254::ZERO; poseidon_sumcheck::EVALUATIONS];
    let mut current_zero = core::array::from_fn(|word| columns[word][left]);
    let mut current_one = core::array::from_fn(|word| columns[word][right]);
    for round in 0..POSEIDON_TRANSITIONS {
        let next_column = STATE_WIDTH * (round + 1);
        let next_zero = core::array::from_fn(|word| columns[next_column + word][left]);
        let next_one = core::array::from_fn(|word| columns[next_column + word][right]);
        if (4..60).contains(&round) {
            let round_residuals = poseidon_sumcheck::partial_round_residual_evaluations(
                current_zero,
                current_one,
                next_zero,
                next_one,
                parameters.internal[round - 4],
                weights[STATE_WIDTH * round..STATE_WIDTH * (round + 1)]
                    .try_into()
                    .expect("a Poseidon round has three constraints"),
                partial_weights[round - 4],
            );
            for evaluation in 0..poseidon_sumcheck::EVALUATIONS {
                residuals[evaluation] += round_residuals[evaluation];
            }
        } else {
            let expected =
                poseidon_full_round_line_evaluations(round, current_zero, current_one, parameters);
            let next = core::array::from_fn::<_, STATE_WIDTH, _>(|word| {
                poseidon_sumcheck::line_evaluations(next_zero[word], next_one[word])
            });
            for evaluation in 0..poseidon_sumcheck::EVALUATIONS {
                for word in 0..STATE_WIDTH {
                    residuals[evaluation] += weights[STATE_WIDTH * round + word]
                        * (next[word][evaluation] - expected[evaluation][word]);
                }
            }
        }
        current_zero = next_zero;
        current_one = next_one;
    }
    core::array::from_fn(|evaluation| eq_values[evaluation] * residuals[evaluation])
}

fn poseidon_full_round_line_evaluations(
    round: usize,
    mut zero: [Bn254; STATE_WIDTH],
    mut one: [Bn254; STATE_WIDTH],
    parameters: &PoseidonParameters,
) -> [[Bn254; STATE_WIDTH]; poseidon_sumcheck::EVALUATIONS] {
    debug_assert!(!(4..60).contains(&round));
    if round == 0 {
        zero = external_linear(zero);
        one = external_linear(one);
    }
    let constants = if round < 4 {
        parameters.initial[round]
    } else {
        parameters.terminal[round - 60]
    };
    let powered = core::array::from_fn::<_, STATE_WIDTH, _>(|word| {
        poseidon_sumcheck::fifth_line_evaluations(
            zero[word] + constants[word],
            one[word] + constants[word],
        )
    });
    core::array::from_fn(|evaluation| {
        external_linear(core::array::from_fn(|word| powered[word][evaluation]))
    })
}

fn combined_poseidon_residual(
    values: &[Bn254],
    weights: &[Bn254],
    parameters: &PoseidonParameters,
) -> Bn254 {
    let mut result = Bn254::ZERO;
    for round in 0..POSEIDON_TRANSITIONS {
        let input = [
            values[3 * round],
            values[3 * round + 1],
            values[3 * round + 2],
        ];
        let expected = poseidon_round(round, input, parameters);
        for word in 0..3 {
            result += weights[3 * round + word] * (values[3 * (round + 1) + word] - expected[word]);
        }
    }
    result
}

fn verify_sumcheck(
    proof: &SumcheckProof,
    degree: usize,
    interpolate_round: fn(&[Bn254], Bn254) -> Bn254,
    variables: usize,
    round_tag: u64,
    challenge_base: u64,
    transcript: &mut RawTranscript,
) -> Result<(Bn254, Vec<Bn254>), Error> {
    if proof.rounds.len() != variables {
        return Err(Error::Sumcheck);
    }
    let mut claim = Bn254::ZERO;
    let mut point = Vec::with_capacity(variables);
    for (round, evaluations) in proof.rounds.iter().enumerate() {
        if evaluations.len() != degree + 1 || evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(round_tag + round as u64, evaluations);
        let challenge = transcript.challenge(challenge_base + round as u64);
        claim = interpolate_round(evaluations, challenge);
        point.push(challenge);
    }
    Ok((claim, point))
}

fn opening_points(
    rows: usize,
    width: usize,
    padded: usize,
    poseidon_point: &[Bn254],
    routing_point: &[Bn254],
) -> Vec<Vec<Bn254>> {
    let mut points = Vec::new();
    for column in 0..POSEIDON_COLUMNS {
        points.push(table_point(column, poseidon_point, width));
    }
    for column in 0..3 {
        points.push(table_point(column, routing_point, width));
    }
    let height = padded.trailing_zeros() as usize;
    for child_bit in [Bn254::ZERO, Bn254::ONE] {
        let mut child = vec![child_bit];
        child.extend_from_slice(&routing_point[..height]);
        child.resize(rows.trailing_zeros() as usize, Bn254::ZERO);
        points.push(table_point(3 * POSEIDON_TRANSITIONS, &child, width));
    }
    let mut root = vec![Bn254::ZERO; rows.trailing_zeros() as usize];
    root[0] = Bn254::ONE;
    points.push(table_point(3 * POSEIDON_TRANSITIONS, &root, width));
    points
}

fn table_point(column: usize, row_point: &[Bn254], width: usize) -> Vec<Bn254> {
    let mut result = (0..width.trailing_zeros() as usize)
        .map(|bit| Bn254::from_bool(column & (1 << bit) != 0))
        .collect::<Vec<_>>();
    result.extend_from_slice(row_point);
    result
}

fn routing_terminal(
    point: &[Bn254],
    assignment_len: usize,
    padded: usize,
    rows: usize,
    weights: &[Bn254],
    values: &[Bn254],
    assignment: Bn254,
) -> Bn254 {
    let input = [values[0], values[1], values[2]];
    let left = values[3];
    let right = values[4];
    let _root = values[5];
    let height = padded.trailing_zeros() as usize;
    let row_variables = rows.trailing_zeros() as usize;
    let high_zero = (height..row_variables).fold(Bn254::ONE, |product, bit| {
        product * (Bn254::ONE - point[bit])
    });
    let zero_row = point
        .iter()
        .fold(Bn254::ONE, |product, &value| product * (Bn254::ONE - value));
    let internal = high_zero - zero_row;
    let leaf = point[height]
        * (height + 1..row_variables).fold(Bn254::ONE, |product, bit| {
            product * (Bn254::ONE - point[bit])
        });
    let domain = domain_mle(point, height);
    let index = point[height]
        * (height + 1..row_variables).fold(Bn254::ONE, |product, bit| {
            product * (Bn254::ONE - point[bit])
        })
        * (0..height).fold(Bn254::ZERO, |sum, bit| {
            sum + Bn254::from_usize(1usize << bit) * point[bit]
        });
    let internal_residual = weights[0] * (input[0] - left)
        + weights[1] * (input[1] - right)
        + weights[2] * (input[2] - domain);
    let active = prefix_selector_mle(&point[..height], assignment_len);
    let leaf_residual = weights[3] * (input[0] - active * assignment)
        + weights[4] * (input[1] - index)
        + weights[5] * (input[2] - domain);
    // The root is opened directly at heap row one.
    internal * internal_residual + leaf * leaf_residual
}

fn domain_mle(point: &[Bn254], height: usize) -> Bn254 {
    let variables = point.len();
    let leaf = point[height]
        * (height + 1..variables).fold(Bn254::ONE, |product, bit| {
            product * (Bn254::ONE - point[bit])
        });
    let mut result = leaf;
    for depth in 0..height {
        let selector = point[depth]
            * (depth + 1..variables).fold(Bn254::ONE, |product, bit| {
                product * (Bn254::ONE - point[bit])
            });
        result += Bn254::from_usize(2 + height - 1 - depth) * selector;
    }
    result
}

/// MLE of the Boolean table that is one exactly on indices `[0, end)`.
fn prefix_selector_mle(point: &[Bn254], end: usize) -> Bn254 {
    if point.is_empty() {
        return Bn254::from_bool(end != 0);
    }
    let half = 1usize << (point.len() - 1);
    let high = point[point.len() - 1];
    if end <= half {
        (Bn254::ONE - high) * prefix_selector_mle(&point[..point.len() - 1], end)
    } else {
        (Bn254::ONE - high) + high * prefix_selector_mle(&point[..point.len() - 1], end - half)
    }
}

fn eq_evaluations(point: &[Bn254]) -> Vec<Bn254> {
    let mut result = vec![Bn254::ONE];
    for &coordinate in point {
        let old = result.len();
        result.resize(old << 1, Bn254::ZERO);
        for index in 0..old {
            let value = result[index];
            result[index] = value * (Bn254::ONE - coordinate);
            result[index | old] = value * coordinate;
        }
    }
    result
}

fn eq_eval(left: &[Bn254], right: &[Bn254]) -> Bn254 {
    left.iter()
        .zip(right)
        .fold(Bn254::ONE, |product, (&a, &b)| {
            product * ((Bn254::ONE - a) * (Bn254::ONE - b) + a * b)
        })
}

fn fold(values: &mut Vec<Bn254>, challenge: Bn254) {
    for pair in 0..values.len() / 2 {
        values[pair] = lerp(values[2 * pair], values[2 * pair + 1], challenge);
    }
    values.truncate(values.len() / 2);
}

fn lerp(zero: Bn254, one: Bn254, point: Bn254) -> Bn254 {
    zero + point * (one - zero)
}

fn interpolate(evaluations: &[Bn254], point: Bn254) -> Bn254 {
    debug_assert!(!evaluations.is_empty());
    let mut scratch = (0..evaluations.len())
        .map(|index| {
            let x = Bn254::from_usize(index);
            (0..evaluations.len())
                .filter(|&other| other != index)
                .fold(Bn254::ONE, |product, other| {
                    product * (x - Bn254::from_usize(other))
                })
        })
        .collect::<Vec<_>>();
    let mut inverse_denominators = vec![Bn254::ZERO; scratch.len()];
    // All Lagrange denominators are nonzero constants. Montgomery's trick
    // replaces one inversion per evaluation with one inversion for the round.
    batch_multiplicative_inverse_general(&scratch, &mut inverse_denominators, |value| {
        value.inverse()
    });

    // Prefix/suffix products evaluate every Lagrange numerator in linear time
    // and remain valid when `point` is one of the interpolation nodes.
    scratch.resize(evaluations.len() + 1, Bn254::ZERO);
    scratch[0] = Bn254::ONE;
    for index in 0..evaluations.len() {
        scratch[index + 1] = scratch[index] * (point - Bn254::from_usize(index));
    }
    let mut suffix = Bn254::ONE;
    (0..evaluations.len())
        .rev()
        .fold(Bn254::ZERO, |sum, index| {
            let result =
                sum + evaluations[index] * scratch[index] * suffix * inverse_denominators[index];
            suffix *= point - Bn254::from_usize(index);
            result
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_leaf, hash_node};
    use crate::merkle::MerkleTree;

    #[test]
    fn poseidon_trace_matches_merkle_hashes() {
        let assignment = [3, 5, 8].map(Bn254::from_u64);
        let (columns, root) = poseidon_trace(&assignment, 8);
        let leaves = [
            hash_leaf(0, assignment[0]),
            hash_leaf(1, assignment[1]),
            hash_leaf(2, assignment[2]),
            hash_leaf(3, Bn254::ZERO),
        ];
        let left = hash_node(0, leaves[0], leaves[1]);
        let right = hash_node(0, leaves[2], leaves[3]);
        assert_eq!(root, hash_node(1, left, right));
        assert_eq!(columns[3 * POSEIDON_TRANSITIONS][1], root);
    }

    #[test]
    fn cair_round_trip_and_tamper_rejection() {
        // Five values make the 16-row Merkle heap larger than the 8-row
        // static trace and exercise CAIR's independent row padding.
        let assignment = [3, 4, 7, 9, 11].map(Bn254::from_u64).to_vec();
        let mut committed_main = assignment.clone();
        committed_main.resize(8, Bn254::ZERO);
        let static_seed = [Bn254::from_u64(41), Bn254::from_u64(43)];
        let root = MerkleTree::new(assignment.clone())
            .unwrap()
            .commitment()
            .root;
        let (proof, link) = prove(
            &assignment,
            root,
            &static_seed,
            committed_main.len(),
            committed_main.clone(),
        )
        .unwrap();
        let static_evaluation = evaluate_mle(&committed_main, &link.point);
        verify(
            assignment.len(),
            root,
            &static_seed,
            committed_main.len(),
            &proof,
            &[static_evaluation],
        )
        .unwrap();

        let mut bad_sumcheck = proof.clone();
        bad_sumcheck.poseidon.rounds[0][0] += Bn254::ONE;
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &bad_sumcheck,
                &[static_evaluation],
            )
            .is_err()
        );

        let mut bad_routing = proof.clone();
        bad_routing.routing.rounds[0][0] += Bn254::ONE;
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &bad_routing,
                &[static_evaluation],
            )
            .is_err()
        );

        let mut bad_opening = proof.clone();
        bad_opening.table_opening.opening.evaluations[0] += Bn254::ONE;
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &bad_opening,
                &[static_evaluation],
            )
            .is_err()
        );
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &proof,
                &[static_evaluation + Bn254::ONE],
            )
            .is_err()
        );
        assert!(
            verify(
                assignment.len(),
                root + Bn254::ONE,
                &static_seed,
                committed_main.len(),
                &proof,
                &[static_evaluation],
            )
            .is_err()
        );
    }

    #[test]
    fn prefix_selector_handles_non_power_of_two_lengths() {
        let point = [Bn254::from_u64(2), Bn254::from_u64(3), Bn254::from_u64(5)];
        for end in 0..=8 {
            let expected = (0..end).fold(Bn254::ZERO, |sum, index| {
                sum + point
                    .iter()
                    .enumerate()
                    .fold(Bn254::ONE, |product, (bit, &coordinate)| {
                        product
                            * if index & (1 << bit) == 0 {
                                Bn254::ONE - coordinate
                            } else {
                                coordinate
                            }
                    })
            });
            assert_eq!(prefix_selector_mle(&point, end), expected);
        }
    }

    fn evaluate_mle(table: &[Bn254], point: &[Bn254]) -> Bn254 {
        let mut folded = table.to_vec();
        for &challenge in point {
            fold(&mut folded, challenge);
        }
        folded[0]
    }
}
