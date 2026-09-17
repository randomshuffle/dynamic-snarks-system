//! Commit-all-intermediate-rounds proof for the initial Merkle computation.
//!
//! CAIR commits a 64-column scalar Poseidon2 trace.  One degree-six sumcheck
//! checks the exact recurrence for all 56 partial rounds, four batched
//! GKR-style sumchecks reduce the two four-full-round caps, and a degree-three
//! sumcheck checks heap routing, leaf inputs, domains, and indices. The
//! assignment is linked directly to the static SNARK's Boolean-hypercube
//! main-column MLE, so no inverse-Mobius/FFT bridge is needed.

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

use crate::poseidon_scalar::{
    self, DIGEST_COLUMN, FullRoundClaims, FullRoundProof, INPUT_0_COLUMN, INPUT_1_COLUMN,
    PARTIAL_CONSTRAINTS, SCALAR_COLUMNS, SUMCHECK_DEGREE, Trace, TraceBuilder,
};
use crate::poseidon_sumcheck;
use crate::static_snark::{MleOpeningProof, commit_mle, commitment_seed, verify_mle_opening};
use crate::transcript::RawTranscript;

#[cfg(feature = "poseidon-gkr")]
pub(crate) mod round_reduction;

const COMPOSED_DEGREE: usize = 3;
const TRANSCRIPT_DOMAIN: u64 = 0x4341_4952_4d4c_4532;
const COLUMN_BATCH_DOMAIN: u64 = 0x4341_4952_434f_4c42;
const ROUTING_ROUND_TAG: u64 = 0x4341_4952_5254_4e44;
const POSEIDON_ROUND_TAG: u64 = 0x4341_4952_5053_4e44;

/// One CAIR proof and a shared WHIR opening of all terminal claims.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    table_rows: usize,
    table_width: usize,
    routing: SumcheckProof,
    poseidon: SumcheckProof,
    full_rounds: FullRoundProof,
    poseidon_values: Vec<Bn254>,
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
    let phase = Instant::now();
    let (scalar_trace, computed_root) = poseidon_trace(assignment, table_rows)?;
    profile_checkpoint("initial CAIR: Poseidon/Merkle trace construction", phase);
    if computed_root != root {
        return Err(Error::RootMismatch);
    }
    let table_width = SCALAR_COLUMNS;
    let phase = Instant::now();
    let table = crate::parallel::pack_columns(
        table_rows,
        table_width,
        &scalar_trace
            .columns
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
    );
    profile_checkpoint("initial CAIR: packed commitment table", phase);
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
    let phase = Instant::now();
    let routing_work = routing_work(
        &scalar_trace,
        &committed_main_column,
        assignment.len(),
        padded_len,
        table_rows,
    );
    profile_checkpoint("initial CAIR: routing work table", phase);
    let (routing, routing_point) = prove_routing_sumcheck(
        routing_work,
        &routing_weights,
        &routing_target,
        padded_len,
        &mut transcript,
    )?;

    let poseidon_weights = challenges(&transcript, 0x3000, PARTIAL_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x3100, table_rows.trailing_zeros() as usize);
    let (poseidon, poseidon_point, poseidon_values) = prove_poseidon_sumcheck(
        crate::parallel::clone_columns(&scalar_trace.columns),
        &poseidon_weights,
        &poseidon_target,
        &mut transcript,
    )?;
    let (full_rounds, full_round_claims) = scalar_trace
        .prove_full_rounds(&mut transcript, "CAIR checkpoint")
        .map_err(|_| Error::Sumcheck)?;

    let mut link_point = routing_point[..padded_len.trailing_zeros() as usize].to_vec();
    link_point.resize(trace_len.trailing_zeros() as usize, Bn254::ZERO);
    let base_opening_seed = raw_opening_seed(
        assignment.len(),
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
        &routing,
        &poseidon,
        &full_rounds,
    );
    let opening_seed = column_batch_seed(&base_opening_seed, &poseidon_values);
    let column_point = column_batch_point(&opening_seed, table_width.trailing_zeros() as usize);
    let opening_points = opening_points(
        table_rows,
        table_width,
        padded_len,
        &column_point,
        &poseidon_point,
        &routing_point,
        &full_round_claims,
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
            full_rounds,
            poseidon_values,
            table_opening,
        },
        StaticLink {
            point: link_point,
            transcript_binding: opening_seed,
        },
    ))
}

fn profile_checkpoint(label: &str, started: Instant) {
    if std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some() {
        eprintln!(
            "profile checkpoint: {label} complete in {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
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
    let table_width = SCALAR_COLUMNS;
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

    let poseidon_weights = challenges(&transcript, 0x3000, PARTIAL_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x3100, table_rows.trailing_zeros() as usize);
    let (poseidon_claim, poseidon_point) = verify_sumcheck(
        &proof.poseidon,
        SUMCHECK_DEGREE,
        poseidon_sumcheck::interpolate,
        table_rows.trailing_zeros() as usize,
        POSEIDON_ROUND_TAG,
        0x3200,
        &mut transcript,
    )?;
    let full_round_claims = poseidon_scalar::verify_full_rounds(
        &proof.full_rounds,
        table_rows.trailing_zeros() as usize,
        &mut transcript,
    )
    .map_err(|_| Error::Sumcheck)?;
    let mut link_point = routing_point[..padded_len.trailing_zeros() as usize].to_vec();
    link_point.resize(trace_len.trailing_zeros() as usize, Bn254::ZERO);

    if proof.poseidon_values.len() != SCALAR_COLUMNS {
        return Err(Error::TableShape);
    }
    let base_opening_seed = raw_opening_seed(
        assignment_len,
        trace_len,
        root,
        static_commitment_seed,
        &cair_commitment_seed,
        table_rows,
        table_width,
        &proof.routing,
        &proof.poseidon,
        &proof.full_rounds,
    );
    let opening_seed = column_batch_seed(&base_opening_seed, &proof.poseidon_values);
    let column_point = column_batch_point(&opening_seed, table_width.trailing_zeros() as usize);
    let points = opening_points(
        table_rows,
        table_width,
        padded_len,
        &column_point,
        &poseidon_point,
        &routing_point,
        &full_round_claims,
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
    let expected_values = 15;
    if values.len() != expected_values {
        return Err(Error::TableShape);
    }
    let column_weights = eq_evaluations(&column_point);
    let column_batch = proof
        .poseidon_values
        .iter()
        .zip(&column_weights)
        .fold(Bn254::ZERO, |sum, (&value, &weight)| sum + value * weight);
    if values[0] != column_batch {
        return Err(Error::Terminal);
    }
    let poseidon_terminal = eq_eval(&poseidon_target, &poseidon_point)
        * combined_poseidon_residual(&proof.poseidon_values, &poseidon_weights);
    if poseidon_terminal != poseidon_claim {
        return Err(Error::Terminal);
    }

    let route_values = &values[1..6];
    if route_values[4] != root {
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
    verify_full_round_openings(
        &values[6..],
        &full_round_claims,
        &routing_point,
        padded_len,
        table_rows,
    )?;
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
    full_rounds: &FullRoundProof,
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
    full_rounds.append_transcript(&mut seed);
    seed
}

fn column_batch_seed(base: &[Bn254], values: &[Bn254]) -> Vec<Bn254> {
    let mut seed = Vec::with_capacity(base.len() + values.len() + 2);
    seed.extend_from_slice(base);
    seed.push(Bn254::from_u64(COLUMN_BATCH_DOMAIN));
    seed.push(Bn254::from_usize(values.len()));
    seed.extend_from_slice(values);
    seed
}

fn column_batch_point(seed: &[Bn254], variables: usize) -> Vec<Bn254> {
    let mut transcript = RawTranscript::new(COLUMN_BATCH_DOMAIN);
    transcript.absorb_message(1, seed);
    challenges(&transcript, 0x434f_4c00, variables)
}

fn poseidon_trace(assignment: &[Bn254], rows: usize) -> Result<(Trace, Bn254), Error> {
    let padded = assignment.len().next_power_of_two();
    let heap_rows = padded << 1;
    let mut trace = TraceBuilder::new(rows).map_err(|_| Error::TableShape)?;
    let mut digests = vec![Bn254::ZERO; heap_rows];
    trace
        .fill_rows(padded..heap_rows, |row| {
            let index = row - padded;
            [
                assignment.get(index).copied().unwrap_or(Bn254::ZERO),
                Bn254::from_usize(index),
                Bn254::ONE,
            ]
        })
        .map_err(|_| Error::TableShape)?;
    digests[padded..].copy_from_slice(trace.digests(padded..heap_rows));
    let mut start = padded / 2;
    let mut level = 0;
    while start > 0 {
        trace
            .fill_rows(start..2 * start, |node| {
                [
                    digests[node << 1],
                    digests[(node << 1) | 1],
                    Bn254::from_usize(2 + level),
                ]
            })
            .map_err(|_| Error::TableShape)?;
        digests[start..2 * start].copy_from_slice(trace.digests(start..2 * start));
        start /= 2;
        level += 1;
    }
    let _ = trace
        .fill_row(0, [Bn254::ZERO; 3])
        .map_err(|_| Error::TableShape)?;
    trace
        .fill_rows(heap_rows..rows, |_| [Bn254::ZERO; 3])
        .map_err(|_| Error::TableShape)?;
    Ok((trace.finish(), digests[1]))
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
    trace: &Trace,
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
    let digest = &trace.columns[DIGEST_COLUMN];
    let mut outputs = [
        left.as_mut_slice(),
        right.as_mut_slice(),
        assignment_table.as_mut_slice(),
        active.as_mut_slice(),
        domain.as_mut_slice(),
        index.as_mut_slice(),
        internal.as_mut_slice(),
        leaf.as_mut_slice(),
    ];
    crate::parallel::rows_mut(&mut outputs, 0..rows, 64, |start, output| {
        for offset in 0..output[0].len() {
            let row = start + offset;
            let parent = row & (padded - 1);
            output[0][offset] = digest[parent << 1];
            output[1][offset] = digest[(parent << 1) | 1];
            output[2][offset] = assignment[parent];
            output[3][offset] = Bn254::from_bool(parent < assignment_len);
            if row > 0 && row < padded {
                output[6][offset] = Bn254::ONE;
                let depth = (usize::BITS - 1 - row.leading_zeros()) as usize;
                output[4][offset] = Bn254::from_usize(2 + height - 1 - depth);
            } else if row >= padded && row < 2 * padded {
                output[7][offset] = Bn254::ONE;
                output[4][offset] = Bn254::ONE;
                output[5][offset] = Bn254::from_usize(row - padded);
            }
        }
    });
    RoutingWork {
        input: [
            trace.columns[INPUT_0_COLUMN].clone(),
            trace.columns[INPUT_1_COLUMN].clone(),
            trace.input_2.clone(),
        ],
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
        let evaluations = crate::parallel::sumcheck(
            work.eq.len() / 2,
            COMPOSED_DEGREE + 1,
            (COMPOSED_DEGREE + 1) * 12,
            || (),
            |scratch, pair, t| {
                let _ = scratch;

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
                get(&work.eq) * (internal * internal_residual + leaf * leaf_residual)
            },
        );
        if evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(ROUTING_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge(0x2200 + round as u64);
        claim = interpolate(&evaluations, challenge);
        point.push(challenge);
        work.input
            .par_iter_mut()
            .chain(
                [
                    &mut work.left,
                    &mut work.right,
                    &mut work.assignment,
                    &mut work.active,
                    &mut work.domain,
                    &mut work.index,
                    &mut work.internal,
                    &mut work.leaf,
                    &mut work.eq,
                ]
                .into_par_iter(),
            )
            .for_each(|values| fold(values, challenge));
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
) -> Result<(SumcheckProof, Vec<Bn254>, Vec<Bn254>), Error> {
    let phase_started = Instant::now();
    let mut eq = eq_evaluations(target);
    let variables = target.len();
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let weights = poseidon_scalar::PartialWeights::new(weights);
    for round in 0..variables {
        let evaluations = poseidon_sumcheck::sum_pairs(eq.len() / 2, |pair| {
            poseidon_scalar::partial_pair_evaluations(&columns, &eq, pair, &weights)
        });
        if evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(POSEIDON_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge(0x3200 + round as u64);
        claim = poseidon_sumcheck::interpolate(&evaluations, challenge);
        point.push(challenge);
        fold(&mut eq, challenge);
        crate::parallel::fold_columns(&mut columns, challenge);
        rounds.push(evaluations.to_vec());
        eprintln!(
            "CAIR checkpoint: Poseidon sumcheck round {}/{} complete ({:.3}s phase elapsed)",
            round + 1,
            variables,
            phase_started.elapsed().as_secs_f64(),
        );
    }
    let terminal_values = columns.iter().map(|column| column[0]).collect();
    Ok((SumcheckProof { rounds }, point, terminal_values))
}

fn combined_poseidon_residual(values: &[Bn254], weights: &[Bn254]) -> Bn254 {
    poseidon_scalar::combined_partial_residual(values, weights)
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
    column_point: &[Bn254],
    poseidon_point: &[Bn254],
    routing_point: &[Bn254],
    full_rounds: &FullRoundClaims,
) -> Vec<Vec<Bn254>> {
    debug_assert_eq!(column_point.len(), width.trailing_zeros() as usize);
    let mut points = Vec::with_capacity(15);
    let mut poseidon_batch = column_point.to_vec();
    poseidon_batch.extend_from_slice(poseidon_point);
    points.push(poseidon_batch);
    for column in [INPUT_0_COLUMN, INPUT_1_COLUMN] {
        points.push(table_point(column, routing_point, width));
    }
    let height = padded.trailing_zeros() as usize;
    for child_bit in [Bn254::ZERO, Bn254::ONE] {
        let mut child = vec![child_bit];
        child.extend_from_slice(&routing_point[..height]);
        child.resize(rows.trailing_zeros() as usize, Bn254::ZERO);
        points.push(table_point(DIGEST_COLUMN, &child, width));
    }
    let mut root = vec![Bn254::ZERO; rows.trailing_zeros() as usize];
    root[0] = Bn254::ONE;
    points.push(table_point(DIGEST_COLUMN, &root, width));
    append_full_round_opening_points(&mut points, width, full_rounds);
    points
}

fn append_full_round_opening_points(
    points: &mut Vec<Vec<Bn254>>,
    width: usize,
    claims: &FullRoundClaims,
) {
    for column in [
        0,
        poseidon_scalar::START_B_COLUMN,
        poseidon_scalar::START_C_COLUMN,
    ] {
        points.push(table_point(column, &claims.initial_output_point, width));
    }
    points.push(table_point(
        DIGEST_COLUMN,
        &claims.terminal_output_point,
        width,
    ));
    for column in [INPUT_0_COLUMN, INPUT_1_COLUMN] {
        points.push(table_point(column, &claims.input_point, width));
    }
    for column in [
        poseidon_scalar::PARTIAL_STATES - 1,
        poseidon_scalar::END_B_COLUMN,
        poseidon_scalar::END_C_COLUMN,
    ] {
        points.push(table_point(column, &claims.input_point, width));
    }
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
    let height = padded.trailing_zeros() as usize;
    let row_variables = rows.trailing_zeros() as usize;
    let input = [values[0], values[1], domain_mle(point, height)];
    let left = values[2];
    let right = values[3];
    let _root = values[4];
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

fn verify_full_round_openings(
    values: &[Bn254],
    claims: &FullRoundClaims,
    _routing_point: &[Bn254],
    padded: usize,
    rows: usize,
) -> Result<(), Error> {
    if values.len() != 9 {
        return Err(Error::TableShape);
    }
    if values[..3] != claims.initial_output
        || values[3] != claims.terminal_digest
        || values[4] != claims.initial_input[0]
        || values[5] != claims.initial_input[1]
        || values[6..9] != claims.terminal_input
    {
        return Err(Error::Terminal);
    }
    let expected_domain = domain_mle(&claims.input_point, padded.trailing_zeros() as usize);
    if claims.initial_input[2] != expected_domain
        || claims.input_point.len() != rows.trailing_zeros() as usize
    {
        return Err(Error::Terminal);
    }
    Ok(())
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
    crate::parallel::eq_evaluations(point)
}

fn eq_eval(left: &[Bn254], right: &[Bn254]) -> Bn254 {
    left.iter()
        .zip(right)
        .fold(Bn254::ONE, |product, (&a, &b)| {
            product * ((Bn254::ONE - a) * (Bn254::ONE - b) + a * b)
        })
}

fn fold(values: &mut Vec<Bn254>, challenge: Bn254) {
    crate::parallel::fold(values, challenge);
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
        let (trace, root) = poseidon_trace(&assignment, 8).unwrap();
        let leaves = [
            hash_leaf(0, assignment[0]),
            hash_leaf(1, assignment[1]),
            hash_leaf(2, assignment[2]),
            hash_leaf(3, Bn254::ZERO),
        ];
        let left = hash_node(0, leaves[0], leaves[1]);
        let right = hash_node(0, leaves[2], leaves[3]);
        assert_eq!(root, hash_node(1, left, right));
        assert_eq!(trace.columns[DIGEST_COLUMN][1], root);
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
        assert_eq!(proof.table_width, SCALAR_COLUMNS);
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

        let mut bad_full_round = proof.clone();
        bad_full_round.full_rounds.tamper_for_test();
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &bad_full_round,
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

        let mut bad_column_value = proof.clone();
        bad_column_value.poseidon_values[0] += Bn254::ONE;
        assert!(
            verify(
                assignment.len(),
                root,
                &static_seed,
                committed_main.len(),
                &bad_column_value,
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
