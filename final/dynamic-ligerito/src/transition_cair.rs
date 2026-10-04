//! Private transition PIOP: local constraints, checkpoint GKR, routing product.
pub(crate) mod packed;
mod product_gkr;
pub(crate) mod split;
use crate::field::{F, batch_multiplicative_inverse_general};
use crate::parallel::prelude::*;
use crate::{
    circuit::{Circuit, CircuitError},
    merkle::{Commitment, MerkleError, MerkleTree},
    multiset::{RoutingChallenges, compress_fields},
    static_snark::{
        MleOpeningProof, TraceCommitment, commit_mle, commitment_seed, verify_mle_opening,
    },
    transcript::RawTranscript,
    transition_relation::{Statement, TransitionTable},
    wiring::CircuitShape,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;
const TRANSITION_VERSION: u64 = 100;
const TRANSCRIPT_DOMAIN: u64 = 0x4341_4952_5452_414e;
const LOCAL_ROUND_TAG: u64 = 0x4341_4952_4c43_4c52;
const PRODUCT_ROUND_TAG: u64 = 0x4341_4952_5052_5252;
const ROUTE_LANES: usize = 4;
const PRODUCT_BASE_COLUMNS: usize = 14;
#[derive(Clone, Serialize, Deserialize)]
struct SumcheckProof {
    rounds: Vec<Vec<F>>,
}

#[derive(Clone, Copy)]
struct MainLayout {
    compact_width: usize,
    width: usize,
}

#[derive(Clone, Copy)]
struct ProductLayout {
    row_variables: usize,
    used_columns: usize,
    width: usize,
}

impl ProductLayout {
    fn new(rows: usize) -> Self {
        let row_variables = rows.trailing_zeros() as usize;
        let used_columns = PRODUCT_BASE_COLUMNS + 2 * row_variables;
        Self {
            row_variables,
            used_columns,
            width: used_columns.next_power_of_two(),
        }
    }

    const fn cross_column(self, stage: usize, side: usize) -> usize {
        PRODUCT_BASE_COLUMNS + 2 * stage + side
    }

    const fn root_column(self, side: usize) -> usize {
        self.cross_column(self.row_variables - 1, side)
    }
}

struct CrossWork {
    output_column: usize,
    left: Vec<F>,
    right: Vec<F>,
}
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("transition row relation: {0}")]
    Relation(#[from] crate::transition_relation::Error),
    #[error("update count {size} is outside level range {lower}..={capacity}")]
    LevelSize {
        size: usize,
        lower: usize,
        capacity: usize,
    },
    #[error("transition assignment commitment is inconsistent with the update")]
    AssignmentAuthentication,
    #[error("malformed sparse transition CAIR table")]
    TableShape,
    #[error("transition CAIR sumcheck is malformed or inconsistent")]
    Sumcheck,
    #[error("transition CAIR terminal identity failed")]
    Terminal,
    #[error("transition CAIR routing products differ")]
    ProductMismatch,
    #[error("transition CAIR Ligerito: {0}")]
    Pcs(String),
}
fn authenticate_roots(
    old_tree: &MerkleTree,
    new_tree: &MerkleTree,
    old_commitment: Commitment,
    new_commitment: Commitment,
) -> Result<(), Error> {
    if old_tree.commitment() != old_commitment {
        return Err(Error::AssignmentAuthentication);
    }
    if new_tree.commitment() != new_commitment {
        return Err(Error::AssignmentAuthentication);
    }
    Ok(())
}

fn validate_level_size(size: usize, lower: usize, capacity: usize) -> Result<(), Error> {
    if size < lower || size > capacity {
        Err(Error::LevelSize {
            size,
            lower,
            capacity,
        })
    } else {
        Ok(())
    }
}

fn pack_columns<'a>(
    rows: usize,
    width: usize,
    columns: impl Iterator<Item = &'a Vec<F>>,
) -> Vec<F> {
    let columns = columns.map(|column| column.as_slice()).collect::<Vec<_>>();
    crate::parallel::pack_columns(rows, width, &columns)
}

fn product_trace(
    rows: usize,
    layout: ProductLayout,
    producers: &[F],
    references: &[F],
) -> Vec<Vec<F>> {
    assert_eq!(producers.len(), ROUTE_LANES * rows);
    assert_eq!(references.len(), ROUTE_LANES * rows);
    let mut columns = vec![vec![F::ZERO; rows]; layout.used_columns];
    crate::parallel::rows_mut(
        &mut columns[..PRODUCT_BASE_COLUMNS]
            .iter_mut()
            .map(Vec::as_mut_slice)
            .collect::<Vec<_>>(),
        0..rows,
        32,
        |start, columns| {
            for row in 0..columns[0].len() {
                for lane in 0..ROUTE_LANES {
                    columns[lane][row] = producers[ROUTE_LANES * (start + row) + lane];
                    columns[ROUTE_LANES + lane][row] =
                        references[ROUTE_LANES * (start + row) + lane];
                }
                columns[8][row] = columns[0][row] * columns[1][row];
                columns[9][row] = columns[2][row] * columns[3][row];
                columns[10][row] = columns[4][row] * columns[5][row];
                columns[11][row] = columns[6][row] * columns[7][row];
                columns[12][row] = columns[8][row] * columns[9][row];
                columns[13][row] = columns[10][row] * columns[11][row];
            }
        },
    );
    for stage in 0..layout.row_variables {
        let active = rows >> (stage + 1);
        for side in 0..2 {
            let previous = if stage == 0 {
                12 + side
            } else {
                layout.cross_column(stage - 1, side)
            };
            let output = layout.cross_column(stage, side);
            let (inputs, outputs) = columns.split_at_mut(output);
            outputs[0][..active]
                .par_iter_mut()
                .enumerate()
                .for_each(|(row, value)| {
                    *value = inputs[previous][2 * row] * inputs[previous][2 * row + 1];
                });
        }
    }
    columns
}

fn cross_work(product: &[Vec<F>], rows: usize, layout: ProductLayout) -> Vec<CrossWork> {
    let mut work = Vec::with_capacity(2 * layout.row_variables);
    for stage in 0..layout.row_variables {
        let active = rows >> (stage + 1);
        for side in 0..2 {
            let previous_column = if stage == 0 {
                12 + side
            } else {
                layout.cross_column(stage - 1, side)
            };
            let output_column = layout.cross_column(stage, side);
            let mut left = vec![F::ZERO; rows];
            let mut right = vec![F::ZERO; rows];
            for row in 0..active {
                left[row] = product[previous_column][2 * row];
                right[row] = product[previous_column][2 * row + 1];
            }
            work.push(CrossWork {
                output_column,
                left,
                right,
            });
        }
    }
    work
}

fn finish_prover_round(
    evaluations: &[F],
    claim: &mut F,
    point: &mut Vec<F>,
    round: usize,
    round_tag: u64,
    challenge_base: u64,
    interpolate_round: fn(&[F], F) -> F,
    transcript: &mut RawTranscript,
) -> Result<(), Error> {
    if evaluations[0] + evaluations[1] != *claim {
        return Err(Error::Sumcheck);
    }
    transcript.absorb_message(round_tag + round as u64, evaluations);
    let challenge = transcript.challenge(challenge_base + round as u64);
    *claim = interpolate_round(evaluations, challenge);
    point.push(challenge);
    Ok(())
}

fn checkpoint(phase: &str, round: usize, variables: usize, started: Instant) {
    eprintln!(
        "transition CAIR checkpoint: {phase} sumcheck round {}/{} complete ({:.3}s phase elapsed)",
        round + 1,
        variables,
        started.elapsed().as_secs_f64(),
    );
}

fn profile_checkpoint(label: &str, started: Instant) {
    if std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some() {
        eprintln!(
            "profile checkpoint: {label} complete in {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
}

fn verify_sumcheck(
    proof: &SumcheckProof,
    degree: usize,
    interpolate_round: fn(&[F], F) -> F,
    variables: usize,
    round_tag: u64,
    challenge_base: u64,
    transcript: &mut RawTranscript,
) -> Result<(F, Vec<F>), Error> {
    if proof.rounds.len() != variables {
        return Err(Error::Sumcheck);
    }
    let mut claim = F::ZERO;
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

fn product_opening_points(layout: ProductLayout, point: &[F]) -> Vec<Vec<F>> {
    let mut points = Vec::new();
    for column in 0..layout.used_columns {
        points.push(table_point(column, point, layout.width));
    }
    for stage in 0..layout.row_variables {
        let low_variables = layout.row_variables - stage - 1;
        for side in 0..2 {
            let previous = if stage == 0 {
                12 + side
            } else {
                layout.cross_column(stage - 1, side)
            };
            for bit_value in [F::ZERO, F::ONE] {
                let mut transformed = vec![F::ZERO; layout.row_variables];
                transformed[0] = bit_value;
                if low_variables > 0 {
                    transformed[1..=low_variables].copy_from_slice(&point[..low_variables]);
                }
                points.push(table_point(previous, &transformed, layout.width));
            }
        }
    }
    let zero = vec![F::ZERO; layout.row_variables];
    points.push(table_point(layout.root_column(0), &zero, layout.width));
    points.push(table_point(layout.root_column(1), &zero, layout.width));
    points
}

fn table_point(column: usize, row_point: &[F], width: usize) -> Vec<F> {
    let mut point = (0..width.trailing_zeros() as usize)
        .map(|bit| F::from_bool(column & (1 << bit) != 0))
        .collect::<Vec<_>>();
    point.extend_from_slice(row_point);
    point
}

#[allow(clippy::too_many_arguments)]
fn statement_seed(
    shape: CircuitShape,
    level: usize,
    lower: usize,
    capacity: usize,
    permutation: Commitment,
    old: Commitment,
    new: Commitment,
    row_count: usize,
    layout: MainLayout,
    table: &TraceCommitment,
) -> Vec<F> {
    let mut seed = vec![
        F::from_u64(TRANSITION_VERSION),
        F::from_usize(shape.gate_pairs),
        F::from_usize(shape.public_inputs),
        F::from_usize(shape.assignment_len),
        F::from_usize(level),
        F::from_usize(lower),
        F::from_usize(capacity),
        F::from_usize(row_count),
        F::from_usize(layout.compact_width),
        F::from_usize(layout.width),
        F::from_usize(permutation.len),
        permutation.root[0],
        permutation.root[1],
        old.root[0],
        old.root[1],
        new.root[0],
        new.root[1],
    ];
    seed.extend(commitment_seed(table));
    seed
}

fn transition_transcript(public_seed: &[F], product_seed: &[F]) -> RawTranscript {
    let mut transcript = RawTranscript::new(TRANSCRIPT_DOMAIN);
    transcript.absorb_message(1, public_seed);
    transcript.absorb_message(2, product_seed);
    transcript
}

fn challenges(transcript: &RawTranscript, base: u64, count: usize) -> Vec<F> {
    (0..count)
        .map(|index| transcript.challenge(base + index as u64))
        .collect()
}

fn role_seed(seed: &[F], role: u64) -> Vec<F> {
    let mut result = Vec::with_capacity(seed.len() + 1);
    result.push(F::from_u64(role));
    result.extend_from_slice(seed);
    result
}

fn eq_evaluations(point: &[F]) -> Vec<F> {
    crate::parallel::eq_evaluations(point)
}

fn eq_eval(left: &[F], right: &[F]) -> F {
    left.iter()
        .zip(right)
        .fold(F::ONE, |product, (&left, &right)| {
            product * (left * right + (F::ONE - left) * (F::ONE - right))
        })
}

fn fold(values: &mut Vec<F>, challenge: F) {
    crate::parallel::fold(values, challenge);
}

fn interpolate(evaluations: &[F], point: F) -> F {
    debug_assert!(!evaluations.is_empty());
    let mut scratch = (0..evaluations.len())
        .map(|index| {
            let x = F::from_usize(index);
            (0..evaluations.len())
                .filter(|&other| other != index)
                .fold(F::ONE, |product, other| {
                    product * (x - F::from_usize(other))
                })
        })
        .collect::<Vec<_>>();
    let mut inverse_denominators = vec![F::ZERO; scratch.len()];
    // All Lagrange denominators are nonzero constants. Montgomery's trick
    // replaces one inversion per evaluation with one inversion for the round.
    batch_multiplicative_inverse_general(&scratch, &mut inverse_denominators, |value| {
        value.inverse()
    });

    // Prefix/suffix products evaluate every Lagrange numerator in linear time
    // and remain valid when `point` is one of the interpolation nodes.
    scratch.resize(evaluations.len() + 1, F::ZERO);
    scratch[0] = F::ONE;
    for index in 0..evaluations.len() {
        scratch[index + 1] = scratch[index] * (point - F::from_usize(index));
    }
    let mut suffix = F::ONE;
    (0..evaluations.len()).rev().fold(F::ZERO, |sum, index| {
        let result =
            sum + evaluations[index] * scratch[index] * suffix * inverse_denominators[index];
        suffix *= point - F::from_usize(index);
        result
    })
}

fn pcs_error(error: impl std::fmt::Display) -> Error {
    Error::Pcs(error.to_string())
}

fn lerp(a: F, b: F, t: F) -> F {
    a + (b - a) * t
}
