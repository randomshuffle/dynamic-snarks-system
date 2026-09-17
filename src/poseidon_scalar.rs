//! Scalar CAIR representation of the width-three Poseidon2 permutation.
//!
//! The 56 partial rounds are represented by the 57 first-coordinate values.
//! Cayley--Hamilton eliminates the other two coordinates while preserving a
//! degree-five recurrence.  The two four-full-round caps are reduced with
//! four batched GKR-style sumchecks and therefore need no committed
//! intermediate states.

use std::sync::OnceLock;
use std::time::Instant;

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::poseidon2_constants;
use crate::poseidon_sumcheck;
use crate::transcript::RawTranscript;

#[cfg(feature = "poseidon-gkr")]
pub(crate) mod round_reduction;

pub(crate) const STATE_WIDTH: usize = 3;
pub(crate) const PARTIAL_ROUNDS: usize = 56;
pub(crate) const PARTIAL_STATES: usize = PARTIAL_ROUNDS + 1;
pub(crate) const SCALAR_COLUMNS: usize = 64;
pub(crate) const PARTIAL_CONSTRAINTS: usize = 58;
pub(crate) const SUMCHECK_DEGREE: usize = 6;

pub(crate) const START_B_COLUMN: usize = PARTIAL_STATES;
pub(crate) const START_C_COLUMN: usize = START_B_COLUMN + 1;
pub(crate) const END_B_COLUMN: usize = START_C_COLUMN + 1;
pub(crate) const END_C_COLUMN: usize = END_B_COLUMN + 1;
pub(crate) const INPUT_0_COLUMN: usize = END_C_COLUMN + 1;
pub(crate) const INPUT_1_COLUMN: usize = INPUT_0_COLUMN + 1;
pub(crate) const DIGEST_COLUMN: usize = INPUT_1_COLUMN + 1;

const INITIAL_FULL_ROUNDS: usize = 4;
const TERMINAL_FULL_START: usize = 60;
const FULL_CAP_DEPTH: usize = 4;

const FULL_INITIAL_TARGET_BASE: u64 = 0x5000;
const FULL_TERMINAL_TARGET_BASE: u64 = 0x5100;
const FULL_BOUNDARY_TAG: u64 = 0x5350_4341_4952_4244;
const FULL_WEIGHT_BASE: u64 = 0x5200;
const FULL_MIX_BASE: u64 = 0x5300;
const FULL_ROUND_TAG: u64 = 0x5350_4341_4952_5244;
const FULL_CHALLENGE_BASE: u64 = 0x5400;
const FULL_INPUT_TAG: u64 = 0x5350_4341_4952_494e;

type StateColumns = [Vec<Bn254>; STATE_WIDTH];

/// The committed scalar columns and transient full-round layer witnesses.
pub(crate) struct Trace {
    pub(crate) columns: Vec<Vec<Bn254>>,
    pub(crate) input_2: Vec<Bn254>,
    initial_layers: Vec<StateColumns>,
    terminal_layers: Vec<StateColumns>,
}

/// Incremental construction for Merkle heaps whose parent inputs depend on
/// digests produced by earlier rows.
pub(crate) struct TraceBuilder {
    columns: Vec<Vec<Bn254>>,
    input_2: Vec<Bn254>,
    initial_layers: Vec<StateColumns>,
    terminal_layers: Vec<StateColumns>,
    parameters: &'static Parameters,
}

/// Four batched reductions for the initial and terminal full-round caps.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FullRoundProof {
    initial_output: Vec<Bn254>,
    terminal_digest: Bn254,
    layers: Vec<FullRoundLayerProof>,
}

#[derive(Clone, Serialize, Deserialize)]
struct FullRoundLayerProof {
    rounds: Vec<Vec<Bn254>>,
    input_values: Vec<Bn254>,
}

/// Committed endpoint evaluations to authenticate after verifying sumcheck.
pub(crate) struct FullRoundClaims {
    pub(crate) initial_output_point: Vec<Bn254>,
    pub(crate) initial_output: [Bn254; STATE_WIDTH],
    pub(crate) terminal_output_point: Vec<Bn254>,
    pub(crate) terminal_digest: Bn254,
    pub(crate) input_point: Vec<Bn254>,
    pub(crate) initial_input: [Bn254; STATE_WIDTH],
    pub(crate) terminal_input: [Bn254; STATE_WIDTH],
}

impl FullRoundProof {
    /// Append a length-delimited field encoding for a later opening transcript.
    pub(crate) fn append_transcript(&self, seed: &mut Vec<Bn254>) {
        seed.push(Bn254::from_usize(self.initial_output.len()));
        seed.extend_from_slice(&self.initial_output);
        seed.push(self.terminal_digest);
        seed.push(Bn254::from_usize(self.layers.len()));
        for layer in &self.layers {
            seed.push(Bn254::from_usize(layer.rounds.len()));
            for round in &layer.rounds {
                seed.push(Bn254::from_usize(round.len()));
                seed.extend_from_slice(round);
            }
            seed.push(Bn254::from_usize(layer.input_values.len()));
            seed.extend_from_slice(&layer.input_values);
        }
    }

    #[cfg(test)]
    pub(crate) fn tamper_for_test(&mut self) {
        self.layers[0].rounds[0][0] += Bn254::ONE;
    }
}

struct Parameters {
    initial: Vec<[Bn254; STATE_WIDTH]>,
    internal: Vec<Bn254>,
    terminal: Vec<[Bn254; STATE_WIDTH]>,
}

impl Parameters {
    fn new() -> Self {
        let (external, internal) = poseidon2_constants();
        Self {
            initial: external.get_initial_constants().clone(),
            internal,
            terminal: external.get_terminal_constants().clone(),
        }
    }
}

/// A malformed full-round reduction.
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("scalar Poseidon trace inputs have inconsistent lengths")]
    TraceShape,
    #[error("scalar Poseidon full-round sumcheck is malformed or inconsistent")]
    Sumcheck,
}

impl Trace {
    /// Build the 64 committed columns and the transient full-round witnesses.
    pub(crate) fn new(inputs: [Vec<Bn254>; STATE_WIDTH]) -> Result<Self, Error> {
        let rows = inputs[0].len();
        if rows == 0 || inputs.iter().any(|column| column.len() != rows) {
            return Err(Error::TraceShape);
        }
        let mut builder = TraceBuilder::new(rows)?;
        builder.fill_rows(0..rows, |row| std::array::from_fn(|word| inputs[word][row]))?;
        Ok(builder.finish())
    }

    /// Prove both four-full-round caps with four batched reductions.
    pub(crate) fn prove_full_rounds(
        &self,
        transcript: &mut RawTranscript,
        checkpoint_label: &str,
    ) -> Result<(FullRoundProof, FullRoundClaims), Error> {
        let variables = self.columns[0].len().trailing_zeros() as usize;
        let initial_target = challenges(transcript, FULL_INITIAL_TARGET_BASE, variables);
        let terminal_target = challenges(transcript, FULL_TERMINAL_TARGET_BASE, variables);
        let initial_output: [Bn254; STATE_WIDTH] = std::array::from_fn(|word| {
            evaluate_column(
                &self.initial_layers[INITIAL_FULL_ROUNDS][word],
                &initial_target,
            )
        });
        let terminal_digest =
            evaluate_column(&self.terminal_layers[FULL_CAP_DEPTH][0], &terminal_target);
        let mut boundary_message = initial_output.to_vec();
        boundary_message.push(terminal_digest);
        transcript.absorb_message(FULL_BOUNDARY_TAG, &boundary_message);

        let mut current_initial = initial_output;
        let mut current_terminal = [terminal_digest, Bn254::ZERO, Bn254::ZERO];
        let mut current_initial_target = initial_target.clone();
        let mut current_terminal_target = terminal_target.clone();
        let mut layers = Vec::with_capacity(FULL_CAP_DEPTH);
        let started = Instant::now();
        let parameters = parameters();

        for depth in 0..FULL_CAP_DEPTH {
            let initial_weights = full_weights(transcript, depth, 0);
            let terminal_weights = if depth == 0 {
                [Bn254::ONE, Bn254::ZERO, Bn254::ZERO]
            } else {
                full_weights(transcript, depth, 1)
            };
            let mix = transcript.challenge(FULL_MIX_BASE + depth as u64);
            let mut claim = dot(initial_weights, current_initial)
                + mix * dot(terminal_weights, current_terminal);
            let initial_round = INITIAL_FULL_ROUNDS - 1 - depth;
            let terminal_round = 63 - depth;
            let mut initial_inputs = self.initial_layers[initial_round].clone();
            let mut terminal_inputs = self.terminal_layers[FULL_CAP_DEPTH - 1 - depth].clone();
            let mut initial_eq = eq_evaluations(&current_initial_target);
            let mut terminal_eq = eq_evaluations(&current_terminal_target);
            let mut point = Vec::with_capacity(variables);
            let mut rounds = Vec::with_capacity(variables);

            for variable in 0..variables {
                let evaluations = poseidon_sumcheck::sum_pairs(initial_eq.len() / 2, |pair| {
                    full_round_pair_evaluations(
                        &initial_inputs,
                        &terminal_inputs,
                        &initial_eq,
                        &terminal_eq,
                        pair,
                        initial_round,
                        terminal_round,
                        initial_weights,
                        terminal_weights,
                        mix,
                        parameters,
                    )
                });
                if evaluations[0] + evaluations[1] != claim {
                    return Err(Error::Sumcheck);
                }
                transcript.absorb_message(
                    FULL_ROUND_TAG + (depth * 64 + variable) as u64,
                    &evaluations,
                );
                let challenge =
                    transcript.challenge(FULL_CHALLENGE_BASE + (depth * 64 + variable) as u64);
                claim = poseidon_sumcheck::interpolate(&evaluations, challenge);
                point.push(challenge);
                fold(&mut initial_eq, challenge);
                fold(&mut terminal_eq, challenge);
                initial_inputs
                    .par_iter_mut()
                    .chain(terminal_inputs.par_iter_mut())
                    .for_each(|column| fold(column, challenge));
                rounds.push(evaluations.to_vec());
                eprintln!(
                    "{checkpoint_label}: full-round sumcheck {}/{} round {}/{} complete ({:.3}s phase elapsed)",
                    depth + 1,
                    FULL_CAP_DEPTH,
                    variable + 1,
                    variables,
                    started.elapsed().as_secs_f64(),
                );
            }
            let mut input_values = initial_inputs
                .iter()
                .chain(&terminal_inputs)
                .map(|column| column[0])
                .collect::<Vec<_>>();
            let initial_input: [Bn254; STATE_WIDTH] = input_values[..STATE_WIDTH]
                .try_into()
                .expect("three initial lanes");
            let terminal_input: [Bn254; STATE_WIDTH] = input_values[STATE_WIDTH..]
                .try_into()
                .expect("three terminal lanes");
            let expected = eq_eval(&current_initial_target, &point)
                * dot(
                    initial_weights,
                    poseidon_round(initial_round, initial_input, parameters),
                )
                + mix
                    * eq_eval(&current_terminal_target, &point)
                    * dot(
                        terminal_weights,
                        poseidon_round(terminal_round, terminal_input, parameters),
                    );
            if claim != expected {
                return Err(Error::Sumcheck);
            }
            transcript.absorb_message(FULL_INPUT_TAG + depth as u64, &input_values);
            current_initial = initial_input;
            current_terminal = terminal_input;
            current_initial_target = point.clone();
            current_terminal_target = point;
            layers.push(FullRoundLayerProof {
                rounds,
                input_values: std::mem::take(&mut input_values),
            });
        }

        let claims = FullRoundClaims {
            initial_output_point: initial_target,
            initial_output,
            terminal_output_point: terminal_target,
            terminal_digest,
            input_point: current_initial_target,
            initial_input: current_initial,
            terminal_input: current_terminal,
        };
        Ok((
            FullRoundProof {
                initial_output: initial_output.to_vec(),
                terminal_digest,
                layers,
            },
            claims,
        ))
    }
}

impl TraceBuilder {
    /// Allocate an empty scalar trace with `rows` rows.
    pub(crate) fn new(rows: usize) -> Result<Self, Error> {
        if rows == 0 || !rows.is_power_of_two() {
            return Err(Error::TraceShape);
        }
        Ok(Self {
            columns: (0..SCALAR_COLUMNS)
                .into_par_iter()
                .map(|_| vec![Bn254::ZERO; rows])
                .collect(),
            input_2: vec![Bn254::ZERO; rows],
            initial_layers: (0..=INITIAL_FULL_ROUNDS)
                .map(|_| std::array::from_fn(|_| vec![Bn254::ZERO; rows]))
                .collect(),
            terminal_layers: (0..=FULL_CAP_DEPTH)
                .map(|_| std::array::from_fn(|_| vec![Bn254::ZERO; rows]))
                .collect(),
            parameters: parameters(),
        })
    }

    /// Fill one row and return its Poseidon2 digest.
    pub(crate) fn fill_row(
        &mut self,
        row: usize,
        input: [Bn254; STATE_WIDTH],
    ) -> Result<Bn254, Error> {
        self.fill_rows(row..row + 1, |_| input)?;
        Ok(self.columns[DIGEST_COLUMN][row])
    }

    /// Fill independent rows using disjoint column slices; no full witness copy.
    pub(crate) fn fill_rows(
        &mut self,
        range: std::ops::Range<usize>,
        input: impl Fn(usize) -> [Bn254; STATE_WIDTH] + Sync + Send,
    ) -> Result<(), Error> {
        if range.start > range.end || range.end > self.columns[0].len() {
            return Err(Error::TraceShape);
        }
        let parameters = self.parameters;
        let mut columns = self
            .columns
            .iter_mut()
            .map(Vec::as_mut_slice)
            .chain(std::iter::once(self.input_2.as_mut_slice()))
            .chain(
                self.initial_layers
                    .iter_mut()
                    .flat_map(|layer| layer.iter_mut().map(Vec::as_mut_slice)),
            )
            .chain(
                self.terminal_layers
                    .iter_mut()
                    .flat_map(|layer| layer.iter_mut().map(Vec::as_mut_slice)),
            )
            .collect::<Vec<_>>();
        crate::parallel::rows_mut(&mut columns, range, 1, |start, columns| {
            for row in 0..columns[0].len() {
                let values = trace_row(input(start + row), parameters);
                for (column, value) in columns.iter_mut().zip(values) {
                    column[row] = value;
                }
            }
        });
        Ok(())
    }

    pub(crate) fn digests(&self, range: std::ops::Range<usize>) -> &[Bn254] {
        &self.columns[DIGEST_COLUMN][range]
    }

    /// Finish construction.
    pub(crate) fn finish(self) -> Trace {
        debug_assert_eq!(DIGEST_COLUMN + 1, SCALAR_COLUMNS);
        Trace {
            columns: self.columns,
            input_2: self.input_2,
            initial_layers: self.initial_layers,
            terminal_layers: self.terminal_layers,
        }
    }
}

/// Verify the four batched full-round reductions and return their endpoints.
pub(crate) fn verify_full_rounds(
    proof: &FullRoundProof,
    variables: usize,
    transcript: &mut RawTranscript,
) -> Result<FullRoundClaims, Error> {
    if proof.initial_output.len() != STATE_WIDTH || proof.layers.len() != FULL_CAP_DEPTH {
        return Err(Error::Sumcheck);
    }
    let initial_target = challenges(transcript, FULL_INITIAL_TARGET_BASE, variables);
    let terminal_target = challenges(transcript, FULL_TERMINAL_TARGET_BASE, variables);
    let initial_output: [Bn254; STATE_WIDTH] = proof.initial_output[..]
        .try_into()
        .map_err(|_| Error::Sumcheck)?;
    let mut boundary_message = proof.initial_output.clone();
    boundary_message.push(proof.terminal_digest);
    transcript.absorb_message(FULL_BOUNDARY_TAG, &boundary_message);

    let mut current_initial = initial_output;
    let mut current_terminal = [proof.terminal_digest, Bn254::ZERO, Bn254::ZERO];
    let mut current_initial_target = initial_target.clone();
    let mut current_terminal_target = terminal_target.clone();

    for (depth, layer) in proof.layers.iter().enumerate() {
        if layer.rounds.len() != variables || layer.input_values.len() != 2 * STATE_WIDTH {
            return Err(Error::Sumcheck);
        }
        let initial_weights = full_weights(transcript, depth, 0);
        let terminal_weights = if depth == 0 {
            [Bn254::ONE, Bn254::ZERO, Bn254::ZERO]
        } else {
            full_weights(transcript, depth, 1)
        };
        let mix = transcript.challenge(FULL_MIX_BASE + depth as u64);
        let mut claim =
            dot(initial_weights, current_initial) + mix * dot(terminal_weights, current_terminal);
        let mut point = Vec::with_capacity(variables);
        for (variable, evaluations) in layer.rounds.iter().enumerate() {
            if evaluations.len() != SUMCHECK_DEGREE + 1 || evaluations[0] + evaluations[1] != claim
            {
                return Err(Error::Sumcheck);
            }
            transcript.absorb_message(FULL_ROUND_TAG + (depth * 64 + variable) as u64, evaluations);
            let challenge =
                transcript.challenge(FULL_CHALLENGE_BASE + (depth * 64 + variable) as u64);
            claim = poseidon_sumcheck::interpolate(evaluations, challenge);
            point.push(challenge);
        }
        let initial_input: [Bn254; STATE_WIDTH] = layer.input_values[..STATE_WIDTH]
            .try_into()
            .map_err(|_| Error::Sumcheck)?;
        let terminal_input: [Bn254; STATE_WIDTH] = layer.input_values[STATE_WIDTH..]
            .try_into()
            .map_err(|_| Error::Sumcheck)?;
        let parameters = parameters();
        let initial_round = INITIAL_FULL_ROUNDS - 1 - depth;
        let terminal_round = 63 - depth;
        let expected = eq_eval(&current_initial_target, &point)
            * dot(
                initial_weights,
                poseidon_round(initial_round, initial_input, parameters),
            )
            + mix
                * eq_eval(&current_terminal_target, &point)
                * dot(
                    terminal_weights,
                    poseidon_round(terminal_round, terminal_input, parameters),
                );
        if claim != expected {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(FULL_INPUT_TAG + depth as u64, &layer.input_values);
        current_initial = initial_input;
        current_terminal = terminal_input;
        current_initial_target = point.clone();
        current_terminal_target = point;
    }

    Ok(FullRoundClaims {
        initial_output_point: initial_target,
        initial_output,
        terminal_output_point: terminal_target,
        terminal_digest: proof.terminal_digest,
        input_point: current_initial_target,
        initial_input: current_initial,
        terminal_input: current_terminal,
    })
}

/// Evaluate all partial-round constraints at one MLE point.
pub(crate) fn combined_partial_residual(values: &[Bn254], weights: &[Bn254]) -> Bn254 {
    debug_assert_eq!(values.len(), SCALAR_COLUMNS);
    debug_assert_eq!(weights.len(), PARTIAL_CONSTRAINTS);
    let parameters = parameters();
    let a: [Bn254; PARTIAL_STATES] = values[..PARTIAL_STATES]
        .try_into()
        .expect("57 partial states");
    let u: [Bn254; PARTIAL_ROUNDS] =
        std::array::from_fn(|round| fifth(a[round] + parameters.internal[round]));
    combined_partial_from_parts(
        &a,
        &u,
        values[START_B_COLUMN],
        values[START_C_COLUMN],
        values[END_B_COLUMN],
        values[END_C_COLUMN],
        weights,
    )
}

/// Fixed linear functional on partial states, their fifth powers, and cap lanes.
/// Transpose the scalar recurrence once per sumcheck instead of reconstructing
/// and weighting every residual at every message point and row pair.
pub(crate) struct PartialWeights {
    states: [Bn254; PARTIAL_STATES],
    fifths: [Bn254; PARTIAL_ROUNDS],
    caps: [Bn254; 4],
}

impl PartialWeights {
    pub(crate) fn new(weights: &[Bn254]) -> Self {
        debug_assert_eq!(weights.len(), PARTIAL_CONSTRAINTS);
        let mut states = [Bn254::ZERO; PARTIAL_STATES];
        let mut fifths = [Bn254::ZERO; PARTIAL_ROUNDS];
        states[1] = weights[0];
        states[2] = weights[1];
        fifths[0] = -(weights[0] + weights[1]).double();
        fifths[1] = -weights[1].double();
        for round in 0..PARTIAL_ROUNDS - 2 {
            let weight = weights[2 + round];
            states[round + 3] += weight;
            states[round + 2] -= Bn254::from_u64(5) * weight;
            states[round + 1] += Bn254::from_u64(5) * weight;
            fifths[round] -= Bn254::from_u64(7) * weight;
            fifths[round + 1] += Bn254::from_u64(8) * weight;
            fifths[round + 2] -= weight.double();
        }
        // The final two linear layers simplify to
        // b56 = 5*a55 - 7*u54 + u55,
        // c56 = -10*a55 + 5*a56 + 14*u54 - 9*u55.
        states[55] += -Bn254::from_u64(5) * weights[56] + Bn254::from_u64(10) * weights[57];
        states[56] -= Bn254::from_u64(5) * weights[57];
        fifths[54] += Bn254::from_u64(7) * weights[56] - Bn254::from_u64(14) * weights[57];
        fifths[55] += -weights[56] + Bn254::from_u64(9) * weights[57];
        Self {
            states,
            fifths,
            caps: [
                -weights[0] - Bn254::from_u64(3) * weights[1],
                -weights[0] - Bn254::from_u64(4) * weights[1],
                weights[56],
                weights[57],
            ],
        }
    }
}

/// Seven line evaluations of the batched partial-round residual times `eq`.
pub(crate) fn partial_pair_evaluations(
    columns: &[Vec<Bn254>],
    eq: &[Bn254],
    pair: usize,
    weights: &PartialWeights,
) -> [Bn254; poseidon_sumcheck::EVALUATIONS] {
    debug_assert_eq!(columns.len(), SCALAR_COLUMNS);
    let left = pair << 1;
    let right = left | 1;
    let parameters = parameters();
    let mut coefficients = [Bn254::ZERO; poseidon_sumcheck::FIFTH_COEFFICIENTS];
    for (column, &weight) in columns[..PARTIAL_STATES].iter().zip(&weights.states).chain(
        [START_B_COLUMN, START_C_COLUMN, END_B_COLUMN, END_C_COLUMN]
            .into_iter()
            .map(|column| &columns[column])
            .zip(&weights.caps),
    ) {
        coefficients[0] += weight * column[left];
        coefficients[1] += weight * (column[right] - column[left]);
    }
    for round in 0..PARTIAL_ROUNDS {
        let fifth = poseidon_sumcheck::fifth_line_coefficients(
            columns[round][left] + parameters.internal[round],
            columns[round][right] + parameters.internal[round],
        );
        for (coefficient, value) in coefficients.iter_mut().zip(fifth) {
            *coefficient += weights.fifths[round] * value;
        }
    }
    let residuals = poseidon_sumcheck::degree_five_evaluations(coefficients);
    let eq_line = poseidon_sumcheck::line_evaluations(eq[left], eq[right]);
    std::array::from_fn(|evaluation| eq_line[evaluation] * residuals[evaluation])
}

fn combined_partial_from_parts(
    a: &[Bn254; PARTIAL_STATES],
    u: &[Bn254; PARTIAL_ROUNDS],
    start_b: Bn254,
    start_c: Bn254,
    end_b: Bn254,
    end_c: Bn254,
    weights: &[Bn254],
) -> Bn254 {
    let mut result = weights[0] * (a[1] - (u[0].double() + start_b + start_c));
    result += weights[1]
        * (a[2]
            - (u[1].double()
                + u[0].double()
                + Bn254::from_u64(3) * start_b
                + Bn254::from_u64(4) * start_c));
    for round in 0..PARTIAL_ROUNDS - 2 {
        let left =
            a[round + 3] - Bn254::from_u64(5) * a[round + 2] + Bn254::from_u64(5) * a[round + 1];
        let right = Bn254::from_u64(7) * u[round] - Bn254::from_u64(8) * u[round + 1]
            + Bn254::TWO * u[round + 2];
        result += weights[2 + round] * (left - right);
    }

    let q1 = a[55] - u[54].double();
    let q2 = a[56] - u[55].double() - u[54].double();
    let b54 = Bn254::from_u64(4) * q1 - q2;
    let c54 = q2 - Bn254::from_u64(3) * q1;
    let state55 = partial_round_from_u([a[54], b54, c54], u[54]);
    let state56 = partial_round_from_u(state55, u[55]);
    result += weights[56] * (end_b - state56[1]);
    result += weights[57] * (end_c - state56[2]);
    result
}

#[allow(clippy::too_many_arguments)]
fn full_round_pair_evaluations(
    initial: &StateColumns,
    terminal: &StateColumns,
    initial_eq: &[Bn254],
    terminal_eq: &[Bn254],
    pair: usize,
    initial_round: usize,
    terminal_round: usize,
    initial_weights: [Bn254; STATE_WIDTH],
    terminal_weights: [Bn254; STATE_WIDTH],
    mix: Bn254,
    parameters: &Parameters,
) -> [Bn254; poseidon_sumcheck::EVALUATIONS] {
    let left = pair << 1;
    let right = left | 1;
    let initial_expected = full_round_line_evaluations(
        initial_round,
        std::array::from_fn(|word| initial[word][left]),
        std::array::from_fn(|word| initial[word][right]),
        parameters,
    );
    let terminal_expected = full_round_line_evaluations(
        terminal_round,
        std::array::from_fn(|word| terminal[word][left]),
        std::array::from_fn(|word| terminal[word][right]),
        parameters,
    );
    let initial_eq_line = poseidon_sumcheck::line_evaluations(initial_eq[left], initial_eq[right]);
    let terminal_eq_line =
        poseidon_sumcheck::line_evaluations(terminal_eq[left], terminal_eq[right]);
    std::array::from_fn(|evaluation| {
        initial_eq_line[evaluation] * dot(initial_weights, initial_expected[evaluation])
            + mix
                * terminal_eq_line[evaluation]
                * dot(terminal_weights, terminal_expected[evaluation])
    })
}

fn full_round_line_evaluations(
    round: usize,
    mut zero: [Bn254; STATE_WIDTH],
    mut one: [Bn254; STATE_WIDTH],
    parameters: &Parameters,
) -> [[Bn254; STATE_WIDTH]; poseidon_sumcheck::EVALUATIONS] {
    debug_assert!(round < 4 || round >= 60);
    if round == 0 {
        zero = external_linear(zero);
        one = external_linear(one);
    }
    let constants = if round < 4 {
        parameters.initial[round]
    } else {
        parameters.terminal[round - TERMINAL_FULL_START]
    };
    let powered = std::array::from_fn::<_, STATE_WIDTH, _>(|word| {
        poseidon_sumcheck::fifth_line_evaluations(
            zero[word] + constants[word],
            one[word] + constants[word],
        )
    });
    std::array::from_fn(|evaluation| {
        external_linear(std::array::from_fn(|word| powered[word][evaluation]))
    })
}

fn poseidon_round(
    round: usize,
    mut state: [Bn254; STATE_WIDTH],
    parameters: &Parameters,
) -> [Bn254; STATE_WIDTH] {
    if round == 0 {
        state = external_linear(state);
    }
    if round < INITIAL_FULL_ROUNDS {
        full_round(state, parameters.initial[round])
    } else if round < TERMINAL_FULL_START {
        partial_round(state, parameters.internal[round - INITIAL_FULL_ROUNDS])
    } else {
        full_round(state, parameters.terminal[round - TERMINAL_FULL_START])
    }
}

fn full_round(
    state: [Bn254; STATE_WIDTH],
    constants: [Bn254; STATE_WIDTH],
) -> [Bn254; STATE_WIDTH] {
    external_linear(std::array::from_fn(|word| {
        fifth(state[word] + constants[word])
    }))
}

fn partial_round(state: [Bn254; STATE_WIDTH], constant: Bn254) -> [Bn254; STATE_WIDTH] {
    partial_round_from_u(state, fifth(state[0] + constant))
}

fn partial_round_from_u(state: [Bn254; STATE_WIDTH], first: Bn254) -> [Bn254; STATE_WIDTH] {
    [
        first.double() + state[1] + state[2],
        first + state[1].double() + state[2],
        first + state[1] + Bn254::from_u64(3) * state[2],
    ]
}

fn external_linear(state: [Bn254; STATE_WIDTH]) -> [Bn254; STATE_WIDTH] {
    let sum = state.into_iter().sum::<Bn254>();
    std::array::from_fn(|word| sum + state[word])
}

fn fifth(value: Bn254) -> Bn254 {
    let square = value * value;
    square * square * value
}

fn full_weights(transcript: &RawTranscript, depth: usize, side: usize) -> [Bn254; STATE_WIDTH] {
    std::array::from_fn(|word| {
        transcript.challenge(FULL_WEIGHT_BASE + (depth * 8 + side * 3 + word) as u64)
    })
}

fn challenges(transcript: &RawTranscript, base: u64, count: usize) -> Vec<Bn254> {
    (0..count)
        .map(|index| transcript.challenge(base + index as u64))
        .collect()
}

fn parameters() -> &'static Parameters {
    static PARAMETERS: OnceLock<Parameters> = OnceLock::new();
    PARAMETERS.get_or_init(Parameters::new)
}

fn dot(weights: [Bn254; STATE_WIDTH], values: [Bn254; STATE_WIDTH]) -> Bn254 {
    weights
        .into_iter()
        .zip(values)
        .fold(Bn254::ZERO, |sum, (weight, value)| sum + weight * value)
}

fn evaluate_column(column: &[Bn254], point: &[Bn254]) -> Bn254 {
    let mut values = column.to_vec();
    for &challenge in point {
        fold(&mut values, challenge);
    }
    values[0]
}

fn eq_evaluations(point: &[Bn254]) -> Vec<Bn254> {
    crate::parallel::eq_evaluations(point)
}

fn eq_eval(left: &[Bn254], right: &[Bn254]) -> Bn254 {
    left.iter()
        .zip(right)
        .fold(Bn254::ONE, |product, (&left, &right)| {
            product * (left * right + (Bn254::ONE - left) * (Bn254::ONE - right))
        })
}

fn fold(values: &mut Vec<Bn254>, challenge: Bn254) {
    crate::parallel::fold(values, challenge);
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_symmetric::Permutation;

    #[test]
    fn transposed_partial_weights_match_each_original_message_evaluation() {
        let points = [
            Bn254::ZERO,
            Bn254::ONE,
            -Bn254::ONE,
            Bn254::TWO,
            -Bn254::TWO,
            Bn254::ONE.halve(),
            -Bn254::ONE.halve(),
        ];
        for seed in [1, 7, 23] {
            // Arbitrary off-trace columns test the residual polynomial itself,
            // including all seven message points and independent equality data.
            let columns = (0..SCALAR_COLUMNS)
                .map(|column| {
                    (0..4)
                        .map(|row| Bn254::from_usize(seed + column * column + 13 * row).exp_u64(7))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let eq = [
                Bn254::from_u64(3),
                Bn254::from_u64(17),
                Bn254::ZERO,
                Bn254::ONE,
            ];
            for weights in [
                vec![Bn254::ZERO; PARTIAL_CONSTRAINTS],
                vec![Bn254::ONE; PARTIAL_CONSTRAINTS],
                (0..PARTIAL_CONSTRAINTS)
                    .map(|i| Bn254::from_usize(seed + i).exp_u64(5))
                    .collect(),
            ] {
                let transposed = PartialWeights::new(&weights);
                for pair in 0..2 {
                    let actual = partial_pair_evaluations(&columns, &eq, pair, &transposed);
                    for (index, point) in points.into_iter().enumerate() {
                        let line = |values: &[Bn254]| {
                            values[2 * pair] + point * (values[2 * pair + 1] - values[2 * pair])
                        };
                        let values = columns
                            .iter()
                            .map(|column| line(column))
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual[index],
                            line(&eq) * combined_partial_residual(&values, &weights)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scalar_trace_matches_poseidon_and_recurrence() {
        let inputs = [
            (0..8).map(Bn254::from_usize).collect(),
            (8..16).map(Bn254::from_usize).collect(),
            (16..24).map(Bn254::from_usize).collect(),
        ];
        let trace = Trace::new(inputs.clone()).unwrap();
        let weights = (0..PARTIAL_CONSTRAINTS)
            .map(|index| Bn254::from_usize(index + 1))
            .collect::<Vec<_>>();
        for row in 0..8 {
            let values = trace
                .columns
                .iter()
                .map(|column| column[row])
                .collect::<Vec<_>>();
            assert_eq!(combined_partial_residual(&values, &weights), Bn254::ZERO);
            let mut state = std::array::from_fn(|word| inputs[word][row]);
            crate::hash::poseidon2().permute_mut(&mut state);
            assert_eq!(values[DIGEST_COLUMN], state[0]);
        }
    }

    #[test]
    fn recurrence_detects_a_changed_partial_state() {
        let inputs = [
            vec![Bn254::from_u64(3); 2],
            vec![Bn254::from_u64(5); 2],
            vec![Bn254::from_u64(7); 2],
        ];
        let trace = Trace::new(inputs).unwrap();
        let weights = vec![Bn254::ONE; PARTIAL_CONSTRAINTS];
        let mut values = trace
            .columns
            .iter()
            .map(|column| column[0])
            .collect::<Vec<_>>();
        values[17] += Bn254::ONE;
        assert_ne!(combined_partial_residual(&values, &weights), Bn254::ZERO);
    }

    #[test]
    fn full_round_reduction_round_trip_and_tamper() {
        let inputs = [
            (0..8).map(Bn254::from_usize).collect(),
            (8..16).map(Bn254::from_usize).collect(),
            (16..24).map(Bn254::from_usize).collect(),
        ];
        let trace = Trace::new(inputs).unwrap();
        let mut prover_transcript = RawTranscript::new(0x7363_616c_6172_7465);
        let (mut proof, prover_claims) = trace
            .prove_full_rounds(&mut prover_transcript, "scalar test checkpoint")
            .unwrap();
        let mut verifier_transcript = RawTranscript::new(0x7363_616c_6172_7465);
        let verifier_claims = verify_full_rounds(&proof, 3, &mut verifier_transcript).unwrap();
        assert_eq!(prover_claims.initial_output, verifier_claims.initial_output);
        assert_eq!(prover_claims.terminal_input, verifier_claims.terminal_input);

        proof.layers[0].rounds[0][0] += Bn254::ONE;
        let mut bad_transcript = RawTranscript::new(0x7363_616c_6172_7465);
        assert!(verify_full_rounds(&proof, 3, &mut bad_transcript).is_err());
    }
}

const TRACE_WIDTH: usize =
    SCALAR_COLUMNS + 1 + (INITIAL_FULL_ROUNDS + FULL_CAP_DEPTH + 2) * STATE_WIDTH;

fn trace_row(input: [Bn254; STATE_WIDTH], parameters: &Parameters) -> [Bn254; TRACE_WIDTH] {
    let mut output = [Bn254::ZERO; TRACE_WIDTH];
    let mut state = input;
    output[INPUT_0_COLUMN] = state[0];
    output[INPUT_1_COLUMN] = state[1];
    output[SCALAR_COLUMNS] = state[2];
    for word in 0..STATE_WIDTH {
        output[SCALAR_COLUMNS + 1 + (0) * STATE_WIDTH + word] = state[word];
    }
    for round in 0..INITIAL_FULL_ROUNDS {
        state = poseidon_round(round, state, parameters);
        for word in 0..STATE_WIDTH {
            output[SCALAR_COLUMNS + 1 + (round + 1) * STATE_WIDTH + word] = state[word];
        }
    }

    output[0] = state[0];
    output[START_B_COLUMN] = state[1];
    output[START_C_COLUMN] = state[2];
    for partial_index in 0..PARTIAL_ROUNDS {
        state = partial_round(state, parameters.internal[partial_index]);
        output[partial_index + 1] = state[0];
    }
    output[END_B_COLUMN] = state[1];
    output[END_C_COLUMN] = state[2];
    for word in 0..STATE_WIDTH {
        output[SCALAR_COLUMNS
            + 1
            + (INITIAL_FULL_ROUNDS + 1) * STATE_WIDTH
            + (0) * STATE_WIDTH
            + word] = state[word];
    }
    for depth in 0..FULL_CAP_DEPTH {
        state = poseidon_round(TERMINAL_FULL_START + depth, state, parameters);
        for word in 0..STATE_WIDTH {
            output[SCALAR_COLUMNS
                + 1
                + (INITIAL_FULL_ROUNDS + 1) * STATE_WIDTH
                + (depth + 1) * STATE_WIDTH
                + word] = state[word];
        }
    }
    output[DIGEST_COLUMN] = state[0];
    output
}
