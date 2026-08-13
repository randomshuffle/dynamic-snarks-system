//! Commit-all-intermediate-rounds proof for one sparse transition.
//!
//! The main commitment contains the universal sparse-DAG row assignment and
//! both full Poseidon2 round traces.  Three row-batched sumchecks check the
//! local relation, the Poseidon rounds, and the routing multiset product.  The
//! product tree is committed in a second phase because its leaves depend on
//! Fiat--Shamir tuple-compression challenges sampled after the main table is
//! bound.  Each commitment has exactly one batched WHIR opening proof.

use std::time::Instant;

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::circuit::{Circuit, CircuitError};
use crate::hash::poseidon2_constants;
use crate::merkle::{Commitment, MerkleError, MerkleTree};
use crate::multiset::{RoutingChallenges, compress_fields};
use crate::poseidon_sumcheck;
use crate::static_snark::{
    MleOpeningProof, TraceCommitment, commit_mle, commitment_seed, verify_mle_opening,
};
use crate::transcript::RawTranscript;
use crate::transition_relation::{
    Statement, TransitionTable, compact_column_count, compact_constraint_degree,
    compact_main_width, compact_residuals, compact_route_values,
};
use crate::wiring::CircuitShape;

const TRANSITION_VERSION: u64 = 7;
const TRANSCRIPT_DOMAIN: u64 = 0x4341_4952_5452_414e;
const LOCAL_ROUND_TAG: u64 = 0x4341_4952_4c43_4c52;
const POSEIDON_ROUND_TAG: u64 = 0x4341_4952_5053_5252;
const PRODUCT_ROUND_TAG: u64 = 0x4341_4952_5052_5252;
const POSEIDON_DEGREE: usize = 6;
const PRODUCT_DEGREE: usize = 4;
const STATE_WIDTH: usize = 3;
const POSEIDON_TRANSITIONS: usize = 64;
const POSEIDON_STATES: usize = POSEIDON_TRANSITIONS + 1;
const POSEIDON_COLUMNS_PER_HASH: usize = POSEIDON_STATES * STATE_WIDTH;
const POSEIDON_COLUMNS: usize = POSEIDON_COLUMNS_PER_HASH;
const POSEIDON_CONSTRAINTS_PER_HASH: usize = POSEIDON_TRANSITIONS * STATE_WIDTH + 1;
const POSEIDON_CONSTRAINTS: usize = POSEIDON_CONSTRAINTS_PER_HASH;
const LOCAL_HASH_FIELDS: usize = 8;
const ROUTE_LANES: usize = 4;
const TUPLE_WIDTH: usize = 6;
const PRODUCT_BASE_COLUMNS: usize = 14;

/// One private-position sparse transition CAIR proof.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    row_count: usize,
    main_opening: MleOpeningProof,
    product_opening: MleOpeningProof,
    local: SumcheckProof,
    poseidon: SumcheckProof,
    product: SumcheckProof,
}

#[derive(Clone, Serialize, Deserialize)]
struct SumcheckProof {
    rounds: Vec<Vec<Bn254>>,
}

#[derive(Clone, Copy)]
struct MainLayout {
    compact_width: usize,
    width: usize,
}

impl MainLayout {
    fn new(statement: Statement) -> Self {
        let compact_width = compact_column_count(statement);
        Self {
            compact_width,
            width: compact_main_width(statement),
        }
    }

    const fn poseidon_column(self, state_column: usize) -> usize {
        self.compact_width + state_column
    }

    const fn digest_column(self) -> usize {
        self.compact_width + POSEIDON_COLUMNS
    }
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
    left: Vec<Bn254>,
    right: Vec<Bn254>,
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

/// Sparse transition CAIR proving or verification failure.
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
    #[error("transition permutation commitment is inconsistent with preprocessing")]
    PermutationAuthentication,
    #[error("malformed sparse transition CAIR table")]
    TableShape,
    #[error("transition CAIR sumcheck is malformed or inconsistent")]
    Sumcheck,
    #[error("transition CAIR terminal identity failed")]
    Terminal,
    #[error("transition CAIR routing products differ")]
    ProductMismatch,
    #[error("transition CAIR WHIR: {0}")]
    Whir(String),
}

/// Prove one hierarchy-level transition with CAIR.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    circuit: &Circuit,
    permutation_tree: &MerkleTree,
    old_tree: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, Bn254, Bn254)],
    old_commitment: Commitment,
    new_commitment: Commitment,
) -> Result<Proof, Error> {
    validate_level_size(updates.len(), lower, capacity)?;
    authenticate_trees(
        circuit,
        permutation_tree,
        old_tree,
        updates,
        old_commitment,
        new_commitment,
    )?;
    let mut new_tree = old_tree.clone();
    new_tree.update(
        &updates
            .iter()
            .map(|&(index, _, new)| (index, new))
            .collect::<Vec<_>>(),
    )?;
    let table = TransitionTable::build(circuit, permutation_tree, old_tree, &new_tree, updates)?;
    let row_count = table.row_count();
    let statement = table.statement();
    let main_layout = MainLayout::new(statement);
    let compact = table.compact_witness();
    let poseidon_columns = poseidon_trace(&compact.hash_inputs);
    let digest_columns = vec![compact.hash_inputs[3].clone()];
    let mut committed_compact = compact.columns.clone();
    for column in &mut committed_compact {
        column.resize(2 * row_count, Bn254::ZERO);
    }
    let main_table = pack_columns(
        2 * row_count,
        main_layout.width,
        committed_compact
            .iter()
            .chain(&poseidon_columns)
            .chain(&digest_columns),
    );
    let commitment_started = Instant::now();
    let main_committed = commit_mle(main_table).map_err(whir_error)?;
    eprintln!(
        "transition CAIR checkpoint: main commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );

    let public_seed = statement_seed(
        CircuitShape::from_circuit(circuit),
        level,
        lower,
        capacity,
        permutation_tree.commitment(),
        old_commitment,
        new_commitment,
        row_count,
        main_layout,
        main_committed.commitment(),
    );
    let routing_challenges = RoutingChallenges::derive(&public_seed, main_committed.commitment());
    let factors = table.product_factors(routing_challenges);
    factors.verify().map_err(|_| Error::ProductMismatch)?;
    let product_layout = ProductLayout::new(row_count);
    let product_columns = product_trace(
        row_count,
        product_layout,
        &factors.producers,
        &factors.references,
    );
    let product_table = pack_columns(row_count, product_layout.width, product_columns.iter());
    let commitment_started = Instant::now();
    let product_committed = commit_mle(product_table).map_err(whir_error)?;
    eprintln!(
        "transition CAIR checkpoint: product commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );

    let product_seed = commitment_seed(product_committed.commitment());
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let local_constraint_count = compact_residuals(
        &vec![Bn254::ZERO; main_layout.compact_width],
        &[Bn254::ZERO; LOCAL_HASH_FIELDS],
        statement,
    )
    .len();
    let local_weights = challenges(&transcript, 0x1000, local_constraint_count);
    let local_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let local_hash_columns = local_hash_columns(&compact.hash_inputs, row_count);
    let (local, local_point) = prove_local_sumcheck(
        compact
            .columns
            .clone()
            .into_iter()
            .chain(local_hash_columns)
            .collect(),
        main_layout.compact_width,
        statement,
        &local_weights,
        &local_target,
        &mut transcript,
    )?;

    let poseidon_weights = challenges(&transcript, 0x2000, POSEIDON_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x2100, product_layout.row_variables + 1);
    let (poseidon, poseidon_point) = prove_poseidon_sumcheck(
        poseidon_columns,
        vec![compact.hash_inputs[3].clone()],
        &poseidon_weights,
        &poseidon_target,
        &mut transcript,
    )?;

    let product_weights = challenges(
        &transcript,
        0x3000,
        PRODUCT_BASE_COLUMNS + 2 * product_layout.row_variables,
    );
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let route_columns = compact.columns.clone();
    let cross_work = cross_work(&product_columns, row_count, product_layout);
    let (product, product_point) = prove_product_sumcheck(
        product_columns,
        route_columns,
        cross_work,
        statement,
        routing_challenges,
        &product_weights,
        &product_target,
        &mut transcript,
    )?;

    let main_points = main_opening_points(
        statement,
        main_layout,
        &local_point,
        &poseidon_point,
        &product_point,
    );
    let product_points = product_opening_points(product_layout, &product_point);
    let opening_seed = raw_opening_seed(&public_seed, &product_seed, &local, &poseidon, &product);
    let main_seed = role_seed(&opening_seed, 1);
    let product_opening_seed = role_seed(&opening_seed, 2);
    let main_refs = main_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let product_refs = product_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let main_opening = main_committed.open_with_checkpoints(
        &main_refs,
        &main_seed,
        "transition CAIR main checkpoint",
    );
    let product_opening = product_committed.open_with_checkpoints(
        &product_refs,
        &product_opening_seed,
        "transition CAIR product checkpoint",
    );
    Ok(Proof {
        row_count,
        main_opening,
        product_opening,
        local,
        poseidon,
        product,
    })
}

/// Verify one sparse transition in public-input plus polylogarithmic work.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    shape: CircuitShape,
    permutation_commitment: Commitment,
    old_commitment: Commitment,
    new_commitment: Commitment,
    level: usize,
    lower: usize,
    capacity: usize,
    proof: &Proof,
) -> Result<(), Error> {
    let assignment_len = shape.assignment_len;
    if permutation_commitment.len != assignment_len
        || old_commitment.len != assignment_len
        || new_commitment.len != assignment_len
    {
        return Err(Error::AssignmentAuthentication);
    }
    let max_rows = 16usize
        .checked_mul(assignment_len.next_power_of_two())
        .ok_or(Error::TableShape)?;
    if proof.row_count < 2 || !proof.row_count.is_power_of_two() || proof.row_count > max_rows {
        return Err(Error::TableShape);
    }
    let statement = Statement {
        gate_pairs: shape.gate_pairs,
        public_inputs: shape.public_inputs,
        assignment_len,
        height: assignment_len.next_power_of_two().trailing_zeros() as usize,
        permutation: permutation_commitment,
        old_assignment: old_commitment,
        new_assignment: new_commitment,
    };
    let main_layout = MainLayout::new(statement);
    let product_layout = ProductLayout::new(proof.row_count);
    let public_seed = statement_seed(
        shape,
        level,
        lower,
        capacity,
        permutation_commitment,
        old_commitment,
        new_commitment,
        proof.row_count,
        main_layout,
        &proof.main_opening.commitment,
    );
    let routing_challenges =
        RoutingChallenges::derive(&public_seed, &proof.main_opening.commitment);
    let product_seed = commitment_seed(&proof.product_opening.commitment);
    let mut transcript = transition_transcript(&public_seed, &product_seed);

    let local_constraint_count = compact_residuals(
        &vec![Bn254::ZERO; main_layout.compact_width],
        &[Bn254::ZERO; LOCAL_HASH_FIELDS],
        statement,
    )
    .len();
    let local_weights = challenges(&transcript, 0x1000, local_constraint_count);
    let local_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let (local_claim, local_point) = verify_sumcheck(
        &proof.local,
        compact_constraint_degree(statement),
        interpolate,
        product_layout.row_variables,
        LOCAL_ROUND_TAG,
        0x1200,
        &mut transcript,
    )?;
    let poseidon_weights = challenges(&transcript, 0x2000, POSEIDON_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x2100, product_layout.row_variables + 1);
    let (poseidon_claim, poseidon_point) = verify_sumcheck(
        &proof.poseidon,
        POSEIDON_DEGREE,
        poseidon_sumcheck::interpolate,
        product_layout.row_variables + 1,
        POSEIDON_ROUND_TAG,
        0x2200,
        &mut transcript,
    )?;
    let product_weights = challenges(
        &transcript,
        0x3000,
        PRODUCT_BASE_COLUMNS + 2 * product_layout.row_variables,
    );
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let (product_claim, product_point) = verify_sumcheck(
        &proof.product,
        PRODUCT_DEGREE,
        interpolate,
        product_layout.row_variables,
        PRODUCT_ROUND_TAG,
        0x3200,
        &mut transcript,
    )?;

    let main_points = main_opening_points(
        statement,
        main_layout,
        &local_point,
        &poseidon_point,
        &product_point,
    );
    let product_points = product_opening_points(product_layout, &product_point);
    let opening_seed = raw_opening_seed(
        &public_seed,
        &product_seed,
        &proof.local,
        &proof.poseidon,
        &proof.product,
    );
    let main_refs = main_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let product_refs = product_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    verify_mle_opening(
        2 * proof.row_count * main_layout.width,
        &main_refs,
        &proof.main_opening,
        &role_seed(&opening_seed, 1),
    )
    .map_err(whir_error)?;
    verify_mle_opening(
        proof.row_count * product_layout.width,
        &product_refs,
        &proof.product_opening,
        &role_seed(&opening_seed, 2),
    )
    .map_err(whir_error)?;

    let main_values = &proof.main_opening.opening.evaluations;
    let expected_main_values =
        2 * main_layout.compact_width + LOCAL_HASH_FIELDS + POSEIDON_COLUMNS + 1;
    if main_values.len() != expected_main_values {
        return Err(Error::TableShape);
    }
    let mut cursor = 0;
    let local_values = &main_values[cursor..cursor + main_layout.compact_width];
    cursor += main_layout.compact_width;
    let local_hash_values = &main_values[cursor..cursor + LOCAL_HASH_FIELDS];
    cursor += LOCAL_HASH_FIELDS;
    let poseidon_values = &main_values[cursor..cursor + POSEIDON_COLUMNS];
    cursor += POSEIDON_COLUMNS;
    let hash_values = &main_values[cursor..cursor + 1];
    cursor += 1;
    let route_values = &main_values[cursor..cursor + main_layout.compact_width];

    let local_terminal = eq_eval(&local_target, &local_point)
        * combined_local_residual(local_values, local_hash_values, statement, &local_weights);
    if local_terminal != local_claim {
        return Err(Error::Terminal);
    }
    let poseidon_terminal = eq_eval(&poseidon_target, &poseidon_point)
        * combined_poseidon_residual(
            poseidon_values,
            hash_values,
            &poseidon_weights,
            &PoseidonParameters::new(),
        );
    if poseidon_terminal != poseidon_claim {
        return Err(Error::Terminal);
    }

    let product_values = &proof.product_opening.opening.evaluations;
    let expected_product_values =
        product_layout.used_columns + 4 * product_layout.row_variables + 2;
    if product_values.len() != expected_product_values {
        return Err(Error::TableShape);
    }
    let general = &product_values[..product_layout.used_columns];
    let transformed = &product_values[product_layout.used_columns
        ..product_layout.used_columns + 4 * product_layout.row_variables];
    let roots = &product_values[product_values.len() - 2..];
    if roots[0] != roots[1] {
        return Err(Error::ProductMismatch);
    }
    let product_terminal = eq_eval(&product_target, &product_point)
        * combined_product_terminal(
            general,
            transformed,
            route_values,
            &product_point,
            product_layout,
            statement,
            routing_challenges,
            &product_weights,
        );
    if product_terminal != product_claim {
        return Err(Error::Terminal);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn authenticate_trees(
    circuit: &Circuit,
    permutation_tree: &MerkleTree,
    old_tree: &MerkleTree,
    updates: &[(usize, Bn254, Bn254)],
    old_commitment: Commitment,
    new_commitment: Commitment,
) -> Result<(), Error> {
    if old_tree.commitment() != old_commitment {
        return Err(Error::AssignmentAuthentication);
    }
    let expected_permutation = MerkleTree::new(
        circuit
            .permutation
            .iter()
            .copied()
            .map(Bn254::from_usize)
            .collect(),
    )?
    .commitment();
    if permutation_tree.commitment() != expected_permutation {
        return Err(Error::PermutationAuthentication);
    }
    let mut new_tree = old_tree.clone();
    new_tree.update(
        &updates
            .iter()
            .map(|&(index, _, new)| (index, new))
            .collect::<Vec<_>>(),
    )?;
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
    columns: impl Iterator<Item = &'a Vec<Bn254>>,
) -> Vec<Bn254> {
    let columns = columns.collect::<Vec<_>>();
    debug_assert!(columns.len() <= width);
    debug_assert!(columns.iter().all(|column| column.len() == rows));
    let mut table = vec![Bn254::ZERO; rows * width];
    for (column, values) in columns.into_iter().enumerate() {
        for (row, &value) in values.iter().enumerate() {
            table[row * width + column] = value;
        }
    }
    table
}

fn poseidon_trace(hash_inputs: &[Vec<Bn254>; 4]) -> Vec<Vec<Bn254>> {
    let rows = hash_inputs[0].len();
    let parameters = PoseidonParameters::new();
    let mut columns = vec![vec![Bn254::ZERO; rows]; POSEIDON_COLUMNS_PER_HASH];
    for row in 0..rows {
        let input = core::array::from_fn(|word| hash_inputs[word][row]);
        fill_poseidon_row(&mut columns, row, input, &parameters);
    }
    columns
}

fn local_hash_columns(hash_inputs: &[Vec<Bn254>; 4], rows: usize) -> Vec<Vec<Bn254>> {
    let mut columns = vec![vec![Bn254::ZERO; rows]; LOCAL_HASH_FIELDS];
    for side in 0..2 {
        for field in 0..4 {
            for row in 0..rows {
                columns[4 * side + field][row] = hash_inputs[field][2 * row + side];
            }
        }
    }
    columns
}

fn fill_poseidon_row(
    columns: &mut [Vec<Bn254>],
    row: usize,
    input: [Bn254; 3],
    parameters: &PoseidonParameters,
) {
    for word in 0..STATE_WIDTH {
        columns[word][row] = input[word];
    }
    let mut state = input;
    for round in 0..POSEIDON_TRANSITIONS {
        state = poseidon_round(round, state, parameters);
        for word in 0..STATE_WIDTH {
            columns[STATE_WIDTH * (round + 1) + word][row] = state[word];
        }
    }
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
    let powered = core::array::from_fn(|index| fifth(state[index] + constants[index]));
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

fn product_trace(
    rows: usize,
    layout: ProductLayout,
    producers: &[Bn254],
    references: &[Bn254],
) -> Vec<Vec<Bn254>> {
    assert_eq!(producers.len(), ROUTE_LANES * rows);
    assert_eq!(references.len(), ROUTE_LANES * rows);
    let mut columns = vec![vec![Bn254::ZERO; rows]; layout.used_columns];
    for row in 0..rows {
        for lane in 0..ROUTE_LANES {
            columns[lane][row] = producers[ROUTE_LANES * row + lane];
            columns[ROUTE_LANES + lane][row] = references[ROUTE_LANES * row + lane];
        }
        columns[8][row] = columns[0][row] * columns[1][row];
        columns[9][row] = columns[2][row] * columns[3][row];
        columns[10][row] = columns[4][row] * columns[5][row];
        columns[11][row] = columns[6][row] * columns[7][row];
        columns[12][row] = columns[8][row] * columns[9][row];
        columns[13][row] = columns[10][row] * columns[11][row];
    }
    for stage in 0..layout.row_variables {
        let active = rows >> (stage + 1);
        for side in 0..2 {
            let previous = if stage == 0 {
                12 + side
            } else {
                layout.cross_column(stage - 1, side)
            };
            let output = layout.cross_column(stage, side);
            for row in 0..active {
                columns[output][row] = columns[previous][2 * row] * columns[previous][2 * row + 1];
            }
        }
    }
    columns
}

fn cross_work(product: &[Vec<Bn254>], rows: usize, layout: ProductLayout) -> Vec<CrossWork> {
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
            let mut left = vec![Bn254::ZERO; rows];
            let mut right = vec![Bn254::ZERO; rows];
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

fn prove_local_sumcheck(
    mut columns: Vec<Vec<Bn254>>,
    compact_width: usize,
    statement: Statement,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let mut values = vec![Bn254::ZERO; columns.len()];
    let degree = compact_constraint_degree(statement);
    for round in 0..variables {
        let mut evaluations = vec![Bn254::ZERO; degree + 1];
        for (evaluation_index, evaluation) in evaluations.iter_mut().enumerate() {
            let t = Bn254::from_usize(evaluation_index);
            for pair in 0..eq.len() / 2 {
                for (value, column) in values.iter_mut().zip(&columns) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_local_residual(
                        &values[..compact_width],
                        &values[compact_width..],
                        statement,
                        weights,
                    );
            }
        }
        finish_prover_round(
            &evaluations,
            &mut claim,
            &mut point,
            round,
            LOCAL_ROUND_TAG,
            0x1200,
            interpolate,
            transcript,
        )?;
        fold(&mut eq, point[round]);
        for column in &mut columns {
            fold(column, point[round]);
        }
        rounds.push(evaluations);
        checkpoint("local", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
}

fn prove_poseidon_sumcheck(
    mut states: Vec<Vec<Bn254>>,
    mut hashes: Vec<Vec<Bn254>>,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let parameters = PoseidonParameters::new();
    let partial_weights = poseidon_sumcheck::partial_round_weights(weights);
    for round in 0..variables {
        let evaluations = poseidon_sumcheck::sum_pairs(eq.len() / 2, |pair| {
            poseidon_pair_evaluations(
                &states,
                &hashes,
                &eq,
                pair,
                weights,
                &partial_weights,
                &parameters,
            )
        });
        finish_prover_round(
            &evaluations,
            &mut claim,
            &mut point,
            round,
            POSEIDON_ROUND_TAG,
            0x2200,
            poseidon_sumcheck::interpolate,
            transcript,
        )?;
        fold(&mut eq, point[round]);
        for column in states.iter_mut().chain(&mut hashes) {
            fold(column, point[round]);
        }
        rounds.push(evaluations.to_vec());
        checkpoint("Poseidon", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
}

#[allow(clippy::too_many_arguments)]
fn prove_product_sumcheck(
    mut product: Vec<Vec<Bn254>>,
    mut routes: Vec<Vec<Bn254>>,
    mut cross: Vec<CrossWork>,
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let mut product_values = vec![Bn254::ZERO; product.len()];
    let mut route_values = vec![Bn254::ZERO; routes.len()];
    let mut cross_values = vec![[Bn254::ZERO; 2]; cross.len()];
    for round in 0..variables {
        let mut evaluations = vec![Bn254::ZERO; PRODUCT_DEGREE + 1];
        for (evaluation_index, evaluation) in evaluations.iter_mut().enumerate() {
            let t = Bn254::from_usize(evaluation_index);
            for pair in 0..eq.len() / 2 {
                for (value, column) in product_values.iter_mut().zip(&product) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                for (value, column) in route_values.iter_mut().zip(&routes) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                for (value, work) in cross_values.iter_mut().zip(&cross) {
                    *value = [
                        lerp(work.left[2 * pair], work.left[2 * pair + 1], t),
                        lerp(work.right[2 * pair], work.right[2 * pair + 1], t),
                    ];
                }
                *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_product_residual(
                        &product_values,
                        &route_values,
                        &cross_values,
                        &cross,
                        statement,
                        routing,
                        weights,
                    );
            }
        }
        finish_prover_round(
            &evaluations,
            &mut claim,
            &mut point,
            round,
            PRODUCT_ROUND_TAG,
            0x3200,
            interpolate,
            transcript,
        )?;
        fold(&mut eq, point[round]);
        for column in product.iter_mut().chain(&mut routes) {
            fold(column, point[round]);
        }
        for work in &mut cross {
            fold(&mut work.left, point[round]);
            fold(&mut work.right, point[round]);
        }
        rounds.push(evaluations);
        checkpoint("product", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
}

fn poseidon_pair_evaluations(
    states: &[Vec<Bn254>],
    hashes: &[Vec<Bn254>],
    eq: &[Bn254],
    pair: usize,
    weights: &[Bn254],
    partial_weights: &[[Bn254; STATE_WIDTH]; poseidon_sumcheck::PARTIAL_ROUNDS],
    parameters: &PoseidonParameters,
) -> [Bn254; poseidon_sumcheck::EVALUATIONS] {
    debug_assert_eq!(states.len(), POSEIDON_COLUMNS);
    debug_assert_eq!(hashes.len(), 1);
    let left = pair << 1;
    let right = left | 1;
    let eq_values = poseidon_sumcheck::line_evaluations(eq[left], eq[right]);
    let mut residuals = [Bn254::ZERO; poseidon_sumcheck::EVALUATIONS];
    let mut current_zero = core::array::from_fn(|word| states[word][left]);
    let mut current_one = core::array::from_fn(|word| states[word][right]);
    for round in 0..POSEIDON_TRANSITIONS {
        let next_column = STATE_WIDTH * (round + 1);
        let next_zero = core::array::from_fn(|word| states[next_column + word][left]);
        let next_one = core::array::from_fn(|word| states[next_column + word][right]);
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
    let digest_weight = weights[POSEIDON_TRANSITIONS * STATE_WIDTH];
    let digest_residual = poseidon_sumcheck::line_evaluations(
        digest_weight * (current_zero[0] - hashes[0][left]),
        digest_weight * (current_one[0] - hashes[0][right]),
    );
    for evaluation in 0..poseidon_sumcheck::EVALUATIONS {
        residuals[evaluation] += digest_residual[evaluation];
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

#[allow(clippy::too_many_arguments)]
fn finish_prover_round(
    evaluations: &[Bn254],
    claim: &mut Bn254,
    point: &mut Vec<Bn254>,
    round: usize,
    round_tag: u64,
    challenge_base: u64,
    interpolate_round: fn(&[Bn254], Bn254) -> Bn254,
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

fn combined_local_residual(
    values: &[Bn254],
    hashes: &[Bn254],
    statement: Statement,
    weights: &[Bn254],
) -> Bn254 {
    compact_residuals(values, hashes, statement)
        .into_iter()
        .zip(weights)
        .fold(Bn254::ZERO, |sum, (residual, &weight)| {
            sum + weight * residual
        })
}

fn combined_poseidon_residual(
    states: &[Bn254],
    hashes: &[Bn254],
    weights: &[Bn254],
    parameters: &PoseidonParameters,
) -> Bn254 {
    let mut result = Bn254::ZERO;
    let mut weight = 0;
    debug_assert_eq!(states.len(), POSEIDON_COLUMNS);
    debug_assert_eq!(hashes.len(), 1);
    for round in 0..POSEIDON_TRANSITIONS {
        let current = [
            states[3 * round],
            states[3 * round + 1],
            states[3 * round + 2],
        ];
        let expected = poseidon_round(round, current, parameters);
        for word in 0..STATE_WIDTH {
            result += weights[weight] * (states[3 * (round + 1) + word] - expected[word]);
            weight += 1;
        }
    }
    result += weights[weight] * (states[POSEIDON_COLUMNS_PER_HASH - STATE_WIDTH] - hashes[0]);
    weight += 1;
    debug_assert_eq!(weight, weights.len());
    result
}

fn combined_product_residual(
    product: &[Bn254],
    compact: &[Bn254],
    cross_values: &[[Bn254; 2]],
    cross: &[CrossWork],
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[Bn254],
) -> Bn254 {
    let routes = compact_route_values(compact, statement);
    let mut result = Bn254::ZERO;
    for side in 0..2 {
        for lane in 0..ROUTE_LANES {
            let tuple_offset = side * ROUTE_LANES * TUPLE_WIDTH + lane * TUPLE_WIDTH;
            let fields: [Bn254; TUPLE_WIDTH] = routes[tuple_offset..tuple_offset + TUPLE_WIDTH]
                .try_into()
                .expect("tuple width is fixed");
            let factor = routing.gamma + compress_fields(fields, routing.theta);
            result +=
                weights[side * ROUTE_LANES + lane] * (product[side * ROUTE_LANES + lane] - factor);
        }
    }
    let pair_residuals = [
        product[8] - product[0] * product[1],
        product[9] - product[2] * product[3],
        product[10] - product[4] * product[5],
        product[11] - product[6] * product[7],
        product[12] - product[8] * product[9],
        product[13] - product[10] * product[11],
    ];
    for (index, residual) in pair_residuals.into_iter().enumerate() {
        result += weights[8 + index] * residual;
    }
    for (index, (values, work)) in cross_values.iter().zip(cross).enumerate() {
        result += weights[PRODUCT_BASE_COLUMNS + index]
            * (product[work.output_column] - values[0] * values[1]);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn combined_product_terminal(
    product: &[Bn254],
    transformed: &[Bn254],
    compact: &[Bn254],
    point: &[Bn254],
    layout: ProductLayout,
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[Bn254],
) -> Bn254 {
    let mut cross_values = Vec::with_capacity(2 * layout.row_variables);
    let mut cursor = 0;
    for stage in 0..layout.row_variables {
        let low_variables = layout.row_variables - stage - 1;
        let selector = (low_variables..layout.row_variables)
            .fold(Bn254::ONE, |value, bit| value * (Bn254::ONE - point[bit]));
        for _side in 0..2 {
            cross_values.push([
                selector * transformed[cursor],
                selector * transformed[cursor + 1],
            ]);
            cursor += 2;
        }
    }
    let cross_meta = (0..layout.row_variables)
        .flat_map(|stage| {
            (0..2).map(move |side| CrossWork {
                output_column: layout.cross_column(stage, side),
                left: Vec::new(),
                right: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    combined_product_residual(
        product,
        compact,
        &cross_values,
        &cross_meta,
        statement,
        routing,
        weights,
    )
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

fn main_opening_points(
    statement: Statement,
    layout: MainLayout,
    local_point: &[Bn254],
    poseidon_point: &[Bn254],
    product_point: &[Bn254],
) -> Vec<Vec<Bn254>> {
    debug_assert_eq!(layout.compact_width, compact_column_count(statement));
    let mut points =
        Vec::with_capacity(2 * layout.compact_width + LOCAL_HASH_FIELDS + POSEIDON_COLUMNS + 1);
    let local_sparse_point = padded_sparse_point(local_point);
    for column in 0..layout.compact_width {
        points.push(table_point(column, &local_sparse_point, layout.width));
    }

    for side in [Bn254::ZERO, Bn254::ONE] {
        let mut hash_point = Vec::with_capacity(local_point.len() + 1);
        hash_point.push(side);
        hash_point.extend_from_slice(local_point);
        for field in 0..4 {
            let column = if field < STATE_WIDTH {
                layout.poseidon_column(field)
            } else {
                layout.digest_column()
            };
            points.push(table_point(column, &hash_point, layout.width));
        }
    }

    for state_column in 0..POSEIDON_COLUMNS_PER_HASH {
        points.push(table_point(
            layout.poseidon_column(state_column),
            poseidon_point,
            layout.width,
        ));
    }
    points.push(table_point(
        layout.digest_column(),
        poseidon_point,
        layout.width,
    ));

    let product_sparse_point = padded_sparse_point(product_point);
    for column in 0..layout.compact_width {
        points.push(table_point(column, &product_sparse_point, layout.width));
    }
    points
}

fn padded_sparse_point(point: &[Bn254]) -> Vec<Bn254> {
    let mut padded = Vec::with_capacity(point.len() + 1);
    padded.extend_from_slice(point);
    padded.push(Bn254::ZERO);
    padded
}

fn product_opening_points(layout: ProductLayout, point: &[Bn254]) -> Vec<Vec<Bn254>> {
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
            for bit_value in [Bn254::ZERO, Bn254::ONE] {
                let mut transformed = vec![Bn254::ZERO; layout.row_variables];
                transformed[0] = bit_value;
                if low_variables > 0 {
                    transformed[1..=low_variables].copy_from_slice(&point[..low_variables]);
                }
                points.push(table_point(previous, &transformed, layout.width));
            }
        }
    }
    let zero = vec![Bn254::ZERO; layout.row_variables];
    points.push(table_point(layout.root_column(0), &zero, layout.width));
    points.push(table_point(layout.root_column(1), &zero, layout.width));
    points
}

fn table_point(column: usize, row_point: &[Bn254], width: usize) -> Vec<Bn254> {
    let mut point = (0..width.trailing_zeros() as usize)
        .map(|bit| Bn254::from_bool(column & (1 << bit) != 0))
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
) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(TRANSITION_VERSION),
        Bn254::from_usize(shape.gate_pairs),
        Bn254::from_usize(shape.public_inputs),
        Bn254::from_usize(shape.assignment_len),
        Bn254::from_usize(level),
        Bn254::from_usize(lower),
        Bn254::from_usize(capacity),
        Bn254::from_usize(row_count),
        Bn254::from_usize(layout.compact_width),
        Bn254::from_usize(layout.width),
        Bn254::from_usize(permutation.len),
        permutation.root,
        old.root,
        new.root,
    ];
    seed.extend(commitment_seed(table));
    seed
}

fn transition_transcript(public_seed: &[Bn254], product_seed: &[Bn254]) -> RawTranscript {
    let mut transcript = RawTranscript::new(TRANSCRIPT_DOMAIN);
    transcript.absorb_message(1, public_seed);
    transcript.absorb_message(2, product_seed);
    transcript
}

fn challenges(transcript: &RawTranscript, base: u64, count: usize) -> Vec<Bn254> {
    (0..count)
        .map(|index| transcript.challenge(base + index as u64))
        .collect()
}

fn raw_opening_seed(
    public_seed: &[Bn254],
    product_seed: &[Bn254],
    local: &SumcheckProof,
    poseidon: &SumcheckProof,
    product: &SumcheckProof,
) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(TRANSCRIPT_DOMAIN),
        Bn254::from_usize(public_seed.len()),
    ];
    seed.extend_from_slice(public_seed);
    seed.push(Bn254::from_usize(product_seed.len()));
    seed.extend_from_slice(product_seed);
    for proof in [local, poseidon, product] {
        seed.push(Bn254::from_usize(proof.rounds.len()));
        for round in &proof.rounds {
            seed.push(Bn254::from_usize(round.len()));
            seed.extend_from_slice(round);
        }
    }
    seed
}

fn role_seed(seed: &[Bn254], role: u64) -> Vec<Bn254> {
    let mut result = Vec::with_capacity(seed.len() + 1);
    result.push(Bn254::from_u64(role));
    result.extend_from_slice(seed);
    result
}

fn eq_evaluations(point: &[Bn254]) -> Vec<Bn254> {
    let mut values = vec![Bn254::ONE];
    for &coordinate in point.iter().rev() {
        let mut next = Vec::with_capacity(values.len() * 2);
        for &value in &values {
            next.push(value * (Bn254::ONE - coordinate));
            next.push(value * coordinate);
        }
        values = next;
    }
    values
}

fn eq_eval(left: &[Bn254], right: &[Bn254]) -> Bn254 {
    left.iter()
        .zip(right)
        .fold(Bn254::ONE, |product, (&left, &right)| {
            product * (left * right + (Bn254::ONE - left) * (Bn254::ONE - right))
        })
}

fn fold(values: &mut Vec<Bn254>, challenge: Bn254) {
    for index in 0..values.len() / 2 {
        values[index] = lerp(values[2 * index], values[2 * index + 1], challenge);
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

fn whir_error(error: impl std::fmt::Display) -> Error {
    Error::Whir(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        Circuit,
        MerkleTree,
        MerkleTree,
        MerkleTree,
        Vec<(usize, Bn254, Bn254)>,
    ) {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let permutation = MerkleTree::new((0..7).map(Bn254::from_usize).collect()).unwrap();
        let old_values = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let old = MerkleTree::new(old_values).unwrap();
        let mut new = old.clone();
        new.update(&[
            (0, Bn254::from_u64(5)),
            (1, Bn254::from_u64(6)),
            (2, Bn254::from_u64(11)),
        ])
        .unwrap();
        let updates = [0usize, 1, 2]
            .map(|index| (index, old.values()[index], new.values()[index]))
            .to_vec();
        (circuit, permutation, old, new, updates)
    }

    #[test]
    fn transition_cair_round_trip_and_tamper_rejection() {
        let (circuit, permutation, old, new, updates) = fixture();
        let mut proof = prove(
            &circuit,
            &permutation,
            &old,
            2,
            2,
            3,
            &updates,
            old.commitment(),
            new.commitment(),
        )
        .unwrap();
        let verify_proof = |proof: &Proof| {
            verify(
                CircuitShape::from_circuit(&circuit),
                permutation.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                proof,
            )
        };
        verify_proof(&proof).unwrap();

        proof.local.rounds[0][0] += Bn254::ONE;
        assert!(verify_proof(&proof).is_err());
        proof.local.rounds[0][0] -= Bn254::ONE;
        proof.main_opening.opening.evaluations[0] += Bn254::ONE;
        assert!(verify_proof(&proof).is_err());
    }
}
