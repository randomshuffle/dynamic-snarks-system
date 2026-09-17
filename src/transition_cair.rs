//! Commit-all-intermediate-rounds proof for one sparse transition.
//!
//! The main commitment contains the universal sparse-DAG row assignment and
//! one 64-column scalar Poseidon2 trace over both old/new hash lanes.  The
//! partial-round recurrence and four batched full-round reductions replace
//! the former 195-state trace.  Row-batched sumchecks check the local relation,
//! Poseidon execution, and routing multiset product.  The
//! product tree is committed in a second phase because its leaves depend on
//! Fiat--Shamir tuple-compression challenges sampled after the main table is
//! bound.  Each commitment has exactly one batched WHIR opening proof.

use p3_maybe_rayon::prelude::*;
use std::time::Instant;

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::circuit::{Circuit, CircuitError};
use crate::merkle::{Commitment, MerkleError, MerkleTree};
use crate::multiset::{RoutingChallenges, compress_fields};
use crate::poseidon_scalar::{
    self, DIGEST_COLUMN, FullRoundClaims, FullRoundProof, INPUT_0_COLUMN, INPUT_1_COLUMN,
    PARTIAL_CONSTRAINTS, SCALAR_COLUMNS, SUMCHECK_DEGREE, Trace,
};
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

#[cfg(feature = "compact-merkle")]
pub(crate) mod packed;
#[cfg(feature = "poseidon-gkr")]
pub(crate) mod round_reduction;

const TRANSITION_VERSION: u64 = 9;
const TRANSCRIPT_DOMAIN: u64 = 0x4341_4952_5452_414e;
const COLUMN_BATCH_DOMAIN: u64 = 0x4341_4952_5452_4342;
const LOCAL_ROUND_TAG: u64 = 0x4341_4952_4c43_4c52;
const POSEIDON_ROUND_TAG: u64 = 0x4341_4952_5053_5252;
const PRODUCT_ROUND_TAG: u64 = 0x4341_4952_5052_5252;
const PRODUCT_DEGREE: usize = 4;
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
    full_rounds: FullRoundProof,
    poseidon_batch_values: Vec<Bn254>,
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

    const fn poseidon_column(self, scalar_column: usize) -> usize {
        self.compact_width + scalar_column
    }

    const fn input_domain_column(self) -> usize {
        self.compact_width + SCALAR_COLUMNS
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
    new_tree: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, Bn254, Bn254)],
    old_commitment: Commitment,
    new_commitment: Commitment,
) -> Result<Proof, Error> {
    let phase = Instant::now();
    validate_level_size(updates.len(), lower, capacity)?;
    authenticate_roots(old_tree, new_tree, old_commitment, new_commitment)?;
    profile_checkpoint("transition CAIR: statement/tree authentication", phase);
    let phase = Instant::now();
    let table = TransitionTable::build(circuit, permutation_tree, old_tree, new_tree, updates)?;
    profile_checkpoint("transition CAIR: sparse DAG/table construction", phase);
    let row_count = table.row_count();
    let statement = table.statement();
    let main_layout = MainLayout::new(statement);
    eprintln!(
        "transition CAIR shape: updated_positions={}, level={level}, rows={row_count}, main_width={}, product_width={}",
        updates.len(),
        main_layout.width,
        ProductLayout::new(row_count).width,
    );
    let phase = Instant::now();
    let compact = table.compact_witness();
    profile_checkpoint("transition CAIR: compact witness columns", phase);
    let phase = Instant::now();
    let scalar_trace = Trace::new([
        compact.hash_inputs[0].clone(),
        compact.hash_inputs[1].clone(),
        compact.hash_inputs[2].clone(),
    ])
    .map_err(|_| Error::TableShape)?;
    if scalar_trace.columns[DIGEST_COLUMN] != compact.hash_inputs[3] {
        return Err(Error::AssignmentAuthentication);
    }
    profile_checkpoint("transition CAIR: Poseidon round trace", phase);
    let mut committed_compact = crate::parallel::clone_columns(&compact.columns);
    for column in &mut committed_compact {
        column.resize(2 * row_count, Bn254::ZERO);
    }
    let phase = Instant::now();
    let main_table = pack_columns(
        2 * row_count,
        main_layout.width,
        committed_compact
            .iter()
            .chain(&scalar_trace.columns)
            .chain(std::iter::once(&scalar_trace.input_2)),
    );
    profile_checkpoint("transition CAIR: packed main table", phase);
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
    let phase = Instant::now();
    let factors = table.product_factors(routing_challenges);
    factors.verify().map_err(|_| Error::ProductMismatch)?;
    profile_checkpoint("transition CAIR: routing product factors", phase);
    let product_layout = ProductLayout::new(row_count);
    let phase = Instant::now();
    let product_columns = product_trace(
        row_count,
        product_layout,
        &factors.producers,
        &factors.references,
    );
    profile_checkpoint("transition CAIR: product-tree trace", phase);
    let phase = Instant::now();
    let product_table = pack_columns(row_count, product_layout.width, product_columns.iter());
    profile_checkpoint("transition CAIR: packed product table", phase);
    let commitment_started = Instant::now();
    let product_committed = commit_mle(product_table).map_err(whir_error)?;
    eprintln!(
        "transition CAIR checkpoint: product commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );

    let product_seed = commitment_seed(product_committed.commitment());
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let phase = Instant::now();
    let local_constraint_count = compact_residuals(
        &vec![Bn254::ZERO; main_layout.compact_width],
        &[Bn254::ZERO; LOCAL_HASH_FIELDS],
        statement,
    )
    .len();
    let local_weights = challenges(&transcript, 0x1000, local_constraint_count);
    let local_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let local_hash_columns = local_hash_columns(&compact.hash_inputs, row_count);
    let local_columns = compact
        .columns
        .clone()
        .into_iter()
        .chain(local_hash_columns)
        .collect();
    profile_checkpoint("transition CAIR: local sumcheck preparation", phase);
    let phase = Instant::now();
    let (local, local_point) = prove_local_sumcheck(
        local_columns,
        main_layout.compact_width,
        statement,
        &local_weights,
        &local_target,
        &mut transcript,
    )?;
    profile_checkpoint("transition CAIR: local sumcheck total", phase);

    let phase = Instant::now();
    let poseidon_weights = challenges(&transcript, 0x2000, PARTIAL_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x2100, product_layout.row_variables + 1);
    profile_checkpoint("transition CAIR: Poseidon sumcheck preparation", phase);
    let phase = Instant::now();
    let (poseidon, poseidon_point, poseidon_terminal_values) = prove_poseidon_sumcheck(
        crate::parallel::clone_columns(&scalar_trace.columns),
        &poseidon_weights,
        &poseidon_target,
        &mut transcript,
    )?;
    profile_checkpoint("transition CAIR: Poseidon sumcheck total", phase);
    let phase = Instant::now();
    let (full_rounds, full_round_claims) = scalar_trace
        .prove_full_rounds(&mut transcript, "transition CAIR checkpoint")
        .map_err(|_| Error::Sumcheck)?;
    profile_checkpoint("transition CAIR: full-round reductions", phase);

    let phase = Instant::now();
    let product_weights = challenges(
        &transcript,
        0x3000,
        PRODUCT_BASE_COLUMNS + 2 * product_layout.row_variables,
    );
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let route_columns = crate::parallel::clone_columns(&compact.columns);
    let cross_work = cross_work(&product_columns, row_count, product_layout);
    profile_checkpoint("transition CAIR: product sumcheck preparation", phase);
    let phase = Instant::now();
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
    profile_checkpoint("transition CAIR: product sumcheck total", phase);

    let phase = Instant::now();
    let mut poseidon_batch_values = evaluate_columns(committed_compact, &poseidon_point);
    poseidon_batch_values.extend(poseidon_terminal_values);
    poseidon_batch_values
        .push(evaluate_columns(vec![scalar_trace.input_2.clone()], &poseidon_point)[0]);
    let base_opening_seed = raw_opening_seed(
        &public_seed,
        &product_seed,
        &local,
        &poseidon,
        &full_rounds,
        &product,
    );
    let opening_seed = column_batch_seed(&base_opening_seed, &poseidon_batch_values);
    let column_point =
        column_batch_point(&opening_seed, main_layout.width.trailing_zeros() as usize);
    let main_points = main_opening_points(
        statement,
        main_layout,
        &local_point,
        &column_point,
        &poseidon_point,
        &product_point,
        &full_round_claims,
    );
    let product_points = product_opening_points(product_layout, &product_point);
    let main_seed = role_seed(&opening_seed, 1);
    let product_opening_seed = role_seed(&opening_seed, 2);
    let main_refs = main_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let product_refs = product_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    profile_checkpoint("transition CAIR: opening preparation", phase);
    let (main_opening, product_opening) = join(
        || {
            main_committed.open_with_checkpoints(
                &main_refs,
                &main_seed,
                "transition CAIR main checkpoint",
            )
        },
        || {
            product_committed.open_with_checkpoints(
                &product_refs,
                &product_opening_seed,
                "transition CAIR product checkpoint",
            )
        },
    );
    Ok(Proof {
        row_count,
        main_opening,
        product_opening,
        local,
        poseidon,
        full_rounds,
        poseidon_batch_values,
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
    let physical_len = shape.assignment_tree_len();
    if permutation_commitment.len != physical_len
        || old_commitment.len != physical_len
        || new_commitment.len != physical_len
    {
        return Err(Error::AssignmentAuthentication);
    }
    let max_rows = 16usize.checked_mul(physical_len).ok_or(Error::TableShape)?;
    if proof.row_count < 2 || !proof.row_count.is_power_of_two() || proof.row_count > max_rows {
        return Err(Error::TableShape);
    }
    let statement = Statement {
        gate_pairs: shape.gate_pairs,
        public_inputs: shape.public_inputs,
        assignment_len,
        height: physical_len.trailing_zeros() as usize,
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
    let poseidon_weights = challenges(&transcript, 0x2000, PARTIAL_CONSTRAINTS);
    let poseidon_target = challenges(&transcript, 0x2100, product_layout.row_variables + 1);
    let (poseidon_claim, poseidon_point) = verify_sumcheck(
        &proof.poseidon,
        SUMCHECK_DEGREE,
        poseidon_sumcheck::interpolate,
        product_layout.row_variables + 1,
        POSEIDON_ROUND_TAG,
        0x2200,
        &mut transcript,
    )?;
    let full_round_claims = poseidon_scalar::verify_full_rounds(
        &proof.full_rounds,
        product_layout.row_variables + 1,
        &mut transcript,
    )
    .map_err(|_| Error::Sumcheck)?;
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

    let used_main_columns = main_layout.input_domain_column() + 1;
    if proof.poseidon_batch_values.len() != used_main_columns {
        return Err(Error::TableShape);
    }
    let base_opening_seed = raw_opening_seed(
        &public_seed,
        &product_seed,
        &proof.local,
        &proof.poseidon,
        &proof.full_rounds,
        &proof.product,
    );
    let opening_seed = column_batch_seed(&base_opening_seed, &proof.poseidon_batch_values);
    let column_point =
        column_batch_point(&opening_seed, main_layout.width.trailing_zeros() as usize);
    let main_points = main_opening_points(
        statement,
        main_layout,
        &local_point,
        &column_point,
        &poseidon_point,
        &product_point,
        &full_round_claims,
    );
    let product_points = product_opening_points(product_layout, &product_point);
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
    let expected_main_values = 2 * main_layout.compact_width + LOCAL_HASH_FIELDS + 11;
    if main_values.len() != expected_main_values {
        return Err(Error::TableShape);
    }
    let mut cursor = 0;
    let local_values = &main_values[cursor..cursor + main_layout.compact_width];
    cursor += main_layout.compact_width;
    let local_hash_values = &main_values[cursor..cursor + LOCAL_HASH_FIELDS];
    cursor += LOCAL_HASH_FIELDS;
    let batched_value = main_values[cursor];
    cursor += 1;
    let route_values = &main_values[cursor..cursor + main_layout.compact_width];
    cursor += main_layout.compact_width;
    let full_round_values = &main_values[cursor..];

    let column_weights = eq_evaluations(&column_point);
    let expected_batch = proof
        .poseidon_batch_values
        .iter()
        .zip(&column_weights)
        .fold(Bn254::ZERO, |sum, (&value, &weight)| sum + value * weight);
    if batched_value != expected_batch {
        return Err(Error::Terminal);
    }
    let poseidon_start = main_layout.compact_width;
    let poseidon_values =
        &proof.poseidon_batch_values[poseidon_start..poseidon_start + SCALAR_COLUMNS];

    let local_terminal = eq_eval(&local_target, &local_point)
        * combined_local_residual(local_values, local_hash_values, statement, &local_weights);
    if local_terminal != local_claim {
        return Err(Error::Terminal);
    }
    let poseidon_terminal = eq_eval(&poseidon_target, &poseidon_point)
        * combined_poseidon_residual(poseidon_values, &poseidon_weights);
    if poseidon_terminal != poseidon_claim {
        return Err(Error::Terminal);
    }
    verify_full_round_openings(full_round_values, &full_round_claims)?;

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
    columns: impl Iterator<Item = &'a Vec<Bn254>>,
) -> Vec<Bn254> {
    let columns = columns.map(|column| column.as_slice()).collect::<Vec<_>>();
    crate::parallel::pack_columns(rows, width, &columns)
}

fn local_hash_columns(hash_inputs: &[Vec<Bn254>; 4], rows: usize) -> Vec<Vec<Bn254>> {
    (0..LOCAL_HASH_FIELDS)
        .into_par_iter()
        .map(|column| {
            let side = column / 4;
            let field = column % 4;
            (0..rows)
                .into_par_iter()
                .map(|row| hash_inputs[field][2 * row + side])
                .collect()
        })
        .collect()
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
    let degree = compact_constraint_degree(statement);
    for round in 0..variables {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            degree + 1,
            (degree + 1) * columns.len(),
            || {
                (
                    vec![Bn254::ZERO; columns.len()],
                    Vec::with_capacity(weights.len()),
                )
            },
            |scratch, pair, t| {
                let (values, residuals) = scratch;

                for (value, column) in values.iter_mut().zip(&columns) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                lerp(eq[2 * pair], eq[2 * pair + 1], t) * {
                    crate::transition_relation::compact_residuals_into(
                        &values[..compact_width],
                        &values[compact_width..],
                        statement,
                        residuals,
                    );
                    residuals
                        .iter()
                        .zip(weights)
                        .fold(Bn254::ZERO, |sum, (&residual, &weight)| {
                            sum + weight * residual
                        })
                }
            },
        );
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
        crate::parallel::fold_columns(&mut columns, point[round]);
        rounds.push(evaluations);
        checkpoint("local", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
}

fn prove_poseidon_sumcheck(
    mut states: Vec<Vec<Bn254>>,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>, Vec<Bn254>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    let weights = poseidon_scalar::PartialWeights::new(weights);
    for round in 0..variables {
        let evaluations = poseidon_sumcheck::sum_pairs(eq.len() / 2, |pair| {
            poseidon_scalar::partial_pair_evaluations(&states, &eq, pair, &weights)
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
        crate::parallel::fold_columns(&mut states, point[round]);
        rounds.push(evaluations.to_vec());
        checkpoint("Poseidon", round, variables, started);
    }
    let terminal_values = states.iter().map(|column| column[0]).collect();
    Ok((SumcheckProof { rounds }, point, terminal_values))
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
    for round in 0..variables {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            PRODUCT_DEGREE + 1,
            (PRODUCT_DEGREE + 1) * (product.len() + routes.len() + 2 * cross.len()),
            || {
                (
                    vec![Bn254::ZERO; product.len()],
                    vec![Bn254::ZERO; routes.len()],
                    vec![[Bn254::ZERO; 2]; cross.len()],
                )
            },
            |scratch, pair, t| {
                let (product_values, route_values, cross_values) = scratch;

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
                lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_product_residual(
                        &product_values,
                        &route_values,
                        &cross_values,
                        &cross,
                        statement,
                        routing,
                        weights,
                    )
            },
        );
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
        product
            .par_iter_mut()
            .chain(routes.par_iter_mut())
            .for_each(|column| fold(column, point[round]));
        cross.par_iter_mut().for_each(|work| {
            fold(&mut work.left, point[round]);
            fold(&mut work.right, point[round]);
        });
        rounds.push(evaluations);
        checkpoint("product", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
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

fn profile_checkpoint(label: &str, started: Instant) {
    if std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some() {
        eprintln!(
            "profile checkpoint: {label} complete in {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
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

fn combined_poseidon_residual(states: &[Bn254], weights: &[Bn254]) -> Bn254 {
    poseidon_scalar::combined_partial_residual(states, weights)
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
    column_point: &[Bn254],
    poseidon_point: &[Bn254],
    product_point: &[Bn254],
    full_rounds: &FullRoundClaims,
) -> Vec<Vec<Bn254>> {
    debug_assert_eq!(layout.compact_width, compact_column_count(statement));
    debug_assert_eq!(column_point.len(), layout.width.trailing_zeros() as usize);
    let mut points = Vec::with_capacity(2 * layout.compact_width + LOCAL_HASH_FIELDS + 11);
    let local_sparse_point = padded_sparse_point(local_point);
    for column in 0..layout.compact_width {
        points.push(table_point(column, &local_sparse_point, layout.width));
    }

    for side in [Bn254::ZERO, Bn254::ONE] {
        let mut hash_point = Vec::with_capacity(local_point.len() + 1);
        hash_point.push(side);
        hash_point.extend_from_slice(local_point);
        for field in 0..4 {
            let column = match field {
                0 => layout.poseidon_column(INPUT_0_COLUMN),
                1 => layout.poseidon_column(INPUT_1_COLUMN),
                2 => layout.input_domain_column(),
                3 => layout.poseidon_column(DIGEST_COLUMN),
                _ => unreachable!(),
            };
            points.push(table_point(column, &hash_point, layout.width));
        }
    }

    let mut poseidon_batch = column_point.to_vec();
    poseidon_batch.extend_from_slice(poseidon_point);
    points.push(poseidon_batch);

    let product_sparse_point = padded_sparse_point(product_point);
    for column in 0..layout.compact_width {
        points.push(table_point(column, &product_sparse_point, layout.width));
    }
    append_full_round_opening_points(&mut points, layout, full_rounds);
    points
}

fn append_full_round_opening_points(
    points: &mut Vec<Vec<Bn254>>,
    layout: MainLayout,
    claims: &FullRoundClaims,
) {
    for column in [
        0,
        poseidon_scalar::START_B_COLUMN,
        poseidon_scalar::START_C_COLUMN,
    ] {
        points.push(table_point(
            layout.poseidon_column(column),
            &claims.initial_output_point,
            layout.width,
        ));
    }
    points.push(table_point(
        layout.poseidon_column(DIGEST_COLUMN),
        &claims.terminal_output_point,
        layout.width,
    ));
    for column in [
        layout.poseidon_column(INPUT_0_COLUMN),
        layout.poseidon_column(INPUT_1_COLUMN),
        layout.input_domain_column(),
    ] {
        points.push(table_point(column, &claims.input_point, layout.width));
    }
    for column in [
        poseidon_scalar::PARTIAL_STATES - 1,
        poseidon_scalar::END_B_COLUMN,
        poseidon_scalar::END_C_COLUMN,
    ] {
        points.push(table_point(
            layout.poseidon_column(column),
            &claims.input_point,
            layout.width,
        ));
    }
}

fn verify_full_round_openings(values: &[Bn254], claims: &FullRoundClaims) -> Result<(), Error> {
    if values.len() != 10
        || values[..3] != claims.initial_output
        || values[3] != claims.terminal_digest
        || values[4..7] != claims.initial_input
        || values[7..10] != claims.terminal_input
    {
        return Err(Error::Terminal);
    }
    Ok(())
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
    full_rounds: &FullRoundProof,
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

fn role_seed(seed: &[Bn254], role: u64) -> Vec<Bn254> {
    let mut result = Vec::with_capacity(seed.len() + 1);
    result.push(Bn254::from_u64(role));
    result.extend_from_slice(seed);
    result
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

fn evaluate_columns(mut columns: Vec<Vec<Bn254>>, point: &[Bn254]) -> Vec<Bn254> {
    for &challenge in point {
        crate::parallel::fold_columns(&mut columns, challenge);
    }
    columns.into_iter().map(|column| column[0]).collect()
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

    pub(super) fn fixture() -> (
        Circuit,
        MerkleTree,
        MerkleTree,
        MerkleTree,
        Vec<(usize, Bn254, Bn254)>,
    ) {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let permutation = MerkleTree::new(
            circuit
                .encoded_permutation()
                .into_iter()
                .map(Bn254::from_usize)
                .collect(),
        )
        .unwrap();
        let old_values = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let old = MerkleTree::new(circuit.encode_assignment(&old_values)).unwrap();
        let mut new = old.clone();
        new.update(&[
            (0, Bn254::from_u64(5)),
            (1, Bn254::from_u64(6)),
            (2, Bn254::from_u64(11)),
        ])
        .unwrap();
        let updates = [0usize, 1, 2]
            .map(|index| (index, old.value(index).unwrap(), new.value(index).unwrap()))
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
            &new,
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
        proof.main_opening.opening.evaluations[0] -= Bn254::ONE;
        proof.poseidon_batch_values[0] += Bn254::ONE;
        assert!(verify_proof(&proof).is_err());
        proof.poseidon_batch_values[0] -= Bn254::ONE;
        proof.full_rounds.tamper_for_test();
        assert!(verify_proof(&proof).is_err());
    }

    #[test]
    fn indexed_permutation_commitment_rejects_a_substituted_prover_tree() {
        let (circuit, permutation, old, new, updates) = fixture();
        let mut wrong_values = (0..circuit.assignment_tree_len())
            .map(Bn254::from_usize)
            .collect::<Vec<_>>();
        // Preserve every permutation leaf opened by this update while changing
        // an unopened subtree and therefore the indexed root.
        wrong_values.swap(4, 5);
        let wrong_permutation = MerkleTree::new(wrong_values).unwrap();
        let proof = prove(
            &circuit,
            &wrong_permutation,
            &old,
            &new,
            2,
            2,
            3,
            &updates,
            old.commitment(),
            new.commitment(),
        )
        .unwrap();

        assert!(
            verify(
                CircuitShape::from_circuit(&circuit),
                permutation.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                &proof,
            )
            .is_err()
        );
    }
}
