//! Section 4 hierarchical dynamic-SNARK compiler.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::mem::size_of;
use thiserror::Error;

use crate::cair::{self, Proof as CairProof};
use crate::circuit::{Circuit, CircuitError};
use crate::merkle::{Commitment, MerkleError, MerkleTree, MultiProof, verify as verify_merkle};
use crate::static_snark::{
    ConstraintProgram, ExtraMainOpenings, ProgramBuilder, Proof as StaticProof,
    ProvingKey as StaticProvingKey, VerifyingKey as StaticVerifyingKey, commitment_seed,
    main_column_point, prove_with_main_openings, setup as static_setup, verify_with_main_openings,
};
use crate::transition_cair::{self, Proof as TransitionProof};
use crate::transition_relation::estimate_shape as estimate_transition_shape;
use crate::wiring::{ProverWiringIndex, VerifierWiringIndex, preprocess as preprocess_wiring};

pub(crate) mod gadgets;

/// Indexed dynamic proving key and retained permutation tree.
pub struct ProvingKey {
    circuit: Circuit,
    wiring: ProverWiringIndex,
    initial: StaticProvingKey,
}

/// Indexed dynamic verification key.
pub struct VerifyingKey {
    wiring: VerifierWiringIndex,
    initial: StaticVerifyingKey,
}

/// Current dynamic proof object from Figure 3 of Section 4.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    commitments: Vec<Commitment>,
    initial_proof: StaticProof,
    initial_cair: CairProof,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
}

/// Prover auxiliary state, including hierarchical update witness tables.
#[derive(Clone)]
pub struct State {
    base_assignment: Vec<Bn254>,
    current_assignment: Vec<Bn254>,
    tables: Vec<Option<UpdateTable>>,
    proof: Proof,
}

/// Prover state for timing transition proofs without constructing the excluded
/// initial static/CAIR proof.
///
/// The base assignment is checked natively and its Merkle commitment is treated
/// as trusted.  Every subsequent hierarchy transition and final public-input
/// opening is identical to the production dynamic prover.  This type is only a
/// benchmark harness: it is not a replacement for [`State`] in a sound protocol.
#[derive(Clone)]
pub struct TransitionBenchmarkState {
    base_assignment: Vec<Bn254>,
    current_assignment: Vec<Bn254>,
    tables: Vec<Option<UpdateTable>>,
    commitments: Vec<Commitment>,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
}

#[derive(Clone)]
struct UpdateEntry {
    index: usize,
    old: Bn254,
    new: Bn254,
}

#[derive(Clone)]
struct UpdateTable {
    entries: Vec<UpdateEntry>,
}

/// Dynamic indexing, proving, or verification failure.
#[derive(Debug, Error)]
pub enum Error {
    /// The circuit or assignment violates its arithmetic relation.
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    /// A Poseidon2 Merkle commitment or opening is invalid.
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    /// A static WHIR-backed proof failed.
    #[error("static SNARK: {0}")]
    Static(String),
    /// The commit-all-intermediate-rounds initial proof failed.
    #[error("initial Merkle CAIR: {0}")]
    Cair(String),
    /// A sparse transition CAIR proof or its WHIR openings failed.
    #[error("transition CAIR: {0}")]
    Transition(String),
    /// Update indices must be strictly increasing and unique.
    #[error("update indices must be strictly increasing")]
    NonCanonicalUpdate,
    /// At least one position must be updated.
    #[error("an update must contain at least one position")]
    EmptyUpdate,
    /// A requested update-table size lies outside the assignment vector.
    #[error("update-table size {size} is outside 1..={assignment_len}")]
    UpdateSizeOutOfRange {
        /// Number of assignment positions in the update table.
        size: usize,
        /// Length of the committed assignment vector.
        assignment_len: usize,
    },
    /// The dynamic proof has the wrong number of hierarchy components.
    #[error("malformed hierarchy")]
    MalformedHierarchy,
    /// A composed table is inconsistent with its input vector.
    #[error("update table old value does not match position {0}")]
    OldValueMismatch(usize),
}

/// Preprocess the initial relation. Sparse CAIR transitions require no
/// circuit-size-dependent transition proving keys.
pub fn index(circuit: Circuit) -> Result<(ProvingKey, VerifyingKey), Error> {
    let (prover_wiring, verifier_wiring) = preprocess_wiring(&circuit)?;
    let zero_assignment = vec![Bn254::ZERO; circuit.assignment_len()];
    let initial_program = initial_program(&circuit, &zero_assignment);
    let (initial_pk, initial_vk) = static_setup(&initial_program).map_err(static_error)?;

    Ok((
        ProvingKey {
            circuit,
            wiring: prover_wiring,
            initial: initial_pk,
        },
        VerifyingKey {
            wiring: verifier_wiring,
            initial: initial_vk,
        },
    ))
}

impl ProvingKey {
    /// Number of rows in the initial relation's padded HyperPlonk trace.
    #[must_use]
    pub const fn initial_trace_len(&self) -> usize {
        self.initial.trace_len()
    }
}

impl VerifyingKey {
    /// Number of rows in the initial relation's padded HyperPlonk trace.
    #[must_use]
    pub const fn initial_trace_len(&self) -> usize {
        self.initial.trace_len()
    }
}

/// Compute the initial relation's padded HyperPlonk trace length without
/// materializing its constraint program.
#[must_use]
pub fn initial_trace_len(circuit: &Circuit) -> usize {
    initial_program_operation_count(circuit.n, circuit.assignment_len())
        .max(2)
        .next_power_of_two()
}

/// Compute the initial padded trace length from the compact circuit shape,
/// without allocating its wiring permutation.
pub fn initial_trace_len_for_shape(
    gate_pairs: usize,
    num_public_inputs: usize,
) -> Result<usize, CircuitError> {
    if gate_pairs == 0 {
        return Err(CircuitError::Empty);
    }
    if num_public_inputs > gate_pairs {
        return Err(CircuitError::TooManyPublicInputs {
            n: gate_pairs,
            public_inputs: num_public_inputs,
        });
    }
    let assignment_len = 6 * gate_pairs + num_public_inputs;
    Ok(initial_program_operation_count(gate_pairs, assignment_len)
        .max(2)
        .next_power_of_two())
}

/// Arithmetize the ordinary from-scratch relation used by the benchmark.
///
/// Unlike the dynamic initial relation, this program binds the public-input
/// suffix directly as relation public inputs. It contains only the circuit's
/// copy and arithmetic constraints: no Merkle commitment or CAIR relation.
pub fn regular_hyperplonk_program(
    circuit: &Circuit,
    assignment: &[Bn254],
) -> Result<ConstraintProgram, CircuitError> {
    circuit.check_assignment(assignment)?;
    Ok(arithmetic_program(circuit, assignment, true))
}

/// Return the dense HyperPlonk transition trace length.
///
/// Sparse CAIR transitions do not materialize a HyperPlonk trace, so every
/// valid update size returns zero.
pub fn transition_trace_len(circuit: &Circuit, size: usize) -> Result<usize, Error> {
    let assignment_len = circuit.assignment_len();
    if size == 0 || size > assignment_len {
        return Err(Error::UpdateSizeOutOfRange {
            size,
            assignment_len,
        });
    }
    Ok(0)
}

/// Count Poseidon2 permutations in the sparse transition DAG for concrete update
/// positions. Positions must be sorted, unique, and gate-tuple closed.
pub fn transition_cair_hash_count(circuit: &Circuit, indices: &[usize]) -> Result<usize, Error> {
    if indices.is_empty()
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
        || indices
            .iter()
            .any(|&index| index >= circuit.assignment_len())
    {
        return Err(Error::NonCanonicalUpdate);
    }
    estimate_transition_shape(circuit, indices)
        .map(|(_, _, hashes)| hashes)
        .map_err(transition_error)
}

/// Backwards-compatible name for [`transition_cair_hash_count`].
#[doc(hidden)]
pub fn transition_gkr_hash_count(circuit: &Circuit, indices: &[usize]) -> Result<usize, Error> {
    transition_cair_hash_count(circuit, indices)
}

/// Conservative memory preflight for one sparse transition proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionResourceEstimate {
    /// Exact number of non-boundary old/new Poseidon checks.
    pub poseidon_hashes: usize,
    /// Padded number of universal sparse-DAG rows.
    pub row_count: usize,
    /// Columns in the packed main CAIR table (over `2 * row_count` rows).
    pub row_width: usize,
    /// Field elements in the committed main CAIR polynomial.
    pub master_fields: usize,
    /// Conservative peak bytes for current CAIR and WHIR allocations.
    pub conservative_peak_bytes: u128,
}

/// Estimate the exact table shape and a conservative peak allocation without
/// proving or preprocessing an update.
pub fn transition_resource_estimate(
    circuit: &Circuit,
    indices: &[usize],
) -> Result<TransitionResourceEstimate, Error> {
    let (row_count, row_width, poseidon_hashes) =
        estimate_transition_shape(circuit, indices).map_err(transition_error)?;
    let master_fields = row_count
        .checked_mul(2)
        .and_then(|rows| rows.checked_mul(row_width))
        .ok_or(Error::MalformedHierarchy)?;
    // The main estimate already includes one packed 195-column Poseidon trace
    // over `2 * rows`. The small adaptive product CAIR uses
    // `14 + 2 log(rows)` columns. Twelve copies conservatively cover
    // commitment LDEs, sumcheck folds, and opening buffers.
    let product_width = (14 + 2 * row_count.trailing_zeros() as usize).next_power_of_two();
    let product_fields = row_count
        .checked_mul(product_width)
        .ok_or(Error::MalformedHierarchy)?;
    let cair_fields = master_fields
        .checked_add(product_fields)
        .ok_or(Error::MalformedHierarchy)?;
    let conservative_peak_bytes = cair_fields as u128 * 12 * size_of::<Bn254>() as u128;
    Ok(TransitionResourceEstimate {
        poseidon_hashes,
        row_count,
        row_width,
        master_fields,
        conservative_peak_bytes,
    })
}

/// Validate update sizes. Sparse CAIR transitions require no preprocessing.
pub fn preprocess_update_sizes(key: &ProvingKey, sizes: &[usize]) -> Result<(), Error> {
    let assignment_len = key.circuit.assignment_len();
    for &size in sizes {
        if size == 0 || size > assignment_len {
            return Err(Error::UpdateSizeOutOfRange {
                size,
                assignment_len,
            });
        }
    }
    Ok(())
}

/// Compatibility no-op: sparse CAIR transitions have no per-level keys.
pub fn preprocess_all_levels(_key: &ProvingKey) -> Result<(), Error> {
    Ok(())
}

/// Prove a valid initial assignment and initialize empty update tables.
pub fn initialize(key: &ProvingKey, assignment: Vec<Bn254>) -> Result<State, Error> {
    key.circuit.check_assignment(&assignment)?;
    initialize_unchecked(key, assignment)
}

/// Initialize the transition-only benchmark from a natively checked, trusted
/// base assignment, omitting the initial static/CAIR proof that is excluded from
/// update timings.
pub fn initialize_transition_benchmark(
    key: &ProvingKey,
    assignment: Vec<Bn254>,
) -> Result<TransitionBenchmarkState, Error> {
    key.circuit.check_assignment(&assignment)?;
    initialize_transition_benchmark_unchecked(key, assignment)
}

fn initialize_transition_benchmark_unchecked(
    key: &ProvingKey,
    assignment: Vec<Bn254>,
) -> Result<TransitionBenchmarkState, Error> {
    let tree = MerkleTree::new(assignment.clone())?;
    let commitment = tree.commitment();
    let depth = key.circuit.hierarchy_depth();
    let public_input_opening = open_public_inputs(&key.circuit, &tree)?;
    Ok(TransitionBenchmarkState {
        base_assignment: assignment.clone(),
        current_assignment: assignment,
        tables: vec![None; depth],
        commitments: vec![commitment; depth + 1],
        transition_proofs: vec![None; depth],
        public_input_opening,
    })
}

fn initialize_unchecked(key: &ProvingKey, assignment: Vec<Bn254>) -> Result<State, Error> {
    let tree = MerkleTree::new(assignment.clone())?;
    let commitment = tree.commitment();
    let program = initial_program(&key.circuit, &assignment);
    let trace_len = key.initial.trace_len();
    let mut initial_cair = None;
    let initial_proof = prove_with_main_openings(
        &key.initial,
        &program,
        &[],
        |main_commitment, main_evaluations| {
            let seed = commitment_seed(main_commitment);
            let committed_main_column = main_evaluations[0].clone();
            let (proof, link) = cair::prove(
                &assignment,
                commitment.root,
                &seed,
                trace_len,
                committed_main_column,
            )
            .map_err(|error| error.to_string())?;
            initial_cair = Some(proof);
            Ok(ExtraMainOpenings {
                points: vec![main_column_point(&link.point, trace_len)],
                transcript_binding: link.transcript_binding,
            })
        },
    )
    .map_err(static_error)?;
    let depth = key.circuit.hierarchy_depth();
    let commitments = vec![commitment; depth + 1];
    let public_input_opening = open_public_inputs(&key.circuit, &tree)?;
    Ok(State {
        base_assignment: assignment.clone(),
        current_assignment: assignment,
        tables: vec![None; depth],
        proof: Proof {
            commitments,
            initial_proof,
            initial_cair: initial_cair.expect("successful composed proving returns a CAIR proof"),
            transition_proofs: vec![None; depth],
            public_input_opening,
        },
    })
}

/// Apply a valid, gate-tuple-closed update and refresh the affected hierarchy.
pub fn update(
    key: &ProvingKey,
    state: &mut State,
    updates: &[(usize, Bn254)],
) -> Result<(), Error> {
    let resulting_assignment = validate_update(key, &state.current_assignment, updates)?;

    if state.tables.iter().all(Option::is_some) {
        *state = initialize_unchecked(key, resulting_assignment)?;
        return Ok(());
    }
    insert_update_table(
        key.circuit.hierarchy_depth(),
        &state.current_assignment,
        &mut state.tables,
        updates,
    );
    rebuild_hierarchy_components(
        key,
        &state.base_assignment,
        &state.tables,
        &mut state.current_assignment,
        &mut state.proof.commitments,
        &mut state.proof.transition_proofs,
        &mut state.proof.public_input_opening,
    )?;
    debug_assert_eq!(state.current_assignment, resulting_assignment);
    Ok(())
}

/// Apply an update using the exact sparse hierarchy and transition-CAIR prover,
/// but retain no initial static/CAIR proof.
pub fn update_transition_benchmark(
    key: &ProvingKey,
    state: &mut TransitionBenchmarkState,
    updates: &[(usize, Bn254)],
) -> Result<(), Error> {
    let resulting_assignment = validate_update(key, &state.current_assignment, updates)?;
    if state.tables.iter().all(Option::is_some) {
        *state = initialize_transition_benchmark_unchecked(key, resulting_assignment)?;
        return Ok(());
    }
    insert_update_table(
        key.circuit.hierarchy_depth(),
        &state.current_assignment,
        &mut state.tables,
        updates,
    );
    rebuild_hierarchy_components(
        key,
        &state.base_assignment,
        &state.tables,
        &mut state.current_assignment,
        &mut state.commitments,
        &mut state.transition_proofs,
        &mut state.public_input_opening,
    )?;
    debug_assert_eq!(state.current_assignment, resulting_assignment);
    Ok(())
}

/// Verify the full initial/transition chain and the current public-input opening.
pub fn verify(key: &VerifyingKey, public_inputs: &[Bn254], proof: &Proof) -> Result<(), Error> {
    let shape = key.wiring.shape();
    let depth = shape.hierarchy_depth();
    if proof.commitments.len() != depth + 1 || proof.transition_proofs.len() != depth {
        return Err(Error::MalformedHierarchy);
    }
    if proof
        .commitments
        .iter()
        .any(|commitment| commitment.len != shape.assignment_len)
    {
        return Err(Error::MalformedHierarchy);
    }
    let seed = commitment_seed(proof.initial_proof.main_commitment());
    let link = cair::verify(
        shape.assignment_len,
        proof.commitments[0].root,
        &seed,
        key.initial.trace_len(),
        &proof.initial_cair,
        proof.initial_proof.extra_main_evaluations(),
    )
    .map_err(cair_error)?;
    let openings = ExtraMainOpenings {
        points: vec![main_column_point(&link.point, key.initial.trace_len())],
        transcript_binding: link.transcript_binding,
    };
    verify_with_main_openings(&key.initial, &[], &proof.initial_proof, &openings)
        .map_err(static_error)?;
    verify_transition_hierarchy(
        key,
        public_inputs,
        &proof.commitments,
        &proof.transition_proofs,
        proof.public_input_opening.as_ref(),
    )
}

/// Verify all transition proofs and the current public-input opening in a
/// transition-only benchmark state.  The first commitment is trusted rather
/// than linked to an initial static/CAIR proof.
pub fn verify_transition_benchmark(
    key: &VerifyingKey,
    public_inputs: &[Bn254],
    state: &TransitionBenchmarkState,
) -> Result<(), Error> {
    verify_transition_hierarchy(
        key,
        public_inputs,
        &state.commitments,
        &state.transition_proofs,
        state.public_input_opening.as_ref(),
    )
}

fn verify_transition_hierarchy(
    key: &VerifyingKey,
    public_inputs: &[Bn254],
    commitments: &[Commitment],
    transition_proofs: &[Option<TransitionProof>],
    public_input_opening: Option<&MultiProof>,
) -> Result<(), Error> {
    let shape = key.wiring.shape();
    let depth = shape.hierarchy_depth();
    if commitments.len() != depth + 1 || transition_proofs.len() != depth {
        return Err(Error::MalformedHierarchy);
    }
    if commitments
        .iter()
        .any(|commitment| commitment.len != shape.assignment_len)
    {
        return Err(Error::MalformedHierarchy);
    }
    for level in 1..=depth {
        let old = commitments[level - 1];
        let new = commitments[level];
        if let Some(transition) = &transition_proofs[level - 1] {
            let lower = 1usize << (depth - level);
            let capacity = ((lower << 1) - 1).min(shape.assignment_len);
            transition_cair::verify(
                shape,
                key.wiring.permutation_commitment(),
                old,
                new,
                level,
                lower,
                capacity,
                transition,
            )
            .map_err(transition_error)?;
        } else if new != old {
            return Err(Error::MalformedHierarchy);
        }
    }
    let positions = shape.public_positions();
    if positions.is_empty() {
        if !public_inputs.is_empty() || public_input_opening.is_some() {
            return Err(Error::MalformedHierarchy);
        }
    } else {
        if public_inputs.len() != positions.len() {
            return Err(Error::MalformedHierarchy);
        }
        verify_merkle(
            commitments[depth],
            &positions,
            public_inputs,
            public_input_opening.ok_or(Error::MalformedHierarchy)?,
        )?;
    }
    Ok(())
}

impl State {
    /// Borrow the current proof object.
    #[must_use]
    pub const fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Borrow the current full assignment retained by the prover.
    pub fn current_assignment(&self) -> &[Bn254] {
        &self.current_assignment
    }

    /// Return the current public vector commitment.
    #[must_use]
    pub fn current_commitment(&self) -> Commitment {
        *self
            .proof
            .commitments
            .last()
            .expect("a hierarchy always contains its base commitment")
    }
}

fn validate_update(
    key: &ProvingKey,
    current_assignment: &[Bn254],
    updates: &[(usize, Bn254)],
) -> Result<Vec<Bn254>, Error> {
    if updates.is_empty() {
        return Err(Error::EmptyUpdate);
    }
    let indices: Vec<_> = updates.iter().map(|&(index, _)| index).collect();
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::NonCanonicalUpdate);
    }
    key.circuit.check_update_indices(&indices)?;
    let mut resulting_assignment = current_assignment.to_vec();
    for &(index, value) in updates {
        if index >= resulting_assignment.len() {
            return Err(CircuitError::AssignmentLength {
                expected: resulting_assignment.len(),
                actual: index + 1,
            }
            .into());
        }
        resulting_assignment[index] = value;
    }
    key.circuit.check_assignment(&resulting_assignment)?;
    Ok(resulting_assignment)
}

fn insert_update_table(
    depth: usize,
    current_assignment: &[Bn254],
    tables: &mut [Option<UpdateTable>],
    updates: &[(usize, Bn254)],
) {
    let mut incoming = UpdateTable {
        entries: updates
            .iter()
            .map(|&(index, new)| UpdateEntry {
                index,
                old: current_assignment[index],
                new,
            })
            .collect(),
    };
    let target;
    loop {
        let level = level_for_size(depth, incoming.entries.len());
        let affected: Vec<_> = (level - 1..depth)
            .filter(|&position| tables[position].is_some())
            .collect();
        if affected.is_empty() {
            target = level;
            break;
        }
        let mut sequence = Vec::with_capacity(affected.len() + 1);
        for position in &affected {
            sequence.push(tables[*position].take().expect("table is present"));
        }
        sequence.push(incoming);
        incoming = compose_tables(sequence);
    }
    tables[target - 1] = Some(incoming);
}

#[allow(clippy::too_many_arguments)]
fn rebuild_hierarchy_components(
    key: &ProvingKey,
    base_assignment: &[Bn254],
    tables: &[Option<UpdateTable>],
    current_assignment: &mut Vec<Bn254>,
    commitments_out: &mut Vec<Commitment>,
    transition_proofs_out: &mut Vec<Option<TransitionProof>>,
    public_input_opening_out: &mut Option<MultiProof>,
) -> Result<(), Error> {
    let depth = key.circuit.hierarchy_depth();
    let mut tree = MerkleTree::new(base_assignment.to_vec())?;
    let mut commitments = vec![tree.commitment()];
    let mut transition_proofs = Vec::with_capacity(depth);

    for level in 1..=depth {
        if let Some(table) = &tables[level - 1] {
            let lower = 1usize << (depth - level);
            let capacity = ((lower << 1) - 1).min(key.circuit.assignment_len());
            let old = tree.commitment();
            let mut new_tree = tree.clone();
            let replacements = table
                .entries
                .iter()
                .map(|entry| {
                    if tree.values()[entry.index] != entry.old {
                        return Err(Error::OldValueMismatch(entry.index));
                    }
                    Ok((entry.index, entry.new))
                })
                .collect::<Result<Vec<_>, _>>()?;
            new_tree.update(&replacements)?;
            let new = new_tree.commitment();
            let updates = table
                .entries
                .iter()
                .map(|entry| (entry.index, entry.old, entry.new))
                .collect::<Vec<_>>();
            let transition = transition_cair::prove(
                &key.circuit,
                key.wiring.permutation_tree(),
                &tree,
                level,
                lower,
                capacity,
                &updates,
                old,
                new,
            )
            .map_err(transition_error)?;
            tree = new_tree;
            commitments.push(new);
            transition_proofs.push(Some(transition));
        } else {
            commitments.push(tree.commitment());
            transition_proofs.push(None);
        }
    }
    *current_assignment = tree.values().to_vec();
    *commitments_out = commitments;
    *transition_proofs_out = transition_proofs;
    *public_input_opening_out = open_public_inputs(&key.circuit, &tree)?;
    Ok(())
}

fn compose_tables(sequence: Vec<UpdateTable>) -> UpdateTable {
    let mut composed = BTreeMap::<usize, UpdateEntry>::new();
    for table in sequence {
        for entry in table.entries {
            composed
                .entry(entry.index)
                .and_modify(|existing| existing.new = entry.new)
                .or_insert(entry);
        }
    }
    UpdateTable {
        entries: composed.into_values().collect(),
    }
}

fn level_for_size(depth: usize, size: usize) -> usize {
    (1..=depth)
        .find(|&level| {
            let lower = 1usize << (depth - level);
            lower <= size && size < (lower << 1)
        })
        .expect("every nonempty update set of size at most m has a hierarchy level")
}

fn open_public_inputs(
    circuit: &Circuit,
    tree: &MerkleTree,
) -> Result<Option<MultiProof>, MerkleError> {
    let positions = circuit.public_positions();
    if positions.is_empty() {
        Ok(None)
    } else {
        tree.open(&positions).map(Some)
    }
}

fn initial_program(circuit: &Circuit, assignment: &[Bn254]) -> ConstraintProgram {
    arithmetic_program(circuit, assignment, false)
}

fn arithmetic_program(
    circuit: &Circuit,
    assignment: &[Bn254],
    expose_public_inputs: bool,
) -> ConstraintProgram {
    let mut builder = ProgramBuilder::new(if expose_public_inputs {
        circuit.num_public_inputs
    } else {
        0
    });
    let public_start = 6 * circuit.n;
    let values = assignment
        .iter()
        .copied()
        .enumerate()
        .map(|(position, value)| {
            if expose_public_inputs && position >= public_start {
                builder.public(position - public_start, value)
            } else {
                builder.variable(value)
            }
        })
        .collect::<Vec<_>>();

    // Put the wiring equalities first. Their left operands make main column
    // zero begin with the unpadded assignment. CAIR's range-selector routing supplies
    // the canonical zeros from `m` to `m.next_power_of_two()`, so the static
    // relation itself is padded only once, after all real operations exist.
    for (position, &permuted) in circuit.permutation.iter().enumerate() {
        builder.assert_equal(values[position], values[permuted]);
    }
    for gate in 0..circuit.n {
        let sum = builder.add(values[6 * gate], values[6 * gate + 1]);
        builder.assert_equal(sum, values[6 * gate + 2]);
        let product = builder.mul(values[6 * gate + 3], values[6 * gate + 4]);
        builder.assert_equal(product, values[6 * gate + 5]);
    }
    builder.finish()
}

fn initial_program_operation_count(gate_pairs: usize, assignment_len: usize) -> usize {
    // Copy constraints double as the assignment-prefix binding, followed by
    // two compute-and-compare rows for each addition and multiplication gate.
    assignment_len + 4 * gate_pairs
}

fn static_error(error: impl std::fmt::Display) -> Error {
    Error::Static(error.to_string())
}

fn cair_error(error: impl std::fmt::Display) -> Error {
    Error::Cair(error.to_string())
}

fn transition_error(error: impl std::fmt::Display) -> Error {
    Error::Transition(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_trace_estimate_matches_materialized_program() {
        for n in [1, 2, 5, 16] {
            let circuit = Circuit::new(n, 1, (0..6 * n + 1).collect()).unwrap();
            let assignment = vec![Bn254::ZERO; circuit.assignment_len()];
            let program = initial_program(&circuit, &assignment);
            assert_eq!(initial_trace_len(&circuit), program.trace_len());
        }
    }

    #[test]
    fn sparse_transitions_have_no_dense_trace() {
        for n in [1, 2, 5] {
            let circuit = Circuit::new(n, 1, (0..6 * n + 1).collect()).unwrap();
            for size in [1, 3, circuit.assignment_len()] {
                assert_eq!(transition_trace_len(&circuit, size).unwrap(), 0);
            }
        }
    }

    #[test]
    fn regular_hyperplonk_baseline_has_no_merkle_relation_and_binds_public_inputs() {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let assignment = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let program = regular_hyperplonk_program(&circuit, &assignment).unwrap();
        let (pk, vk) = crate::static_snark::setup(&program).unwrap();
        let proof = crate::static_snark::prove(&pk, &program, &[Bn254::from_u64(9)]).unwrap();
        crate::static_snark::verify(&vk, &[Bn254::from_u64(9)], &proof).unwrap();
        assert!(crate::static_snark::verify(&vk, &[Bn254::from_u64(10)], &proof).is_err());
    }

    #[test]
    fn dynamic_verifier_accepts_initial_proof_and_rejects_malformed_variants() {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let assignment = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let (pk, vk) = index(circuit).unwrap();
        let state = initialize(&pk, assignment).unwrap();
        verify(&vk, &[Bn254::from_u64(9)], state.proof()).unwrap();

        assert!(verify(&vk, &[Bn254::from_u64(10)], state.proof()).is_err());

        let mut malformed = state.proof().clone();
        malformed.commitments.pop();
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &malformed),
            Err(Error::MalformedHierarchy)
        ));

        let mut malformed = state.proof().clone();
        malformed.transition_proofs.pop();
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &malformed),
            Err(Error::MalformedHierarchy)
        ));

        let mut broken_chain = state.proof().clone();
        broken_chain.commitments[1].root += Bn254::ONE;
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &broken_chain),
            Err(Error::MalformedHierarchy)
        ));

        let mut wrong_initial_statement = state.proof().clone();
        wrong_initial_statement.commitments[0].root += Bn254::ONE;
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &wrong_initial_statement,),
            Err(Error::Cair(_))
        ));

        let mut missing_public_opening = state.proof().clone();
        missing_public_opening.public_input_opening = None;
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &missing_public_opening,),
            Err(Error::MalformedHierarchy)
        ));

        let mut forged_public_opening = state.proof().clone();
        forged_public_opening
            .public_input_opening
            .as_mut()
            .expect("this circuit has a public input")
            .nodes[0]
            .digest += Bn254::ONE;
        assert!(matches!(
            verify(&vk, &[Bn254::from_u64(9)], &forged_public_opening,),
            Err(Error::Merkle(_))
        ));
    }

    #[test]
    fn transition_benchmark_harness_uses_the_production_transition_proof() {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let assignment = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let (pk, vk) = index(circuit).unwrap();
        let mut state = initialize_transition_benchmark(&pk, assignment).unwrap();
        verify_transition_benchmark(&vk, &[Bn254::from_u64(9)], &state).unwrap();

        let update = [
            (0, Bn254::from_u64(2)),
            (1, Bn254::from_u64(2)),
            (2, Bn254::from_u64(4)),
        ];
        update_transition_benchmark(&pk, &mut state, &update).unwrap();
        verify_transition_benchmark(&vk, &[Bn254::from_u64(9)], &state).unwrap();
        assert!(verify_transition_benchmark(&vk, &[Bn254::from_u64(10)], &state).is_err());
    }
}
