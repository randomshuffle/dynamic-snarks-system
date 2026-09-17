//! Section 4 hierarchical dynamic-SNARK compiler.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::time::Instant;
use thiserror::Error;

#[cfg(feature = "poseidon-gkr")]
use crate::cair::round_reduction::{self as cair, Proof as CairProof};
#[cfg(not(feature = "poseidon-gkr"))]
use crate::cair::{self, Proof as CairProof};
use crate::circuit::{Circuit, CircuitError};
use crate::merkle::{Commitment, MerkleError, MerkleTree, MultiProof, verify as verify_merkle};
use crate::static_snark::{
    ConstraintProgram, ExtraMainOpenings, ProgramBuilder, Proof as StaticProof,
    ProvingKey as StaticProvingKey, VerifyingKey as StaticVerifyingKey, commitment_seed,
    main_table_point, prove_with_main_openings, setup as static_setup, verify_with_main_openings,
};
#[cfg(feature = "poseidon-gkr")]
use crate::transition_cair::round_reduction::{self as transition_cair, Proof as TransitionProof};
#[cfg(not(feature = "poseidon-gkr"))]
use crate::transition_cair::{self, Proof as TransitionProof};
#[cfg(feature = "poseidon-gkr")]
use crate::transition_relation::estimate_endpoint_shape as estimate_transition_shape;
#[cfg(not(feature = "poseidon-gkr"))]
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
    base_tree: MerkleTree,
    hierarchy_trees: Vec<MerkleTree>,
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
    base_tree: MerkleTree,
    hierarchy_trees: Vec<MerkleTree>,
    current_assignment: Vec<Bn254>,
    tables: Vec<Option<UpdateTable>>,
    commitments: Vec<Commitment>,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
}

impl TransitionBenchmarkState {
    /// Serializable transmitted components, excluding the trusted initial proof,
    /// assignments, prover trees, and indexing keys. For benchmark accounting only.
    pub fn proof_payload(&self) -> impl Serialize + '_ {
        #[derive(Serialize)]
        struct Payload<'a> {
            commitments: &'a [Commitment],
            transition_proofs: &'a [Option<TransitionProof>],
            public_input_opening: &'a Option<MultiProof>,
        }
        Payload {
            commitments: &self.commitments,
            transition_proofs: &self.transition_proofs,
            public_input_opening: &self.public_input_opening,
        }
    }
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
    /// The selected initial Merkle PIOP failed.
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

    /// Number of permutation columns committed by initial preprocessing.
    #[must_use]
    pub fn initial_preprocessed_width(&self) -> usize {
        self.initial.preprocessed_width()
    }
}

impl VerifyingKey {
    /// Number of rows in the initial relation's padded HyperPlonk trace.
    #[must_use]
    pub const fn initial_trace_len(&self) -> usize {
        self.initial.trace_len()
    }

    /// Number of permutation columns committed by initial preprocessing.
    #[must_use]
    pub fn initial_preprocessed_width(&self) -> usize {
        self.initial.preprocessed_width()
    }
}

/// Compute the initial relation's padded HyperPlonk trace length without
/// materializing its constraint program.
#[must_use]
pub fn initial_trace_len(circuit: &Circuit) -> usize {
    initial_program_row_count(circuit.n, circuit.assignment_len())
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
    Ok(initial_program_row_count(gate_pairs, assignment_len)
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
    /// Columns in the main table: `2R` rows normally, `R` with endpoint GKR.
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
    let main_row_factor = if cfg!(feature = "poseidon-gkr") { 1 } else { 2 };
    let master_fields = row_count
        .checked_mul(main_row_factor)
        .and_then(|rows| rows.checked_mul(row_width))
        .ok_or(Error::MalformedHierarchy)?;
    // The adaptive product CAIR uses `14 + 2 log(rows)` columns.
    // Twelve copies conservatively cover commitment LDEs, sumcheck folds,
    // and opening buffers; endpoint GKR's transient trace is added below.
    let product_width = (14 + 2 * row_count.trailing_zeros() as usize).next_power_of_two();
    let product_fields = row_count
        .checked_mul(product_width)
        .ok_or(Error::MalformedHierarchy)?;
    let cair_fields = master_fields
        .checked_add(product_fields)
        .ok_or(Error::MalformedHierarchy)?;
    // Endpoint GKR stores 65 transient width-three layers over 2R hashes.
    let transient_fields = if cfg!(feature = "poseidon-gkr") {
        390 * row_count as u128
    } else {
        0
    };
    let conservative_peak_bytes =
        (cair_fields as u128 * 12 + transient_fields) * size_of::<Bn254>() as u128;
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
    let phase = Instant::now();
    key.circuit.check_assignment(&assignment)?;
    profile_checkpoint("initial: native assignment validation", phase);
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
    let encoded = key.circuit.encode_assignment(&assignment);
    let tree = MerkleTree::new(encoded)?;
    let commitment = tree.commitment();
    let depth = key.circuit.hierarchy_depth();
    let public_input_opening = open_public_inputs(&key.circuit, &tree)?;
    Ok(TransitionBenchmarkState {
        base_tree: tree.clone(),
        hierarchy_trees: vec![tree; depth + 1],
        current_assignment: assignment,
        tables: vec![None; depth],
        commitments: vec![commitment; depth + 1],
        transition_proofs: vec![None; depth],
        public_input_opening,
    })
}

fn initialize_unchecked(key: &ProvingKey, assignment: Vec<Bn254>) -> Result<State, Error> {
    let phase = Instant::now();
    let encoded = key.circuit.encode_assignment(&assignment);
    let tree = MerkleTree::new(encoded.clone())?;
    profile_checkpoint("initial: assignment Merkle tree", phase);
    let commitment = tree.commitment();
    let phase = Instant::now();
    let program = initial_program(&key.circuit, &assignment);
    profile_checkpoint("initial: relation arithmetization", phase);
    let trace_len = key.initial.trace_len();
    let assignment_link_len = encoded.len();
    let mut initial_cair = None;
    let phase = Instant::now();
    let initial_proof = prove_with_main_openings(
        &key.initial,
        &program,
        &[],
        |main_commitment, main_evaluations| {
            let seed = commitment_seed(main_commitment);
            debug_assert_eq!(main_evaluations.len(), 4);
            let committed_assignment = crate::parallel::pack_columns(
                trace_len,
                4,
                &main_evaluations
                    .iter()
                    .map(Vec::as_slice)
                    .collect::<Vec<_>>(),
            );
            let (proof, link) = cair::prove(
                &encoded,
                commitment.root,
                &seed,
                assignment_link_len,
                committed_assignment,
            )
            .map_err(|error| error.to_string())?;
            initial_cair = Some(proof);
            Ok(ExtraMainOpenings {
                points: vec![main_table_point(&link.point)],
                transcript_binding: link.transcript_binding,
            })
        },
    )
    .map_err(static_error)?;
    profile_checkpoint("initial: composed static+CAIR proof", phase);
    let depth = key.circuit.hierarchy_depth();
    let commitments = vec![commitment; depth + 1];
    let phase = Instant::now();
    let public_input_opening = open_public_inputs(&key.circuit, &tree)?;
    profile_checkpoint("initial: public-input Merkle opening", phase);
    Ok(State {
        base_tree: tree.clone(),
        hierarchy_trees: vec![tree; depth + 1],
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
    let phase = Instant::now();
    validate_update(key, &state.current_assignment, updates)?;
    profile_checkpoint("transition: update validation", phase);
    let phase = Instant::now();
    let target = insert_update_table(
        key.circuit.hierarchy_depth(),
        &state.current_assignment,
        &mut state.tables,
        updates,
    );
    profile_checkpoint("transition: hierarchy table insertion/composition", phase);
    let phase = Instant::now();
    rebuild_hierarchy_components(
        key,
        &state.base_tree,
        &mut state.hierarchy_trees,
        &state.tables,
        target,
        &mut state.proof.commitments,
        &mut state.proof.transition_proofs,
        &mut state.proof.public_input_opening,
        updates,
    )?;
    profile_checkpoint("transition: complete hierarchy rebuild", phase);
    for &(index, value) in updates {
        state.current_assignment[index] = value;
    }
    Ok(())
}

/// Apply an update using the exact sparse hierarchy and transition-CAIR prover,
/// but retain no initial static/CAIR proof.
pub fn update_transition_benchmark(
    key: &ProvingKey,
    state: &mut TransitionBenchmarkState,
    updates: &[(usize, Bn254)],
) -> Result<(), Error> {
    let phase = Instant::now();
    validate_update(key, &state.current_assignment, updates)?;
    profile_checkpoint("transition: update validation", phase);
    let phase = Instant::now();
    let target = insert_update_table(
        key.circuit.hierarchy_depth(),
        &state.current_assignment,
        &mut state.tables,
        updates,
    );
    profile_checkpoint("transition: hierarchy table insertion/composition", phase);
    let phase = Instant::now();
    rebuild_hierarchy_components(
        key,
        &state.base_tree,
        &mut state.hierarchy_trees,
        &state.tables,
        target,
        &mut state.commitments,
        &mut state.transition_proofs,
        &mut state.public_input_opening,
        updates,
    )?;
    profile_checkpoint("transition: complete hierarchy rebuild", phase);
    for &(index, value) in updates {
        state.current_assignment[index] = value;
    }
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
        .any(|commitment| commitment.len != shape.assignment_tree_len())
    {
        return Err(Error::MalformedHierarchy);
    }
    let seed = commitment_seed(proof.initial_proof.main_commitment());
    let assignment_link_len = shape.assignment_tree_len();
    let link = cair::verify(
        assignment_link_len,
        proof.commitments[0].root,
        &seed,
        assignment_link_len,
        &proof.initial_cair,
        proof.initial_proof.extra_main_evaluations(),
    )
    .map_err(cair_error)?;
    let openings = ExtraMainOpenings {
        points: vec![main_table_point(&link.point)],
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
        .any(|commitment| commitment.len != shape.assignment_tree_len())
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
) -> Result<(), Error> {
    if updates.is_empty() {
        return Err(Error::EmptyUpdate);
    }
    let indices: Vec<_> = updates.iter().map(|&(index, _)| index).collect();
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::NonCanonicalUpdate);
    }
    key.circuit.check_update_indices(&indices)?;
    let value_after_update = |index: usize| {
        updates
            .binary_search_by_key(&index, |&(position, _)| position)
            .map_or(current_assignment[index], |position| updates[position].1)
    };

    let gate_starts = indices
        .iter()
        .copied()
        .filter(|&index| index < 6 * key.circuit.n)
        .map(|index| index - index % 3)
        .collect::<std::collections::BTreeSet<_>>();
    for start in gate_starts {
        let pair = start / 6;
        let left = value_after_update(start);
        let right = value_after_update(start + 1);
        let output = value_after_update(start + 2);
        let valid = if start % 6 == 0 {
            left + right == output
        } else {
            left * right == output
        };
        if !valid {
            return Err(CircuitError::GateConstraint { pair }.into());
        }
    }
    for &index in &indices {
        let neighbor = key.circuit.permutation[index];
        if value_after_update(index) != value_after_update(neighbor) {
            return Err(CircuitError::WiringConstraint { position: index }.into());
        }
    }
    Ok(())
}

fn insert_update_table(
    depth: usize,
    current_assignment: &[Bn254],
    tables: &mut [Option<UpdateTable>],
    updates: &[(usize, Bn254)],
) -> usize {
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
    target
}

#[allow(clippy::too_many_arguments)]
fn rebuild_hierarchy_components(
    key: &ProvingKey,
    base_tree: &MerkleTree,
    hierarchy_trees: &mut [MerkleTree],
    tables: &[Option<UpdateTable>],
    target: usize,
    commitments_out: &mut Vec<Commitment>,
    transition_proofs_out: &mut Vec<Option<TransitionProof>>,
    public_input_opening_out: &mut Option<MultiProof>,
    immediate_updates: &[(usize, Bn254)],
) -> Result<(), Error> {
    let depth = key.circuit.hierarchy_depth();
    if hierarchy_trees.len() != depth + 1
        || commitments_out.len() != depth + 1
        || transition_proofs_out.len() != depth
        || hierarchy_trees[0].commitment() != base_tree.commitment()
        || tables[target..].iter().any(Option::is_some)
    {
        return Err(Error::MalformedHierarchy);
    }
    let table = tables[target - 1]
        .as_ref()
        .ok_or(Error::MalformedHierarchy)?;
    let old_tree = &hierarchy_trees[target - 1];
    if old_tree.commitment() != commitments_out[target - 1] {
        return Err(Error::MalformedHierarchy);
    }
    let lower = 1usize << (depth - target);
    let capacity = ((lower << 1) - 1).min(key.circuit.assignment_len());
    let phase = Instant::now();
    let mut replacements = table
        .entries
        .iter()
        .map(|entry| {
            if old_tree.value(key.circuit.assignment_leaf_index(entry.index)) != Some(entry.old) {
                return Err(Error::OldValueMismatch(entry.index));
            }
            Ok((key.circuit.assignment_leaf_index(entry.index), entry.new))
        })
        .collect::<Result<Vec<_>, _>>()?;
    replacements.sort_unstable_by_key(|&(index, _)| index);
    let new_tree = old_tree.updated(&replacements)?;
    profile_checkpoint("transition: update sparse Merkle paths", phase);
    let old = old_tree.commitment();
    let new = new_tree.commitment();
    let transition_updates = table
        .entries
        .iter()
        .map(|entry| (entry.index, entry.old, entry.new))
        .collect::<Vec<_>>();
    let phase = Instant::now();
    let transition = transition_cair::prove(
        &key.circuit,
        key.wiring.permutation_tree(),
        old_tree,
        &new_tree,
        target,
        lower,
        capacity,
        &transition_updates,
        old,
        new,
    )
    .map_err(transition_error)?;
    profile_checkpoint("transition: CAIR proof total", phase);

    commitments_out[target..].fill(new);
    transition_proofs_out[target - 1] = Some(transition);
    transition_proofs_out[target..].fill(None);
    hierarchy_trees[target..].fill(new_tree.clone());
    let phase = Instant::now();
    if key.circuit.num_public_inputs == 0 {
        if public_input_opening_out.is_some() {
            return Err(Error::MalformedHierarchy);
        }
    } else {
        let mut changed_indices = immediate_updates
            .iter()
            .map(|&(index, _)| key.circuit.assignment_leaf_index(index))
            .collect::<Vec<_>>();
        changed_indices.sort_unstable();
        new_tree.refresh_opening(
            public_input_opening_out
                .as_mut()
                .ok_or(Error::MalformedHierarchy)?,
            &changed_indices,
        )?;
    }
    profile_checkpoint("transition: refresh cached public-input opening", phase);
    Ok(())
}

fn profile_checkpoint(label: &str, started: Instant) {
    if std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some() {
        eprintln!(
            "profile checkpoint: {label} complete in {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
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
    let positions = circuit
        .public_positions()
        .into_iter()
        .map(|index| circuit.assignment_leaf_index(index))
        .collect::<Vec<_>>();
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
    // Allocate one program variable per wiring-permutation cycle.  Its
    // occurrences in the gate rows and public column are tied by PermCheck.
    let mut values = vec![None; assignment.len()];
    for start in 0..assignment.len() {
        if values[start].is_some() {
            continue;
        }
        let variable = builder.variable(assignment[start]);
        let mut position = start;
        loop {
            debug_assert!(values[position].is_none());
            values[position] = Some(variable);
            position = circuit.permutation[position];
            if position == start {
                break;
            }
        }
    }
    let values = values
        .into_iter()
        .map(|variable| variable.expect("a permutation partitions every position"))
        .collect::<Vec<_>>();

    for gate in 0..circuit.n {
        builder.assert_add(values[6 * gate], values[6 * gate + 1], values[6 * gate + 2]);
        builder.assert_mul(
            values[6 * gate + 3],
            values[6 * gate + 4],
            values[6 * gate + 5],
        );
    }
    builder.align_arithmetic(&values[6 * circuit.n..], circuit.encoded_permutation());
    builder.finish()
}

fn initial_program_row_count(gate_pairs: usize, _assignment_len: usize) -> usize {
    2 * gate_pairs
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
    fn paper_style_gate_rows_do_not_compile_copy_constraints_into_rows() {
        let public_inputs = 4;
        let circuit = Circuit::new(16, public_inputs, (0..100).collect()).unwrap();
        let assignment = vec![Bn254::ZERO; circuit.assignment_len()];
        let dynamic = initial_program(&circuit, &assignment);
        let base = regular_hyperplonk_program(&circuit, &assignment).unwrap();
        assert_eq!(dynamic.operations.len(), 2 * circuit.n);
        assert_eq!(base.operations.len(), 2 * circuit.n);
        assert_eq!(dynamic.trace_len(), 32);
        assert_eq!(base.trace_len(), 32);
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
        crate::merkle::reset_dense_construction_count();
        crate::circuit::reset_dense_work_counts();
        update_transition_benchmark(&pk, &mut state, &update).unwrap();
        assert_eq!(crate::merkle::dense_construction_count(), 0);
        assert_eq!(crate::circuit::dense_work_counts(), (0, 0));
        verify_transition_benchmark(&vk, &[Bn254::from_u64(9)], &state).unwrap();
        assert!(verify_transition_benchmark(&vk, &[Bn254::from_u64(10)], &state).is_err());
    }

    #[test]
    fn production_update_performs_no_dense_merkle_assignment_or_public_input_work() {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let assignment = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64).to_vec();
        let (pk, vk) = index(circuit).unwrap();
        let mut state = initialize(&pk, assignment).unwrap();
        let update_values = [
            (0, Bn254::from_u64(2)),
            (1, Bn254::from_u64(2)),
            (2, Bn254::from_u64(4)),
        ];

        crate::merkle::reset_dense_construction_count();
        crate::circuit::reset_dense_work_counts();
        update(&pk, &mut state, &update_values).unwrap();
        assert_eq!(crate::merkle::dense_construction_count(), 0);
        assert_eq!(crate::circuit::dense_work_counts(), (0, 0));
        verify(&vk, &[Bn254::from_u64(9)], state.proof()).unwrap();
    }

    #[test]
    fn sparse_validation_rejects_gate_and_wiring_violations_without_dense_scan() {
        let circuit = Circuit::new(1, 0, vec![0, 1, 3, 2, 4, 5]).unwrap();
        let assignment = [1, 2, 3, 3, 4, 12].map(Bn254::from_u64).to_vec();
        let (pk, _) = index(circuit).unwrap();

        crate::circuit::reset_dense_work_counts();
        let wiring_error = validate_update(
            &pk,
            &assignment,
            &[
                (0, Bn254::from_u64(2)),
                (1, Bn254::from_u64(2)),
                (2, Bn254::from_u64(4)),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            wiring_error,
            Error::Circuit(CircuitError::WiringConstraint { position: 2 })
        ));
        assert_eq!(crate::circuit::dense_work_counts(), (0, 0));

        let gate_error = validate_update(
            &pk,
            &assignment,
            &[
                (3, Bn254::from_u64(2)),
                (4, Bn254::from_u64(2)),
                (5, Bn254::from_u64(5)),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            gate_error,
            Error::Circuit(CircuitError::GateConstraint { pair: 0 })
        ));
        assert_eq!(crate::circuit::dense_work_counts(), (0, 0));
    }
}
