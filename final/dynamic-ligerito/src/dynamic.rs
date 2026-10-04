//! Section 4 hierarchical dynamic-SNARK compiler.

use crate::direct_transition;
use crate::field::F;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::time::Instant;
use thiserror::Error;

#[cfg(feature = "poseidon-gkr")]
use crate::cair::{self, Proof as CairProof};
#[cfg(not(feature = "poseidon-gkr"))]
use crate::cair::{self, Proof as CairProof};
use crate::circuit::{Circuit, CircuitError};
use crate::merkle::{Commitment, MerkleError, MerkleTree, MultiProof, verify as verify_merkle};
use crate::static_snark::{
    ConstraintProgram, ExtraMainOpenings, ProgramBuilder, Proof as StaticProof,
    ProvingKey as StaticProvingKey, VerifyingKey as StaticVerifyingKey, commitment_seed,
    main_table_point, prove_with_main_openings, setup as static_setup, verify_with_main_openings,
};
#[cfg(all(feature = "poseidon-gkr", not(feature = "compact-merkle")))]
use crate::transition_cair::round_reduction::{self as transition_cair, Proof as TransitionProof};
#[cfg(feature = "compact-merkle")]
use crate::transition_cair::split::{self as transition_cair, Proof as TransitionProof};
#[cfg(not(feature = "poseidon-gkr"))]
use crate::transition_cair::{self, Proof as TransitionProof};
#[cfg(all(feature = "poseidon-gkr", not(feature = "compact-merkle")))]
use crate::transition_relation::estimate_endpoint_shape as estimate_transition_shape;
#[cfg(not(feature = "poseidon-gkr"))]
use crate::transition_relation::estimate_shape as estimate_transition_shape;
#[cfg(feature = "compact-merkle")]
use crate::transition_relation::split::estimate_shape as estimate_transition_shape;
use crate::wiring::{ProverWiringIndex, VerifierWiringIndex, preprocess as preprocess_wiring};

/// Indexed dynamic proving key and retained permutation tree.
pub struct ProvingKey {
    circuit: Circuit,
    wiring: ProverWiringIndex,
    initial: StaticProvingKey,
    plaintext_cap: usize,
    hierarchy: Hierarchy,
}

/// Indexed dynamic verification key.
pub struct VerifyingKey {
    wiring: VerifierWiringIndex,
    initial: StaticVerifyingKey,
    plaintext_cap: usize,
    hierarchy: Hierarchy,
}

/// Size buckets are [base^k, base^(k+1)), in distinct assignment positions.
/// Each bucket has base-1 chronological slots. A full bucket and an incoming
/// table are composed and reclassified by their union size. Merkle arity is 2.
#[derive(Clone, Copy, Debug)]
struct Hierarchy {
    base: usize,
    depth: usize, // Total proof-chain slots, including empty slots.
    assignment_len: usize,
}

impl Hierarchy {
    fn new(base: usize, assignment_len: usize) -> Result<Self, Error> {
        if ![2, 4, 8].contains(&base) || assignment_len == 0 {
            return Err(Error::InvalidHierarchyBase(base));
        }
        let levels = (usize::BITS - assignment_len.leading_zeros()).div_ceil(base.ilog2()) as usize;
        let depth = levels * (base - 1);
        Ok(Self {
            base,
            depth,
            assignment_len,
        })
    }

    fn bounds(self, level: usize) -> (usize, usize) {
        assert!((1..=self.depth).contains(&level));
        let bucket = (level - 1) / (self.base - 1);
        let levels = self.depth / (self.base - 1);
        let lower = self.base.pow((levels - bucket - 1) as u32);
        let upper = lower.checked_mul(self.base).map_or(usize::MAX, |n| n - 1);
        (lower, upper.min(self.assignment_len))
    }

    fn level_for_size(self, size: usize) -> usize {
        assert!((1..=self.assignment_len).contains(&size));
        let bucket = (size.ilog2() / self.base.ilog2()) as usize;
        self.depth - (bucket + 1) * (self.base - 1) + 1
    }
}

/// Current dynamic proof object from Figure 3 of Section 4.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    commitments: Vec<Commitment>,
    initial_proof: StaticProof,
    initial_cair: CairProof,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
    direct_tail: Option<direct_transition::Proof>,
}

impl Proof {
    /// Experimental proof-size accounting, including all retained transitions.
    pub fn oracle_statistics(&self) -> serde_json::Value {
        let transitions: Vec<_> = self
            .transition_proofs
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                p.as_ref()
                    .map(|p| serde_json::json!({"level":i,"statistics":p.statistics()}))
            })
            .collect();
        let plain: usize = self
            .transition_proofs
            .iter()
            .flatten()
            .map(|p| p.plaintext_bytes())
            .sum::<usize>()
            + self.direct_tail.as_ref().map_or(0, |p| p.bytes());
        let total = bincode::serialized_size(self).unwrap();
        serde_json::json!({"transition_oracles":transitions,"direct_tail":self.direct_tail.as_ref().map(|p|p.statistics()),"total_plaintext_bytes":plain,"total_serialized_bytes":total,"other_proof_bytes":total-plain as u64})
    }
}

/// Prover auxiliary state, including hierarchical update witness tables.
#[derive(Clone)]
pub struct State {
    base_tree: MerkleTree,
    hierarchy_trees: Vec<MerkleTree>,
    current_assignment: Vec<F>,
    tables: Vec<Option<UpdateTable>>,
    proof: Proof,
    // Immutable initialization payload, counted once rather than on every update.
    initial_proof_bytes: u64,
    // Serialized bodies of the retained PCS transition proofs, refreshed only
    // when the upper hierarchy changes. Container metadata is counted below.
    retained_transition_bytes: u64,
    current_tree: MerkleTree,
    tail_table: Option<UpdateTable>,
    last_update: Option<UpdateStatistics>,
}

/// Per-update accounting, read outside the benchmark's prover timer.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateStatistics {
    pub mode: &'static str,
    pub candidate_plaintext_bytes: usize,
    pub plaintext_credit_bytes: u64,
    pub candidate_gates: usize,
    pub polynomial_gates: usize,
    pub polynomial_positions: usize,
    pub hierarchy_level: Option<usize>,
}

/// Prover state for timing transition proofs without constructing the excluded
/// initial static/CAIR proof.
///
/// The base assignment is checked natively and its Merkle commitment is treated
/// as trusted.  Every subsequent hierarchy transition and final public-input
/// opening proves the same relation as the full dynamic prover. Without an
/// initialization payload, its plaintext size budget can select fewer tables.
/// This type is only a
/// benchmark harness: it is not a replacement for [`State`] in a sound protocol.
#[derive(Clone)]
pub struct TransitionBenchmarkState {
    base_tree: MerkleTree,
    hierarchy_trees: Vec<MerkleTree>,
    current_assignment: Vec<F>,
    tables: Vec<Option<UpdateTable>>,
    commitments: Vec<Commitment>,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
}

/// Serializable transition-only benchmark proof; its first commitment is trusted.
#[derive(Clone, Serialize, Deserialize)]
pub struct TransitionBenchmarkProof {
    commitments: Vec<Commitment>,
    transition_proofs: Vec<Option<TransitionProof>>,
    public_input_opening: Option<MultiProof>,
}

impl TransitionBenchmarkState {
    /// Copy transmitted components, excluding the trusted initial proof,
    /// assignments, prover trees, and indexing keys. For benchmark accounting only.
    pub fn proof_payload(&self) -> TransitionBenchmarkProof {
        TransitionBenchmarkProof {
            commitments: self.commitments.clone(),
            transition_proofs: self.transition_proofs.clone(),
            public_input_opening: self.public_input_opening.clone(),
        }
    }
}

#[derive(Clone)]
struct UpdateEntry {
    index: usize,
    old: F,
    new: F,
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
    /// A static Ligerito-backed proof failed.
    #[error("static SNARK: {0}")]
    Static(String),
    /// The selected initial Merkle PIOP failed.
    #[error("initial Merkle CAIR: {0}")]
    Cair(String),
    /// A sparse transition CAIR proof or its Ligerito openings failed.
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
    /// Supported growth factors use power-of-two level-size thresholds.
    #[error("hierarchy base must be 2, 4 or 8, received {0}")]
    InvalidHierarchyBase(usize),
    /// A composed table is inconsistent with its input vector.
    #[error("update table old value does not match position {0}")]
    OldValueMismatch(usize),
}

/// Preprocess the initial relation. Sparse CAIR transitions require no
/// circuit-size-dependent transition proving keys.
pub fn index(circuit: Circuit) -> Result<(ProvingKey, VerifyingKey), Error> {
    index_with_plaintext_cap(circuit, 64 * 1024)
}

/// Configure the maximum serialized direct tail (zero disables it).
pub fn index_with_plaintext_cap(
    circuit: Circuit,
    plaintext_cap: usize,
) -> Result<(ProvingKey, VerifyingKey), Error> {
    index_with_hierarchy(circuit, plaintext_cap, 2)
}

/// Select the hierarchy growth factor (2, 4 or 8) and direct-tail byte cap.
/// Both keys retain the same geometry; level bounds are checked and bound into
/// transition transcripts. This does not change Merkle arity or PCS parameters.
pub fn index_with_hierarchy(
    circuit: Circuit,
    plaintext_cap: usize,
    hierarchy_base: usize,
) -> Result<(ProvingKey, VerifyingKey), Error> {
    let hierarchy = Hierarchy::new(hierarchy_base, circuit.assignment_len())?;
    if plaintext_cap > 2 * 1024 * 1024 {
        return Err(Error::Transition("plaintext cap exceeds 2 MiB".into()));
    }
    let (prover_wiring, verifier_wiring) = preprocess_wiring(&circuit)?;
    let zero_assignment = vec![F::ZERO; circuit.assignment_len()];
    let initial_program = initial_program(&circuit, &zero_assignment);
    let (initial_pk, initial_vk) = static_setup(&initial_program).map_err(static_error)?;

    Ok((
        ProvingKey {
            circuit,
            wiring: prover_wiring,
            initial: initial_pk,
            plaintext_cap,
            hierarchy,
        },
        VerifyingKey {
            wiring: verifier_wiring,
            initial: initial_vk,
            plaintext_cap,
            hierarchy,
        },
    ))
}

impl ProvingKey {
    /// Total slots in the proof chain, with base-1 slots per size level.
    pub fn hierarchy_slots(&self) -> usize {
        self.hierarchy.depth
    }

    /// Number of size levels, excluding the within-level slots.
    pub fn hierarchy_levels(&self) -> usize {
        self.hierarchy.depth / (self.hierarchy.base - 1)
    }

    /// Growth factor used for the level-size thresholds.
    pub fn hierarchy_base(&self) -> usize {
        self.hierarchy.base
    }
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
    assignment: &[F],
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
    /// Number of proved hashes, including padded old/new lanes.
    pub poseidon_hashes: usize,
    /// Padded sparse node rows (combined node/update rows in older variants).
    pub row_count: usize,
    /// Main-table columns: `R` rows with endpoint GKR, `2R` for scalar traces.
    pub row_width: usize,
    /// Field elements in the main oracle, excluding auxiliary/product oracles.
    pub master_fields: usize,
    /// Padded update/gate rows; zero when these records share the main table.
    pub auxiliary_rows: usize,
    /// Padded update/gate columns; zero when there is no separate oracle.
    pub auxiliary_width: usize,
    /// Field elements in the separate update/gate oracle.
    pub auxiliary_fields: usize,
    /// Padded columns in the shared routing product table.
    pub product_width: usize,
    /// Field elements in the shared routing product oracle.
    pub product_fields: usize,
    /// Boundary-oracle fields, separate from computed hash rows.
    pub boundary_fields: usize,
    /// Round-33 checkpoint fields, four words per computed hash.
    pub checkpoint_fields: usize,
    /// Logical fields across all four committed oracles, before PCS minimum padding.
    pub total_committed_fields: usize,
    /// Conservative allocation estimate for CAIR and Ligerito, not measured RSS.
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
    let main_row_factor = 1;
    let master_fields = row_count
        .checked_mul(main_row_factor)
        .and_then(|rows| rows.checked_mul(row_width))
        .ok_or(Error::MalformedHierarchy)?;
    #[cfg(feature = "compact-merkle")]
    let (auxiliary_rows, auxiliary_width) = {
        let gates = indices
            .iter()
            .copied()
            .filter(|&index| index < 6 * circuit.n)
            .map(|index| index / 3)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let rows = indices
            .len()
            .checked_add(gates)
            .and_then(|rows| rows.max(2).checked_next_power_of_two())
            .ok_or(Error::MalformedHierarchy)?;
        let width = crate::transition_relation::packed::auxiliary_column_count(
            circuit.n,
            circuit.num_public_inputs,
        )
        .next_power_of_two();
        (rows, width)
    };
    #[cfg(not(feature = "compact-merkle"))]
    let (auxiliary_rows, auxiliary_width): (usize, usize) = (0, 0);
    let auxiliary_fields = auxiliary_rows
        .checked_mul(auxiliary_width)
        .ok_or(Error::MalformedHierarchy)?;
    let (_, boundary_rows, _) = crate::transition_relation::split::shape_details(circuit, indices)
        .map_err(transition_error)?;
    let boundary_fields = 8 * boundary_rows;
    let product_width = 0;
    let product_fields = 0;
    let checkpoint_fields = 4 * poseidon_hashes;
    let total_committed_fields =
        master_fields + boundary_fields + auxiliary_fields + checkpoint_fields;
    let retained_states = if poseidon_hashes <= 32768 { 70 } else { 28 };
    let transient_fields = retained_states * 4 * poseidon_hashes as u128;
    let conservative_peak_bytes =
        (total_committed_fields as u128 * 12 + transient_fields) * size_of::<F>() as u128;
    Ok(TransitionResourceEstimate {
        poseidon_hashes,
        row_count,
        row_width,
        master_fields,
        auxiliary_rows,
        auxiliary_width,
        auxiliary_fields,
        product_width,
        product_fields,
        boundary_fields,
        checkpoint_fields,
        total_committed_fields,
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
pub fn initialize(key: &ProvingKey, assignment: Vec<F>) -> Result<State, Error> {
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
    assignment: Vec<F>,
) -> Result<TransitionBenchmarkState, Error> {
    key.circuit.check_assignment(&assignment)?;
    initialize_transition_benchmark_unchecked(key, assignment)
}

fn initialize_transition_benchmark_unchecked(
    key: &ProvingKey,
    assignment: Vec<F>,
) -> Result<TransitionBenchmarkState, Error> {
    let encoded = key.circuit.encode_assignment(&assignment);
    let tree = MerkleTree::new(encoded)?;
    let commitment = tree.commitment();
    let depth = key.hierarchy.depth;
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

fn initialize_unchecked(key: &ProvingKey, assignment: Vec<F>) -> Result<State, Error> {
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
                points: link.points.iter().map(|p| main_table_point(p)).collect(),
                transcript_binding: link.transcript_binding,
            })
        },
    )
    .map_err(static_error)?;
    profile_checkpoint("initial: composed static+CAIR proof", phase);
    let depth = key.hierarchy.depth;
    let commitments = vec![commitment; depth + 1];
    let phase = Instant::now();
    let public_input_opening = open_public_inputs(&key.circuit, &tree)?;
    profile_checkpoint("initial: public-input Merkle opening", phase);
    let initial_cair = initial_cair.expect("successful composed proving returns a CAIR proof");
    let initial_proof_bytes = bincode::serialized_size(&(&initial_proof, &initial_cair))
        .map_err(|_| Error::MalformedHierarchy)?;
    Ok(State {
        base_tree: tree.clone(),
        current_tree: tree.clone(),
        tail_table: None,
        last_update: None,
        hierarchy_trees: vec![tree; depth + 1],
        current_assignment: assignment,
        tables: vec![None; depth],
        proof: Proof {
            commitments,
            initial_proof,
            initial_cair,
            transition_proofs: vec![None; depth],
            public_input_opening,
            direct_tail: None,
        },
        initial_proof_bytes,
        retained_transition_bytes: 0,
    })
}

/// Apply a valid, gate-tuple-closed update and refresh the affected hierarchy.
pub fn update(key: &ProvingKey, state: &mut State, updates: &[(usize, F)]) -> Result<(), Error> {
    update_with_hash_checkpoints(key, state, updates, 1)
}

/// Apply an update using 1, 3, or 7 committed intermediate hash states.
/// Initialization retains its default hash proof; the verifier accepts mixed
/// checkpoint counts because each transition proves the same hash relation.
pub fn update_with_hash_checkpoints(
    key: &ProvingKey,
    state: &mut State,
    updates: &[(usize, F)],
    hash_checkpoints: usize,
) -> Result<(), Error> {
    if ![1, 3, 7].contains(&hash_checkpoints) {
        return Err(Error::Transition(
            "unsupported hash checkpoint count".into(),
        ));
    }
    let phase = Instant::now();
    validate_update(key, &state.current_assignment, updates)?;
    profile_checkpoint("transition: update validation", phase);
    let incoming = UpdateTable {
        entries: updates
            .iter()
            .map(|&(index, new)| UpdateEntry {
                index,
                old: state.current_assignment[index],
                new,
            })
            .collect(),
    };
    let incoming = if let Some(tail) = &state.tail_table {
        compose_tables(vec![tail.clone(), incoming])
    } else {
        incoming
    };
    let candidate_gates = table_gate_count(&incoming, &key.circuit);
    let plaintext_credit_bytes = state.plaintext_credit_bytes()?;
    let mut candidate_bytes = 0;
    let mut direct = None;
    let mut next_tree = None;
    if key.plaintext_cap > 0 {
        let mut replacements: Vec<_> = updates
            .iter()
            .map(|&(i, v)| (key.circuit.assignment_leaf_index(i), v))
            .collect();
        replacements.sort_unstable_by_key(|u| u.0);
        let new = state.current_tree.updated(&replacements)?;
        let tuples = incoming
            .entries
            .iter()
            .map(|e| (e.index, e.old, e.new))
            .collect::<Vec<_>>();
        let candidate = direct_transition::prove(
            &key.circuit,
            key.wiring.permutation_tree(),
            state.hierarchy_trees.last().unwrap(),
            &new,
            &tuples,
        )
        .map_err(transition_error)?;
        candidate_bytes = candidate.bytes();
        // Upper transitions use PCS. Count all retained non-plaintext bytes,
        // including their cached bodies, rather than only initialization.
        if candidate_bytes <= key.plaintext_cap && candidate_bytes as u64 <= plaintext_credit_bytes
        {
            direct = Some(candidate);
            next_tree = Some(new);
        }
    }
    if let Some(direct) = direct {
        let new = next_tree.unwrap();
        refresh_public_opening(
            &key.circuit,
            &new,
            &mut state.proof.public_input_opening,
            updates,
        )?;
        state.current_tree = new;
        state.tail_table = Some(incoming);
        state.proof.direct_tail = Some(direct);
        state.last_update = Some(UpdateStatistics {
            mode: "direct",
            candidate_plaintext_bytes: candidate_bytes,
            plaintext_credit_bytes,
            candidate_gates,
            polynomial_gates: 0,
            polynomial_positions: 0,
            hierarchy_level: None,
        });
    } else {
        let target = insert_composed_table(key.hierarchy, &mut state.tables, incoming);
        let table = state.tables[target - 1].as_ref().unwrap();
        let positions = table.entries.len();
        let gates = table_gate_count(table, &key.circuit);
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
            hash_checkpoints,
            state.initial_proof_bytes,
            false,
        )?;
        state.current_tree = state.hierarchy_trees.last().unwrap().clone();
        state.tail_table = None;
        state.proof.direct_tail = None;
        state.retained_transition_bytes = state
            .proof
            .transition_proofs
            .iter()
            .flatten()
            .try_fold(0, |bytes, p| {
                bincode::serialized_size(p).map(|size| bytes + size)
            })
            .map_err(|_| Error::MalformedHierarchy)?;
        state.last_update = Some(UpdateStatistics {
            mode: "polynomial",
            candidate_plaintext_bytes: candidate_bytes,
            plaintext_credit_bytes,
            candidate_gates,
            polynomial_gates: gates,
            polynomial_positions: positions,
            hierarchy_level: Some(target),
        });
    }
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
    updates: &[(usize, F)],
) -> Result<(), Error> {
    let phase = Instant::now();
    validate_update(key, &state.current_assignment, updates)?;
    profile_checkpoint("transition: update validation", phase);
    let phase = Instant::now();
    let target = insert_update_table(
        key.hierarchy,
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
        1,
        0,
        true,
    )?;
    profile_checkpoint("transition: complete hierarchy rebuild", phase);
    for &(index, value) in updates {
        state.current_assignment[index] = value;
    }
    Ok(())
}

/// Verify the full initial/transition chain and the current public-input opening.
pub fn verify(key: &VerifyingKey, public_inputs: &[F], proof: &Proof) -> Result<(), Error> {
    let shape = key.wiring.shape();
    let depth = key.hierarchy.depth;
    if proof.commitments.len() != depth + 1 || proof.transition_proofs.len() != depth {
        return Err(Error::MalformedHierarchy);
    }
    let direct_bytes = proof.direct_tail.as_ref().map_or(0, |p| p.bytes());
    let plain = direct_bytes
        + proof
            .transition_proofs
            .iter()
            .flatten()
            .map(|p| p.plaintext_bytes())
            .sum::<usize>();
    if plain > key.plaintext_cap {
        return Err(Error::Transition("plaintext cap exceeded".into()));
    }
    check_plain_ratio(proof, &proof.transition_proofs, direct_bytes)?;
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
        points: link.points.iter().map(|p| main_table_point(p)).collect(),
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
        proof.direct_tail.as_ref(),
    )
}

/// Verify all transition proofs and the current public-input opening in a
/// transition-only benchmark state.  The first commitment is trusted rather
/// than linked to an initial static/CAIR proof.
pub fn verify_transition_benchmark(
    key: &VerifyingKey,
    public_inputs: &[F],
    state: &TransitionBenchmarkState,
) -> Result<(), Error> {
    check_plain_ratio(
        &(
            &state.commitments,
            &state.transition_proofs,
            &state.public_input_opening,
        ),
        &state.transition_proofs,
        0,
    )?;
    verify_transition_hierarchy(
        key,
        public_inputs,
        &state.commitments,
        &state.transition_proofs,
        state.public_input_opening.as_ref(),
        None,
    )
}

/// Verify a decoded transition-only benchmark payload, with its base commitment
/// trusted exactly as in [`verify_transition_benchmark`].
pub fn verify_transition_benchmark_proof(
    key: &VerifyingKey,
    public_inputs: &[F],
    proof: &TransitionBenchmarkProof,
) -> Result<(), Error> {
    check_plain_ratio(proof, &proof.transition_proofs, 0)?;
    verify_transition_hierarchy(
        key,
        public_inputs,
        &proof.commitments,
        &proof.transition_proofs,
        proof.public_input_opening.as_ref(),
        None,
    )
}

fn check_plain_ratio(
    proof: &impl Serialize,
    transitions: &[Option<TransitionProof>],
    direct_bytes: usize,
) -> Result<(), Error> {
    let plain: usize = transitions
        .iter()
        .flatten()
        .map(|p| p.plaintext_bytes())
        .sum::<usize>()
        + direct_bytes;
    let total = bincode::serialized_size(proof).map_err(|_| Error::MalformedHierarchy)?;
    if 2 * plain as u128 > total as u128 {
        return Err(Error::Transition(
            "plaintext exceeds the other proof bytes".into(),
        ));
    }
    Ok(())
}

fn verify_transition_hierarchy(
    key: &VerifyingKey,
    public_inputs: &[F],
    commitments: &[Commitment],
    transition_proofs: &[Option<TransitionProof>],
    public_input_opening: Option<&MultiProof>,
    direct: Option<&direct_transition::Proof>,
) -> Result<(), Error> {
    let shape = key.wiring.shape();
    let depth = key.hierarchy.depth;
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
            let (lower, capacity) = key.hierarchy.bounds(level);
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
    let final_commitment = if let Some(direct) = direct {
        direct_transition::verify(
            shape,
            key.wiring.permutation_commitment(),
            commitments[depth],
            direct,
            key.plaintext_cap,
        )
        .map_err(transition_error)?
    } else {
        commitments[depth]
    };
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
            final_commitment,
            &positions,
            public_inputs,
            public_input_opening.ok_or(Error::MalformedHierarchy)?,
        )?;
    }
    Ok(())
}

impl State {
    fn plaintext_credit_bytes(&self) -> Result<u64, Error> {
        // Option<()> has the same one-byte tag as either proof option, without
        // counting its body. Public-input query coordinates stay fixed, so
        // refreshing their digests does not change this metadata size.
        let metadata = bincode::serialized_size(&(
            &self.proof.commitments,
            &self.proof.public_input_opening,
            vec![None::<()>; self.proof.transition_proofs.len()],
            None::<()>,
        ))
        .map_err(|_| Error::MalformedHierarchy)?;
        Ok(self.initial_proof_bytes + self.retained_transition_bytes + metadata)
    }

    /// Borrow the current proof object.
    #[must_use]
    pub const fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Borrow the current full assignment retained by the prover.
    pub fn current_assignment(&self) -> &[F] {
        &self.current_assignment
    }

    /// Return the current public vector commitment.
    #[must_use]
    pub fn current_commitment(&self) -> Commitment {
        self.current_tree.commitment()
    }

    pub fn last_update_statistics(&self) -> Option<&UpdateStatistics> {
        self.last_update.as_ref()
    }
}

fn validate_update(
    key: &ProvingKey,
    current_assignment: &[F],
    updates: &[(usize, F)],
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
    hierarchy: Hierarchy,
    current_assignment: &[F],
    tables: &mut [Option<UpdateTable>],
    updates: &[(usize, F)],
) -> usize {
    let incoming = UpdateTable {
        entries: updates
            .iter()
            .map(|&(index, new)| UpdateEntry {
                index,
                old: current_assignment[index],
                new,
            })
            .collect(),
    };
    insert_composed_table(hierarchy, tables, incoming)
}

fn table_gate_count(table: &UpdateTable, circuit: &Circuit) -> usize {
    table
        .entries
        .iter()
        .filter(|e| e.index < 6 * circuit.n)
        .map(|e| e.index / 3)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

fn insert_composed_table(
    hierarchy: Hierarchy,
    tables: &mut [Option<UpdateTable>],
    mut incoming: UpdateTable,
) -> usize {
    let target;
    loop {
        let first = hierarchy.level_for_size(incoming.entries.len()) - 1;
        let end = first + hierarchy.base - 1;
        // Lower levels contain newer tables: consume them before placing a
        // larger incoming update so the retained proof chain stays chronological.
        let mut affected: Vec<_> = (end..hierarchy.depth)
            .filter(|&position| tables[position].is_some())
            .collect();
        if affected.is_empty() {
            let count = tables[first..end]
                .iter()
                .take_while(|t| t.is_some())
                .count();
            debug_assert!(tables[first + count..end].iter().all(Option::is_none));
            if count < hierarchy.base - 1 {
                target = first + count + 1;
                break;
            }
            // Carry only when all base-1 slots are occupied. Overlapping updates
            // may keep the composed union in this same size bucket.
            affected.extend(first..end);
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
    immediate_updates: &[(usize, F)],
    hash_checkpoints: usize,
    initial_proof_bytes: u64,
    allow_plain_oracles: bool,
) -> Result<(), Error> {
    let depth = key.hierarchy.depth;
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
    let (lower, capacity) = key.hierarchy.bounds(target);
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
    // Count the final container with empty transition slots, then add only the
    // transitions that survive this merge. Each retained plaintext byte also
    // consumes a byte of credit. Initialization is counted once for the chain.
    let metadata = bincode::serialized_size(&(
        &*commitments_out,
        &*public_input_opening_out,
        vec![None::<()>; depth],
    ))
    .map_err(|_| Error::MalformedHierarchy)?;
    let mut other_proof_credit = initial_proof_bytes as i128 + metadata as i128;
    for p in transition_proofs_out[..target - 1].iter().flatten() {
        other_proof_credit += bincode::serialized_size(p).map_err(|_| Error::MalformedHierarchy)?
            as i128
            - 2 * p.plaintext_bytes() as i128;
    }
    let transition = transition_cair::prove_with_oracle_policy(
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
        hash_checkpoints,
        other_proof_credit,
        allow_plain_oracles,
    )
    .map_err(transition_error)?;
    profile_checkpoint("transition: CAIR proof total", phase);

    commitments_out[target..].fill(new);
    transition_proofs_out[target - 1] = Some(transition);
    transition_proofs_out[target..].fill(None);
    hierarchy_trees[target..].fill(new_tree.clone());
    let phase = Instant::now();
    refresh_public_opening(
        &key.circuit,
        &new_tree,
        public_input_opening_out,
        immediate_updates,
    )?;
    profile_checkpoint("transition: refresh cached public-input opening", phase);
    Ok(())
}

fn refresh_public_opening(
    circuit: &Circuit,
    new_tree: &MerkleTree,
    public_input_opening_out: &mut Option<MultiProof>,
    immediate_updates: &[(usize, F)],
) -> Result<(), Error> {
    if circuit.num_public_inputs == 0 {
        if public_input_opening_out.is_some() {
            return Err(Error::MalformedHierarchy);
        }
    } else {
        let mut changed_indices = immediate_updates
            .iter()
            .map(|&(index, _)| circuit.assignment_leaf_index(index))
            .collect::<Vec<_>>();
        changed_indices.sort_unstable();
        new_tree.refresh_opening(
            public_input_opening_out
                .as_mut()
                .ok_or(Error::MalformedHierarchy)?,
            &changed_indices,
        )?;
    }
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

#[cfg(test)]
mod hierarchy_tests {
    use super::*;

    #[test]
    fn radix_counter_retains_base_minus_one_tables() {
        for base in [2, 4, 8] {
            let hierarchy = Hierarchy::new(base, 1024).unwrap();
            let mut tables = vec![None; hierarchy.depth];
            for revision in 1..=512 {
                let incoming = UpdateTable {
                    entries: vec![UpdateEntry {
                        index: revision - 1,
                        old: F::ZERO,
                        new: F::ONE,
                    }],
                };
                insert_composed_table(hierarchy, &mut tables, incoming);
                let mut remainder = revision;
                for group in tables.chunks(base - 1).rev() {
                    assert_eq!(group.iter().flatten().count(), remainder % base);
                    remainder /= base;
                }
                assert_eq!(remainder, 0);
                assert_eq!(
                    tables
                        .iter()
                        .flatten()
                        .map(|t| t.entries.len())
                        .sum::<usize>(),
                    revision
                );
                for (slot, table) in tables.iter().enumerate() {
                    if let Some(t) = table {
                        let (lower, upper) = hierarchy.bounds(slot + 1);
                        assert!((lower..=upper).contains(&t.entries.len()));
                    }
                }
            }
        }
    }

    #[test]
    fn overlapping_variable_size_updates_preserve_chronological_values() {
        for base in [2, 4, 8] {
            let hierarchy = Hierarchy::new(base, 257).unwrap();
            let mut tables = vec![None; hierarchy.depth];
            let mut expected = vec![F::ZERO; 257];
            for revision in 1..=160 {
                let indices = (0..1 + revision % 23)
                    .map(|j| (revision * 31 + j * 17) % 257)
                    .collect::<std::collections::BTreeSet<_>>();
                let entries = indices
                    .into_iter()
                    .map(|index| {
                        let old = expected[index];
                        let new = F::from_usize(revision);
                        expected[index] = new;
                        UpdateEntry { index, old, new }
                    })
                    .collect();
                insert_composed_table(hierarchy, &mut tables, UpdateTable { entries });
                let mut replay = vec![F::ZERO; 257];
                for (slot, table) in tables.iter().enumerate() {
                    if let Some(t) = table {
                        let (lower, upper) = hierarchy.bounds(slot + 1);
                        assert!((lower..=upper).contains(&t.entries.len()));
                        for entry in &t.entries {
                            assert_eq!(replay[entry.index], entry.old);
                            replay[entry.index] = entry.new;
                        }
                    }
                }
                assert_eq!(replay, expected);
            }
        }
    }

    #[test]
    fn geometry_covers_boundaries_and_rejects_unsupported_bases() {
        for base in [2, 4, 8] {
            for m in [1, 2, 3, 4, 7, 8, 15, 16, 63, 64, 255, 256, 1001, usize::MAX] {
                let h = Hierarchy::new(base, m).unwrap();
                for size in [1, m / 2 + 1, m] {
                    let slot = h.level_for_size(size);
                    let (lo, hi) = h.bounds(slot);
                    assert!((lo..=hi).contains(&size));
                }
                assert_eq!(h.bounds(1).1, m);
                assert_eq!(h.bounds(h.depth).0, 1);
            }
        }
        for base in [0, 1, 3, 16] {
            assert!(Hierarchy::new(base, 100).is_err());
        }
    }
}

fn initial_program(circuit: &Circuit, assignment: &[F]) -> ConstraintProgram {
    arithmetic_program(circuit, assignment, false)
}

fn arithmetic_program(
    circuit: &Circuit,
    assignment: &[F],
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
