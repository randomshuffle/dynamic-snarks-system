//! Local row relation for sparse-DAG transitions.

use std::collections::{BTreeMap, BTreeSet};

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use thiserror::Error;

use crate::circuit::{Circuit, CircuitError};
use crate::dynamic::gadgets::{allocate_bits, conditional_equal, constant_bits, less_than, linear};
use crate::hash::poseidon2;
use crate::merkle::{Commitment, MerkleError, MerkleTree};
use crate::multiset::{ProductFactors, RoutingChallenges};
use crate::sparse_dag::{NodeKind, NodeRow, SparseMerkleDag, TreeId};
use crate::static_snark::{ConstraintProgram, ProgramBuilder, Variable};

const ROUTE_LANES: usize = 4;
const TUPLE_WIDTH: usize = 6;
const ASSIGNMENT_LEAF_TAG: u64 = 11;
const PERMUTATION_LEAF_TAG: u64 = 12;
const NEIGHBOR_LEAF_TAG: u64 = 13;
const GATE_TAG: u64 = 20;
#[cfg(test)]
pub(crate) const HASH_OFFSET: usize = 43;
#[cfg(test)]
pub(crate) const PRODUCER_OFFSET: usize = 51;
#[cfg(test)]
pub(crate) const REFERENCE_OFFSET: usize = 75;

pub(crate) const COMPACT_PAYLOAD_OFFSET: usize = 3;

type Tuple = [Bn254; TUPLE_WIDTH];

#[derive(Clone, Copy)]
pub(crate) struct Statement {
    pub(crate) gate_pairs: usize,
    pub(crate) public_inputs: usize,
    pub(crate) assignment_len: usize,
    pub(crate) height: usize,
    pub(crate) permutation: Commitment,
    pub(crate) old_assignment: Commitment,
    pub(crate) new_assignment: Commitment,
}

#[derive(Clone)]
pub(crate) struct TransitionTable {
    statement: Statement,
    rows: Vec<Row>,
    #[cfg(test)]
    programs: Vec<ConstraintProgram>,
}

pub(crate) struct CompactWitness {
    pub(crate) columns: Vec<Vec<Bn254>>,
    pub(crate) hash_inputs: [Vec<Bn254>; 4],
}

#[derive(Clone)]
struct Row {
    active: bool,
    node: NodeSection,
    link: LinkSection,
    gate: GateSection,
    hashes: [[Bn254; 4]; 2],
    producers: [Tuple; ROUTE_LANES],
    references: [Tuple; ROUTE_LANES],
}

#[derive(Clone)]
struct NodeSection {
    active: bool,
    root: bool,
    tree: [bool; 3],
    kind: [bool; 3],
    level: usize,
    index: usize,
    digest: [Bn254; 2],
    children: [Bn254; 4],
    values: [Bn254; 2],
}

#[derive(Clone)]
struct LinkSection {
    active: bool,
    index: usize,
    old: Bn254,
    new: Bn254,
    sigma: usize,
    neighbor: Bn254,
    digests: [Bn254; 4],
    is_gate: bool,
    is_public: bool,
    is_add: bool,
    is_mul: bool,
    offsets: [bool; 3],
    pair: usize,
    public_offset: usize,
}

#[derive(Clone)]
struct GateSection {
    active: bool,
    is_add: bool,
    is_mul: bool,
    pair: usize,
    start: usize,
    values: [Bn254; 3],
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("sparse Merkle DAG: {0}")]
    Sparse(#[from] crate::sparse_dag::Error),
    #[error("transition update indices are not sorted, unique, and in range")]
    Indices,
    #[error("transition update value does not match an assignment tree at index {0}")]
    Value(usize),
    #[error("indexed permutation tree does not match the circuit permutation")]
    Permutation,
}

impl Default for Row {
    fn default() -> Self {
        let dummy = dummy_hash();
        Self {
            active: false,
            node: NodeSection::default(),
            link: LinkSection::default(),
            gate: GateSection::default(),
            hashes: [dummy, dummy],
            producers: [[Bn254::ZERO; TUPLE_WIDTH]; ROUTE_LANES],
            references: [[Bn254::ZERO; TUPLE_WIDTH]; ROUTE_LANES],
        }
    }
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            active: false,
            root: false,
            tree: [false; 3],
            kind: [false; 3],
            level: 0,
            index: 0,
            digest: [Bn254::ZERO; 2],
            children: [Bn254::ZERO; 4],
            values: [Bn254::ZERO; 2],
        }
    }
}

impl Default for LinkSection {
    fn default() -> Self {
        Self {
            active: false,
            index: 0,
            old: Bn254::ZERO,
            new: Bn254::ZERO,
            sigma: 0,
            neighbor: Bn254::ZERO,
            digests: [Bn254::ZERO; 4],
            is_gate: false,
            is_public: false,
            is_add: false,
            is_mul: false,
            offsets: [false; 3],
            pair: 0,
            public_offset: 0,
        }
    }
}

impl Default for GateSection {
    fn default() -> Self {
        Self {
            active: false,
            is_add: false,
            is_mul: false,
            pair: 0,
            start: 0,
            values: [Bn254::ZERO; 3],
        }
    }
}

impl TransitionTable {
    pub(crate) fn build(
        circuit: &Circuit,
        permutation_tree: &MerkleTree,
        old_tree: &MerkleTree,
        new_tree: &MerkleTree,
        updates: &[(usize, Bn254, Bn254)],
    ) -> Result<Self, Error> {
        let indices = updates.iter().map(|update| update.0).collect::<Vec<_>>();
        if indices.is_empty()
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
            || indices
                .iter()
                .any(|&index| index >= circuit.assignment_len())
        {
            return Err(Error::Indices);
        }
        circuit.check_update_indices(&indices)?;
        if old_tree.commitment().len != circuit.assignment_len()
            || new_tree.commitment().len != circuit.assignment_len()
        {
            return Err(Error::Indices);
        }
        for &(index, old, new) in updates {
            if old_tree.values()[index] != old || new_tree.values()[index] != new {
                return Err(Error::Value(index));
            }
        }
        if permutation_tree.values()
            != circuit
                .permutation
                .iter()
                .copied()
                .map(Bn254::from_usize)
                .collect::<Vec<_>>()
        {
            return Err(Error::Permutation);
        }

        let assignment = SparseMerkleDag::paired(TreeId::Assignment, old_tree, new_tree, &indices)?;
        let permutation = SparseMerkleDag::single(TreeId::Permutation, permutation_tree, &indices)?;
        let mut neighbor_indices = indices
            .iter()
            .map(|&index| circuit.permutation[index])
            .collect::<Vec<_>>();
        neighbor_indices.sort_unstable();
        let neighbor = SparseMerkleDag::single(TreeId::Neighbor, new_tree, &neighbor_indices)?;

        let height = circuit
            .assignment_len()
            .next_power_of_two()
            .trailing_zeros() as usize;
        let statement = Statement {
            gate_pairs: circuit.n,
            public_inputs: circuit.num_public_inputs,
            assignment_len: circuit.assignment_len(),
            height,
            permutation: permutation_tree.commitment(),
            old_assignment: old_tree.commitment(),
            new_assignment: new_tree.commitment(),
        };
        let mut rows = Vec::new();
        for dag in [&assignment, &permutation, &neighbor] {
            rows.extend(
                dag.rows()
                    .iter()
                    .enumerate()
                    .map(|(index, row)| node_row(row, index == 0)),
            );
        }

        let assignment_leaves = leaf_map(&assignment);
        let permutation_leaves = leaf_map(&permutation);
        let neighbor_leaves = leaf_map(&neighbor);
        for &(index, old, new) in updates {
            rows.push(link_row(
                circuit,
                index,
                old,
                new,
                assignment_leaves[&index],
                permutation_leaves[&index],
                neighbor_leaves[&circuit.permutation[index]],
            ));
        }
        let gate_starts = indices
            .iter()
            .copied()
            .filter(|&index| index < 6 * circuit.n)
            .map(|index| index - index % 3)
            .collect::<BTreeSet<_>>();
        for start in gate_starts {
            rows.push(gate_row(circuit, new_tree, start));
        }

        rows.resize_with(rows.len().max(2).next_power_of_two(), Row::default);
        #[cfg(test)]
        let programs = {
            let programs = rows
                .iter()
                .map(|row| row_program(row, statement))
                .collect::<Vec<_>>();
            debug_assert!(programs.iter().skip(1).all(|program| {
                program.operations == programs[0].operations
                    && program.values.len() == programs[0].values.len()
            }));
            programs
        };
        Ok(Self {
            statement,
            rows,
            #[cfg(test)]
            programs,
        })
    }

    pub(crate) const fn statement(&self) -> Statement {
        self.statement
    }

    #[cfg(test)]
    pub(crate) fn programs(&self) -> &[ConstraintProgram] {
        &self.programs
    }

    #[cfg(test)]
    pub(crate) fn master_input(&self) -> Vec<Bn254> {
        let template = &self.programs[0];
        let block_size = master_block_size(template);
        debug_assert!(self.programs.iter().all(|program| {
            program.num_public_values == 0
                && program.values.len() == template.values.len()
                && program.operations == template.operations
        }));
        let mut input = Vec::with_capacity(block_size * self.programs.len());
        for program in &self.programs {
            input.extend_from_slice(&program.values);
            input.resize(input.len() + block_size - program.values.len(), Bn254::ZERO);
        }
        input
    }

    pub(crate) const fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn compact_witness(&self) -> CompactWitness {
        let width = compact_column_count(self.statement);
        let rows = self.rows.len();
        let mut columns = vec![vec![Bn254::ZERO; rows]; width];
        let mut hash_inputs = std::array::from_fn(|_| vec![Bn254::ZERO; 2 * rows]);
        for (row_index, row) in self.rows.iter().enumerate() {
            let encoded = compact_row(row, self.statement);
            debug_assert_eq!(encoded.len(), width);
            for (column, value) in encoded.into_iter().enumerate() {
                columns[column][row_index] = value;
            }
            for side in 0..2 {
                for field in 0..4 {
                    hash_inputs[field][2 * row_index + side] = row.hashes[side][field];
                }
            }
        }
        CompactWitness {
            columns,
            hash_inputs,
        }
    }

    pub(crate) fn poseidon_inputs(&self) -> Vec<Bn254> {
        self.rows
            .iter()
            .flat_map(|row| row.hashes.into_iter().flatten())
            .collect()
    }

    pub(crate) fn product_factors(&self, challenges: RoutingChallenges) -> ProductFactors {
        let producers = self
            .rows
            .iter()
            .flat_map(|row| row.producers)
            .collect::<Vec<_>>();
        let references = self
            .rows
            .iter()
            .flat_map(|row| row.references)
            .collect::<Vec<_>>();
        ProductFactors::from_field_rows(&producers, &references, challenges)
    }

    #[cfg(test)]
    fn rebuild_programs(&mut self) {
        self.programs = self
            .rows
            .iter()
            .map(|row| row_program(row, self.statement))
            .collect();
    }
}

pub(crate) fn template_program(statement: Statement) -> ConstraintProgram {
    row_program(&Row::default(), statement)
}

pub(crate) fn estimate_shape(
    circuit: &Circuit,
    indices: &[usize],
) -> Result<(usize, usize, usize), Error> {
    if indices.is_empty()
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
        || indices
            .iter()
            .any(|&index| index >= circuit.assignment_len())
    {
        return Err(Error::Indices);
    }
    circuit.check_update_indices(indices)?;
    let permutation_tree = MerkleTree::new(
        circuit
            .permutation
            .iter()
            .copied()
            .map(Bn254::from_usize)
            .collect(),
    )?;
    let zero_tree = MerkleTree::new(vec![Bn254::ZERO; circuit.assignment_len()])?;
    let assignment = SparseMerkleDag::paired(TreeId::Assignment, &zero_tree, &zero_tree, indices)?;
    let permutation = SparseMerkleDag::single(TreeId::Permutation, &permutation_tree, indices)?;
    let mut neighbors = indices
        .iter()
        .map(|&index| circuit.permutation[index])
        .collect::<Vec<_>>();
    neighbors.sort_unstable();
    let neighbor = SparseMerkleDag::single(TreeId::Neighbor, &zero_tree, &neighbors)?;
    let gate_rows = indices
        .iter()
        .copied()
        .filter(|&index| index < 6 * circuit.n)
        .map(|index| index - index % 3)
        .collect::<BTreeSet<_>>()
        .len();
    let row_count = (assignment.rows().len()
        + permutation.rows().len()
        + neighbor.rows().len()
        + indices.len()
        + gate_rows)
        .max(2)
        .next_power_of_two();
    let poseidon_hashes = 2 * [&assignment, &permutation, &neighbor]
        .into_iter()
        .flat_map(|dag| dag.rows())
        .filter(|row| row.kind != NodeKind::Boundary)
        .count();
    let statement = Statement {
        gate_pairs: circuit.n,
        public_inputs: circuit.num_public_inputs,
        assignment_len: circuit.assignment_len(),
        height: circuit
            .assignment_len()
            .next_power_of_two()
            .trailing_zeros() as usize,
        permutation: permutation_tree.commitment(),
        old_assignment: zero_tree.commitment(),
        new_assignment: zero_tree.commitment(),
    };
    let main_width = compact_main_width(statement);
    Ok((row_count, main_width, poseidon_hashes))
}

fn master_block_size(program: &ConstraintProgram) -> usize {
    program
        .values
        .len()
        .max(2 * program.operations.len())
        .max(2)
        .next_power_of_two()
}

pub(crate) fn compact_column_count(statement: Statement) -> usize {
    COMPACT_PAYLOAD_OFFSET
        + 19
        + pair_bit_count(statement)
        + public_bit_count(statement)
        + level_bit_count(statement)
}

pub(crate) fn compact_main_width(statement: Statement) -> usize {
    // One packed Poseidon trace covers the old and new hashes on a domain
    // twice as large as the sparse-row domain.  The extra column binds the
    // terminal state to the expected digest.
    (compact_column_count(statement) + POSEIDON_COLUMNS_PER_HASH + 1)
        .max(2)
        .next_power_of_two()
}

const POSEIDON_COLUMNS_PER_HASH: usize = 65 * 3;

fn public_bit_count(statement: Statement) -> usize {
    bit_count(statement.public_inputs)
}

fn pair_bit_count(statement: Statement) -> usize {
    bit_count(statement.gate_pairs)
}

fn level_bit_count(statement: Statement) -> usize {
    bit_count(statement.height + 1)
}

fn bit_count(bound: usize) -> usize {
    bound.max(1).next_power_of_two().trailing_zeros().max(1) as usize
}

fn compact_row(row: &Row, statement: Statement) -> Vec<Bn254> {
    let mut result = Vec::with_capacity(compact_column_count(statement));
    result.extend([
        Bn254::from_bool(row.node.active),
        Bn254::from_bool(row.link.active),
        Bn254::from_bool(row.gate.active),
    ]);
    let node = [
        Bn254::from_bool(row.node.root),
        Bn254::from_bool(row.node.tree[0]),
        Bn254::from_bool(row.node.tree[1]),
        Bn254::from_bool(row.node.tree[2]),
        Bn254::from_bool(row.node.kind[0]),
        Bn254::from_bool(row.node.kind[1]),
        Bn254::from_bool(row.node.kind[2]),
        Bn254::from_usize(row.node.level),
        Bn254::from_usize(row.node.index),
        row.node.digest[0],
        row.node.digest[1],
        row.node.children[0],
        row.node.children[1],
        row.node.children[2],
        row.node.children[3],
        row.node.values[0],
        row.node.values[1],
        Bn254::ZERO,
        Bn254::ZERO,
    ];
    let link = [
        Bn254::from_bool(row.link.is_gate),
        Bn254::from_bool(row.link.is_public),
        Bn254::from_bool(row.link.is_add),
        Bn254::from_bool(row.link.is_mul),
        Bn254::from_bool(row.link.offsets[0]),
        Bn254::from_bool(row.link.offsets[1]),
        Bn254::from_bool(row.link.offsets[2]),
        Bn254::from_usize(row.link.index),
        row.link.old,
        row.link.new,
        Bn254::from_usize(row.link.sigma),
        row.link.neighbor,
        row.link.digests[0],
        row.link.digests[1],
        row.link.digests[2],
        row.link.digests[3],
        Bn254::from_usize(row.link.pair),
        Bn254::from_usize(row.link.public_offset),
        Bn254::ZERO,
    ];
    let gate = [
        Bn254::from_bool(row.gate.is_add),
        Bn254::from_bool(row.gate.is_mul),
        Bn254::from_usize(row.gate.pair),
        Bn254::from_usize(row.gate.start),
        row.gate.values[0],
        row.gate.values[1],
        row.gate.values[2],
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
        Bn254::ZERO,
    ];
    for index in 0..19 {
        result.push(node[index] + link[index] + gate[index]);
    }
    let pair = if row.link.active {
        row.link.pair
    } else {
        row.gate.pair
    };
    for bit in 0..pair_bit_count(statement) {
        result.push(Bn254::from_bool(pair & (1 << bit) != 0));
    }
    for bit in 0..public_bit_count(statement) {
        result.push(Bn254::from_bool(row.link.public_offset & (1 << bit) != 0));
    }
    for bit in 0..level_bit_count(statement) {
        result.push(Bn254::from_bool(
            row.node.active && row.node.level & (1 << bit) != 0,
        ));
    }
    result
}

pub(crate) fn compact_constraint_degree(statement: Statement) -> usize {
    // Range/equality selectors have degree equal to their bit width. Account
    // for their row selectors and the equality polynomial used by sumcheck.
    6.max(
        pair_bit_count(statement)
            .max(public_bit_count(statement))
            .max(level_bit_count(statement))
            + 3,
    )
}

pub(crate) fn compact_residuals(
    values: &[Bn254],
    hashes: &[Bn254],
    statement: Statement,
) -> Vec<Bn254> {
    debug_assert_eq!(values.len(), compact_column_count(statement));
    debug_assert_eq!(hashes.len(), 8);
    let node_active = values[0];
    let link_active = values[1];
    let gate_active = values[2];
    let payload = &values[COMPACT_PAYLOAD_OFFSET..COMPACT_PAYLOAD_OFFSET + 19];
    let pair_bit_count = pair_bit_count(statement);
    let pair_bits =
        &values[COMPACT_PAYLOAD_OFFSET + 19..COMPACT_PAYLOAD_OFFSET + 19 + pair_bit_count];
    let public_bits = &values[COMPACT_PAYLOAD_OFFSET + 19 + pair_bit_count..];
    let public_bit_count = public_bit_count(statement);
    let public_bits = &public_bits[..public_bit_count];
    let level_bits = &values[COMPACT_PAYLOAD_OFFSET + 19 + pair_bit_count + public_bit_count..];
    let mut residuals = Vec::new();
    let boolean = |value: Bn254| value * (value - Bn254::ONE);
    residuals.extend([node_active, link_active, gate_active].map(boolean));
    residuals.push(node_active * link_active);
    residuals.push(node_active * gate_active);
    residuals.push(link_active * gate_active);

    let root = payload[0];
    let tree = [payload[1], payload[2], payload[3]];
    let kind = [payload[4], payload[5], payload[6]];
    let level = payload[7];
    let index = payload[8];
    let digest = [payload[9], payload[10]];
    let children = [payload[11], payload[12], payload[13], payload[14]];
    let leaf_values = [payload[15], payload[16]];
    let is_gate = payload[0];
    let is_public = payload[1];
    let is_add = payload[2];
    let is_mul = payload[3];
    let offsets = [payload[4], payload[5], payload[6]];
    let link_index = payload[7];
    let new = payload[9];
    let neighbor = payload[11];
    let link_pair = payload[16];
    let public_offset = payload[17];
    let gate_is_add = payload[0];
    let gate_is_mul = payload[1];
    let gate_pair = payload[2];
    let gate_start = payload[3];
    let gate_values = [payload[4], payload[5], payload[6]];

    for flag in tree.into_iter().chain(kind).chain([root]) {
        residuals.push(node_active * boolean(flag));
    }
    residuals.push(node_active * (tree.into_iter().sum::<Bn254>() - Bn254::ONE));
    residuals.push(node_active * (kind.into_iter().sum::<Bn254>() - Bn254::ONE));
    residuals.push(node_active * kind[0] * level);
    for &bit in level_bits {
        residuals.push(boolean(bit));
        residuals.push((Bn254::ONE - node_active) * bit);
    }
    residuals.push(node_active * (level - bits_value(level_bits)));
    residuals.push(node_active * (prefix_selector(level_bits, statement.height + 1) - Bn254::ONE));
    residuals.push(node_active * kind[2] * equality_selector(level_bits, 0));
    residuals.push(node_active * (root - equality_selector(level_bits, statement.height)));
    residuals.push(node_active * root * index);
    let root_assignment = root * tree[0];
    let root_permutation = root * tree[1];
    let root_neighbor = root * tree[2];
    residuals.push(node_active * root_assignment * (digest[0] - statement.old_assignment.root));
    residuals.push(node_active * root_assignment * (digest[1] - statement.new_assignment.root));
    residuals.push(node_active * root_permutation * (digest[0] - statement.permutation.root));
    residuals.push(node_active * root_permutation * (digest[1] - statement.permutation.root));
    residuals.push(node_active * root_neighbor * (digest[0] - statement.new_assignment.root));
    residuals.push(node_active * root_neighbor * (digest[1] - statement.new_assignment.root));
    let single_tree = tree[1] + tree[2];
    residuals.push(node_active * single_tree * (digest[0] - digest[1]));
    residuals.push(node_active * kind[1] * (digest[0] - digest[1]));
    residuals.push(node_active * single_tree * kind[0] * (leaf_values[0] - leaf_values[1]));

    for side in 0..2 {
        let leaf_expected = [leaf_values[side], index, Bn254::ONE, digest[side]];
        let internal_expected = [
            children[side],
            children[2 + side],
            level + Bn254::ONE,
            digest[side],
        ];
        let selector = node_active * (kind[0] + kind[2]);
        for field in 0..4 {
            let expected = kind[0] * leaf_expected[field] + kind[2] * internal_expected[field];
            residuals.push(selector * (hashes[4 * side + field] - expected));
        }
    }

    for flag in [is_gate, is_public, is_add, is_mul]
        .into_iter()
        .chain(offsets)
    {
        residuals.push(link_active * boolean(flag));
    }
    residuals.push(link_active * (is_gate + is_public - Bn254::ONE));
    residuals.push(link_active * (is_add + is_mul - is_gate));
    residuals.push(link_active * (offsets.into_iter().sum::<Bn254>() - is_gate));
    residuals.push(link_active * (new - neighbor));
    for &bit in pair_bits {
        residuals.push((link_active + gate_active) * boolean(bit));
    }
    let pair = bits_value(pair_bits);
    residuals.push(link_active * is_gate * (link_pair - pair));
    residuals.push(
        link_active * is_gate * (prefix_selector(pair_bits, statement.gate_pairs) - Bn254::ONE),
    );
    let offset = offsets[1] + Bn254::TWO * offsets[2];
    residuals.push(
        link_active
            * is_gate
            * (link_index - (Bn254::from_u64(6) * pair + Bn254::from_u64(3) * is_mul + offset)),
    );
    for &bit in public_bits {
        residuals.push(link_active * boolean(bit));
    }
    residuals.push(link_active * is_public * (public_offset - bits_value(public_bits)));
    residuals.push(
        link_active
            * is_public
            * (prefix_selector(public_bits, statement.public_inputs) - Bn254::ONE),
    );
    residuals.push(
        link_active
            * is_public
            * (link_index - Bn254::from_usize(6 * statement.gate_pairs) - public_offset),
    );

    for flag in [gate_is_add, gate_is_mul] {
        residuals.push(gate_active * boolean(flag));
    }
    residuals.push(gate_active * (gate_is_add + gate_is_mul - Bn254::ONE));
    residuals.push(gate_active * (gate_pair - pair));
    residuals.push(gate_active * (prefix_selector(pair_bits, statement.gate_pairs) - Bn254::ONE));
    residuals.push(
        gate_active * (gate_start - Bn254::from_u64(6) * pair - Bn254::from_u64(3) * gate_is_mul),
    );
    residuals.push(gate_active * gate_is_add * (gate_values[0] + gate_values[1] - gate_values[2]));
    residuals.push(gate_active * gate_is_mul * (gate_values[0] * gate_values[1] - gate_values[2]));

    residuals
}

/// Producer and reference tuples as algebraic functions of one compact row.
/// The product sumcheck evaluates this function directly, so the tuples need
/// no duplicate committed columns.
pub(crate) fn compact_route_values(values: &[Bn254], statement: Statement) -> Vec<Bn254> {
    debug_assert_eq!(values.len(), compact_column_count(statement));
    let node_active = values[0];
    let link_active = values[1];
    let gate_active = values[2];
    let payload = &values[COMPACT_PAYLOAD_OFFSET..COMPACT_PAYLOAD_OFFSET + 19];
    let root = payload[0];
    let tree = [payload[1], payload[2], payload[3]];
    let kind = [payload[4], payload[5], payload[6]];
    let level = payload[7];
    let index = payload[8];
    let digest = [payload[9], payload[10]];
    let children = [payload[11], payload[12], payload[13], payload[14]];
    let leaf_values = [payload[15], payload[16]];
    let is_gate = payload[0];
    let link_index = payload[7];
    let old = payload[8];
    let new = payload[9];
    let sigma = payload[10];
    let neighbor = payload[11];
    let link_digests = [payload[12], payload[13], payload[14], payload[15]];
    let gate_start = payload[3];
    let gate_values = [payload[4], payload[5], payload[6]];

    let tree_value = tree[0] + Bn254::TWO * tree[1] + Bn254::from_u64(3) * tree[2];
    let producer_expected = [
        [Bn254::ONE, tree_value, level, index, digest[0], digest[1]],
        [
            Bn254::from_u64(10) + tree_value,
            index,
            leaf_values[0],
            leaf_values[1],
            digest[0],
            digest[1],
        ],
        [
            Bn254::from_u64(GATE_TAG),
            link_index,
            new,
            Bn254::ZERO,
            Bn254::ZERO,
            Bn254::ZERO,
        ],
        [Bn254::ZERO; TUPLE_WIDTH],
    ];
    let producer_selectors = [
        node_active * (Bn254::ONE - root),
        node_active * kind[0],
        link_active * is_gate,
        Bn254::ZERO,
    ];
    let node_tuples = [
        [
            Bn254::ONE,
            tree_value,
            level - Bn254::ONE,
            Bn254::TWO * index,
            children[0],
            children[1],
        ],
        [
            Bn254::ONE,
            tree_value,
            level - Bn254::ONE,
            Bn254::TWO * index + Bn254::ONE,
            children[2],
            children[3],
        ],
        [Bn254::ZERO; TUPLE_WIDTH],
        [Bn254::ZERO; TUPLE_WIDTH],
    ];
    let link_tuples = [
        [
            Bn254::from_u64(ASSIGNMENT_LEAF_TAG),
            link_index,
            old,
            new,
            link_digests[0],
            link_digests[1],
        ],
        [
            Bn254::from_u64(PERMUTATION_LEAF_TAG),
            link_index,
            sigma,
            sigma,
            link_digests[2],
            link_digests[2],
        ],
        [
            Bn254::from_u64(NEIGHBOR_LEAF_TAG),
            sigma,
            neighbor,
            neighbor,
            link_digests[3],
            link_digests[3],
        ],
        [Bn254::ZERO; TUPLE_WIDTH],
    ];

    let mut routes = Vec::with_capacity(2 * ROUTE_LANES * TUPLE_WIDTH);
    for lane in 0..ROUTE_LANES {
        routes.extend(producer_expected[lane].map(|field| producer_selectors[lane] * field));
    }
    for lane in 0..ROUTE_LANES {
        let gate_tuple = [
            Bn254::from_u64(GATE_TAG),
            gate_start + Bn254::from_usize(lane),
            gate_values[lane.min(2)],
            Bn254::ZERO,
            Bn254::ZERO,
            Bn254::ZERO,
        ];
        for field in 0..TUPLE_WIDTH {
            routes.push(
                node_active * kind[2] * node_tuples[lane][field]
                    + link_active * link_tuples[lane][field]
                    + if lane < 3 {
                        gate_active * gate_tuple[field]
                    } else {
                        Bn254::ZERO
                    },
            );
        }
    }
    routes
}

fn bits_value(bits: &[Bn254]) -> Bn254 {
    bits.iter()
        .enumerate()
        .fold(Bn254::ZERO, |sum, (bit, &value)| {
            sum + Bn254::from_usize(1 << bit) * value
        })
}

fn prefix_selector(bits: &[Bn254], bound: usize) -> Bn254 {
    debug_assert!(bound <= 1usize << bits.len());
    if bound == 1usize << bits.len() {
        return Bn254::ONE;
    }

    // Sum the equality polynomials for all bit strings below `bound` without
    // enumerating them. Scan the bound from most to least significant bit,
    // accumulating the branch that first becomes smaller.
    let mut below = Bn254::ZERO;
    let mut equal_prefix = Bn254::ONE;
    for bit in (0..bits.len()).rev() {
        let value = bits[bit];
        if bound & (1 << bit) == 0 {
            equal_prefix *= Bn254::ONE - value;
        } else {
            below += equal_prefix * (Bn254::ONE - value);
            equal_prefix *= value;
        }
    }
    below
}

fn equality_selector(bits: &[Bn254], value: usize) -> Bn254 {
    debug_assert!(value < 1usize << bits.len());
    bits.iter()
        .enumerate()
        .fold(Bn254::ONE, |product, (bit, &coordinate)| {
            product
                * if value & (1 << bit) == 0 {
                    Bn254::ONE - coordinate
                } else {
                    coordinate
                }
        })
}

fn leaf_map(dag: &SparseMerkleDag) -> BTreeMap<usize, &NodeRow> {
    dag.rows()
        .iter()
        .filter(|row| row.kind == NodeKind::Leaf)
        .map(|row| (row.coordinate.index, row))
        .collect()
}

fn node_row(source: &NodeRow, root: bool) -> Row {
    let mut row = Row {
        active: true,
        node: NodeSection {
            active: true,
            root,
            tree: tree_flags(source.tree),
            kind: kind_flags(source.kind),
            level: source.coordinate.level,
            index: source.coordinate.index,
            digest: [source.digest.old, source.digest.new],
            children: source.children.map_or([Bn254::ZERO; 4], |children| {
                [
                    children[0].old,
                    children[0].new,
                    children[1].old,
                    children[1].new,
                ]
            }),
            values: source.leaf_values.unwrap_or([Bn254::ZERO; 2]),
        },
        ..Row::default()
    };
    row.hashes = match source.kind {
        NodeKind::Leaf => [
            [
                row.node.values[0],
                Bn254::from_usize(row.node.index),
                Bn254::ONE,
                row.node.digest[0],
            ],
            [
                row.node.values[1],
                Bn254::from_usize(row.node.index),
                Bn254::ONE,
                row.node.digest[1],
            ],
        ],
        NodeKind::Internal => [
            [
                row.node.children[0],
                row.node.children[2],
                Bn254::from_usize(row.node.level + 1),
                row.node.digest[0],
            ],
            [
                row.node.children[1],
                row.node.children[3],
                Bn254::from_usize(row.node.level + 1),
                row.node.digest[1],
            ],
        ],
        NodeKind::Boundary => [dummy_hash(), dummy_hash()],
    };
    let tree = source.tree as u64;
    if !root {
        row.producers[0] = [
            Bn254::ONE,
            Bn254::from_u64(tree),
            Bn254::from_usize(source.coordinate.level),
            Bn254::from_usize(source.coordinate.index),
            source.digest.old,
            source.digest.new,
        ];
    }
    if source.kind == NodeKind::Leaf {
        row.producers[1] = [
            Bn254::from_u64(10 + tree),
            Bn254::from_usize(source.coordinate.index),
            row.node.values[0],
            row.node.values[1],
            source.digest.old,
            source.digest.new,
        ];
    }
    if let Some(children) = source.children {
        for child in 0..2 {
            row.references[child] = [
                Bn254::ONE,
                Bn254::from_u64(tree),
                Bn254::from_usize(source.coordinate.level - 1),
                Bn254::from_usize(2 * source.coordinate.index + child),
                children[child].old,
                children[child].new,
            ];
        }
    }
    row
}

fn link_row(
    circuit: &Circuit,
    index: usize,
    old: Bn254,
    new: Bn254,
    assignment: &NodeRow,
    permutation: &NodeRow,
    neighbor: &NodeRow,
) -> Row {
    let sigma = circuit.permutation[index];
    let is_gate = index < 6 * circuit.n;
    let is_mul = is_gate && index % 6 >= 3;
    let offset = if is_gate { index % 3 } else { 0 };
    let mut row = Row {
        active: true,
        link: LinkSection {
            active: true,
            index,
            old,
            new,
            sigma,
            neighbor: neighbor.leaf_values.unwrap()[1],
            digests: [
                assignment.digest.old,
                assignment.digest.new,
                permutation.digest.old,
                neighbor.digest.old,
            ],
            is_gate,
            is_public: !is_gate,
            is_add: is_gate && !is_mul,
            is_mul,
            offsets: std::array::from_fn(|position| is_gate && position == offset),
            pair: if is_gate { index / 6 } else { 0 },
            public_offset: if is_gate { 0 } else { index - 6 * circuit.n },
        },
        ..Row::default()
    };
    row.references[0] = [
        Bn254::from_u64(ASSIGNMENT_LEAF_TAG),
        Bn254::from_usize(index),
        old,
        new,
        assignment.digest.old,
        assignment.digest.new,
    ];
    let sigma_value = Bn254::from_usize(sigma);
    row.references[1] = [
        Bn254::from_u64(PERMUTATION_LEAF_TAG),
        Bn254::from_usize(index),
        sigma_value,
        sigma_value,
        permutation.digest.old,
        permutation.digest.new,
    ];
    row.references[2] = [
        Bn254::from_u64(NEIGHBOR_LEAF_TAG),
        sigma_value,
        row.link.neighbor,
        row.link.neighbor,
        neighbor.digest.old,
        neighbor.digest.new,
    ];
    if is_gate {
        row.producers[2] = [
            Bn254::from_u64(GATE_TAG),
            Bn254::from_usize(index),
            new,
            Bn254::ZERO,
            Bn254::ZERO,
            Bn254::ZERO,
        ];
    }
    row
}

fn gate_row(circuit: &Circuit, new_tree: &MerkleTree, start: usize) -> Row {
    let is_mul = start % 6 == 3;
    let values = std::array::from_fn(|offset| new_tree.values()[start + offset]);
    let mut row = Row {
        active: true,
        gate: GateSection {
            active: true,
            is_add: !is_mul,
            is_mul,
            pair: start / 6,
            start,
            values,
        },
        ..Row::default()
    };
    for offset in 0..3 {
        row.references[offset] = [
            Bn254::from_u64(GATE_TAG),
            Bn254::from_usize(start + offset),
            values[offset],
            Bn254::ZERO,
            Bn254::ZERO,
            Bn254::ZERO,
        ];
    }
    let _ = circuit;
    row
}

fn tree_flags(tree: TreeId) -> [bool; 3] {
    [
        tree == TreeId::Assignment,
        tree == TreeId::Permutation,
        tree == TreeId::Neighbor,
    ]
}

fn kind_flags(kind: NodeKind) -> [bool; 3] {
    [
        kind == NodeKind::Leaf,
        kind == NodeKind::Boundary,
        kind == NodeKind::Internal,
    ]
}

fn dummy_hash() -> [Bn254; 4] {
    let mut state = [Bn254::ZERO; 3];
    poseidon2().permute_mut(&mut state);
    [Bn254::ZERO, Bn254::ZERO, Bn254::ZERO, state[0]]
}

struct RowVariables {
    active: Variable,
    node_active: Variable,
    root: Variable,
    tree: [Variable; 3],
    kind: [Variable; 3],
    level: Variable,
    index: Variable,
    digest: [Variable; 2],
    children: [Variable; 4],
    values: [Variable; 2],
    link_active: Variable,
    link_index: Variable,
    old: Variable,
    new: Variable,
    sigma: Variable,
    neighbor: Variable,
    link_digests: [Variable; 4],
    is_gate: Variable,
    is_public: Variable,
    is_add: Variable,
    is_mul: Variable,
    offsets: [Variable; 3],
    gate_active: Variable,
    gate_is_add: Variable,
    gate_is_mul: Variable,
    gate_start: Variable,
    gate_values: [Variable; 3],
    hashes: [[Variable; 4]; 2],
    producers: [[Variable; TUPLE_WIDTH]; ROUTE_LANES],
    references: [[Variable; TUPLE_WIDTH]; ROUTE_LANES],
}

fn row_program(row: &Row, statement: Statement) -> ConstraintProgram {
    let mut builder = ProgramBuilder::new(0);
    let variables = allocate_row(&mut builder, row);
    let zero = builder.constant(Bn254::ZERO);
    let one = builder.constant(Bn254::ONE);

    for flag in [
        variables.active,
        variables.node_active,
        variables.root,
        variables.link_active,
        variables.is_gate,
        variables.is_public,
        variables.is_add,
        variables.is_mul,
        variables.gate_active,
        variables.gate_is_add,
        variables.gate_is_mul,
    ]
    .into_iter()
    .chain(variables.tree)
    .chain(variables.kind)
    .chain(variables.offsets)
    {
        builder.assert_boolean(flag);
    }
    let type_sum = add_many(
        &mut builder,
        &[
            variables.node_active,
            variables.link_active,
            variables.gate_active,
        ],
        zero,
    );
    builder.assert_equal(type_sum, variables.active);
    let tree_sum = add_many(&mut builder, &variables.tree, zero);
    builder.assert_equal(tree_sum, variables.node_active);
    let kind_sum = add_many(&mut builder, &variables.kind, zero);
    builder.assert_equal(kind_sum, variables.node_active);

    let level_flags = (0..=statement.height)
        .map(|level| {
            let flag =
                builder.variable(Bn254::from_bool(row.node.active && row.node.level == level));
            builder.assert_boolean(flag);
            flag
        })
        .collect::<Vec<_>>();
    let level_sum = add_many(&mut builder, &level_flags, zero);
    builder.assert_equal(level_sum, variables.node_active);
    let weighted_level = level_flags
        .iter()
        .enumerate()
        .fold(zero, |sum, (level, &flag)| {
            let term = scale(&mut builder, flag, Bn254::from_usize(level), zero);
            builder.add(sum, term)
        });
    builder.assert_equal(weighted_level, variables.level);
    conditional_equal(&mut builder, variables.kind[0], variables.level, zero, zero);
    let internal_at_leaf = builder.mul(variables.kind[2], level_flags[0]);
    builder.assert_equal(internal_at_leaf, zero);
    builder.assert_equal(level_flags[statement.height], variables.root);

    let tree_value = linear(
        &mut builder,
        [
            (variables.tree[0], Bn254::ONE),
            (variables.tree[1], Bn254::TWO),
            (variables.tree[2], Bn254::from_u64(3)),
        ],
        Bn254::ZERO,
    );
    conditional_equal(&mut builder, variables.root, variables.index, zero, zero);
    let root_assignment = builder.mul(variables.root, variables.tree[0]);
    let root_permutation = builder.mul(variables.root, variables.tree[1]);
    let root_neighbor = builder.mul(variables.root, variables.tree[2]);
    let old_root = builder.constant(statement.old_assignment.root);
    let new_root = builder.constant(statement.new_assignment.root);
    let permutation_root = builder.constant(statement.permutation.root);
    conditional_equal(
        &mut builder,
        root_assignment,
        variables.digest[0],
        old_root,
        zero,
    );
    conditional_equal(
        &mut builder,
        root_assignment,
        variables.digest[1],
        new_root,
        zero,
    );
    for selector in [root_permutation, root_neighbor] {
        let root = if selector == root_permutation {
            permutation_root
        } else {
            new_root
        };
        conditional_equal(&mut builder, selector, variables.digest[0], root, zero);
        conditional_equal(&mut builder, selector, variables.digest[1], root, zero);
    }
    let single_tree = builder.add(variables.tree[1], variables.tree[2]);
    conditional_equal(
        &mut builder,
        single_tree,
        variables.digest[0],
        variables.digest[1],
        zero,
    );
    conditional_equal(
        &mut builder,
        variables.kind[1],
        variables.digest[0],
        variables.digest[1],
        zero,
    );
    let single_leaf = builder.mul(single_tree, variables.kind[0]);
    conditional_equal(
        &mut builder,
        single_leaf,
        variables.values[0],
        variables.values[1],
        zero,
    );

    constrain_hash_blocks(&mut builder, &variables, zero, one);
    constrain_link(&mut builder, row, statement, &variables, zero, one);
    constrain_gate(&mut builder, row, statement, &variables, zero, one);
    constrain_tuples(&mut builder, &variables, tree_value, zero, one);
    builder.finish()
}

fn allocate_row(builder: &mut ProgramBuilder, row: &Row) -> RowVariables {
    let mut variable = |value| builder.variable(value);
    RowVariables {
        active: variable(Bn254::from_bool(row.active)),
        node_active: variable(Bn254::from_bool(row.node.active)),
        root: variable(Bn254::from_bool(row.node.root)),
        tree: row.node.tree.map(|flag| variable(Bn254::from_bool(flag))),
        kind: row.node.kind.map(|flag| variable(Bn254::from_bool(flag))),
        level: variable(Bn254::from_usize(row.node.level)),
        index: variable(Bn254::from_usize(row.node.index)),
        digest: row.node.digest.map(&mut variable),
        children: row.node.children.map(&mut variable),
        values: row.node.values.map(&mut variable),
        link_active: variable(Bn254::from_bool(row.link.active)),
        link_index: variable(Bn254::from_usize(row.link.index)),
        old: variable(row.link.old),
        new: variable(row.link.new),
        sigma: variable(Bn254::from_usize(row.link.sigma)),
        neighbor: variable(row.link.neighbor),
        link_digests: row.link.digests.map(&mut variable),
        is_gate: variable(Bn254::from_bool(row.link.is_gate)),
        is_public: variable(Bn254::from_bool(row.link.is_public)),
        is_add: variable(Bn254::from_bool(row.link.is_add)),
        is_mul: variable(Bn254::from_bool(row.link.is_mul)),
        offsets: row
            .link
            .offsets
            .map(|flag| variable(Bn254::from_bool(flag))),
        gate_active: variable(Bn254::from_bool(row.gate.active)),
        gate_is_add: variable(Bn254::from_bool(row.gate.is_add)),
        gate_is_mul: variable(Bn254::from_bool(row.gate.is_mul)),
        gate_start: variable(Bn254::from_usize(row.gate.start)),
        gate_values: row.gate.values.map(&mut variable),
        hashes: row.hashes.map(|hash| hash.map(&mut variable)),
        producers: row.producers.map(|tuple| tuple.map(&mut variable)),
        references: row.references.map(|tuple| tuple.map(&mut variable)),
    }
}

fn constrain_hash_blocks(
    builder: &mut ProgramBuilder,
    row: &RowVariables,
    zero: Variable,
    one: Variable,
) {
    for old_new in 0..2 {
        let leaf_expected = [row.values[old_new], row.index, one, row.digest[old_new]];
        let level_domain = linear(
            builder,
            [
                (row.level, Bn254::ONE),
                (zero, Bn254::ZERO),
                (zero, Bn254::ZERO),
            ],
            Bn254::ONE,
        );
        let internal_expected = [
            row.children[old_new],
            row.children[2 + old_new],
            level_domain,
            row.digest[old_new],
        ];
        for field in 0..4 {
            let leaf = builder.mul(row.kind[0], leaf_expected[field]);
            let internal = builder.mul(row.kind[2], internal_expected[field]);
            let expected = builder.add(leaf, internal);
            let hash_selector = builder.add(row.kind[0], row.kind[2]);
            conditional_equal(
                builder,
                hash_selector,
                row.hashes[old_new][field],
                expected,
                zero,
            );
        }
    }
}

fn constrain_link(
    builder: &mut ProgramBuilder,
    native: &Row,
    statement: Statement,
    row: &RowVariables,
    zero: Variable,
    one: Variable,
) {
    let link_kind_sum = builder.add(row.is_gate, row.is_public);
    builder.assert_equal(link_kind_sum, row.link_active);
    let gate_kind_sum = builder.add(row.is_add, row.is_mul);
    builder.assert_equal(gate_kind_sum, row.is_gate);
    let offset_sum = add_many(builder, &row.offsets, zero);
    builder.assert_equal(offset_sum, row.is_gate);
    conditional_equal(builder, row.link_active, row.new, row.neighbor, zero);

    let bit_count = statement.height.max(1);
    let (pair, pair_bits) = allocate_bits(builder, native.link.pair, bit_count, zero);
    let pair_bound = less_than_constant(builder, &pair_bits, statement.gate_pairs, zero, one);
    conditional_equal(builder, row.is_gate, pair_bound, one, zero);
    let offset = linear(
        builder,
        [
            (row.offsets[1], Bn254::ONE),
            (row.offsets[2], Bn254::TWO),
            (zero, Bn254::ZERO),
        ],
        Bn254::ZERO,
    );
    let gate_index = linear(
        builder,
        [
            (pair, Bn254::from_u64(6)),
            (row.is_mul, Bn254::from_u64(3)),
            (offset, Bn254::ONE),
        ],
        Bn254::ZERO,
    );
    conditional_equal(builder, row.is_gate, row.link_index, gate_index, zero);

    let public_bit_count = statement
        .public_inputs
        .max(1)
        .next_power_of_two()
        .trailing_zeros() as usize;
    let (public_offset, public_bits) = allocate_bits(
        builder,
        native.link.public_offset,
        public_bit_count.max(1),
        zero,
    );
    let public_bound = if statement.public_inputs == 0 {
        zero
    } else {
        less_than_constant(builder, &public_bits, statement.public_inputs, zero, one)
    };
    conditional_equal(builder, row.is_public, public_bound, one, zero);
    let public_index = linear(
        builder,
        [
            (public_offset, Bn254::ONE),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        Bn254::from_usize(6 * statement.gate_pairs),
    );
    conditional_equal(builder, row.is_public, row.link_index, public_index, zero);
}

fn constrain_gate(
    builder: &mut ProgramBuilder,
    native: &Row,
    statement: Statement,
    row: &RowVariables,
    zero: Variable,
    one: Variable,
) {
    let gate_kind_sum = builder.add(row.gate_is_add, row.gate_is_mul);
    builder.assert_equal(gate_kind_sum, row.gate_active);
    let (pair, pair_bits) = allocate_bits(builder, native.gate.pair, statement.height.max(1), zero);
    let in_range = less_than_constant(builder, &pair_bits, statement.gate_pairs, zero, one);
    conditional_equal(builder, row.gate_active, in_range, one, zero);
    let expected_start = linear(
        builder,
        [
            (pair, Bn254::from_u64(6)),
            (row.gate_is_mul, Bn254::from_u64(3)),
            (zero, Bn254::ZERO),
        ],
        Bn254::ZERO,
    );
    conditional_equal(
        builder,
        row.gate_active,
        row.gate_start,
        expected_start,
        zero,
    );
    let sum = builder.add(row.gate_values[0], row.gate_values[1]);
    conditional_equal(builder, row.gate_is_add, sum, row.gate_values[2], zero);
    let product = builder.mul(row.gate_values[0], row.gate_values[1]);
    conditional_equal(builder, row.gate_is_mul, product, row.gate_values[2], zero);
}

fn constrain_tuples(
    builder: &mut ProgramBuilder,
    row: &RowVariables,
    tree_value: Variable,
    zero: Variable,
    one: Variable,
) {
    let non_root = linear(
        builder,
        [
            (row.node_active, Bn254::ONE),
            (row.root, -Bn254::ONE),
            (zero, Bn254::ZERO),
        ],
        Bn254::ZERO,
    );
    let level_minus_one = linear(
        builder,
        [
            (row.level, Bn254::ONE),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        -Bn254::ONE,
    );
    let left_index = scale(builder, row.index, Bn254::TWO, zero);
    let right_index = linear(
        builder,
        [
            (left_index, Bn254::ONE),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        Bn254::ONE,
    );
    assert_scaled_tuple(
        builder,
        &row.producers[0],
        non_root,
        [
            one,
            tree_value,
            row.level,
            row.index,
            row.digest[0],
            row.digest[1],
        ],
        zero,
    );
    let leaf_tag = linear(
        builder,
        [
            (tree_value, Bn254::ONE),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        Bn254::from_u64(10),
    );
    assert_scaled_tuple(
        builder,
        &row.producers[1],
        row.kind[0],
        [
            leaf_tag,
            row.index,
            row.values[0],
            row.values[1],
            row.digest[0],
            row.digest[1],
        ],
        zero,
    );
    let gate_tag = builder.constant(Bn254::from_u64(GATE_TAG));
    assert_scaled_tuple(
        builder,
        &row.producers[2],
        row.is_gate,
        [gate_tag, row.link_index, row.new, zero, zero, zero],
        zero,
    );
    assert_zero_tuple(builder, &row.producers[3], zero);

    let node_left = [
        one,
        tree_value,
        level_minus_one,
        left_index,
        row.children[0],
        row.children[1],
    ];
    let node_right = [
        one,
        tree_value,
        level_minus_one,
        right_index,
        row.children[2],
        row.children[3],
    ];
    let assignment_tag = builder.constant(Bn254::from_u64(ASSIGNMENT_LEAF_TAG));
    let permutation_tag = builder.constant(Bn254::from_u64(PERMUTATION_LEAF_TAG));
    let neighbor_tag = builder.constant(Bn254::from_u64(NEIGHBOR_LEAF_TAG));
    let link_tuples = [
        [
            assignment_tag,
            row.link_index,
            row.old,
            row.new,
            row.link_digests[0],
            row.link_digests[1],
        ],
        [
            permutation_tag,
            row.link_index,
            row.sigma,
            row.sigma,
            row.link_digests[2],
            row.link_digests[2],
        ],
        [
            neighbor_tag,
            row.sigma,
            row.neighbor,
            row.neighbor,
            row.link_digests[3],
            row.link_digests[3],
        ],
    ];
    let gate_tuples: [[Variable; TUPLE_WIDTH]; 3] = std::array::from_fn(|offset| {
        let index = linear(
            builder,
            [
                (row.gate_start, Bn254::ONE),
                (zero, Bn254::ZERO),
                (zero, Bn254::ZERO),
            ],
            Bn254::from_usize(offset),
        );
        [gate_tag, index, row.gate_values[offset], zero, zero, zero]
    });
    for lane in 0..3 {
        let node_tuple = if lane == 0 { node_left } else { node_right };
        let node_selector = if lane < 2 { row.kind[2] } else { zero };
        assert_sum_of_scaled_tuples(
            builder,
            &row.references[lane],
            &[
                (node_selector, node_tuple),
                (row.link_active, link_tuples[lane]),
                (row.gate_active, gate_tuples[lane]),
            ],
            zero,
        );
    }
    assert_zero_tuple(builder, &row.references[3], zero);
}

fn assert_scaled_tuple(
    builder: &mut ProgramBuilder,
    actual: &[Variable; TUPLE_WIDTH],
    selector: Variable,
    expected: [Variable; TUPLE_WIDTH],
    zero: Variable,
) {
    for (&actual, expected) in actual.iter().zip(expected) {
        let scaled = builder.mul(selector, expected);
        builder.assert_equal(actual, scaled);
    }
    let _ = zero;
}

fn assert_sum_of_scaled_tuples(
    builder: &mut ProgramBuilder,
    actual: &[Variable; TUPLE_WIDTH],
    terms: &[(Variable, [Variable; TUPLE_WIDTH])],
    zero: Variable,
) {
    for field in 0..TUPLE_WIDTH {
        let expected = terms.iter().fold(zero, |sum, (selector, tuple)| {
            let scaled = builder.mul(*selector, tuple[field]);
            builder.add(sum, scaled)
        });
        builder.assert_equal(actual[field], expected);
    }
}

fn assert_zero_tuple(
    builder: &mut ProgramBuilder,
    tuple: &[Variable; TUPLE_WIDTH],
    zero: Variable,
) {
    for &field in tuple {
        builder.assert_equal(field, zero);
    }
}

fn add_many(builder: &mut ProgramBuilder, values: &[Variable], zero: Variable) -> Variable {
    values
        .iter()
        .copied()
        .fold(zero, |sum, value| builder.add(sum, value))
}

fn scale(
    builder: &mut ProgramBuilder,
    value: Variable,
    coefficient: Bn254,
    zero: Variable,
) -> Variable {
    linear(
        builder,
        [
            (value, coefficient),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        Bn254::ZERO,
    )
}

fn less_than_constant(
    builder: &mut ProgramBuilder,
    value_bits: &[Variable],
    bound: usize,
    zero: Variable,
    one: Variable,
) -> Variable {
    if bound == 1usize << value_bits.len() {
        one
    } else {
        let bound_bits = constant_bits(builder, bound, value_bits.len());
        less_than(builder, value_bits, &bound_bits, zero, one)
    }
}

#[cfg(test)]
mod tests {
    use crate::gkr::{
        periodic_constraint_circuit, periodic_constraint_input, prove_layered, verify_layered,
    };

    use super::*;

    fn assert_compact_rows(table: &TransitionTable) {
        let witness = table.compact_witness();
        let statement = table.statement();
        for row in 0..table.row_count() {
            let compact = witness
                .columns
                .iter()
                .map(|column| column[row])
                .collect::<Vec<_>>();
            let hashes = (0..2)
                .flat_map(|side| {
                    (0..4).map({
                        let hash_inputs = &witness.hash_inputs;
                        move |field| hash_inputs[field][2 * row + side]
                    })
                })
                .collect::<Vec<_>>();
            assert!(
                compact_residuals(&compact, &hashes, statement)
                    .into_iter()
                    .all(|residual| residual == Bn254::ZERO)
            );

            let expected_routes = table.rows[row]
                .producers
                .into_iter()
                .flatten()
                .chain(table.rows[row].references.into_iter().flatten())
                .collect::<Vec<_>>();
            assert_eq!(compact_route_values(&compact, statement), expected_routes);
        }
    }

    fn fixture() -> (
        Circuit,
        MerkleTree,
        MerkleTree,
        MerkleTree,
        Vec<(usize, Bn254, Bn254)>,
    ) {
        let n = 3;
        let n0 = 2;
        let m = 6 * n + n0;
        let circuit = Circuit::new(n, n0, (0..m).collect()).unwrap();
        let permutation = MerkleTree::new((0..m).map(Bn254::from_usize).collect()).unwrap();
        let mut old_values = vec![Bn254::ZERO; m];
        for pair in 0..n {
            old_values[6 * pair] = Bn254::from_usize(pair + 2);
            old_values[6 * pair + 1] = Bn254::from_usize(pair + 3);
            old_values[6 * pair + 2] = old_values[6 * pair] + old_values[6 * pair + 1];
            old_values[6 * pair + 3] = Bn254::from_usize(pair + 4);
            old_values[6 * pair + 4] = Bn254::from_usize(pair + 5);
            old_values[6 * pair + 5] = old_values[6 * pair + 3] * old_values[6 * pair + 4];
        }
        let old = MerkleTree::new(old_values.clone()).unwrap();
        let mut new_values = old_values;
        new_values[0] = Bn254::from_u64(9);
        new_values[1] = Bn254::from_u64(10);
        new_values[2] = Bn254::from_u64(19);
        new_values[18] = Bn254::from_u64(77);
        let new = MerkleTree::new(new_values.clone()).unwrap();
        let updates = [0usize, 1, 2, 18]
            .map(|index| (index, old.values()[index], new_values[index]))
            .to_vec();
        (circuit, permutation, old, new, updates)
    }

    fn prove_local(table: &TransitionTable) -> Result<(), crate::gkr::Error> {
        let circuit = periodic_constraint_circuit(&table.programs()[0], table.row_count());
        let input = periodic_constraint_input(table.programs());
        let seed = [Bn254::from_u64(303)];
        let (proof, claims) = prove_layered(&circuit, input.clone(), &[], &seed)?;
        let verified = verify_layered(&circuit, &[], &seed, &proof)?;
        let evaluations = verified
            .mle_points()
            .map(|point| super::super::gkr::mle_evaluation_low(&input, point));
        verified.verify_mle_openings(&evaluations)?;
        assert_eq!(claims.transcript_binding(), verified.transcript_binding());
        Ok(())
    }

    #[test]
    fn local_relation_links_assignment_sigma_neighbor_and_gate_rows() {
        let (circuit, permutation, old, new, updates) = fixture();
        let table = TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        prove_local(&table).unwrap();
        assert_compact_rows(&table);
        assert_eq!(table.poseidon_inputs().len(), 8 * table.row_count());
        let challenges = RoutingChallenges {
            theta: Bn254::from_u64(17),
            gamma: Bn254::from_u64(29),
        };
        table.product_factors(challenges).verify().unwrap();
    }

    #[test]
    fn compact_relation_and_derived_routes_match_the_reference_rows() {
        let (circuit, permutation, old, new, updates) = fixture();
        let table = TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        assert_compact_rows(&table);

        let statement = table.statement();
        let witness = table.compact_witness();
        let row = table.rows.iter().position(|row| row.node.active).unwrap();
        let mut compact = witness
            .columns
            .iter()
            .map(|column| column[row])
            .collect::<Vec<_>>();
        let hashes = (0..2)
            .flat_map(|side| {
                (0..4).map({
                    let hash_inputs = &witness.hash_inputs;
                    move |field| hash_inputs[field][2 * row + side]
                })
            })
            .collect::<Vec<_>>();
        compact[COMPACT_PAYLOAD_OFFSET + 9] += Bn254::ONE;
        assert!(
            compact_residuals(&compact, &hashes, statement)
                .into_iter()
                .any(|residual| residual != Bn254::ZERO)
        );

        compact[COMPACT_PAYLOAD_OFFSET + 9] -= Bn254::ONE;
        let level_bit_offset =
            COMPACT_PAYLOAD_OFFSET + 19 + pair_bit_count(statement) + public_bit_count(statement);
        compact[level_bit_offset] = Bn254::ONE - compact[level_bit_offset];
        assert!(
            compact_residuals(&compact, &hashes, statement)
                .into_iter()
                .any(|residual| residual != Bn254::ZERO)
        );
    }

    #[test]
    fn prefix_selector_matches_the_enumerated_multilinear_polynomial() {
        for width in 1..=6 {
            let bits = (0..width)
                .map(|bit| Bn254::from_usize(bit + 2))
                .collect::<Vec<_>>();
            for bound in 1..=1usize << width {
                let enumerated = (0..bound)
                    .map(|value| equality_selector(&bits, value))
                    .sum::<Bn254>();
                assert_eq!(prefix_selector(&bits, bound), enumerated);
            }
        }
    }

    #[test]
    fn default_transition_shape_rounds_to_256_columns() {
        let gate_pairs = 1usize << 15;
        let public_inputs = 1usize << 8;
        let assignment_len = 6 * gate_pairs + public_inputs;
        let commitment = Commitment {
            root: Bn254::ZERO,
            len: assignment_len,
        };
        let statement = Statement {
            gate_pairs,
            public_inputs,
            assignment_len,
            height: assignment_len.next_power_of_two().trailing_zeros() as usize,
            permutation: commitment,
            old_assignment: commitment,
            new_assignment: commitment,
        };

        assert_eq!(pair_bit_count(statement), 15);
        assert_eq!(public_bit_count(statement), 8);
        assert_eq!(level_bit_count(statement), 5);
        assert_eq!(compact_column_count(statement), 50);
        assert_eq!(
            compact_column_count(statement) + POSEIDON_COLUMNS_PER_HASH + 1,
            246
        );
        assert_eq!(compact_main_width(statement), 256);
        assert_eq!(compact_constraint_degree(statement), 18);
    }

    #[test]
    fn compact_shape_for_2_10_gates_and_2_4_updates_is_2_18() {
        let gate_rows = 1usize << 10;
        let gate_pairs = gate_rows / 2;
        let public_inputs = 1usize << 8;
        let assignment_len = 6 * gate_pairs + public_inputs;
        let circuit =
            Circuit::new(gate_pairs, public_inputs, (0..assignment_len).collect()).unwrap();
        let indices = (0..3 * (1usize << 4)).collect::<Vec<_>>();
        let (rows, main_width, _) = estimate_shape(&circuit, &indices).unwrap();
        assert_eq!(rows, 1 << 9);
        assert_eq!(main_width, 1 << 8);
        assert_eq!(2 * rows * main_width, 1 << 18);
    }

    #[test]
    fn local_relation_rejects_wrong_neighbor_and_gate_value() {
        let (circuit, permutation, old, new, updates) = fixture();
        let mut table =
            TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        let link = table.rows.iter_mut().find(|row| row.link.active).unwrap();
        link.link.neighbor += Bn254::ONE;
        table.rebuild_programs();
        assert!(prove_local(&table).is_err());

        let mut table =
            TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        let gate = table.rows.iter_mut().find(|row| row.gate.active).unwrap();
        gate.gate.values[2] += Bn254::ONE;
        table.rebuild_programs();
        assert!(prove_local(&table).is_err());
    }

    #[test]
    fn public_input_updates_are_supported_and_gate_closure_is_enforced() {
        let (circuit, permutation, old, new, updates) = fixture();
        TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        let incomplete = vec![updates[0], updates[1], updates[3]];
        assert!(matches!(
            TransitionTable::build(&circuit, &permutation, &old, &new, &incomplete),
            Err(Error::Circuit(CircuitError::InvalidUpdateSet { .. }))
        ));
    }
}
