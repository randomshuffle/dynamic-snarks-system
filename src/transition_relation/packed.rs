//! Compact partial trees and a separate small update/gate table.
use super::*;
use p3_field::Field;

pub(crate) const NODE_COLUMNS: usize = 14;
pub(crate) const NODE_WIDTH: usize = 16;
// Degree-four type indicators times the tree-id cubic, then the equality factor.
pub(crate) const NODE_DEGREE: usize = 8;
// Node tuples have degree five; auxiliary tuples degree three. Multiplying
// their shifted factors gives degree eight, then the equality factor adds one.
pub(crate) const ROUTE_DEGREE: usize = 9;

// Old compact-row columns retained in E, in their new order. Drop the unused
// node flag (0), duplicate neighbor value (14), reconstructed index copies
// (19,20), and reserved zero (21). Gate rows reuse the same payload slots.
const AUXILIARY_SOURCE_COLUMNS: [usize; 17] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18];
const AUXILIARY_BASE_COLUMNS: usize = AUXILIARY_SOURCE_COLUMNS.len();

pub(crate) struct Witness {
    pub(crate) nodes: Vec<Vec<Bn254>>,
    pub(crate) updates: Vec<Vec<Bn254>>,
    pub(crate) hash_inputs: [Vec<Bn254>; 4],
    pub(crate) update_count: usize,
    pub(crate) gate_count: usize,
}

pub(crate) fn auxiliary_columns(statement: Statement) -> usize {
    auxiliary_column_count(statement.gate_pairs, statement.public_inputs)
}

pub(crate) fn auxiliary_column_count(gate_pairs: usize, public_inputs: usize) -> usize {
    AUXILIARY_BASE_COLUMNS + bit_count(gate_pairs).max(bit_count(public_inputs))
}

pub(crate) fn auxiliary_degree(statement: Statement) -> usize {
    let range_degree = |width, bound| {
        if bound == 0 || bound == 1usize << width {
            0
        } else {
            width
        }
    };
    6.max(range_degree(pair_bit_count(statement), statement.gate_pairs) + 3)
        .max(range_degree(public_bit_count(statement), statement.public_inputs) + 3)
}

impl TransitionTable {
    pub(crate) fn packed_witness(&self) -> Witness {
        let mut node_rows = self
            .rows
            .iter()
            .filter(|r| r.node.active)
            .collect::<Vec<_>>();
        node_rows.sort_by_key(|r| !r.node.root);
        let auxiliary = self
            .rows
            .iter()
            .filter(|r| r.link.active || r.gate.active)
            .collect::<Vec<_>>();
        let update_count = auxiliary.iter().filter(|r| r.link.active).count();
        let gate_count = auxiliary.len() - update_count;
        let auxiliary_rows = auxiliary.len().max(2).next_power_of_two();
        let rows = node_rows
            .len()
            .max(auxiliary_rows)
            .max(4)
            .next_power_of_two();
        let mut nodes = vec![vec![Bn254::ZERO; rows]; NODE_COLUMNS];
        let mut hash_inputs = std::array::from_fn(|_| vec![Bn254::ZERO; 2 * rows]);
        static DUMMY: std::sync::OnceLock<[Bn254; 4]> = std::sync::OnceLock::new();
        let dummy = *DUMMY.get_or_init(dummy_hash);
        for row in 0..rows {
            let mut values = [Bn254::ZERO; NODE_COLUMNS];
            values[..4].copy_from_slice(&dummy);
            values[4..8].copy_from_slice(&dummy);
            if let Some(source) = node_rows.get(row) {
                for side in 0..2 {
                    values[4 * side..4 * side + 4].copy_from_slice(&source.hashes[side]);
                }
                values[8] = Bn254::from_u64(if source.node.root {
                    4
                } else if source.node.kind[0] {
                    1
                } else if source.node.kind[1] {
                    2
                } else {
                    3
                });
                values[9] =
                    Bn254::from_usize(source.node.tree.iter().position(|&x| x).unwrap() + 1);
                values[10] = Bn254::from_usize(source.node.level);
                values[11] = Bn254::from_usize(
                    (1usize << (self.statement.height - source.node.level)) + source.node.index,
                );
                if source.node.kind[1] {
                    values[12] = source.node.digest[0];
                    values[13] = source.node.digest[1];
                } else if source.node.kind[2] {
                    values[12] = values[10].inverse();
                }
            }
            for column in 0..NODE_COLUMNS {
                nodes[column][row] = values[column];
            }
            for word in 0..4 {
                hash_inputs[word][2 * row] = values[word];
                hash_inputs[word][2 * row + 1] = values[4 + word];
            }
        }
        let mut updates =
            vec![vec![Bn254::ZERO; auxiliary_rows]; auxiliary_columns(self.statement)];
        for (row, source) in auxiliary.iter().enumerate() {
            let values = compact_row(source, self.statement);
            for (column, &old_column) in AUXILIARY_SOURCE_COLUMNS.iter().enumerate() {
                updates[column][row] = values[old_column];
            }
            let index = if source.link.is_public {
                source.link.public_offset
            } else if source.link.active {
                source.link.pair
            } else {
                source.gate.pair
            };
            for (bit, column) in updates[AUXILIARY_BASE_COLUMNS..].iter_mut().enumerate() {
                column[row] = Bn254::from_bool(index & (1usize << bit) != 0);
            }
        }
        Witness {
            nodes,
            updates,
            hash_inputs,
            update_count,
            gate_count,
        }
    }
}

pub(crate) fn type_selectors(tau: Bn254) -> [Bn254; 5] {
    // Denominators are 24,-6,4,-6,24; inverses are constants.
    static INV: std::sync::OnceLock<[Bn254; 5]> = std::sync::OnceLock::new();
    let inv = INV.get_or_init(|| {
        [
            Bn254::from_u64(24).inverse(),
            -Bn254::from_u64(6).inverse(),
            Bn254::from_u64(4).inverse(),
            -Bn254::from_u64(6).inverse(),
            Bn254::from_u64(24).inverse(),
        ]
    });
    std::array::from_fn(|kind| {
        (0..5)
            .filter(|&i| i != kind)
            .fold(inv[kind], |p, i| p * (tau - Bn254::from_usize(i)))
    })
}

pub(crate) fn node_residuals(
    values: &[Bn254],
    roots: &[Bn254],
    statement: Statement,
) -> Vec<Bn254> {
    let [pad, leaf, boundary, internal, root] = type_selectors(values[8]);
    let tree = values[9];
    let ell = values[10];
    let heap = values[11];
    let active = Bn254::ONE - pad;
    let computed = internal + root;
    let mut residuals = vec![
        (0..5).fold(Bn254::ONE, |p, i| p * (values[8] - Bn254::from_usize(i))),
        active * (tree - Bn254::ONE) * (tree - Bn254::TWO) * (tree - Bn254::from_u64(3)),
        root - roots.iter().copied().sum::<Bn254>(),
        root * (ell - Bn254::from_usize(statement.height)),
        root * (heap - Bn254::ONE),
        leaf * ell,
        computed * (ell * values[12] - Bn254::ONE),
        computed * values[13],
        leaf * values[12],
        leaf * values[13],
        boundary * (values[12] - values[13]),
    ];
    let root_digests = [
        [statement.old_assignment.root, statement.new_assignment.root],
        [statement.permutation.root; 2],
        [statement.new_assignment.root; 2],
    ];
    for (tree_index, &selector) in roots.iter().enumerate() {
        residuals.push(selector * (tree - Bn254::from_usize(tree_index + 1)));
        for side in 0..2 {
            residuals.push(selector * (values[4 * side + 3] - root_digests[tree_index][side]));
        }
    }
    static DUMMY: std::sync::OnceLock<[Bn254; 4]> = std::sync::OnceLock::new();
    let dummy = *DUMMY.get_or_init(dummy_hash);
    for side in 0..2 {
        let hash = &values[4 * side..4 * side + 4];
        residuals.push(leaf * (hash[1] - heap + Bn254::from_usize(1 << statement.height)));
        residuals.push(leaf * (hash[2] - Bn254::ONE));
        residuals.push(computed * (hash[2] - ell - Bn254::ONE));
        for word in 0..4 {
            residuals.push((pad + boundary) * (hash[word] - dummy[word]));
        }
    }
    for word in 0..4 {
        residuals.push(active * (tree - Bn254::ONE) * (values[word] - values[4 + word]));
    }
    residuals
}

pub(crate) fn auxiliary_residuals(
    values: &[Bn254],
    selectors: &[Bn254],
    statement: Statement,
) -> Vec<Bn254> {
    let extended = expand_auxiliary(values, statement);
    let mut residuals = compact_residuals(&extended, &[Bn254::ZERO; 8], statement);
    residuals.extend([values[0] - selectors[0], values[1] - selectors[1]]);
    // Each row interprets the shared bits in exactly one index domain. Keep
    // unused high bits zero with low-degree checks rather than widening a
    // range selector (which could increase the sumcheck degree).
    let gate = values[1] + values[0] * values[2];
    let public = values[0] * values[3];
    let bits = &values[AUXILIARY_BASE_COLUMNS..];
    residuals.extend(bits[pair_bit_count(statement)..].iter().map(|&b| gate * b));
    residuals.extend(
        bits[public_bit_count(statement)..]
            .iter()
            .map(|&b| public * b),
    );
    residuals
}

/// Reconstruct the previous relation's inputs by linear substitutions. This
/// keeps the existing range, gate, and routing equations while committing only
/// independent fields. In particular the neighbor opening authenticates beta
/// directly, so a separate neighbor-value equality/column is unnecessary.
fn expand_auxiliary(values: &[Bn254], statement: Statement) -> Vec<Bn254> {
    debug_assert_eq!(values.len(), auxiliary_columns(statement));
    let mut extended = vec![Bn254::ZERO; compact_column_count(statement)];
    for (&value, &old_column) in values.iter().zip(&AUXILIARY_SOURCE_COLUMNS) {
        extended[old_column] = value;
    }
    extended[14] = extended[12];
    let bits = &values[AUXILIARY_BASE_COLUMNS..];
    let pairs = &bits[..pair_bit_count(statement)];
    let public = &bits[..public_bit_count(statement)];
    extended[19] = bits_value(pairs);
    extended[20] = bits_value(public);
    extended[22..22 + pairs.len()].copy_from_slice(pairs);
    extended[22 + pairs.len()..22 + pairs.len() + public.len()].copy_from_slice(public);
    extended
}

pub(crate) fn node_routes(v: &[Bn254], statement: Statement) -> Vec<Bn254> {
    let [_pad, leaf, boundary, internal, root] = type_selectors(v[8]);
    let nonroot = leaf + boundary + internal;
    let computed_nonroot = leaf + internal;
    let branch = internal + root;
    let tree = v[9];
    let ell = v[10];
    let heap = v[11];
    let position = heap - Bn254::from_usize(1 << statement.height);
    let mut routes = vec![Bn254::ZERO; 48];
    routes[..6].copy_from_slice(&[
        nonroot,
        nonroot * tree,
        nonroot * ell,
        nonroot * heap,
        computed_nonroot * v[3] + boundary * v[12],
        computed_nonroot * v[7] + boundary * v[13],
    ]);
    routes[6..12].copy_from_slice(&[
        leaf * (Bn254::from_u64(10) + tree),
        leaf * position,
        leaf * v[0],
        leaf * v[4],
        leaf * v[3],
        leaf * v[7],
    ]);
    for child in 0..2 {
        let tuple = [
            Bn254::ONE,
            tree,
            ell - Bn254::ONE,
            Bn254::TWO * heap + Bn254::from_usize(child),
            v[child],
            v[4 + child],
        ];
        for field in 0..6 {
            routes[24 + 6 * child + field] = branch * tuple[field];
        }
    }
    routes
}

pub(crate) fn auxiliary_routes(values: &[Bn254], statement: Statement) -> Vec<Bn254> {
    compact_route_values(&expand_auxiliary(values, statement), statement)
}

pub(crate) fn estimate_shape(
    circuit: &Circuit,
    indices: &[usize],
) -> Result<(usize, usize, usize), Error> {
    let (_, _, hashes) = super::estimate_endpoint_shape(circuit, indices)?;
    let mut physical = indices
        .iter()
        .map(|&i| circuit.assignment_leaf_index(i))
        .collect::<Vec<_>>();
    physical.sort_unstable();
    let mut neighbors = indices
        .iter()
        .map(|&i| circuit.assignment_leaf_index(circuit.permutation[i]))
        .collect::<Vec<_>>();
    neighbors.sort_unstable();
    let nodes = 2 * SparseMerkleDag::shape(circuit.assignment_tree_len(), &physical)?.0
        + SparseMerkleDag::shape(circuit.assignment_tree_len(), &neighbors)?.0;
    let gates = indices
        .iter()
        .copied()
        .filter(|&i| i < 6 * circuit.n)
        .map(|i| i - i % 3)
        .collect::<BTreeSet<_>>()
        .len();
    Ok((
        nodes
            .max((indices.len() + gates).max(2).next_power_of_two())
            .max(4)
            .next_power_of_two(),
        NODE_WIDTH,
        hashes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(pairs: usize, public: usize) -> TransitionTable {
        let circuit = Circuit::new(pairs, public, (0..6 * pairs + public).collect()).unwrap();
        let tree = MerkleTree::new(vec![Bn254::ZERO; circuit.assignment_tree_len()]).unwrap();
        let permutation = MerkleTree::new(
            circuit
                .encoded_permutation()
                .into_iter()
                .map(Bn254::from_usize)
                .collect(),
        )
        .unwrap();
        // Both gate types at the highest pair, and the highest public offset.
        let mut indices = (6 * (pairs - 1)..6 * pairs).collect::<Vec<_>>();
        if public != 0 {
            indices.push(6 * pairs + public - 1);
        }
        let updates = indices
            .into_iter()
            .map(|i| (i, Bn254::ZERO, Bn254::ZERO))
            .collect::<Vec<_>>();
        TransitionTable::build(&circuit, &permutation, &tree, &tree, &updates).unwrap()
    }

    #[test]
    fn shared_index_bits_preserve_gate_public_and_padding_routes() {
        assert_eq!(auxiliary_column_count(1 << 15, 256), 32);
        for (pairs, public) in [(1, 0), (3, 3), (5, 3), (16, 2)] {
            let table = fixture(pairs, public);
            let statement = table.statement;
            let witness = table.packed_witness();
            let previous = table
                .rows
                .iter()
                .filter(|r| r.link.active || r.gate.active)
                .collect::<Vec<_>>();
            for row in 0..witness.updates[0].len() {
                let values = witness.updates.iter().map(|c| c[row]).collect::<Vec<_>>();
                let selectors = [
                    Bn254::from_bool(row < witness.update_count),
                    Bn254::from_bool(
                        row >= witness.update_count
                            && row < witness.update_count + witness.gate_count,
                    ),
                ];
                assert!(
                    auxiliary_residuals(&values, &selectors, statement)
                        .iter()
                        .all(|&r| r == Bn254::ZERO)
                );
                let expected = previous.get(row).map_or_else(
                    || vec![Bn254::ZERO; 48],
                    |source| compact_route_values(&compact_row(source, statement), statement),
                );
                assert_eq!(auxiliary_routes(&values, statement), expected);
            }
        }
    }

    #[test]
    fn shared_index_bits_reject_nonboolean_out_of_range_and_unused_high_bits() {
        let table = fixture(5, 3);
        let statement = table.statement;
        let witness = table.packed_witness();
        let row = |i: usize| witness.updates.iter().map(|c| c[i]).collect::<Vec<_>>();
        let rejects = |values: &[Bn254], gate_row: bool| {
            let selectors = [Bn254::from_bool(!gate_row), Bn254::from_bool(gate_row)];
            assert!(
                auxiliary_residuals(values, &selectors, statement)
                    .iter()
                    .any(|&r| r != Bn254::ZERO)
            );
        };
        let set_index = |values: &mut [Bn254], index: usize| {
            for (bit, value) in values[AUXILIARY_BASE_COLUMNS..].iter_mut().enumerate() {
                *value = Bn254::from_bool(index & (1 << bit) != 0);
            }
        };
        let public = row(witness.update_count - 1);
        let mut high_bit = public.clone();
        high_bit[AUXILIARY_BASE_COLUMNS + public_bit_count(statement)] = Bn254::ONE;
        rejects(&high_bit, false);
        let mut public_oob = public;
        set_index(&mut public_oob, statement.public_inputs);
        public_oob[9] = Bn254::from_usize(4 * statement.public_inputs + 3);
        rejects(&public_oob, false);
        let mut gate_oob = row(0);
        set_index(&mut gate_oob, statement.gate_pairs);
        gate_oob[9] = Bn254::from_usize(8 * statement.gate_pairs);
        rejects(&gate_oob, false);
        let mut gate_record_oob = row(witness.update_count);
        set_index(&mut gate_record_oob, statement.gate_pairs);
        gate_record_oob[4] = Bn254::from_usize(statement.gate_pairs);
        gate_record_oob[5] = Bn254::from_usize(8 * statement.gate_pairs);
        rejects(&gate_record_oob, true);
        let mut fractional = row(0);
        fractional[AUXILIARY_BASE_COLUMNS] = Bn254::TWO;
        rejects(&fractional, false);
    }
}
