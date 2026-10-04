//! Paired hashes occupy twelve fields; private routing metadata occupies ten.
use super::*;
use crate::{hash::compress, sparse_dag::NodeKind};
pub(crate) const NODE_COLUMNS: usize = 22;
pub(crate) const NODE_WIDTH: usize = 32;
pub(crate) const NODE_DEGREE: usize = 8;
pub(crate) const ROUTE_DEGREE: usize = 9;
pub(crate) struct Witness {
    pub nodes: Vec<Vec<F>>,
    pub updates: Vec<Vec<F>>,
    pub hash_inputs: [Vec<F>; 6],
    pub update_count: usize,
    pub gate_count: usize,
}
pub(crate) fn auxiliary_column_count(gates: usize, public: usize) -> usize {
    22 + bits(gates).max(bits(public))
}
pub(crate) fn auxiliary_columns(s: Statement) -> usize {
    auxiliary_column_count(s.gate_pairs, s.public_inputs)
}
fn bits(n: usize) -> usize {
    n.max(1).next_power_of_two().ilog2() as usize
}
pub(crate) fn auxiliary_degree(s: Statement) -> usize {
    6.max(if s.gate_pairs.is_power_of_two() {
        0
    } else {
        bits(s.gate_pairs) + 3
    })
    .max(if s.public_inputs.is_power_of_two() {
        0
    } else {
        bits(s.public_inputs) + 3
    })
}
fn record(input: [F; 4]) -> [F; 6] {
    let d = compress(input);
    [input[0], input[1], input[2], input[3], d[0], d[1]]
}
fn level(n: usize) -> F {
    F::TWO.exp_u64(n as u64)
}
fn dummy_record() -> [F; 6] {
    static D: std::sync::OnceLock<[F; 6]> = std::sync::OnceLock::new();
    *D.get_or_init(|| record([F::ZERO; 4]))
}
fn inverses(n: usize) -> [F; 2] {
    static I: std::sync::OnceLock<Vec<[F; 2]>> = std::sync::OnceLock::new();
    I.get_or_init(|| {
        (0..64)
            .map(|i| {
                [
                    level(i).inverse(),
                    if i == 0 {
                        F::ZERO
                    } else {
                        (level(i) + F::ONE).inverse()
                    },
                ]
            })
            .collect()
    })[n]
}

impl TransitionTable {
    pub fn packed_witness(&self) -> Witness {
        let rows = self
            .nodes
            .len()
            .max(self.aux.len())
            .max(4)
            .next_power_of_two();
        let aux_rows = self.aux.len().max(2).next_power_of_two();
        let mut nodes = vec![vec![F::ZERO; rows]; NODE_COLUMNS];
        let mut hashes = std::array::from_fn(|_| vec![F::ZERO; 2 * rows]);
        let dummy = dummy_record();
        for row in 0..rows {
            let mut v = [F::ZERO; NODE_COLUMNS];
            v[..6].copy_from_slice(&dummy);
            v[6..12].copy_from_slice(&dummy);
            if let Some(n) = self.nodes.get(row) {
                let root = n.coordinate.level == self.statement.height;
                v[12] = F::from_usize(if root {
                    4
                } else {
                    match n.kind {
                        NodeKind::Leaf => 1,
                        NodeKind::Boundary => 2,
                        NodeKind::Internal => 3,
                    }
                });
                v[13] = F::from_u64(n.tree as u64);
                v[14] = level(n.coordinate.level);
                v[15] = F::from_usize(
                    (1 << (self.statement.height - n.coordinate.level)) + n.coordinate.index,
                );
                v[20] = inverses(n.coordinate.level)[0];
                match n.kind {
                    NodeKind::Boundary => {
                        v[16..18].copy_from_slice(&n.digest.old);
                        v[18..20].copy_from_slice(&n.digest.new);
                    }
                    NodeKind::Leaf => {
                        for side in 0..2 {
                            let input = [
                                n.leaf_values.unwrap()[side],
                                F::from_usize(n.coordinate.index),
                                F::ZERO,
                                F::ZERO,
                            ];
                            v[6 * side..6 * side + 6].copy_from_slice(&record(input));
                        }
                    }
                    NodeKind::Internal => {
                        v[21] = inverses(n.coordinate.level)[1];
                        let child = n.children.unwrap();
                        for side in 0..2 {
                            let left = if side == 0 {
                                child[0].old
                            } else {
                                child[0].new
                            };
                            let right = if side == 0 {
                                child[1].old
                            } else {
                                child[1].new
                            };
                            v[6 * side..6 * side + 6]
                                .copy_from_slice(&record([left[0], left[1], right[0], right[1]]));
                        }
                    }
                }
            }
            for j in 0..NODE_COLUMNS {
                nodes[j][row] = v[j];
            }
            for j in 0..6 {
                hashes[j][2 * row] = v[j];
                hashes[j][2 * row + 1] = v[6 + j];
            }
        }
        let mut updates = vec![vec![F::ZERO; aux_rows]; auxiliary_columns(self.statement)];
        for (i, v) in self.aux.iter().enumerate() {
            for (j, x) in v.iter().enumerate() {
                updates[j][i] = *x;
            }
        }
        Witness {
            nodes,
            updates,
            hash_inputs: hashes,
            update_count: self.update_count,
            gate_count: self.gate_count,
        }
    }
}
pub(crate) fn type_selectors(t: F) -> [F; 5] {
    static INV: std::sync::OnceLock<[F; 5]> = std::sync::OnceLock::new();
    let inv = INV.get_or_init(|| {
        std::array::from_fn(|k| {
            (0..5)
                .filter(|&j| j != k)
                .map(|j| F::from_usize(k) + F::from_usize(j))
                .product::<F>()
                .inverse()
        })
    });
    std::array::from_fn(|k| {
        (0..5)
            .filter(|&j| j != k)
            .fold(inv[k], |p, j| p * (t + F::from_usize(j)))
    })
}
pub(crate) fn node_residuals(v: &[F], roots: &[F], s: Statement) -> Vec<F> {
    let [pad, leaf, boundary, internal, root] = type_selectors(v[12]);
    let tree = v[13];
    let ell = v[14];
    let heap = v[15];
    let active = F::ONE + pad;
    let computed = internal + root;
    let mut r = vec![
        (0..5).map(|i| v[12] + F::from_usize(i)).product(),
        active * (tree + F::ONE) * (tree + F::TWO) * (tree + F::from_u64(3)),
        root + roots.iter().copied().sum::<F>(),
        root * (ell + level(s.height)),
        root * (heap + F::ONE),
        leaf * (ell + F::ONE),
        active * (ell * v[20] + F::ONE),
        computed * ((ell + F::ONE) * v[21] + F::ONE),
    ];
    let ds = [
        [s.old_assignment.root, s.new_assignment.root],
        [s.permutation.root; 2],
        [s.new_assignment.root; 2],
    ];
    for (i, &sel) in roots.iter().enumerate() {
        r.push(sel * (tree + F::from_usize(i + 1)));
        for side in 0..2 {
            for j in 0..2 {
                r.push(sel * (v[6 * side + 4 + j] + ds[i][side][j]));
            }
        }
    }
    let dummy = dummy_record();
    for side in 0..2 {
        let h = &v[6 * side..6 * side + 6];
        r.push(leaf * (h[1] + heap + F::from_usize(1 << s.height)));
        r.push(leaf * h[2]);
        r.push(leaf * h[3]);
        for j in 0..6 {
            r.push((pad + boundary) * (h[j] + dummy[j]));
        }
    }
    for j in 0..6 {
        r.push(active * (tree + F::ONE) * (v[j] + v[6 + j]));
    }
    for j in 0..2 {
        r.push(boundary * (v[16 + j] + v[18 + j]));
    }
    r
}
fn bits_value(v: &[F]) -> F {
    v.iter()
        .enumerate()
        .map(|(i, &b)| F::from_usize(1 << i) * b)
        .sum()
}
fn prefix(v: &[F], n: usize) -> F {
    if n == 1 << v.len() {
        return F::ONE;
    }
    let mut result = F::ZERO;
    let mut same = F::ONE;
    for i in (0..v.len()).rev() {
        if n >> i & 1 == 0 {
            same *= F::ONE + v[i];
        } else {
            result += same * (F::ONE + v[i]);
            same *= v[i];
        }
    }
    result
}
pub(crate) fn auxiliary_residuals(v: &[F], sel: &[F], s: Statement) -> Vec<F> {
    let (l, g, p, m, o0, o1) = (v[0], v[1], v[2], v[3], v[4], v[5]);
    let b = &v[22..];
    let ix = bits_value(b);
    let boolean = |x: F| x * (x + F::ONE);
    let mut r = vec![
        l + sel[0],
        g + sel[1],
        boolean(l),
        boolean(g),
        l * g,
        l * boolean(p),
        (l + g) * boolean(m),
        l * boolean(o0),
        l * boolean(o1),
        l * o0 * o1,
        l * p * m,
        l * p * o0,
        l * p * o1,
    ];
    r.extend(b.iter().map(|&x| (l + g) * boolean(x)));
    let gate = (l * (F::ONE + p)) + g;
    let public = l * p;
    r.push(gate * (prefix(&b[..bits(s.gate_pairs)], s.gate_pairs) + F::ONE));
    r.push(public * (prefix(&b[..bits(s.public_inputs)], s.public_inputs) + F::ONE));
    r.extend(b[bits(s.gate_pairs)..].iter().map(|&x| gate * x));
    r.extend(b[bits(s.public_inputs)..].iter().map(|&x| public * x));
    r.push(l * (F::ONE + p) * (v[6] + F::from_u64(8) * ix + F::from_u64(4) * m + o0 + F::TWO * o1));
    r.push(public * (v[6] + F::from_u64(4) * ix + F::from_u64(3)));
    r.push(g * (v[21] + F::from_u64(8) * ix + F::from_u64(4) * m));
    r.push(g * (F::ONE + m) * (v[18] + v[19] + v[20]));
    r.push(g * m * (v[18] * v[19] + v[20]));
    r
}
pub(crate) fn node_routes(v: &[F], s: Statement) -> Vec<F> {
    let [_, leaf, boundary, internal, root] = type_selectors(v[12]);
    let nonroot = leaf + boundary + internal;
    let computed = leaf + internal;
    let branch = internal + root;
    let (tree, ell, heap) = (v[13], v[14], v[15]);
    let mut r = vec![F::ZERO; 64];
    let tuple = [
        nonroot,
        nonroot * tree,
        nonroot * ell,
        nonroot * heap,
        computed * v[4] + boundary * v[16],
        computed * v[5] + boundary * v[17],
        computed * v[10] + boundary * v[18],
        computed * v[11] + boundary * v[19],
    ];
    r[..8].copy_from_slice(&tuple);
    r[8..16].copy_from_slice(
        &[
            F::from_u64(16) + tree,
            heap + F::from_usize(1 << s.height),
            v[0],
            v[6],
            v[4],
            v[5],
            v[10],
            v[11],
        ]
        .map(|x| leaf * x),
    );
    static XINV: std::sync::OnceLock<F> = std::sync::OnceLock::new();
    let inv = *XINV.get_or_init(|| F::TWO.inverse());
    for child in 0..2 {
        let t = [
            F::ONE,
            tree,
            ell * inv,
            F::TWO * heap + F::from_usize(child),
            v[2 * child],
            v[2 * child + 1],
            v[6 + 2 * child],
            v[7 + 2 * child],
        ]
        .map(|x| branch * x);
        r[32 + 8 * child..40 + 8 * child].copy_from_slice(&t);
    }
    r
}
pub(crate) fn auxiliary_routes(v: &[F], _: Statement) -> Vec<F> {
    let (l, g, p) = (v[0], v[1], v[2]);
    let mut r = vec![F::ZERO; 64];
    r[16..24].copy_from_slice(
        &[
            F::from_u64(32),
            v[6],
            v[8],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]
        .map(|x| l * (F::ONE + p) * x),
    );
    let t = [
        [
            F::from_u64(17),
            v[6],
            v[7],
            v[8],
            v[10],
            v[11],
            v[12],
            v[13],
        ],
        [
            F::from_u64(18),
            v[6],
            v[9],
            v[9],
            v[14],
            v[15],
            v[14],
            v[15],
        ],
        [
            F::from_u64(19),
            v[9],
            v[8],
            v[8],
            v[16],
            v[17],
            v[16],
            v[17],
        ],
    ];
    for lane in 0..3 {
        let gate = [
            F::from_u64(32),
            v[21] + F::from_usize(lane),
            v[18 + lane],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        for j in 0..8 {
            r[32 + 8 * lane + j] = l * t[lane][j] + g * gate[j];
        }
    }
    r
}
pub(crate) fn estimate_shape(
    c: &Circuit,
    indices: &[usize],
) -> Result<(usize, usize, usize), Error> {
    let mut p: Vec<_> = indices
        .iter()
        .map(|&i| c.assignment_leaf_index(i))
        .collect();
    p.sort_unstable();
    p.dedup();
    let mut n: Vec<_> = indices
        .iter()
        .map(|&i| c.assignment_leaf_index(c.permutation[i]))
        .collect();
    n.sort_unstable();
    n.dedup();
    let rows = 2 * SparseMerkleDag::shape(c.assignment_tree_len(), &p)?.0
        + SparseMerkleDag::shape(c.assignment_tree_len(), &n)?.0;
    let gates = indices
        .iter()
        .filter(|&&i| i < 6 * c.n)
        .map(|&i| i / 3)
        .collect::<BTreeSet<_>>()
        .len();
    Ok((
        rows.max(indices.len() + gates).max(4).next_power_of_two(),
        NODE_WIDTH,
        2 * rows.max(indices.len() + gates).max(4).next_power_of_two(),
    ))
}
