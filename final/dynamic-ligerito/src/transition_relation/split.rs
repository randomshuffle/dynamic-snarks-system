//! Separate computed hashes, shared boundary digests, and update records.
use super::*;
use crate::sparse_dag::NodeKind;
pub(crate) const WIDTHS: [usize; 2] = [16, 8];
pub(crate) struct Witness {
    pub columns: [Vec<Vec<F>>; 3],
    pub update_count: usize,
    pub gate_count: usize,
}
fn ell(level: usize) -> F {
    F::TWO.exp_u64(level as u64)
}
pub(crate) fn selectors(t: F) -> [F; 4] {
    static INV: std::sync::OnceLock<[F; 4]> = std::sync::OnceLock::new();
    let inv = INV.get_or_init(|| {
        std::array::from_fn(|i| {
            (0..4)
                .filter(|&j| j != i)
                .map(|j| F::from_usize(i) + F::from_usize(j))
                .product::<F>()
                .inverse()
        })
    });
    std::array::from_fn(|i| {
        (0..4)
            .filter(|&j| j != i)
            .fold(inv[i], |a, j| a * (t + F::from_usize(j)))
    })
}
fn columns(
    mut records: Vec<Vec<F>>,
    width: usize,
    minimum: usize,
    dummy: Option<[F; 2]>,
) -> Vec<Vec<F>> {
    let rows = records.len().max(minimum).next_power_of_two();
    records.resize(rows, vec![F::ZERO; width]);
    let mut c = vec![vec![F::ZERO; rows]; width];
    for (i, r) in records.into_iter().enumerate() {
        for (j, v) in r.into_iter().enumerate() {
            c[j][i] = v;
        }
        if let Some(d) = dummy {
            if c[6][i] == F::ZERO {
                c[4][i] = d[0];
                c[5][i] = d[1];
            }
        }
    }
    c
}
impl TransitionTable {
    pub(crate) fn split_witness(&self) -> Witness {
        let mut hashes = Vec::new();
        let mut boundaries = Vec::new();
        for n in &self.nodes {
            if n.kind == NodeKind::Boundary {
                boundaries.push(vec![
                    F::ONE,
                    F::from_u64(n.tree as u64),
                    ell(n.coordinate.level),
                    F::from_usize(
                        (1 << (self.statement.height - n.coordinate.level)) + n.coordinate.index,
                    ),
                    n.digest.new[0],
                    n.digest.new[1],
                    ell(n.coordinate.level).inverse(),
                ]);
                continue;
            }
            let sides: &[usize] = if n.tree == TreeId::Assignment {
                &[0, 1]
            } else {
                &[1]
            };
            for &side in sides {
                let claim = match n.tree {
                    TreeId::Assignment => 1 + side,
                    TreeId::Permutation => 3,
                    TreeId::Neighbor => 4,
                };
                let level = ell(n.coordinate.level);
                let root = n.coordinate.level == self.statement.height;
                let input = if n.kind == NodeKind::Leaf {
                    [
                        n.leaf_values.unwrap()[side],
                        F::from_usize(n.coordinate.index),
                        F::ZERO,
                        F::ZERO,
                    ]
                } else {
                    let ch = n.children.unwrap();
                    let l = if side == 0 { ch[0].old } else { ch[0].new };
                    let r = if side == 0 { ch[1].old } else { ch[1].new };
                    [l[0], l[1], r[0], r[1]]
                };
                let d = if side == 0 {
                    n.digest.old
                } else {
                    n.digest.new
                };
                let mut v = input.to_vec();
                v.extend(d);
                v.extend([
                    F::from_usize(if root {
                        3
                    } else if n.kind == NodeKind::Leaf {
                        1
                    } else {
                        2
                    }),
                    F::from_usize(claim),
                    level,
                    F::from_usize(
                        (1 << (self.statement.height - n.coordinate.level)) + n.coordinate.index,
                    ),
                    level.inverse(),
                    if n.coordinate.level == 0 {
                        F::ZERO
                    } else {
                        (level + F::ONE).inverse()
                    },
                ]);
                hashes.push(v);
            }
        }
        hashes.sort_by_key(|v| {
            if v[6] == F::from_u64(3) {
                v[7].0.lo as usize
            } else {
                5
            }
        });
        Witness {
            columns: [
                columns(hashes, 12, 4, Some(crate::hash::compress([F::ZERO; 4]))),
                columns(boundaries, 7, 2, None),
                columns(
                    self.aux.clone(),
                    packed::auxiliary_columns(self.statement),
                    2,
                    None,
                ),
            ],
            update_count: self.update_count,
            gate_count: self.gate_count,
        }
    }
}
pub(crate) fn computed_residuals(v: &[F], roots: &[F], s: Statement) -> Vec<F> {
    let [pad, leaf, internal, root] = selectors(v[6]);
    let a = F::ONE + pad;
    let branch = internal + root;
    let mut r = vec![
        (0..4).map(|i| v[6] + F::from_usize(i)).product(),
        a * (1..=4).map(|i| v[7] + F::from_usize(i)).product::<F>(),
        a * (v[8] * v[10] + F::ONE),
        branch * ((v[8] + F::ONE) * v[11] + F::ONE),
        leaf * (v[8] + F::ONE),
        root * (v[8] + ell(s.height)),
        root * (v[9] + F::ONE),
        root + roots.iter().copied().sum::<F>(),
        leaf * (v[1] + v[9] + F::from_usize(1 << s.height)),
        leaf * v[2],
        leaf * v[3],
    ];
    let digests = [
        s.old_assignment.root,
        s.new_assignment.root,
        s.permutation.root,
        s.new_assignment.root,
    ];
    for i in 0..4 {
        r.extend([
            roots[i] * (v[7] + F::from_usize(i + 1)),
            roots[i] * (v[4] + digests[i][0]),
            roots[i] * (v[5] + digests[i][1]),
        ]);
    }
    static D: std::sync::OnceLock<[F; 2]> = std::sync::OnceLock::new();
    let dummy = *D.get_or_init(|| crate::hash::compress([F::ZERO; 4]));
    for j in 0..6 {
        r.push(pad * (v[j] + if j < 4 { F::ZERO } else { dummy[j - 4] }));
    }
    r
}
pub(crate) fn boundary_residuals(v: &[F]) -> Vec<F> {
    vec![
        v[0] * (v[0] + F::ONE),
        v[0] * (1..=3).map(|i| v[1] + F::from_usize(i)).product::<F>(),
        v[0] * (v[2] * v[6] + F::ONE),
    ]
}
fn scaled(a: F, t: [F; 8]) -> [F; 8] {
    t.map(|v| a * v)
}
fn node_tuple(claim: F, level: F, heap: F, d: [F; 2]) -> [F; 8] {
    [claim, level, heap, d[0], d[1], F::ZERO, F::ZERO, F::ZERO]
}
fn leaf_tuple(claim: F, index: F, value: F, d: [F; 2]) -> [F; 8] {
    [
        F::from_u64(16) + claim,
        index,
        value,
        d[0],
        d[1],
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]
}
pub(crate) fn routes(domain: usize, v: &[F], s: Statement) -> [[F; 8]; 8] {
    let mut r = [[F::ZERO; 8]; 8];
    match domain {
        0 => {
            let [_, leaf, internal, root] = selectors(v[6]);
            let branch = internal + root;
            r[0] = scaled(leaf + internal, node_tuple(v[7], v[8], v[9], [v[4], v[5]]));
            r[1] = scaled(
                leaf,
                leaf_tuple(
                    v[7],
                    v[9] + F::from_usize(1 << s.height),
                    v[0],
                    [v[4], v[5]],
                ),
            );
            static XI: std::sync::OnceLock<F> = std::sync::OnceLock::new();
            let inv = *XI.get_or_init(|| F::TWO.inverse());
            for j in 0..2 {
                r[4 + j] = scaled(
                    branch,
                    node_tuple(
                        v[7],
                        v[8] * inv,
                        F::TWO * v[9] + F::from_usize(j),
                        [v[2 * j], v[2 * j + 1]],
                    ),
                );
            }
        }
        1 => {
            let g = selectors(v[1]);
            for (i, claim) in [(1, 1), (2, 3), (3, 4)] {
                let t = scaled(
                    v[0] * g[i],
                    node_tuple(F::from_usize(claim), v[2], v[3], [v[4], v[5]]),
                );
                for j in 0..8 {
                    r[0][j] += t[j];
                }
            }
            r[1] = scaled(v[0] * g[1], node_tuple(F::TWO, v[2], v[3], [v[4], v[5]]));
        }
        2 => {
            let (l, g, p) = (v[0], v[1], v[2]);
            r[0] = scaled(
                l * (F::ONE + p),
                [
                    F::from_u64(32),
                    v[6],
                    v[8],
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                ],
            );
            let ts = [
                leaf_tuple(F::ONE, v[6], v[7], [v[10], v[11]]),
                leaf_tuple(F::TWO, v[6], v[8], [v[12], v[13]]),
                leaf_tuple(F::from_u64(3), v[6], v[9], [v[14], v[15]]),
                leaf_tuple(F::from_u64(4), v[9], v[8], [v[16], v[17]]),
            ];
            for j in 0..4 {
                r[4 + j] = scaled(l, ts[j]);
                if j < 3 {
                    let t = scaled(
                        g,
                        [
                            F::from_u64(32),
                            v[21] + F::from_usize(j),
                            v[18 + j],
                            F::ZERO,
                            F::ZERO,
                            F::ZERO,
                            F::ZERO,
                            F::ZERO,
                        ],
                    );
                    for w in 0..8 {
                        r[4 + j][w] += t[w];
                    }
                }
            }
        }
        _ => unreachable!(),
    }
    r
}

pub(crate) fn shape_details(
    c: &Circuit,
    indices: &[usize],
) -> Result<(usize, usize, usize), Error> {
    let mut p = indices
        .iter()
        .map(|&i| c.assignment_leaf_index(i))
        .collect::<Vec<_>>();
    p.sort_unstable();
    p.dedup();
    let mut n = indices
        .iter()
        .map(|&i| c.assignment_leaf_index(c.permutation[i]))
        .collect::<Vec<_>>();
    n.sort_unstable();
    n.dedup();
    let (pr, ph) = SparseMerkleDag::shape(c.assignment_tree_len(), &p)?;
    let (nr, nh) = SparseMerkleDag::shape(c.assignment_tree_len(), &n)?;
    Ok((
        (3 * ph + nh).max(4).next_power_of_two(),
        (2 * (pr - ph) + nr - nh).max(2).next_power_of_two(),
        16,
    ))
}
pub(crate) fn estimate_shape(
    c: &Circuit,
    indices: &[usize],
) -> Result<(usize, usize, usize), Error> {
    let (h, _, w) = shape_details(c, indices)?;
    Ok((h, w, h))
}
