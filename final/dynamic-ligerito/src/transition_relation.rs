//! Private sparse-Merkle relation over GF128, with two-word digests.
pub(crate) mod packed;
pub(crate) mod split;
use crate::{
    circuit::{Circuit, CircuitError},
    field::F,
    merkle::{Commitment, MerkleError, MerkleTree},
    sparse_dag::{NodeRow, SparseMerkleDag, TreeId},
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
pub(crate) struct Statement {
    pub gate_pairs: usize,
    pub public_inputs: usize,
    pub assignment_len: usize,
    pub height: usize,
    pub permutation: Commitment,
    pub old_assignment: Commitment,
    pub new_assignment: Commitment,
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error(transparent)]
    Sparse(#[from] crate::sparse_dag::Error),
    #[error("invalid update indices or values")]
    Indices,
}
pub(crate) struct TransitionTable {
    statement: Statement,
    nodes: Vec<NodeRow>,
    aux: Vec<Vec<F>>,
    update_count: usize,
    gate_count: usize,
}
impl TransitionTable {
    pub fn statement(&self) -> Statement {
        self.statement
    }
    pub fn build(
        c: &Circuit,
        permutation: &MerkleTree,
        old: &MerkleTree,
        new: &MerkleTree,
        updates: &[(usize, F, F)],
    ) -> Result<Self, Error> {
        let indices: Vec<_> = updates.iter().map(|u| u.0).collect();
        if indices.is_empty()
            || indices.windows(2).any(|p| p[0] >= p[1])
            || indices.iter().any(|&i| i >= c.assignment_len())
        {
            return Err(Error::Indices);
        }
        c.check_update_indices(&indices)?;
        for &(i, a, b) in updates {
            if old.value(c.assignment_leaf_index(i)) != Some(a)
                || new.value(c.assignment_leaf_index(i)) != Some(b)
            {
                return Err(Error::Indices);
            }
        }
        let mut physical: Vec<_> = indices
            .iter()
            .map(|&i| c.assignment_leaf_index(i))
            .collect();
        physical.sort_unstable();
        let mut neighbors: Vec<_> = indices
            .iter()
            .map(|&i| c.assignment_leaf_index(c.permutation[i]))
            .collect();
        neighbors.sort_unstable();
        neighbors.dedup();
        let (a, (p, n)) = rayon::join(
            || SparseMerkleDag::paired(TreeId::Assignment, old, new, &physical),
            || {
                rayon::join(
                    || SparseMerkleDag::single(TreeId::Permutation, permutation, &physical),
                    || SparseMerkleDag::single(TreeId::Neighbor, new, &neighbors),
                )
            },
        );
        let (a, p, n) = (a?, p?, n?);
        let statement = Statement {
            gate_pairs: c.n,
            public_inputs: c.num_public_inputs,
            assignment_len: c.assignment_len(),
            height: c.assignment_tree_len().ilog2() as usize,
            permutation: permutation.commitment(),
            old_assignment: old.commitment(),
            new_assignment: new.commitment(),
        };
        let leaf = |d: &SparseMerkleDag| {
            d.rows()
                .iter()
                .filter(|r| r.coordinate.level == 0)
                .map(|r| (r.coordinate.index, r.digest))
                .collect::<BTreeMap<_, _>>()
        };
        let (al, pl, nl) = (leaf(&a), leaf(&p), leaf(&n));
        let mut aux = Vec::new();
        for &(i, old, new) in updates {
            let index = c.assignment_leaf_index(i);
            let sigma = c.assignment_leaf_index(c.permutation[i]);
            let public = i >= 6 * c.n;
            let gate = i / 3;
            let pair = if public { i - 6 * c.n } else { gate / 2 };
            let mut v = vec![F::ZERO; packed::auxiliary_columns(statement)];
            v[0] = F::ONE;
            v[2] = F::from_bool(public);
            v[3] = F::from_bool(!public && gate % 2 == 1);
            let offset = if public { 0 } else { i % 3 };
            v[4] = F::from_bool(offset & 1 != 0);
            v[5] = F::from_bool(offset & 2 != 0);
            v[6] = F::from_usize(index);
            v[7] = old;
            v[8] = new;
            v[9] = F::from_usize(sigma);
            v[10..12].copy_from_slice(&al[&index].old);
            v[12..14].copy_from_slice(&al[&index].new);
            v[14..16].copy_from_slice(&pl[&index].new);
            v[16..18].copy_from_slice(&nl[&sigma].new);
            for (bit, x) in v[22..].iter_mut().enumerate() {
                *x = F::from_bool(pair >> bit & 1 != 0);
            }
            aux.push(v);
        }
        let starts: BTreeSet<_> = indices
            .iter()
            .filter(|&&i| i < 6 * c.n)
            .map(|&i| i - i % 3)
            .collect();
        let gate_count = starts.len();
        for start in starts {
            let gate = start / 3;
            let pair = gate / 2;
            let mut v = vec![F::ZERO; packed::auxiliary_columns(statement)];
            v[1] = F::ONE;
            v[3] = F::from_bool(gate % 2 == 1);
            for j in 0..3 {
                v[18 + j] = new.value(c.assignment_leaf_index(start + j)).unwrap();
            }
            v[21] = F::from_usize(c.assignment_leaf_index(start));
            for (bit, x) in v[22..].iter_mut().enumerate() {
                *x = F::from_bool(pair >> bit & 1 != 0);
            }
            aux.push(v);
        }
        let mut nodes = Vec::new();
        for d in [&a, &p, &n] {
            nodes.extend_from_slice(d.rows());
        }
        nodes.sort_by_key(|r| r.coordinate.level != statement.height);
        Ok(Self {
            statement,
            nodes,
            aux,
            update_count: updates.len(),
            gate_count,
        })
    }
}
