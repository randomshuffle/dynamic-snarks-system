//! A fully disclosed sparse transition, checked directly without a PIOP/PCS.
use crate::{
    circuit::Circuit,
    field::F,
    hash::Digest,
    merkle::{self, Commitment, MerkleTree, MultiProof, ProofNode},
    wiring::CircuitShape,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    new_root: Digest,
    updates: Vec<(usize, F, F)>,
    // Logical wiring destinations, aligned with updates. Authenticated against
    // the preprocessed physical permutation tree after applying the embedding.
    neighbors: Vec<usize>,
    // Sorted distinct neighbors outside the update set, with equal old/new value.
    external_values: Vec<F>,
    // Coordinates are determined canonically from query sets, so send digests only.
    assignment_boundary: Vec<Digest>,
    permutation_boundary: Vec<Digest>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid direct transition shape or indices")]
    Shape,
    #[error("invalid direct gate or copy constraint")]
    Constraint,
    #[error(transparent)]
    Merkle(#[from] merkle::MerkleError),
}

fn physical(s: CircuitShape, logical: usize) -> usize {
    if logical < 6 * s.gate_pairs {
        4 * (logical / 3) + logical % 3
    } else {
        4 * (logical - 6 * s.gate_pairs) + 3
    }
}

fn external_indices(indices: &[usize], neighbors: &[usize]) -> Vec<usize> {
    neighbors
        .iter()
        .copied()
        .filter(|i| indices.binary_search(i).is_err())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn compact_open(tree: &MerkleTree, indices: &[usize]) -> Result<Vec<Digest>, Error> {
    Ok(tree
        .open(indices)?
        .nodes
        .into_iter()
        .map(|n| n.digest)
        .collect())
}

fn expand(len: usize, indices: &[usize], digests: &[Digest]) -> Result<MultiProof, Error> {
    let coordinates = merkle::required_siblings(indices, len.ilog2() as usize);
    if coordinates.len() != digests.len() {
        return Err(Error::Shape);
    }
    Ok(MultiProof {
        len,
        nodes: coordinates
            .into_iter()
            .zip(digests)
            .map(|((level, index), &digest)| ProofNode {
                level,
                index,
                digest,
            })
            .collect(),
    })
}

impl Proof {
    pub(crate) fn bytes(&self) -> usize {
        bincode::serialized_size(self).unwrap() as usize
    }
    pub(crate) fn new_commitment(&self, len: usize) -> Commitment {
        Commitment {
            root: self.new_root,
            len,
        }
    }
    pub(crate) fn statistics(&self) -> serde_json::Value {
        let gates = self.updates.iter().map(|u| u.0).collect::<Vec<_>>();
        serde_json::json!({"mode":"direct", "serialized_bytes":self.bytes(),
            "update_positions":self.updates.len(), "indices":gates,
            "external_values":self.external_values.len(),
            "assignment_boundary_digests":self.assignment_boundary.len(),
            "permutation_boundary_digests":self.permutation_boundary.len(),
            "polynomial_commitments":0,"sumcheck_rounds":0,"gkr_layers":0})
    }
}

pub(crate) fn prove(
    c: &Circuit,
    permutation: &MerkleTree,
    old: &MerkleTree,
    new: &MerkleTree,
    updates: &[(usize, F, F)],
) -> Result<Proof, Error> {
    let s = CircuitShape::from_circuit(c);
    let indices: Vec<_> = updates.iter().map(|u| u.0).collect();
    if indices.is_empty()
        || indices.windows(2).any(|p| p[0] >= p[1])
        || indices.iter().any(|&i| i >= s.assignment_len)
    {
        return Err(Error::Shape);
    }
    c.check_update_indices(&indices).map_err(|_| Error::Shape)?;
    for &(i, a, b) in updates {
        if old.value(physical(s, i)) != Some(a) || new.value(physical(s, i)) != Some(b) {
            return Err(Error::Shape);
        }
    }
    let neighbors: Vec<_> = indices.iter().map(|&i| c.permutation[i]).collect();
    let external = external_indices(&indices, &neighbors);
    let external_values = external
        .iter()
        .map(|&i| old.value(physical(s, i)).ok_or(Error::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let mut queries: Vec<_> = indices
        .iter()
        .chain(&external)
        .map(|&i| physical(s, i))
        .collect();
    queries.sort_unstable();
    let mut wiring_queries: Vec<_> = indices.iter().map(|&i| physical(s, i)).collect();
    wiring_queries.sort_unstable();
    let (assignment_boundary, permutation_boundary) = rayon::join(
        || compact_open(old, &queries),
        || compact_open(permutation, &wiring_queries),
    );
    Ok(Proof {
        new_root: new.commitment().root,
        updates: updates.to_vec(),
        neighbors,
        external_values,
        assignment_boundary: assignment_boundary?,
        permutation_boundary: permutation_boundary?,
    })
}

pub(crate) fn verify(
    s: CircuitShape,
    permutation: Commitment,
    old: Commitment,
    proof: &Proof,
    cap: usize,
) -> Result<Commitment, Error> {
    let len = s.assignment_tree_len();
    if old.len != len
        || permutation.len != len
        || proof.bytes() > cap
        || proof.updates.is_empty()
        || proof.updates.len() > s.assignment_len
        || proof.neighbors.len() != proof.updates.len()
        || proof.updates.windows(2).any(|p| p[0].0 >= p[1].0)
        || proof.updates.iter().any(|u| u.0 >= s.assignment_len)
        || proof.neighbors.iter().any(|&i| i >= s.assignment_len)
    {
        return Err(Error::Shape);
    }
    let indices: Vec<_> = proof.updates.iter().map(|u| u.0).collect();
    let external = external_indices(&indices, &proof.neighbors);
    if external.len() != proof.external_values.len() {
        return Err(Error::Shape);
    }
    let mut values: BTreeMap<_, _> = proof.updates.iter().map(|&(i, a, b)| (i, (a, b))).collect();
    for (&i, &v) in external.iter().zip(&proof.external_values) {
        values.insert(i, (v, v));
    }
    for (&(i, _, value), &neighbor) in proof.updates.iter().zip(&proof.neighbors) {
        if values.get(&neighbor).map(|v| v.1) != Some(value) {
            return Err(Error::Constraint);
        }
        if i < 6 * s.gate_pairs {
            let start = i - i % 3;
            // Gate closure is on the actual update set, not external neighbors.
            if (0..3).any(|j| indices.binary_search(&(start + j)).is_err()) {
                return Err(Error::Shape);
            }
            if i == start {
                let (a, b, out) = (
                    values[&start].1,
                    values[&(start + 1)].1,
                    values[&(start + 2)].1,
                );
                if (if start % 6 == 0 { a + b } else { a * b }) != out {
                    return Err(Error::Constraint);
                }
            }
        }
    }
    let sorted: BTreeMap<_, _> = values
        .into_iter()
        .map(|(i, v)| (physical(s, i), v))
        .collect();
    let queries: Vec<_> = sorted.keys().copied().collect();
    let old_values: Vec<_> = sorted.values().map(|v| v.0).collect();
    let new_values: Vec<_> = sorted.values().map(|v| v.1).collect();
    let assignment = expand(len, &queries, &proof.assignment_boundary)?;
    let wiring: BTreeMap<_, _> = indices
        .iter()
        .zip(&proof.neighbors)
        .map(|(&i, &n)| (physical(s, i), F::from_usize(physical(s, n))))
        .collect();
    let wiring_queries: Vec<_> = wiring.keys().copied().collect();
    let wiring_values: Vec<_> = wiring.values().copied().collect();
    let wiring_proof = expand(len, &wiring_queries, &proof.permutation_boundary)?;
    let new = proof.new_commitment(len);
    let (a, (b, p)) = rayon::join(
        || merkle::verify(old, &queries, &old_values, &assignment),
        || {
            rayon::join(
                || merkle::verify(new, &queries, &new_values, &assignment),
                || merkle::verify(permutation, &wiring_queries, &wiring_values, &wiring_proof),
            )
        },
    );
    a?;
    b?;
    p?;
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_transition_authenticates_values_wiring_boundaries_and_budget() {
        let n = 11;
        let public = 5;
        let mut sigma: Vec<_> = (0..6 * n + public).collect();
        sigma.swap(1, 4);
        let c = Circuit::new(n, public, sigma).unwrap();
        let z = vec![F::ZERO; c.assignment_len()];
        let old = MerkleTree::new(c.encode_assignment(&z)).unwrap();
        let perm = MerkleTree::new(
            c.encoded_permutation()
                .into_iter()
                .map(F::from_usize)
                .collect(),
        )
        .unwrap();
        // The unchanged right input is authenticated outside the update set.
        let u = [
            (0, F::ZERO, F::from_u64(5)),
            (1, F::ZERO, F::ZERO),
            (2, F::ZERO, F::from_u64(5)),
        ];
        let new = old
            .updated(
                &u.iter()
                    .map(|&(i, _, v)| (c.assignment_leaf_index(i), v))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let p = prove(&c, &perm, &old, &new, &u).unwrap();
        let check = |p: &Proof, cap| {
            verify(
                CircuitShape::from_circuit(&c),
                perm.commitment(),
                old.commitment(),
                p,
                cap,
            )
        };
        assert_eq!(check(&p, p.bytes()).unwrap(), new.commitment());
        assert!(check(&p, p.bytes() - 1).is_err());
        let roundtrip: Proof = bincode::deserialize(&bincode::serialize(&p).unwrap()).unwrap();
        check(&roundtrip, usize::MAX).unwrap();
        for kind in 0..9 {
            let mut bad = p.clone();
            match kind {
                0 => bad.updates[0].1 += F::ONE,
                1 => bad.updates[0].2 += F::ONE,
                2 => bad.neighbors[1] = 1,
                3 => bad.external_values[0] += F::ONE,
                4 => bad.assignment_boundary[0][0] += F::ONE,
                5 => bad.permutation_boundary[0][0] += F::ONE,
                6 => bad.new_root[0] += F::ONE,
                7 => {
                    bad.updates.remove(0);
                    bad.neighbors.remove(0);
                }
                _ => bad.updates.swap(0, 1),
            }
            assert!(check(&bad, usize::MAX).is_err(), "tamper {kind}");
        }
        let mut bad = p.clone();
        bad.assignment_boundary.push([F::ZERO; 2]);
        assert!(check(&bad, usize::MAX).is_err());
        // Shared old/new boundaries must reject an undisclosed external change.
        let outside = new
            .updated(&[(c.assignment_leaf_index(12), F::ONE)])
            .unwrap();
        let bad = prove(&c, &perm, &old, &outside, &u).unwrap();
        assert!(check(&bad, usize::MAX).is_err());
    }
}
