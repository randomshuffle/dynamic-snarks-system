//! Canonical sparse Merkle authentication DAGs used by transition proofs.

use crate::parallel::prelude::*;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::field::F;

use thiserror::Error;

use crate::hash::{Digest, hash_leaf, hash_node};
use crate::merkle::{Commitment, MerkleError, MerkleTree};

/// Domain tag separating independently routed Merkle computations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TreeId {
    Assignment = 1,
    Permutation = 2,
    Neighbor = 3,
}

/// One coordinate in a padded binary Merkle tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Coordinate {
    pub(crate) level: usize,
    pub(crate) index: usize,
}

/// How a sparse authentication node obtains its digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    /// An explicitly queried vector position.
    Leaf,
    /// A supplied digest for a subtree disjoint from all queries.
    Boundary,
    /// A node recomputed from its two child rows.
    Internal,
}

/// The old/new digest pair carried by one routed node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DigestPair {
    pub(crate) old: Digest,
    pub(crate) new: Digest,
}

/// One canonical sparse-DAG row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeRow {
    pub(crate) tree: TreeId,
    pub(crate) coordinate: Coordinate,
    pub(crate) kind: NodeKind,
    pub(crate) digest: DigestPair,
    pub(crate) children: Option<[DigestPair; 2]>,
    pub(crate) leaf_values: Option<[F; 2]>,
}

/// A producer or child-reference tuple before Fiat--Shamir compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteTuple {
    pub(crate) tree: TreeId,
    pub(crate) coordinate: Coordinate,
    pub(crate) digest: DigestPair,
}

/// Canonical union of queried paths and their complement nodes.
#[derive(Clone, Debug)]
pub(crate) struct SparseMerkleDag {
    tree: TreeId,
    height: usize,
    old_commitment: Commitment,
    new_commitment: Commitment,
    rows: Vec<NodeRow>,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("old and new sparse-DAG trees have different logical lengths")]
    Length,
    #[error("new tree changes a complement subtree outside the query set")]
    ChangedBoundary,
    #[error("sparse-DAG row set is incomplete or noncanonical")]
    NonCanonical,
    #[error("sparse-DAG local hash relation failed")]
    Hash,
    #[error("sparse-DAG producer/reference routing failed")]
    Routing,
    #[error("sparse-DAG root does not match its public commitment")]
    Root,
}

impl SparseMerkleDag {
    /// Count all rows and non-boundary hashes from path coordinates alone.
    /// This performs no dense allocation or hashing, even for a very large tree.
    pub(crate) fn shape(tree_len: usize, indices: &[usize]) -> Result<(usize, usize), Error> {
        if tree_len == 0
            || indices.is_empty()
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
            || indices.iter().any(|&index| index >= tree_len)
        {
            return Err(Error::NonCanonical);
        }
        let height = tree_len.next_power_of_two().trailing_zeros();
        let mut active = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut rows = active.len();
        let mut hashes = active.len();
        for _ in 0..height {
            rows += active
                .iter()
                .filter(|&&index| !active.contains(&(index ^ 1)))
                .count();
            active = active.into_iter().map(|index| index >> 1).collect();
            rows += active.len();
            hashes += active.len();
        }
        Ok((rows, hashes))
    }

    /// Build a paired old/new authentication DAG. Complement nodes must be
    /// identical, so the two vectors can differ only at `indices`.
    pub(crate) fn paired(
        tree: TreeId,
        old: &MerkleTree,
        new: &MerkleTree,
        indices: &[usize],
    ) -> Result<Self, Error> {
        if old.commitment().len != new.commitment().len {
            return Err(Error::Length);
        }
        let proof = old.open(indices)?;
        let proof_coordinates = proof
            .nodes
            .iter()
            .map(|node| Coordinate {
                level: node.level,
                index: node.index,
            })
            .collect::<BTreeSet<_>>();
        let height = old.commitment().len.next_power_of_two().trailing_zeros() as usize;
        let mut coordinates = proof_coordinates.clone();
        for &index in indices {
            coordinates.insert(Coordinate { level: 0, index });
            for level in 1..=height {
                coordinates.insert(Coordinate {
                    level,
                    index: index >> level,
                });
            }
        }

        let query_set = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut rows = Vec::with_capacity(coordinates.len());
        for coordinate in coordinates {
            let old_digest = old
                .digest_at(coordinate.level, coordinate.index)
                .ok_or(Error::NonCanonical)?;
            let new_digest = new
                .digest_at(coordinate.level, coordinate.index)
                .ok_or(Error::NonCanonical)?;
            let kind = if proof_coordinates.contains(&coordinate) {
                if old_digest != new_digest {
                    return Err(Error::ChangedBoundary);
                }
                NodeKind::Boundary
            } else if coordinate.level == 0 {
                if !query_set.contains(&coordinate.index) {
                    return Err(Error::NonCanonical);
                }
                NodeKind::Leaf
            } else {
                NodeKind::Internal
            };
            let children = (kind == NodeKind::Internal)
                .then(|| -> Result<[DigestPair; 2], Error> {
                    let child_level = coordinate.level - 1;
                    Ok([
                        DigestPair {
                            old: old
                                .digest_at(child_level, 2 * coordinate.index)
                                .ok_or(Error::NonCanonical)?,
                            new: new
                                .digest_at(child_level, 2 * coordinate.index)
                                .ok_or(Error::NonCanonical)?,
                        },
                        DigestPair {
                            old: old
                                .digest_at(child_level, 2 * coordinate.index + 1)
                                .ok_or(Error::NonCanonical)?,
                            new: new
                                .digest_at(child_level, 2 * coordinate.index + 1)
                                .ok_or(Error::NonCanonical)?,
                        },
                    ])
                })
                .transpose()?;
            let leaf_values = (kind == NodeKind::Leaf).then(|| {
                [
                    old.value(coordinate.index)
                        .expect("a sparse leaf is within the old tree"),
                    new.value(coordinate.index)
                        .expect("a sparse leaf is within the new tree"),
                ]
            });
            rows.push(NodeRow {
                tree,
                coordinate,
                kind,
                digest: DigestPair {
                    old: old_digest,
                    new: new_digest,
                },
                children,
                leaf_values,
            });
        }
        // Roots first, followed by a deterministic level-major ordering.
        rows.sort_by_key(|row| (Reverse(row.coordinate.level), row.coordinate.index));
        let dag = Self {
            tree,
            height,
            old_commitment: old.commitment(),
            new_commitment: new.commitment(),
            rows,
        };
        dag.validate()?;
        Ok(dag)
    }

    /// Build an ordinary single-tree opening using identical old/new digest
    /// columns. Keeping one row format lets all transition DAGs share one
    /// routing product.
    pub(crate) fn single(
        tree: TreeId,
        merkle: &MerkleTree,
        indices: &[usize],
    ) -> Result<Self, Error> {
        Self::paired(tree, merkle, merkle, indices)
    }

    pub(crate) fn rows(&self) -> &[NodeRow] {
        &self.rows
    }

    pub(crate) fn root(&self) -> DigestPair {
        self.rows[0].digest
    }

    /// One tuple for every non-root node.
    pub(crate) fn producers(&self) -> Vec<RouteTuple> {
        self.rows
            .iter()
            .skip(1)
            .map(|row| RouteTuple {
                tree: row.tree,
                coordinate: row.coordinate,
                digest: row.digest,
            })
            .collect()
    }

    /// Two tuple references for every internal node.
    pub(crate) fn references(&self) -> Vec<RouteTuple> {
        self.rows
            .iter()
            .filter_map(|row| row.children.map(|children| (row, children)))
            .flat_map(|(row, children)| {
                let child_level = row.coordinate.level - 1;
                [
                    RouteTuple {
                        tree: row.tree,
                        coordinate: Coordinate {
                            level: child_level,
                            index: 2 * row.coordinate.index,
                        },
                        digest: children[0],
                    },
                    RouteTuple {
                        tree: row.tree,
                        coordinate: Coordinate {
                            level: child_level,
                            index: 2 * row.coordinate.index + 1,
                        },
                        digest: children[1],
                    },
                ]
            })
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.rows.is_empty()
            || self.rows[0].tree != self.tree
            || self.rows[0].coordinate
                != (Coordinate {
                    level: self.height,
                    index: 0,
                })
            || self.rows.windows(2).any(|rows| {
                (Reverse(rows[0].coordinate.level), rows[0].coordinate.index)
                    >= (Reverse(rows[1].coordinate.level), rows[1].coordinate.index)
            })
        {
            return Err(Error::NonCanonical);
        }

        self.rows
            .par_iter()
            .map(|row| {
                match row.kind {
                    NodeKind::Leaf => {
                        let [old, new] = row.leaf_values.ok_or(Error::NonCanonical)?;
                        if row.coordinate.level != 0
                            || row.children.is_some()
                            || row.digest.old != hash_leaf(row.coordinate.index, old)
                            || row.digest.new != hash_leaf(row.coordinate.index, new)
                        {
                            return Err(Error::Hash);
                        }
                    }
                    NodeKind::Boundary => {
                        if row.children.is_some()
                            || row.leaf_values.is_some()
                            || row.digest.old != row.digest.new
                        {
                            return Err(Error::ChangedBoundary);
                        }
                    }
                    NodeKind::Internal => {
                        let [left, right] = row.children.ok_or(Error::NonCanonical)?;
                        if row.coordinate.level == 0
                            || row.leaf_values.is_some()
                            || row.digest.old
                                != hash_node(row.coordinate.level - 1, left.old, right.old)
                            || row.digest.new
                                != hash_node(row.coordinate.level - 1, left.new, right.new)
                        {
                            return Err(Error::Hash);
                        }
                    }
                }
                Ok(())
            })
            .collect::<Vec<Result<(), Error>>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        if self.root().old != self.old_commitment.root
            || self.root().new != self.new_commitment.root
        {
            return Err(Error::Root);
        }
        if !route_multisets_match(&self.producers(), &self.references()) {
            return Err(Error::Routing);
        }
        Ok(())
    }
}

fn route_multisets_match(producers: &[RouteTuple], references: &[RouteTuple]) -> bool {
    if producers.len() != references.len() {
        return false;
    }
    let mut producer_map = BTreeMap::<(TreeId, Coordinate), Vec<DigestPair>>::new();
    let mut reference_map = BTreeMap::<(TreeId, Coordinate), Vec<DigestPair>>::new();
    for tuple in producers {
        producer_map
            .entry((tuple.tree, tuple.coordinate))
            .or_default()
            .push(tuple.digest);
    }
    for tuple in references {
        reference_map
            .entry((tuple.tree, tuple.coordinate))
            .or_default()
            .push(tuple.digest);
    }
    producer_map == reference_map
}
