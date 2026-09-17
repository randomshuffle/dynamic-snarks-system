//! Update-independent indexing for transition wiring.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;

use crate::circuit::Circuit;
use crate::merkle::{Commitment, MerkleError, MerkleTree};

/// Compact circuit shape retained by the transition verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CircuitShape {
    pub(crate) gate_pairs: usize,
    pub(crate) public_inputs: usize,
    pub(crate) assignment_len: usize,
    pub(crate) merkle_height: usize,
}

impl CircuitShape {
    pub(crate) fn from_circuit(circuit: &Circuit) -> Self {
        Self {
            gate_pairs: circuit.n,
            public_inputs: circuit.num_public_inputs,
            assignment_len: circuit.assignment_len(),
            merkle_height: circuit.assignment_tree_len().trailing_zeros() as usize,
        }
    }

    pub(crate) fn hierarchy_depth(self) -> usize {
        usize::BITS as usize - self.assignment_len.leading_zeros() as usize
    }

    pub(crate) fn public_positions(self) -> Vec<usize> {
        (0..self.public_inputs).map(|index| 4 * index + 3).collect()
    }

    pub(crate) fn assignment_tree_len(self) -> usize {
        4 * (2 * self.gate_pairs).next_power_of_two()
    }
}

/// Prover-side indexed wiring state. The full permutation tree is retained so
/// arbitrary update-dependent query sets can be authenticated later.
#[derive(Clone, Debug)]
pub(crate) struct ProverWiringIndex {
    permutation_tree: MerkleTree,
    verifier: VerifierWiringIndex,
}

/// Verifier-side indexed wiring state. It contains no permutation vector and
/// no update positions, only the circuit shape and indexed commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifierWiringIndex {
    shape: CircuitShape,
    permutation: Commitment,
}

/// Commit the fixed wiring permutation once, independently of every update.
pub(crate) fn preprocess(
    circuit: &Circuit,
) -> Result<(ProverWiringIndex, VerifierWiringIndex), MerkleError> {
    let permutation_tree = MerkleTree::new(
        circuit
            .encoded_permutation()
            .into_iter()
            .map(Bn254::from_usize)
            .collect(),
    )?;
    let shape = CircuitShape::from_circuit(circuit);
    let verifier = VerifierWiringIndex {
        shape,
        permutation: permutation_tree.commitment(),
    };
    Ok((
        ProverWiringIndex {
            permutation_tree,
            verifier,
        },
        verifier,
    ))
}

impl ProverWiringIndex {
    pub(crate) const fn permutation_tree(&self) -> &MerkleTree {
        &self.permutation_tree
    }

    pub(crate) const fn verifier(&self) -> VerifierWiringIndex {
        self.verifier
    }
}

impl VerifierWiringIndex {
    pub(crate) const fn shape(&self) -> CircuitShape {
        self.shape
    }

    pub(crate) const fn permutation_commitment(&self) -> Commitment {
        self.permutation
    }

    /// Public, update-independent fields absorbed by transition transcripts.
    pub(crate) fn statement_elements(&self) -> [Bn254; 6] {
        [
            Bn254::from_usize(self.shape.gate_pairs),
            Bn254::from_usize(self.shape.public_inputs),
            Bn254::from_usize(self.shape.assignment_len),
            Bn254::from_usize(self.shape.merkle_height),
            Bn254::from_usize(self.permutation.len),
            self.permutation.root,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sparse_dag::{SparseMerkleDag, TreeId};

    #[test]
    fn preprocessing_supports_arbitrary_non_power_of_two_shapes() {
        let n = 11;
        let n0 = 5;
        let m = 6 * n + n0;
        let circuit = Circuit::new(n, n0, (0..m).rev().collect()).unwrap();
        let (prover, verifier) = preprocess(&circuit).unwrap();
        assert_eq!(verifier.shape().assignment_len, 71);
        assert_eq!(verifier.shape().merkle_height, 7);
        assert_eq!(
            verifier.permutation_commitment(),
            prover.permutation_tree().commitment()
        );
    }

    #[test]
    fn one_index_authenticates_unrelated_future_query_sets() {
        let n = 7;
        let n0 = 3;
        let m = 6 * n + n0;
        let permutation = (0..m).map(|index| (index + 1) % m).collect();
        let circuit = Circuit::new(n, n0, permutation).unwrap();
        let (prover, verifier) = preprocess(&circuit).unwrap();

        let first =
            SparseMerkleDag::single(TreeId::Permutation, prover.permutation_tree(), &[0, 1, 2])
                .unwrap();
        let second = SparseMerkleDag::single(
            TreeId::Permutation,
            prover.permutation_tree(),
            &[17, 31, 44],
        )
        .unwrap();
        assert_eq!(first.root().old, verifier.permutation_commitment().root);
        assert_eq!(second.root().old, verifier.permutation_commitment().root);
        assert_eq!(prover.verifier(), verifier);
        assert_eq!(
            verifier.statement_elements(),
            prover.verifier().statement_elements()
        );
    }
}
