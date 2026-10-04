//! Update-independent indexing for transition wiring.

use crate::field::F;

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
            .map(F::from_usize)
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
    pub(crate) fn statement_elements(&self) -> [F; 7] {
        [
            F::from_usize(self.shape.gate_pairs),
            F::from_usize(self.shape.public_inputs),
            F::from_usize(self.shape.assignment_len),
            F::from_usize(self.shape.merkle_height),
            F::from_usize(self.permutation.len),
            self.permutation.root[0],
            self.permutation.root[1],
        ]
    }
}
