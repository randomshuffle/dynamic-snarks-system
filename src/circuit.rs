//! Section 4 fan-in-two circuit representation.

use p3_bn254::Bn254;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A padded Plonkish circuit with `n` addition and `n` multiplication rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Circuit {
    /// Number of addition gates and, separately, multiplication gates.
    pub n: usize,
    /// Number of public-input occurrences appended after the witness wires.
    pub num_public_inputs: usize,
    /// Wiring permutation over all `m = 6n + n0` occurrences.
    pub permutation: Vec<usize>,
}

/// Invalid circuit or assignment.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CircuitError {
    /// The circuit must contain at least one addition/multiplication pair.
    #[error("the circuit must contain at least one gate pair")]
    Empty,
    /// Public inputs cannot outnumber gate pairs under the paper's padding convention.
    #[error("public-input count {public_inputs} exceeds gate-pair count {n}")]
    TooManyPublicInputs {
        /// Gate-pair count.
        n: usize,
        /// Public-input occurrence count.
        public_inputs: usize,
    },
    /// The permutation has the wrong length.
    #[error("permutation length {actual} does not equal m={expected}")]
    PermutationLength {
        /// Required permutation length.
        expected: usize,
        /// Supplied permutation length.
        actual: usize,
    },
    /// The wiring is not a permutation of `0..m`.
    #[error("wiring is not a permutation")]
    InvalidPermutation,
    /// The assignment has the wrong length.
    #[error("assignment length {actual} does not equal m={expected}")]
    AssignmentLength {
        /// Required assignment length.
        expected: usize,
        /// Supplied assignment length.
        actual: usize,
    },
    /// An arithmetic gate constraint is false.
    #[error("gate constraint failed at pair {pair}")]
    GateConstraint {
        /// Failing gate-pair index.
        pair: usize,
    },
    /// A copy constraint is false.
    #[error("wiring constraint failed at position {position}")]
    WiringConstraint {
        /// Failing wire position.
        position: usize,
    },
    /// An update does not contain complete gate tuples.
    #[error("update set is not closed around gate tuple containing position {position}")]
    InvalidUpdateSet {
        /// Position whose gate tuple is incomplete.
        position: usize,
    },
}

impl Circuit {
    /// Validate and construct a circuit.
    pub fn new(
        n: usize,
        num_public_inputs: usize,
        permutation: Vec<usize>,
    ) -> Result<Self, CircuitError> {
        if n == 0 {
            return Err(CircuitError::Empty);
        }
        if num_public_inputs > n {
            return Err(CircuitError::TooManyPublicInputs {
                n,
                public_inputs: num_public_inputs,
            });
        }
        let m = 6 * n + num_public_inputs;
        if permutation.len() != m {
            return Err(CircuitError::PermutationLength {
                expected: m,
                actual: permutation.len(),
            });
        }
        let mut sorted = permutation.clone();
        sorted.sort_unstable();
        if sorted.iter().copied().ne(0..m) {
            return Err(CircuitError::InvalidPermutation);
        }
        Ok(Self {
            n,
            num_public_inputs,
            permutation,
        })
    }

    /// Total number of committed assignment entries.
    #[must_use]
    pub const fn assignment_len(&self) -> usize {
        6 * self.n + self.num_public_inputs
    }

    /// Number of update hierarchy levels, `ceil(log2(m + 1))`.
    #[must_use]
    pub fn hierarchy_depth(&self) -> usize {
        usize::BITS as usize - self.assignment_len().leading_zeros() as usize
    }

    /// Public-input positions in the assignment vector.
    #[must_use]
    pub fn public_positions(&self) -> Vec<usize> {
        (6 * self.n..self.assignment_len()).collect()
    }

    /// Check all gate and wiring constraints natively.
    pub fn check_assignment(&self, z: &[Bn254]) -> Result<(), CircuitError> {
        if z.len() != self.assignment_len() {
            return Err(CircuitError::AssignmentLength {
                expected: self.assignment_len(),
                actual: z.len(),
            });
        }
        for i in 0..self.n {
            if z[6 * i] + z[6 * i + 1] != z[6 * i + 2]
                || z[6 * i + 3] * z[6 * i + 4] != z[6 * i + 5]
            {
                return Err(CircuitError::GateConstraint { pair: i });
            }
        }
        for (i, &sigma_i) in self.permutation.iter().enumerate() {
            if z[i] != z[sigma_i] {
                return Err(CircuitError::WiringConstraint { position: i });
            }
        }
        Ok(())
    }

    /// Check Section 4's gate-tuple closure rule.
    pub fn check_update_indices(&self, indices: &[usize]) -> Result<(), CircuitError> {
        for &position in indices {
            if position >= self.assignment_len() {
                return Err(CircuitError::AssignmentLength {
                    expected: self.assignment_len(),
                    actual: position + 1,
                });
            }
            if position >= 6 * self.n {
                continue;
            }
            let tuple_start = if position % 6 < 3 {
                position - position % 6
            } else {
                position - position % 6 + 3
            };
            if !(tuple_start..tuple_start + 3)
                .all(|required| indices.binary_search(&required).is_ok())
            {
                return Err(CircuitError::InvalidUpdateSet { position });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn validates_gate_and_wiring_constraints() {
        let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
        let z = [1, 2, 3, 3, 4, 12, 9].map(Bn254::from_u64);
        circuit.check_assignment(&z).unwrap();
    }

    #[test]
    fn update_tuple_closure_is_enforced() {
        let circuit = Circuit::new(1, 0, (0..6).collect()).unwrap();
        assert!(circuit.check_update_indices(&[0, 1, 2]).is_ok());
        assert_eq!(
            circuit.check_update_indices(&[0, 1]),
            Err(CircuitError::InvalidUpdateSet { position: 0 })
        );
    }
}
