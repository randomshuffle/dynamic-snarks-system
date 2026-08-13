//! Homogeneous Plonkish trace and constraint evaluator.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;

use super::program::{ConstraintProgram, Operation, Variable};

pub(super) const MAIN_WIDTH: usize = 4;
pub(super) const PRE_WIDTH: usize = 32;
pub(super) const LOCAL_CONSTRAINT_COUNT: usize = 10;

pub(super) const Q_ADD: usize = 0;
pub(super) const Q_MUL: usize = 1;
pub(super) const Q_POW5: usize = 2;
pub(super) const Q_LIN3: usize = 3;
pub(super) const Q_EQUAL: usize = 4;
pub(super) const Q_BOOLEAN: usize = 5;
pub(super) const Q_CONSTANT: usize = 6;
pub(super) const Q_PUBLIC: usize = 7;
pub(super) const Q_SBOX_LIN3: usize = 8;
pub(super) const Q_POW5_FIRST_LIN3: usize = 9;
pub(super) const C0: usize = 10;
pub(super) const ID0: usize = 16;
pub(super) const SIGMA0: usize = 20;

/// Fixed relation data retained by preprocessing.
#[derive(Clone, Debug)]
pub(super) struct RelationShape {
    pub(super) operations: Vec<Operation>,
    pub(super) num_public_values: usize,
    pub(super) num_variables: usize,
    pub(super) domain_size: usize,
    pub(super) public_rows: Vec<(usize, usize)>,
    pub(super) preprocessed_evaluations: Vec<Vec<Bn254>>,
}

/// Witness-dependent trace evaluations on the base subgroup.
pub(super) struct MainTrace {
    pub(super) columns: Vec<Vec<Bn254>>,
    pub(super) public_column: Vec<Bn254>,
}

impl RelationShape {
    #[allow(clippy::needless_range_loop)]
    pub(super) fn from_program(program: &ConstraintProgram) -> Self {
        let domain_size = program.operations.len().max(2).next_power_of_two();
        let mut preprocessed_evaluations = vec![vec![Bn254::ZERO; domain_size]; PRE_WIDTH];
        let mut occurrences = Vec::with_capacity(4 * domain_size);
        let mut public_rows = Vec::new();
        let dummy_start = program.values.len();

        for row in 0..domain_size {
            let mut variables = [None; 4];
            if let Some(operation) = program.operations.get(row) {
                match operation {
                    Operation::Add(a, b, out) => {
                        preprocessed_evaluations[Q_ADD][row] = Bn254::ONE;
                        variables = [Some(*a), Some(*b), Some(*out), None];
                    }
                    Operation::Mul(a, b, out) => {
                        preprocessed_evaluations[Q_MUL][row] = Bn254::ONE;
                        variables = [Some(*a), Some(*b), Some(*out), None];
                    }
                    Operation::Pow5Add(input, constant, out) => {
                        preprocessed_evaluations[Q_POW5][row] = Bn254::ONE;
                        preprocessed_evaluations[C0][row] = *constant;
                        variables = [Some(*input), Some(*out), None, None];
                    }
                    Operation::Lin3(inputs, coefficients, constant, out) => {
                        preprocessed_evaluations[Q_LIN3][row] = Bn254::ONE;
                        for (column, coefficient) in coefficients.iter().enumerate() {
                            preprocessed_evaluations[C0 + column][row] = *coefficient;
                        }
                        preprocessed_evaluations[C0 + 3][row] = *constant;
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::SboxLin3(inputs, constants, coefficients, out) => {
                        preprocessed_evaluations[Q_SBOX_LIN3][row] = Bn254::ONE;
                        for slot in 0..3 {
                            preprocessed_evaluations[C0 + slot][row] = constants[slot];
                            preprocessed_evaluations[C0 + 3 + slot][row] = coefficients[slot];
                        }
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::Pow5FirstLin3(inputs, constant, coefficients, out) => {
                        preprocessed_evaluations[Q_POW5_FIRST_LIN3][row] = Bn254::ONE;
                        preprocessed_evaluations[C0][row] = *constant;
                        for slot in 0..3 {
                            preprocessed_evaluations[C0 + 3 + slot][row] = coefficients[slot];
                        }
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::Equal(a, b) => {
                        preprocessed_evaluations[Q_EQUAL][row] = Bn254::ONE;
                        variables = [Some(*a), Some(*b), None, None];
                    }
                    Operation::Boolean(variable) => {
                        preprocessed_evaluations[Q_BOOLEAN][row] = Bn254::ONE;
                        variables = [Some(*variable), None, None, None];
                    }
                    Operation::Constant(variable, constant) => {
                        preprocessed_evaluations[Q_CONSTANT][row] = Bn254::ONE;
                        preprocessed_evaluations[C0][row] = *constant;
                        variables = [Some(*variable), None, None, None];
                    }
                    Operation::Public(variable, index) => {
                        preprocessed_evaluations[Q_PUBLIC][row] = Bn254::ONE;
                        public_rows.push((row, *index));
                        variables = [Some(*variable), None, None, None];
                    }
                }
            }
            for (slot, variable) in variables.into_iter().enumerate() {
                let id = variable.map_or(dummy_start + 4 * row + slot, |v| v.0);
                let position = 4 * row + slot;
                preprocessed_evaluations[ID0 + slot][row] = Bn254::from_usize(position + 1);
                occurrences.push((id, row, slot, position));
            }
        }

        // The permutation labels cycle through every occurrence of one program
        // variable. Equality of the two labelled tuple products therefore
        // forces all values on each cycle to agree, without a sorted witness or
        // a next-row constraint.
        occurrences.sort_unstable_by_key(|&(id, _, _, position)| (id, position));
        let mut start = 0;
        while start < occurrences.len() {
            let id = occurrences[start].0;
            let mut end = start + 1;
            while end < occurrences.len() && occurrences[end].0 == id {
                end += 1;
            }
            for offset in start..end {
                let (_, row, slot, _) = occurrences[offset];
                let next = occurrences[if offset + 1 == end { start } else { offset + 1 }].3;
                preprocessed_evaluations[SIGMA0 + slot][row] = Bn254::from_usize(next + 1);
            }
            start = end;
        }

        Self {
            operations: program.operations.clone(),
            num_public_values: program.num_public_values,
            num_variables: program.values.len(),
            domain_size,
            public_rows,
            preprocessed_evaluations,
        }
    }

    pub(super) fn matches(&self, program: &ConstraintProgram) -> bool {
        self.operations == program.operations
            && self.num_public_values == program.num_public_values
            && self.num_variables == program.values.len()
    }

    #[allow(clippy::needless_range_loop)]
    pub(super) fn main_trace(
        &self,
        program: &ConstraintProgram,
        public_values: &[Bn254],
    ) -> MainTrace {
        let mut columns = vec![vec![Bn254::ZERO; self.domain_size]; MAIN_WIDTH];
        let mut public_column = vec![Bn254::ZERO; self.domain_size];
        for row in 0..self.domain_size {
            let variables = self
                .operations
                .get(row)
                .map_or([None; 4], operation_variables);
            for (slot, variable) in variables.into_iter().enumerate() {
                columns[slot][row] = variable.map_or(Bn254::ZERO, |v| program.values[v.0]);
            }
        }
        for &(row, public_index) in &self.public_rows {
            public_column[row] = public_values[public_index];
        }
        MainTrace {
            columns,
            public_column,
        }
    }
}

fn operation_variables(operation: &Operation) -> [Option<Variable>; 4] {
    match operation {
        Operation::Add(a, b, out) | Operation::Mul(a, b, out) => {
            [Some(*a), Some(*b), Some(*out), None]
        }
        Operation::Pow5Add(input, _, out) => [Some(*input), Some(*out), None, None],
        Operation::Lin3(inputs, _, _, out)
        | Operation::SboxLin3(inputs, _, _, out)
        | Operation::Pow5FirstLin3(inputs, _, _, out) => [
            Some(inputs[0]),
            Some(inputs[1]),
            Some(inputs[2]),
            Some(*out),
        ],
        Operation::Equal(a, b) => [Some(*a), Some(*b), None, None],
        Operation::Boolean(variable)
        | Operation::Constant(variable, _)
        | Operation::Public(variable, _) => [Some(*variable), None, None, None],
    }
}

/// Evaluate every local gate constraint at one multilinear row point.
pub(super) fn evaluate_local_constraints(
    pre: &[Bn254],
    main: &[Bn254],
    public_value: Bn254,
) -> [Bn254; LOCAL_CONSTRAINT_COUNT] {
    let values = main;
    let mut result = [Bn254::ZERO; LOCAL_CONSTRAINT_COUNT];

    result[0] = pre[Q_ADD] * (values[0] + values[1] - values[2]);
    result[1] = pre[Q_MUL] * (values[0] * values[1] - values[2]);
    result[2] = pre[Q_POW5] * ((values[0] + pre[C0]).exp_const_u64::<5>() - values[1]);
    result[3] = pre[Q_LIN3]
        * (pre[C0] * values[0] + pre[C0 + 1] * values[1] + pre[C0 + 2] * values[2] + pre[C0 + 3]
            - values[3]);
    result[4] = pre[Q_EQUAL] * (values[0] - values[1]);
    result[5] = pre[Q_BOOLEAN] * values[0] * (values[0] - Bn254::ONE);
    result[6] = pre[Q_CONSTANT] * (values[0] - pre[C0]);
    result[7] = pre[Q_PUBLIC] * (values[0] - public_value);
    result[8] = pre[Q_SBOX_LIN3]
        * ((values[0] + pre[C0]).exp_const_u64::<5>() * pre[C0 + 3]
            + (values[1] + pre[C0 + 1]).exp_const_u64::<5>() * pre[C0 + 4]
            + (values[2] + pre[C0 + 2]).exp_const_u64::<5>() * pre[C0 + 5]
            - values[3]);
    result[9] = pre[Q_POW5_FIRST_LIN3]
        * ((values[0] + pre[C0]).exp_const_u64::<5>() * pre[C0 + 3]
            + values[1] * pre[C0 + 4]
            + values[2] * pre[C0 + 5]
            - values[3]);
    result
}
