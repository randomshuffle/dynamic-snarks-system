//! Homogeneous Plonkish trace and constraint evaluator.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;

use super::program::{AlignedTrace, ConstraintProgram, Operation, Variable};

pub(super) const GATE_WIDTH: usize = 4;
pub(super) const PRE_WIDTH: usize = 32;
pub(super) const LOCAL_PRE_WIDTH: usize = 16;
pub(super) const LOCAL_CONSTRAINT_COUNT: usize = 14;

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

/// Arithmetic circuits have alternating add/multiply rows followed by an
/// optional public-input suffix. Their selectors have succinct public MLEs.
/// Other programs retain committed local selectors and constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreprocessingLayout {
    AlignedArithmetic {
        gate_pairs: usize,
        public_inputs: usize,
        expose_public_inputs: bool,
    },
    Arithmetic {
        gate_pairs: usize,
        public_inputs: usize,
    },
    General,
}

impl PreprocessingLayout {
    fn from_program(program: &ConstraintProgram) -> Self {
        if let Some(aligned) = &program.aligned {
            assert!(!program.operations.is_empty() && program.operations.len() % 2 == 0);
            assert!(
                program
                    .operations
                    .chunks_exact(2)
                    .all(|pair| matches!(pair, [Operation::Add(..), Operation::Mul(..)]))
            );
            assert_eq!(aligned.permutation.len(), GATE_WIDTH * program.trace_len());
            return Self::AlignedArithmetic {
                gate_pairs: program.operations.len() / 2,
                public_inputs: aligned.public_variables.len(),
                expose_public_inputs: program.num_public_values != 0,
            };
        }
        let Some(gate_rows) = program
            .operations
            .len()
            .checked_sub(program.num_public_values)
        else {
            return Self::General;
        };
        if gate_rows == 0 || gate_rows % 2 != 0 {
            return Self::General;
        }
        let gates_match = program.operations[..gate_rows]
            .chunks_exact(2)
            .all(|pair| matches!(pair, [Operation::Add(..), Operation::Mul(..)]));
        let public_match = program.operations[gate_rows..].iter().enumerate().all(|(index, op)| {
            matches!(op, Operation::Public(_, public_index) if *public_index == index)
        });
        if gates_match && public_match {
            Self::Arithmetic {
                gate_pairs: gate_rows / 2,
                public_inputs: program.num_public_values,
            }
        } else {
            Self::General
        }
    }

    pub(super) const fn sigma_offset(self) -> usize {
        match self {
            Self::Arithmetic { .. } | Self::AlignedArithmetic { .. } => 0,
            Self::General => LOCAL_PRE_WIDTH,
        }
    }

    pub(super) fn width(self, main_width: usize) -> usize {
        (self.sigma_offset() + main_width).next_power_of_two()
    }

    pub(super) fn local_columns(self) -> &'static [usize] {
        match self {
            Self::Arithmetic { .. } => &[Q_ADD, Q_MUL, Q_PUBLIC],
            Self::AlignedArithmetic { .. } => &[Q_ADD, Q_MUL, Q_PUBLIC, C0, C0 + 1],
            Self::General => &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        }
    }

    pub(super) fn local_table(
        self,
        column: usize,
        rows: usize,
        committed: &[Vec<Bn254>],
    ) -> Vec<Bn254> {
        match self {
            Self::General => committed[column].clone(),
            Self::AlignedArithmetic {
                gate_pairs,
                public_inputs,
                expose_public_inputs,
            } => (0..rows)
                .into_par_iter()
                .map(|row| {
                    Bn254::from_bool(match column {
                        Q_ADD => row < 2 * gate_pairs && row % 2 == 0,
                        Q_MUL => row < 2 * gate_pairs && row % 2 == 1,
                        Q_PUBLIC => expose_public_inputs && row < public_inputs,
                        C0 => row >= 2 * gate_pairs,
                        x if x == C0 + 1 => row >= public_inputs,
                        _ => false,
                    })
                })
                .collect(),
            Self::Arithmetic {
                gate_pairs,
                public_inputs,
            } => (0..rows)
                .into_par_iter()
                .map(|row| {
                    Bn254::from_bool(match column {
                        Q_ADD => row < 2 * gate_pairs && row % 2 == 0,
                        Q_MUL => row < 2 * gate_pairs && row % 2 == 1,
                        Q_PUBLIC => (2 * gate_pairs..2 * gate_pairs + public_inputs).contains(&row),
                        _ => false,
                    })
                })
                .collect(),
        }
    }

    pub(super) fn local_values(
        self,
        point: &[Bn254],
        openings: &[Bn254],
    ) -> [Bn254; LOCAL_PRE_WIDTH] {
        let mut result = [Bn254::ZERO; LOCAL_PRE_WIDTH];
        match self {
            Self::General => result.copy_from_slice(&openings[..LOCAL_PRE_WIDTH]),
            Self::AlignedArithmetic {
                gate_pairs,
                public_inputs,
                expose_public_inputs,
            } => {
                let active_pairs = prefix_mle(&point[1..], gate_pairs);
                result[Q_ADD] = (Bn254::ONE - point[0]) * active_pairs;
                result[Q_MUL] = point[0] * active_pairs;
                let public = prefix_mle(point, public_inputs);
                result[Q_PUBLIC] = if expose_public_inputs {
                    public
                } else {
                    Bn254::ZERO
                };
                result[C0] = Bn254::ONE - prefix_mle(point, 2 * gate_pairs);
                result[C0 + 1] = Bn254::ONE - public;
            }
            Self::Arithmetic {
                gate_pairs,
                public_inputs,
            } => {
                let active_pairs = prefix_mle(&point[1..], gate_pairs);
                result[Q_ADD] = (Bn254::ONE - point[0]) * active_pairs;
                result[Q_MUL] = point[0] * active_pairs;
                result[Q_PUBLIC] = prefix_mle(point, 2 * gate_pairs + public_inputs)
                    - prefix_mle(point, 2 * gate_pairs);
            }
        }
        result
    }

    /// Bind the uncommitted selector description to Fiat--Shamir.
    pub(super) fn statement_elements(self) -> [Bn254; 4] {
        match self {
            Self::General => [Bn254::ZERO; 4],
            Self::AlignedArithmetic {
                gate_pairs,
                public_inputs,
                expose_public_inputs,
            } => [
                Bn254::TWO,
                Bn254::from_usize(gate_pairs),
                Bn254::from_usize(public_inputs),
                Bn254::from_bool(expose_public_inputs),
            ],
            Self::Arithmetic {
                gate_pairs,
                public_inputs,
            } => [
                Bn254::ONE,
                Bn254::from_usize(gate_pairs),
                Bn254::from_usize(public_inputs),
                Bn254::ZERO,
            ],
        }
    }
}

/// MLE of the indicator of the integer interval [0, end), in low-bit order.
fn prefix_mle(point: &[Bn254], end: usize) -> Bn254 {
    let Some((&high, lower)) = point.split_last() else {
        return Bn254::from_bool(end != 0);
    };
    let half = 1usize << lower.len();
    if end <= half {
        (Bn254::ONE - high) * prefix_mle(lower, end)
    } else {
        (Bn254::ONE - high) + high * prefix_mle(lower, end - half)
    }
}

/// Fixed relation data retained by preprocessing.
#[derive(Clone, Debug)]
pub(super) struct RelationShape {
    pub(super) operations: Vec<Operation>,
    pub(super) num_public_values: usize,
    pub(super) num_variables: usize,
    pub(super) domain_size: usize,
    pub(super) main_width: usize,
    aligned: Option<AlignedTrace>,
    pub(super) public_rows: Vec<(usize, usize)>,
    pub(super) preprocessing: PreprocessingLayout,
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
        let domain_size = program.trace_len();
        let main_width = GATE_WIDTH;
        let preprocessing = PreprocessingLayout::from_program(program);
        let mut local = vec![vec![Bn254::ZERO; domain_size]; preprocessing.sigma_offset()];
        let mut permutation = vec![vec![Bn254::ZERO; domain_size]; main_width];
        let mut occurrences = Vec::with_capacity(if program.aligned.is_some() {
            0
        } else {
            main_width * domain_size
        });
        let mut public_rows = Vec::new();
        let dummy_start = program.values.len();

        for row in 0..domain_size {
            let mut set_local = |column: usize, value: Bn254| {
                if let Some(values) = local.get_mut(column) {
                    values[row] = value;
                }
            };
            let mut variables = [None; GATE_WIDTH];
            if let Some(operation) = program.operations.get(row) {
                match operation {
                    Operation::Add(a, b, out) => {
                        set_local(Q_ADD, Bn254::ONE);
                        variables = [Some(*a), Some(*b), Some(*out), None];
                    }
                    Operation::Mul(a, b, out) => {
                        set_local(Q_MUL, Bn254::ONE);
                        variables = [Some(*a), Some(*b), Some(*out), None];
                    }
                    Operation::Pow5Add(input, constant, out) => {
                        set_local(Q_POW5, Bn254::ONE);
                        set_local(C0, *constant);
                        variables = [Some(*input), Some(*out), None, None];
                    }
                    Operation::Lin3(inputs, coefficients, constant, out) => {
                        set_local(Q_LIN3, Bn254::ONE);
                        for (column, coefficient) in coefficients.iter().enumerate() {
                            set_local(C0 + column, *coefficient);
                        }
                        set_local(C0 + 3, *constant);
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::SboxLin3(inputs, constants, coefficients, out) => {
                        set_local(Q_SBOX_LIN3, Bn254::ONE);
                        for slot in 0..3 {
                            set_local(C0 + slot, constants[slot]);
                            set_local(C0 + 3 + slot, coefficients[slot]);
                        }
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::Pow5FirstLin3(inputs, constant, coefficients, out) => {
                        set_local(Q_POW5_FIRST_LIN3, Bn254::ONE);
                        set_local(C0, *constant);
                        for slot in 0..3 {
                            set_local(C0 + 3 + slot, coefficients[slot]);
                        }
                        variables = [
                            Some(inputs[0]),
                            Some(inputs[1]),
                            Some(inputs[2]),
                            Some(*out),
                        ];
                    }
                    Operation::Equal(a, b) => {
                        set_local(Q_EQUAL, Bn254::ONE);
                        variables = [Some(*a), Some(*b), None, None];
                    }
                    Operation::Boolean(variable) => {
                        set_local(Q_BOOLEAN, Bn254::ONE);
                        variables = [Some(*variable), None, None, None];
                    }
                    Operation::Constant(variable, constant) => {
                        set_local(Q_CONSTANT, Bn254::ONE);
                        set_local(C0, *constant);
                        variables = [Some(*variable), None, None, None];
                    }
                    Operation::Public(variable, index) => {
                        set_local(Q_PUBLIC, Bn254::ONE);
                        public_rows.push((row, *index));
                        variables = [Some(*variable), None, None, None];
                    }
                }
            }
            if let Some(aligned) = &program.aligned {
                variables[3] = aligned.public_variables.get(row).copied();
                if row < aligned.public_variables.len() && program.num_public_values != 0 {
                    public_rows.push((row, row));
                }
            }
            for (slot, variable) in variables.into_iter().enumerate() {
                let position = main_width * row + slot;
                let id = variable.map_or(dummy_start + position, |v| v.0);
                if program.aligned.is_none() {
                    occurrences.push((id, row, slot, position));
                }
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
                permutation[slot][row] = Bn254::from_usize(next + 1);
            }
            start = end;
        }

        if let Some(aligned) = &program.aligned {
            for (position, &next) in aligned.permutation.iter().enumerate() {
                permutation[position % GATE_WIDTH][position / GATE_WIDTH] =
                    Bn254::from_usize(next + 1);
            }
        }

        let mut preprocessed_evaluations = local;
        preprocessed_evaluations.extend(permutation);
        Self {
            operations: program.operations.clone(),
            num_public_values: program.num_public_values,
            num_variables: program.values.len(),
            domain_size,
            main_width,
            aligned: program.aligned.clone(),
            public_rows,
            preprocessing,
            preprocessed_evaluations,
        }
    }

    pub(super) fn matches(&self, program: &ConstraintProgram) -> bool {
        self.operations == program.operations
            && self.num_public_values == program.num_public_values
            && self.num_variables == program.values.len()
            && self.aligned == program.aligned
    }

    #[allow(clippy::needless_range_loop)]
    pub(super) fn main_trace(
        &self,
        program: &ConstraintProgram,
        public_values: &[Bn254],
    ) -> MainTrace {
        let mut columns = vec![vec![Bn254::ZERO; self.domain_size]; self.main_width];
        let mut public_column = vec![Bn254::ZERO; self.domain_size];
        crate::parallel::rows_mut(
            &mut columns
                .iter_mut()
                .map(Vec::as_mut_slice)
                .collect::<Vec<_>>(),
            0..self.domain_size,
            128,
            |start, columns| {
                for offset in 0..columns[0].len() {
                    let row = start + offset;
                    let variables = self
                        .operations
                        .get(row)
                        .map_or([None; 4], operation_variables);
                    for (column, variable) in columns.iter_mut().zip(variables) {
                        column[offset] = variable.map_or(Bn254::ZERO, |v| program.values[v.0]);
                    }
                    if let Some(variable) = self
                        .aligned
                        .as_ref()
                        .and_then(|a| a.public_variables.get(row))
                    {
                        columns[3][offset] = program.values[variable.0];
                    }
                }
            },
        );
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
    layout: PreprocessingLayout,
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
    let aligned = matches!(layout, PreprocessingLayout::AlignedArithmetic { .. });
    result[7] = pre[Q_PUBLIC] * (values[if aligned { 3 } else { 0 }] - public_value);
    if aligned {
        for column in 0..3 {
            result[10 + column] = pre[C0] * values[column];
        }
        result[13] = pre[C0 + 1] * values[3];
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_selectors_and_padding_constraints_match_the_four_column_layout() {
        for (gate_pairs, public_inputs) in [(1usize, 0usize), (1, 1), (3, 2), (5, 1)] {
            let rows = (2 * gate_pairs).next_power_of_two();
            for expose_public_inputs in [false, true] {
                let layout = PreprocessingLayout::AlignedArithmetic {
                    gate_pairs,
                    public_inputs,
                    expose_public_inputs,
                };
                let point = (0..rows.trailing_zeros())
                    .map(|bit| Bn254::from_u64(3 * u64::from(bit) + 2))
                    .collect::<Vec<_>>();
                let analytic = layout.local_values(&point, &[]);
                for (column, &value) in analytic.iter().enumerate() {
                    let expected = layout
                        .local_table(column, rows, &[])
                        .iter()
                        .enumerate()
                        .map(|(row, &entry)| {
                            point.iter().enumerate().fold(entry, |acc, (bit, &x)| {
                                acc * if row & (1 << bit) == 0 {
                                    Bn254::ONE - x
                                } else {
                                    x
                                }
                            })
                        })
                        .sum::<Bn254>();
                    assert_eq!(value, expected);
                }
                for row in 0..rows {
                    let point = (0..rows.trailing_zeros())
                        .map(|bit| Bn254::from_bool(row & (1 << bit) != 0))
                        .collect::<Vec<_>>();
                    let pre = layout.local_values(&point, &[]);
                    let residuals =
                        evaluate_local_constraints(layout, &pre, &[Bn254::ONE; 4], Bn254::ZERO);
                    for &residual in &residuals[10..13] {
                        assert_eq!(residual, Bn254::from_bool(row >= 2 * gate_pairs));
                    }
                    assert_eq!(residuals[13], Bn254::from_bool(row >= public_inputs));
                    assert_eq!(
                        residuals[7],
                        Bn254::from_bool(expose_public_inputs && row < public_inputs)
                    );
                }
            }
        }
    }

    #[test]
    fn succinct_selectors_match_dense_mles_including_padding_and_public_rows() {
        for (gate_pairs, public_inputs) in [
            (1usize, 0usize),
            (1, 1),
            (3, 2),
            (4, 0),
            (4, 4),
            (5, 3),
            (9, 0),
        ] {
            let layout = PreprocessingLayout::Arithmetic {
                gate_pairs,
                public_inputs,
            };
            let rows = (2 * gate_pairs + public_inputs).next_power_of_two();
            let variables = rows.trailing_zeros() as usize;
            for trial in 0..3 {
                let point = (0..variables)
                    .map(|bit| Bn254::from_usize(7 * bit + trial + 2))
                    .collect::<Vec<_>>();
                let actual = layout.local_values(&point, &[]);
                for (column, &value) in actual.iter().enumerate() {
                    let dense = layout.local_table(column, rows, &[]);
                    let expected = dense
                        .iter()
                        .enumerate()
                        .map(|(row, &entry)| {
                            point.iter().enumerate().fold(entry, |product, (bit, &x)| {
                                product
                                    * if row & (1 << bit) == 0 {
                                        Bn254::ONE - x
                                    } else {
                                        x
                                    }
                            })
                        })
                        .sum::<Bn254>();
                    assert_eq!(
                        value, expected,
                        "pairs={gate_pairs}, public={public_inputs}, column={column}"
                    );
                }
            }
        }
    }
}
