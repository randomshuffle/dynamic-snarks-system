//! Low-degree constraint program compiled into a homogeneous Plonkish trace.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;

/// Index of a program variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Variable(pub(crate) usize);

/// A fixed sequence of low-degree operations and one concrete assignment.
#[derive(Clone, Debug)]
pub struct ConstraintProgram {
    pub(crate) values: Vec<Bn254>,
    pub(crate) operations: Vec<Operation>,
    pub(crate) num_public_values: usize,
    pub(crate) aligned: Option<AlignedTrace>,
}

/// A four-column arithmetic layout sharing its table with the assignment tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AlignedTrace {
    pub(crate) public_variables: Vec<Variable>,
    pub(crate) permutation: Vec<usize>,
}

/// Builder whose methods always append a fixed operation sequence.
#[derive(Clone, Debug)]
pub struct ProgramBuilder {
    values: Vec<Bn254>,
    operations: Vec<Operation>,
    num_public_values: usize,
    aligned: Option<AlignedTrace>,
}

impl ConstraintProgram {
    /// Number of rows after padding the operation sequence for arithmetization.
    #[must_use]
    pub fn trace_len(&self) -> usize {
        self.operations.len().max(2).next_power_of_two()
    }
}

impl Operation {
    /// Evaluate the constraint residual on one (possibly multilinearly
    /// interpolated) row assignment.
    pub(crate) fn residual(&self, values: &[Bn254], public_values: &[Bn254]) -> Bn254 {
        let value = |variable: Variable| values[variable.0];
        match self {
            Self::Add(left, right, output) => value(*left) + value(*right) - value(*output),
            Self::Mul(left, right, output) => value(*left) * value(*right) - value(*output),
            Self::Pow5Add(input, constant, output) => {
                fifth(value(*input) + *constant) - value(*output)
            }
            Self::SboxLin3(inputs, constants, coefficients, output) => {
                inputs.iter().zip(constants).zip(coefficients).fold(
                    Bn254::ZERO,
                    |sum, ((&input, &constant), &coefficient)| {
                        sum + coefficient * fifth(value(input) + constant)
                    },
                ) - value(*output)
            }
            Self::Pow5FirstLin3(inputs, constant, coefficients, output) => {
                coefficients[0] * fifth(value(inputs[0]) + *constant)
                    + coefficients[1] * value(inputs[1])
                    + coefficients[2] * value(inputs[2])
                    - value(*output)
            }
            Self::Lin3(inputs, coefficients, constant, output) => {
                inputs
                    .iter()
                    .zip(coefficients)
                    .fold(*constant, |sum, (&input, &coefficient)| {
                        sum + coefficient * value(input)
                    })
                    - value(*output)
            }
            Self::Equal(left, right) => value(*left) - value(*right),
            Self::Boolean(variable) => value(*variable) * value(*variable) - value(*variable),
            Self::Constant(variable, constant) => value(*variable) - *constant,
            Self::Public(variable, public_index) => value(*variable) - public_values[*public_index],
        }
    }
}

fn fifth(value: Bn254) -> Bn254 {
    let square = value * value;
    square * square * value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Add(Variable, Variable, Variable),
    Mul(Variable, Variable, Variable),
    Pow5Add(Variable, Bn254, Variable),
    SboxLin3([Variable; 3], [Bn254; 3], [Bn254; 3], Variable),
    Pow5FirstLin3([Variable; 3], Bn254, [Bn254; 3], Variable),
    Lin3([Variable; 3], [Bn254; 3], Bn254, Variable),
    Equal(Variable, Variable),
    Boolean(Variable),
    Constant(Variable, Bn254),
    Public(Variable, usize),
}

impl ProgramBuilder {
    /// Start a program with `num_public_values` relation inputs.
    #[must_use]
    pub const fn new(num_public_values: usize) -> Self {
        Self {
            values: Vec::new(),
            operations: Vec::new(),
            num_public_values,
            aligned: None,
        }
    }

    /// Allocate a private variable with a concrete prover value.
    pub fn variable(&mut self, value: Bn254) -> Variable {
        let variable = Variable(self.values.len());
        self.values.push(value);
        variable
    }

    /// Allocate and constrain a constant.
    pub fn constant(&mut self, value: Bn254) -> Variable {
        let variable = self.variable(value);
        self.operations.push(Operation::Constant(variable, value));
        variable
    }

    /// Allocate a relation public value and bind it to `public_index`.
    pub fn public(&mut self, public_index: usize, value: Bn254) -> Variable {
        assert!(public_index < self.num_public_values);
        let variable = self.variable(value);
        self.operations
            .push(Operation::Public(variable, public_index));
        variable
    }

    /// Bind an existing witness variable to a relation public input.
    pub fn assert_public(&mut self, variable: Variable, public_index: usize) {
        assert!(public_index < self.num_public_values);
        self.operations
            .push(Operation::Public(variable, public_index));
    }

    /// Constrain three existing variables with one addition gate row.
    pub fn assert_add(&mut self, left: Variable, right: Variable, output: Variable) {
        self.operations.push(Operation::Add(left, right, output));
    }

    /// Constrain three existing variables with one multiplication gate row.
    pub fn assert_mul(&mut self, left: Variable, right: Variable, output: Variable) {
        self.operations.push(Operation::Mul(left, right, output));
    }

    /// Put public-input occurrences in column three and use the supplied cell permutation.
    pub(crate) fn align_arithmetic(
        &mut self,
        public_variables: &[Variable],
        permutation: Vec<usize>,
    ) {
        assert!(self.aligned.is_none());
        self.aligned = Some(AlignedTrace {
            public_variables: public_variables.to_vec(),
            permutation,
        });
    }

    /// Constrain `left + right = output` and return `output`.
    pub fn add(&mut self, left: Variable, right: Variable) -> Variable {
        let output = self.variable(self.value(left) + self.value(right));
        self.operations.push(Operation::Add(left, right, output));
        output
    }

    /// Constrain `left * right = output` and return `output`.
    pub fn mul(&mut self, left: Variable, right: Variable) -> Variable {
        let output = self.variable(self.value(left) * self.value(right));
        self.operations.push(Operation::Mul(left, right, output));
        output
    }

    /// Apply `(input + constant)^5` in one degree-five gate.
    pub fn pow5_add(&mut self, input: Variable, constant: Bn254) -> Variable {
        let x = self.value(input) + constant;
        let output = self.variable(x.exp_const_u64::<5>());
        self.operations
            .push(Operation::Pow5Add(input, constant, output));
        output
    }

    /// Apply a three-input affine map.
    pub fn lin3(
        &mut self,
        inputs: [Variable; 3],
        coefficients: [Bn254; 3],
        constant: Bn254,
    ) -> Variable {
        let value = inputs
            .iter()
            .zip(coefficients)
            .fold(constant, |acc, (&input, coefficient)| {
                acc + self.value(input) * coefficient
            });
        let output = self.variable(value);
        self.operations
            .push(Operation::Lin3(inputs, coefficients, constant, output));
        output
    }

    /// Apply a width-three full Poseidon2 S-box layer followed by one
    /// row of its linear layer.
    pub fn sbox_lin3(
        &mut self,
        inputs: [Variable; 3],
        round_constants: [Bn254; 3],
        coefficients: [Bn254; 3],
    ) -> Variable {
        let value = inputs.iter().zip(round_constants).zip(coefficients).fold(
            Bn254::ZERO,
            |acc, ((&input, constant), coefficient)| {
                acc + (self.value(input) + constant).exp_const_u64::<5>() * coefficient
            },
        );
        let output = self.variable(value);
        self.operations.push(Operation::SboxLin3(
            inputs,
            round_constants,
            coefficients,
            output,
        ));
        output
    }

    /// Apply a partial Poseidon2 S-box to the first input and then one
    /// row of the internal linear layer.
    pub fn pow5_first_lin3(
        &mut self,
        inputs: [Variable; 3],
        round_constant: Bn254,
        coefficients: [Bn254; 3],
    ) -> Variable {
        let value = (self.value(inputs[0]) + round_constant).exp_const_u64::<5>() * coefficients[0]
            + self.value(inputs[1]) * coefficients[1]
            + self.value(inputs[2]) * coefficients[2];
        let output = self.variable(value);
        self.operations.push(Operation::Pow5FirstLin3(
            inputs,
            round_constant,
            coefficients,
            output,
        ));
        output
    }

    /// Assert equality of two existing variables.
    pub fn assert_equal(&mut self, left: Variable, right: Variable) {
        self.operations.push(Operation::Equal(left, right));
    }

    /// Assert that a variable is Boolean.
    pub fn assert_boolean(&mut self, variable: Variable) {
        self.operations.push(Operation::Boolean(variable));
    }

    /// Read a variable's concrete assignment.
    pub fn value(&self, variable: Variable) -> Bn254 {
        self.values[variable.0]
    }

    /// Finish the program.
    #[must_use]
    pub fn finish(self) -> ConstraintProgram {
        ConstraintProgram {
            values: self.values,
            operations: self.operations,
            num_public_values: self.num_public_values,
            aligned: self.aligned,
        }
    }
}
