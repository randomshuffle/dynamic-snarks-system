//! Arithmetic gadgets used by the initial and transition relations.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;

use crate::hash::poseidon2_constants;
use crate::static_snark::{ProgramBuilder, Variable};

pub(crate) struct Gadgets {
    initial_constants: Vec<[Bn254; 3]>,
    terminal_constants: Vec<[Bn254; 3]>,
    internal_constants: Vec<Bn254>,
}

impl Gadgets {
    pub(crate) fn new() -> Self {
        let (external, internal_constants) = poseidon2_constants();
        Self {
            initial_constants: external.get_initial_constants().clone(),
            terminal_constants: external.get_terminal_constants().clone(),
            internal_constants,
        }
    }

    pub(crate) fn poseidon2(
        &self,
        builder: &mut ProgramBuilder,
        mut state: [Variable; 3],
    ) -> [Variable; 3] {
        state = external_linear(builder, state);
        for &constants in &self.initial_constants {
            state = full_round(builder, state, constants);
        }
        for &constant in &self.internal_constants {
            state = partial_round(builder, state, constant);
        }
        for &constants in &self.terminal_constants {
            state = full_round(builder, state, constants);
        }
        state
    }

    pub(crate) fn leaf(
        &self,
        builder: &mut ProgramBuilder,
        index: Variable,
        value: Variable,
    ) -> Variable {
        let domain = builder.constant(Bn254::ONE);
        self.poseidon2(builder, [value, index, domain])[0]
    }

    pub(crate) fn node(
        &self,
        builder: &mut ProgramBuilder,
        level: usize,
        left: Variable,
        right: Variable,
    ) -> Variable {
        let domain = builder.constant(Bn254::from_usize(2 + level));
        self.poseidon2(builder, [left, right, domain])[0]
    }

    pub(crate) fn merkle_path(
        &self,
        builder: &mut ProgramBuilder,
        value: Variable,
        index: Variable,
        index_bits: &[Variable],
        siblings: &[Variable],
    ) -> Variable {
        debug_assert_eq!(index_bits.len(), siblings.len());
        let mut node = self.leaf(builder, index, value);
        for (level, (&bit, &sibling)) in index_bits.iter().zip(siblings).enumerate() {
            let left = select(builder, bit, sibling, node);
            let right = select(builder, bit, node, sibling);
            node = self.node(builder, level, left, right);
        }
        node
    }
}

fn full_round(
    builder: &mut ProgramBuilder,
    state: [Variable; 3],
    constants: [Bn254; 3],
) -> [Variable; 3] {
    [
        builder.sbox_lin3(state, constants, [Bn254::TWO, Bn254::ONE, Bn254::ONE]),
        builder.sbox_lin3(state, constants, [Bn254::ONE, Bn254::TWO, Bn254::ONE]),
        builder.sbox_lin3(state, constants, [Bn254::ONE, Bn254::ONE, Bn254::TWO]),
    ]
}

fn external_linear(builder: &mut ProgramBuilder, state: [Variable; 3]) -> [Variable; 3] {
    [
        builder.lin3(state, [Bn254::TWO, Bn254::ONE, Bn254::ONE], Bn254::ZERO),
        builder.lin3(state, [Bn254::ONE, Bn254::TWO, Bn254::ONE], Bn254::ZERO),
        builder.lin3(state, [Bn254::ONE, Bn254::ONE, Bn254::TWO], Bn254::ZERO),
    ]
}

fn partial_round(
    builder: &mut ProgramBuilder,
    state: [Variable; 3],
    constant: Bn254,
) -> [Variable; 3] {
    [
        builder.pow5_first_lin3(state, constant, [Bn254::TWO, Bn254::ONE, Bn254::ONE]),
        builder.pow5_first_lin3(state, constant, [Bn254::ONE, Bn254::TWO, Bn254::ONE]),
        builder.pow5_first_lin3(
            state,
            constant,
            [Bn254::ONE, Bn254::ONE, Bn254::from_u64(3)],
        ),
    ]
}

pub(crate) fn linear(
    builder: &mut ProgramBuilder,
    terms: [(Variable, Bn254); 3],
    constant: Bn254,
) -> Variable {
    builder.lin3(
        [terms[0].0, terms[1].0, terms[2].0],
        [terms[0].1, terms[1].1, terms[2].1],
        constant,
    )
}

pub(crate) fn not(builder: &mut ProgramBuilder, value: Variable, zero: Variable) -> Variable {
    linear(
        builder,
        [
            (value, -Bn254::ONE),
            (zero, Bn254::ZERO),
            (zero, Bn254::ZERO),
        ],
        Bn254::ONE,
    )
}

/// `selector == 0 || left == right`.
pub(crate) fn conditional_equal(
    builder: &mut ProgramBuilder,
    selector: Variable,
    left: Variable,
    right: Variable,
    zero: Variable,
) {
    let difference = linear(
        builder,
        [
            (left, Bn254::ONE),
            (right, -Bn254::ONE),
            (zero, Bn254::ZERO),
        ],
        Bn254::ZERO,
    );
    let selected = builder.mul(selector, difference);
    builder.assert_equal(selected, zero);
}

/// Return `when_false + selector * (when_true - when_false)`.
pub(crate) fn select(
    builder: &mut ProgramBuilder,
    selector: Variable,
    when_true: Variable,
    when_false: Variable,
) -> Variable {
    let difference = linear(
        builder,
        [
            (when_true, Bn254::ONE),
            (when_false, -Bn254::ONE),
            (selector, Bn254::ZERO),
        ],
        Bn254::ZERO,
    );
    let selected = builder.mul(selector, difference);
    builder.add(when_false, selected)
}

pub(crate) fn allocate_bits(
    builder: &mut ProgramBuilder,
    value: usize,
    bit_count: usize,
    zero: Variable,
) -> (Variable, Vec<Variable>) {
    let encoded = builder.variable(Bn254::from_usize(value));
    let bits: Vec<_> = (0..bit_count)
        .map(|bit| {
            let variable = builder.variable(Bn254::from_bool(value & (1 << bit) != 0));
            builder.assert_boolean(variable);
            variable
        })
        .collect();
    let mut reconstruction = zero;
    for (bit, &variable) in bits.iter().enumerate() {
        let term = linear(
            builder,
            [
                (variable, Bn254::from_u64(1u64 << bit)),
                (zero, Bn254::ZERO),
                (zero, Bn254::ZERO),
            ],
            Bn254::ZERO,
        );
        reconstruction = builder.add(reconstruction, term);
    }
    builder.assert_equal(encoded, reconstruction);
    (encoded, bits)
}

/// Boolean comparison of little-endian bit vectors.
pub(crate) fn less_than(
    builder: &mut ProgramBuilder,
    left: &[Variable],
    right: &[Variable],
    zero: Variable,
    one: Variable,
) -> Variable {
    debug_assert_eq!(left.len(), right.len());
    let mut equal_prefix = one;
    let mut less = zero;
    for (&a, &b) in left.iter().zip(right).rev() {
        let not_a = not(builder, a, zero);
        let a_lt_b = builder.mul(not_a, b);
        let term = builder.mul(equal_prefix, a_lt_b);
        less = builder.add(less, term);
        let ab = builder.mul(a, b);
        let equal_bit = linear(
            builder,
            [(a, -Bn254::ONE), (b, -Bn254::ONE), (ab, Bn254::TWO)],
            Bn254::ONE,
        );
        equal_prefix = builder.mul(equal_prefix, equal_bit);
    }
    less
}

pub(crate) fn constant_bits(
    builder: &mut ProgramBuilder,
    value: usize,
    bit_count: usize,
) -> Vec<Variable> {
    (0..bit_count)
        .map(|bit| builder.constant(Bn254::from_bool(value & (1 << bit) != 0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::hash::{hash_leaf, hash_node};

    use super::*;

    #[test]
    fn poseidon_gadgets_match_native_hashes() {
        let mut builder = ProgramBuilder::new(0);
        let gadgets = Gadgets::new();
        let index = builder.variable(Bn254::from_u64(5));
        let value = builder.variable(Bn254::from_u64(17));
        let leaf = gadgets.leaf(&mut builder, index, value);
        assert_eq!(builder.value(leaf), hash_leaf(5, Bn254::from_u64(17)));
        let right = builder.variable(Bn254::from_u64(23));
        let node = gadgets.node(&mut builder, 2, leaf, right);
        assert_eq!(
            builder.value(node),
            hash_node(2, hash_leaf(5, Bn254::from_u64(17)), Bn254::from_u64(23))
        );
    }
}
