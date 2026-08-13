//! Shared kernels for the degree-six Poseidon sumchecks.

use std::sync::OnceLock;

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_maybe_rayon::prelude::*;

/// A degree-six message needs seven values. Keeping 0 and 1 first preserves
/// the standard sumcheck consistency check; the symmetric dyadic set
/// `{0, +/-1/2, +/-1, +/-2}` makes affine table evaluation use only additions,
/// subtractions, doublings, and BN254's specialized halving operation.
pub(crate) const EVALUATIONS: usize = 7;
pub(crate) const FIFTH_COEFFICIENTS: usize = 6;
pub(crate) const PARTIAL_ROUNDS: usize = 56;
const STATE_WIDTH: usize = 3;
const PARTIAL_ROUND_START: usize = 4;

/// Each item in this reduction performs all 64 Poseidon rounds at all seven
/// points, so a much smaller threshold than a simple field dot product is
/// enough to amortize Rayon scheduling.
const PARALLEL_PAIR_THRESHOLD: usize = 1 << 6;

/// Evaluate the line `zero + t * (one - zero)` at
/// `0, 1, -1, 2, -2, 1/2, -1/2`.
#[inline(always)]
pub(crate) fn line_evaluations(zero: Bn254, one: Bn254) -> [Bn254; EVALUATIONS] {
    let delta = one - zero;
    let twice_delta = delta.double();
    let half_delta = delta.halve();
    [
        zero,
        one,
        zero - delta,
        one + delta,
        zero - twice_delta,
        zero + half_delta,
        zero - half_delta,
    ]
}

/// Evaluate `(zero + t * (one - zero))^5` at the seven Poseidon points.
///
/// Seven independent fifth powers cost 21 general multiplications. Expanding
/// the degree-five polynomial once costs 12; evaluation at the small signed
/// dyadic points then uses only additions, doublings, and halvings.
#[inline]
pub(crate) fn fifth_line_evaluations(zero: Bn254, one: Bn254) -> [Bn254; EVALUATIONS] {
    degree_five_evaluations(fifth_line_coefficients(zero, one))
}

/// Coefficients of `(zero + t * (one - zero))^5` in ascending powers of `t`.
#[inline]
pub(crate) fn fifth_line_coefficients(zero: Bn254, one: Bn254) -> [Bn254; FIFTH_COEFFICIENTS] {
    let delta = one - zero;

    let zero_2 = zero * zero;
    let zero_3 = zero_2 * zero;
    let zero_4 = zero_2 * zero_2;
    let zero_5 = zero_4 * zero;
    let delta_2 = delta * delta;
    let delta_3 = delta_2 * delta;
    let delta_4 = delta_2 * delta_2;
    let delta_5 = delta_4 * delta;

    [
        zero_5,
        times_five(zero_4 * delta),
        times_ten(zero_3 * delta_2),
        times_ten(zero_2 * delta_3),
        times_five(zero * delta_4),
        delta_5,
    ]
}

/// Evaluate an ascending-order degree-five coefficient vector at all seven
/// dyadic message points, sharing the even and odd parts of every +/- pair.
#[inline]
pub(crate) fn degree_five_evaluations(
    coefficients: [Bn254; FIFTH_COEFFICIENTS],
) -> [Bn254; EVALUATIONS] {
    let [c0, c1, c2, c3, c4, c5] = coefficients;
    let one_even = c0 + c2 + c4;
    let one_odd = c1 + c3 + c5;
    let plus_one = one_even + one_odd;
    let minus_one = one_even - one_odd;

    let two_even = c0 + c2.double().double() + c4.double().double().double().double();
    let two_odd = c1.double()
        + c3.double().double().double()
        + c5.double().double().double().double().double();
    let plus_two = two_even + two_odd;
    let minus_two = two_even - two_odd;

    let c2_over_4 = c2.halve().halve();
    let c4_over_16 = c4.halve().halve().halve().halve();
    let c1_over_2 = c1.halve();
    let c3_over_8 = c3.halve().halve().halve();
    let c5_over_32 = c5.halve().halve().halve().halve().halve();
    let half_even = c0 + c2_over_4 + c4_over_16;
    let half_odd = c1_over_2 + c3_over_8 + c5_over_32;
    [
        c0,
        plus_one,
        minus_one,
        plus_two,
        minus_two,
        half_even + half_odd,
        half_even - half_odd,
    ]
}

#[inline(always)]
fn times_five(value: Bn254) -> Bn254 {
    value.double().double() + value
}

#[inline(always)]
fn times_ten(value: Bn254) -> Bn254 {
    times_five(value).double()
}

/// Hoist the transpose of each partial round's linear layer into the fixed
/// constraint weights. The results multiply the nonlinear, second, and third
/// input lanes respectively.
pub(crate) fn partial_round_weights(weights: &[Bn254]) -> [[Bn254; STATE_WIDTH]; PARTIAL_ROUNDS] {
    core::array::from_fn(|partial_round| {
        let offset = STATE_WIDTH * (partial_round + PARTIAL_ROUND_START);
        let [first, second, third]: [Bn254; STATE_WIDTH] = weights[offset..offset + STATE_WIDTH]
            .try_into()
            .expect("a Poseidon round has three constraints");
        [
            first.double() + second + third,
            first + second.double() + third,
            first + second + third.double() + third,
        ]
    })
}

/// Combine a partial round in coefficient form before evaluating its seven
/// message points. This scales six nonlinear coefficients, six next-state
/// coefficients, and four untouched-lane coefficients (16 multiplications),
/// instead of scaling three residuals independently at seven points (21).
#[allow(clippy::too_many_arguments)]
pub(crate) fn partial_round_residual_evaluations(
    current_zero: [Bn254; STATE_WIDTH],
    current_one: [Bn254; STATE_WIDTH],
    next_zero: [Bn254; STATE_WIDTH],
    next_one: [Bn254; STATE_WIDTH],
    constant: Bn254,
    weights: [Bn254; STATE_WIDTH],
    mixed_weights: [Bn254; STATE_WIDTH],
) -> [Bn254; EVALUATIONS] {
    let fifth = fifth_line_coefficients(current_zero[0] + constant, current_one[0] + constant);
    let mut residual: [Bn254; FIFTH_COEFFICIENTS] =
        core::array::from_fn(|degree| -(mixed_weights[0] * fifth[degree]));
    for word in 0..STATE_WIDTH {
        residual[0] += weights[word] * next_zero[word];
        residual[1] += weights[word] * (next_one[word] - next_zero[word]);
    }
    for word in 1..STATE_WIDTH {
        residual[0] -= mixed_weights[word] * current_zero[word];
        residual[1] -= mixed_weights[word] * (current_one[word] - current_zero[word]);
    }
    degree_five_evaluations(residual)
}

/// Sum independent pair contributions, using Rayon only while enough of the
/// expensive Poseidon pair kernels remain to amortize scheduling.
pub(crate) fn sum_pairs<F>(pair_count: usize, evaluate_pair: F) -> [Bn254; EVALUATIONS]
where
    F: Fn(usize) -> [Bn254; EVALUATIONS] + Sync + Send,
{
    if pair_count < PARALLEL_PAIR_THRESHOLD {
        return (0..pair_count).fold([Bn254::ZERO; EVALUATIONS], |sum, pair| {
            add_evaluations(sum, evaluate_pair(pair))
        });
    }
    (0..pair_count).into_par_iter().par_fold_reduce(
        || [Bn254::ZERO; EVALUATIONS],
        |sum, pair| add_evaluations(sum, evaluate_pair(pair)),
        add_evaluations,
    )
}

#[inline(always)]
fn add_evaluations(
    mut left: [Bn254; EVALUATIONS],
    right: [Bn254; EVALUATIONS],
) -> [Bn254; EVALUATIONS] {
    for (left, right) in left.iter_mut().zip(right) {
        *left += right;
    }
    left
}

/// Interpolate values ordered as `0, 1, -1, 2, -2, 1/2, -1/2`.
/// Fixed inverse Lagrange denominators are initialized once; evaluating the
/// degree-six message at a transcript challenge requires no field inversions.
pub(crate) fn interpolate(evaluations: &[Bn254], point: Bn254) -> Bn254 {
    debug_assert_eq!(evaluations.len(), EVALUATIONS);
    let data = interpolation_data();
    let mut result = Bn254::ZERO;
    for (evaluation, &value) in evaluations.iter().enumerate() {
        let mut basis = data.inverse_denominators[evaluation];
        for other in 0..EVALUATIONS {
            if other != evaluation {
                basis *= point - data.points[other];
            }
        }
        result += value * basis;
    }
    result
}

struct InterpolationData {
    points: [Bn254; EVALUATIONS],
    inverse_denominators: [Bn254; EVALUATIONS],
}

fn interpolation_data() -> &'static InterpolationData {
    static DATA: OnceLock<InterpolationData> = OnceLock::new();
    DATA.get_or_init(|| {
        let half = Bn254::ONE.halve();
        let points = [
            Bn254::ZERO,
            Bn254::ONE,
            -Bn254::ONE,
            Bn254::from_u64(2),
            -Bn254::from_u64(2),
            half,
            -half,
        ];
        let denominators: [Bn254; EVALUATIONS] = core::array::from_fn(|index| {
            (0..EVALUATIONS)
                .filter(|&other| other != index)
                .fold(Bn254::ONE, |value, other| {
                    value * (points[index] - points[other])
                })
        });
        let mut prefix = [Bn254::ONE; EVALUATIONS];
        prefix[0] = denominators[0];
        for index in 1..EVALUATIONS {
            prefix[index] = prefix[index - 1] * denominators[index];
        }
        let mut inverse = prefix[EVALUATIONS - 1].inverse();
        let mut inverse_denominators = [Bn254::ZERO; EVALUATIONS];
        for index in (1..EVALUATIONS).rev() {
            inverse_denominators[index] = inverse * prefix[index - 1];
            inverse *= denominators[index];
        }
        inverse_denominators[0] = inverse;
        InterpolationData {
            points,
            inverse_denominators,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fifth(value: Bn254) -> Bn254 {
        let square = value * value;
        square * square * value
    }

    #[test]
    fn small_point_line_evaluations_match_direct_arithmetic() {
        let zero = Bn254::from_u64(17);
        let one = Bn254::from_u64(29);
        let half = Bn254::ONE.halve();
        let points = [
            Bn254::ZERO,
            Bn254::ONE,
            -Bn254::ONE,
            Bn254::from_u64(2),
            -Bn254::from_u64(2),
            half,
            -half,
        ];
        let expected = points.map(|point| zero + point * (one - zero));
        assert_eq!(line_evaluations(zero, one), expected);
        assert_eq!(fifth_line_evaluations(zero, one), expected.map(fifth));
    }

    #[test]
    fn symmetric_interpolation_recovers_degree_six_polynomial() {
        let coefficients = [2, 3, 5, 7, 11, 13, 17].map(Bn254::from_u64);
        let polynomial = |point: Bn254| {
            coefficients
                .iter()
                .rev()
                .fold(Bn254::ZERO, |value, &coefficient| {
                    value * point + coefficient
                })
        };
        let evaluations = interpolation_data().points.map(polynomial);
        let challenge = Bn254::from_u64(91);
        assert_eq!(interpolate(&evaluations, challenge), polynomial(challenge));
    }

    #[test]
    fn pair_reduction_matches_direct_sum() {
        let pair_count = 2 * PARALLEL_PAIR_THRESHOLD;
        let contribution = |pair: usize| {
            core::array::from_fn(|evaluation| Bn254::from_usize((pair + 1) * (evaluation + 3)))
        };
        let expected = (0..pair_count).fold([Bn254::ZERO; EVALUATIONS], |sum, pair| {
            add_evaluations(sum, contribution(pair))
        });
        assert_eq!(sum_pairs(pair_count, contribution), expected);
    }

    #[test]
    fn partial_round_coefficient_kernel_matches_pointwise_constraints() {
        let current_zero = [3, 5, 7].map(Bn254::from_u64);
        let current_one = [11, 13, 17].map(Bn254::from_u64);
        let next_zero = [19, 23, 29].map(Bn254::from_u64);
        let next_one = [31, 37, 41].map(Bn254::from_u64);
        let constant = Bn254::from_u64(43);
        let weights = [47, 53, 59].map(Bn254::from_u64);
        let mixed_weights = [
            weights[0].double() + weights[1] + weights[2],
            weights[0] + weights[1].double() + weights[2],
            weights[0] + weights[1] + weights[2].double() + weights[2],
        ];
        let optimized = partial_round_residual_evaluations(
            current_zero,
            current_one,
            next_zero,
            next_one,
            constant,
            weights,
            mixed_weights,
        );
        let current = core::array::from_fn::<_, STATE_WIDTH, _>(|word| {
            line_evaluations(current_zero[word], current_one[word])
        });
        let next = core::array::from_fn::<_, STATE_WIDTH, _>(|word| {
            line_evaluations(next_zero[word], next_one[word])
        });
        let expected = core::array::from_fn(|evaluation| {
            let first = fifth(current[0][evaluation] + constant);
            let round_output = [
                first.double() + current[1][evaluation] + current[2][evaluation],
                first + current[1][evaluation].double() + current[2][evaluation],
                first
                    + current[1][evaluation]
                    + current[2][evaluation].double()
                    + current[2][evaluation],
            ];
            (0..STATE_WIDTH).fold(Bn254::ZERO, |sum, word| {
                sum + weights[word] * (next[word][evaluation] - round_output[word])
            })
        });
        assert_eq!(optimized, expected);
    }
}
