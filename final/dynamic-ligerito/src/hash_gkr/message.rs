//! Equivalent prover kernels; every variant returns the same nine coefficients.
use super::{F, Schedule, State, WIDTH, hash, line, round_at};
use flock_core::field::mul_by_x;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageKernel {
    Coefficients,
    FactoredCoefficients,
    StructuredEvaluations,
}

impl MessageKernel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Coefficients => "coefficients",
            Self::FactoredCoefficients => "factored",
            Self::StructuredEvaluations => "evaluations",
        }
    }

    pub fn configured() -> Result<Self, String> {
        match std::env::var("DYNAMIC_GKR_KERNEL").as_deref() {
            Ok("coefficients") => Ok(Self::Coefficients),
            Err(std::env::VarError::NotPresent) | Ok("factored") => Ok(Self::FactoredCoefficients),
            Ok("evaluations") => Ok(Self::StructuredEvaluations),
            _ => Err("DYNAMIC_GKR_KERNEL must be coefficients, factored or evaluations".into()),
        }
    }

    pub fn message(
        self,
        columns: &[Vec<F>],
        eq: &[F],
        weights: &[State],
        segments: usize,
        depth: usize,
        target: F,
        schedule: Schedule,
    ) -> [F; 9] {
        let pairs = eq.len() / 2;
        let inputs = |i: usize| {
            let s = i / pairs;
            let p = i % pairs;
            (
                round_at(segments, s, depth),
                std::array::from_fn(|w| columns[WIDTH * s + w][2 * p]),
                std::array::from_fn(|w| columns[WIDTH * s + w][2 * p + 1]),
                weights[s],
                p,
            )
        };
        match self {
            Self::Coefficients => schedule.coefficients(segments * pairs, |i| {
                let (round, zero, one, sw, p) = inputs(i);
                let h = line(round, zero, one, sw);
                let a = eq[2 * p];
                let b = a + eq[2 * p + 1];
                let mut c = [F::ZERO; 9];
                for k in 0..8 {
                    c[k] += a * h[k];
                    c[k + 1] += b * h[k];
                }
                c
            }),
            Self::FactoredCoefficients => {
                let h = schedule.coefficients(segments * pairs, |i| {
                    let (round, zero, one, sw, p) = inputs(i);
                    let tail = eq[2 * p] + eq[2 * p + 1];
                    line(round, zero, one, sw).map(|c| c * tail)
                });
                attach_equality(h, target)
            }
            Self::StructuredEvaluations => {
                let values = schedule.coefficients(segments * pairs, |i| {
                    let (round, zero, one, sw, p) = inputs(i);
                    let tail = eq[2 * p] + eq[2 * p + 1];
                    line_evaluations(round, zero, one, sw).map(|v| v * tail)
                });
                attach_equality(interpolate(values), target)
            }
        }
    }
}

fn attach_equality(h: [F; 8], target: F) -> [F; 9] {
    // eq(target, T) = 1 + target + T. The already-bound equality factors
    // are included in h via eq[2p] + eq[2p+1]; no division is needed.
    let constant = F::ONE + target;
    let mut g = [F::ZERO; 9];
    for k in 0..8 {
        g[k] += constant * h[k];
        g[k + 1] += h[k];
    }
    g
}

/// Values at the additive grid with binary labels 0..7. The three increments
/// correspond to 1, alpha and alpha^2 (or their Frobenius powers).
#[inline]
fn affine_grid(a: F, b: F, alpha_b: F, alpha2_b: F) -> [F; 8] {
    let c = a + alpha_b;
    let d = a + alpha2_b;
    let e = c + alpha2_b;
    [a, a + b, c, c + b, d, d + b, e, e + b]
}

#[inline]
fn shift<const N: usize>(mut a: F) -> F {
    for _ in 0..N {
        a = mul_by_x(a);
    }
    a
}

#[inline]
fn seventh_evaluations(a: F, b: F) -> [F; 8] {
    // (a+bT)^7 = (a+bT)(a^2+b^2 T^2)(a^4+b^4 T^4).
    // Four shared squares; only two general multiplications per grid point.
    let a2 = a * a;
    let a4 = a2 * a2;
    let b2 = b * b;
    let b4 = b2 * b2;
    let x = affine_grid(a, b, shift::<1>(b), shift::<2>(b));
    let x2 = affine_grid(a2, b2, shift::<2>(b2), shift::<4>(b2));
    let x4 = affine_grid(a4, b4, shift::<4>(b4), shift::<8>(b4));
    std::array::from_fn(|i| (x[i] * x2[i]) * x4[i])
}

fn line_evaluations(round: Option<usize>, mut zero: State, mut one: State, sw: State) -> [F; 8] {
    if let Some(r) = round {
        hash::before_sbox(r, &mut zero);
        hash::before_sbox(r, &mut one);
    }
    let mut values = [F::ZERO; 8];
    let mut affine = [F::ZERO; 2];
    for w in 0..WIDTH {
        let b = zero[w] + one[w];
        if round.is_some_and(|r| w == 0 || hash::full(r)) {
            let powers = seventh_evaluations(zero[w], b);
            for i in 0..8 {
                values[i] += sw[w] * powers[i];
            }
        } else {
            affine[0] += sw[w] * zero[w];
            affine[1] += sw[w] * b;
        }
    }
    let linear = affine_grid(
        affine[0],
        affine[1],
        shift::<1>(affine[1]),
        shift::<2>(affine[1]),
    );
    for i in 0..8 {
        values[i] += linear[i];
    }
    values
}

/// Inverse additive transform directly into monomial coefficients. The
/// subspace polynomials are W1(T)=T^2+T and W2(T)=T^4+7*T^2+6*T,
/// where numeric constants are polynomial-basis bit labels. Their values
/// at the next basis elements are W1(alpha)=6 and W2(alpha^2)=0x168.
/// Eight general multiplications plus shift/XOR operations; two inverses
/// are cached once, outside the steady-state loop.
fn interpolate(values: [F; 8]) -> [F; 8] {
    static INVERSES: OnceLock<[F; 2]> = OnceLock::new();
    let inv = INVERSES.get_or_init(|| [F::new(6, 0).inv(), F::new(0x168, 0).inv()]);
    let pairs: [[F; 2]; 4] = std::array::from_fn(|i| {
        let b = values[2 * i] + values[2 * i + 1];
        let offset_b = match i {
            0 => F::ZERO,
            1 => shift::<1>(b),
            2 => shift::<2>(b),
            3 => shift::<1>(b) + shift::<2>(b),
            _ => unreachable!(),
        };
        [values[2 * i] + offset_b, b]
    });
    let halves: [[F; 4]; 2] = std::array::from_fn(|i| {
        let left = pairs[2 * i];
        let right = pairs[2 * i + 1];
        let b: [F; 2] = std::array::from_fn(|j| (left[j] + right[j]) * inv[0]);
        // W1(0)=0, W1(alpha^2)=alpha^4+alpha^2 (bit label 20).
        let a: [F; 2] = std::array::from_fn(|j| {
            left[j]
                + if i == 0 {
                    F::ZERO
                } else {
                    shift::<4>(b[j]) + shift::<2>(b[j])
                }
        });
        [a[0], a[1] + b[0], b[0] + b[1], b[1]]
    });
    let mut result = [F::ZERO; 8];
    result[..4].copy_from_slice(&halves[0]);
    for i in 0..4 {
        let b = (halves[0][i] + halves[1][i]) * inv[1];
        let six_b = shift::<1>(b) + shift::<2>(b);
        result[i + 1] += six_b;
        result[i + 2] += six_b + b;
        result[i + 4] += b;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::math;
    use super::*;

    fn field(i: usize) -> F {
        hash::input(&hash::dataset(i))[i % 4]
    }

    #[test]
    fn structured_transform_and_line_evaluations_match_coefficients() {
        // Dense polynomials and every monomial, including constant/zero.
        for i in 0..40 {
            let coefficients: [F; 8] = std::array::from_fn(|j| {
                if i < 8 {
                    if i == j { F::ONE } else { F::ZERO }
                } else if i == 8 {
                    F::ZERO
                } else {
                    field(8 * i + j)
                }
            });
            let evaluations =
                std::array::from_fn(|j| math::poly_eval(&coefficients, F::new(j as u64, 0)));
            assert_eq!(interpolate(evaluations), coefficients);
        }
        for round in (0..hash::HASH_ROUNDS).map(Some).chain([None]) {
            for i in 0..4 {
                let zero = std::array::from_fn(|w| field(12 * i + w));
                let one = std::array::from_fn(|w| field(12 * i + 4 + w));
                let sw = std::array::from_fn(|w| field(12 * i + 8 + w));
                let coeffs = line(round, zero, one, sw);
                let evals = line_evaluations(round, zero, one, sw);
                for j in 0..8 {
                    assert_eq!(evals[j], math::poly_eval(&coeffs, F::new(j as u64, 0)));
                }
                assert_eq!(interpolate(evals), coeffs);
            }
        }
    }

    #[test]
    fn factored_messages_cover_zero_equality_and_boolean_targets() {
        let schedule = Schedule::default();
        for target in [F::ZERO, F::ONE, field(15)] {
            for prefix in [F::ZERO, F::ONE, field(23)] {
                let columns: Vec<Vec<F>> = (0..8)
                    .map(|w| (0..8).map(|r| field(8 * w + r)).collect())
                    .collect();
                let eq: Vec<_> = (0..4)
                    .flat_map(|p| {
                        let tail = prefix * field(71 + p);
                        [(F::ONE + target) * tail, target * tail]
                    })
                    .collect();
                let weights = [std::array::from_fn(|w| field(90 + w)); 2];
                let reference = MessageKernel::Coefficients
                    .message(&columns, &eq, &weights, 2, 0, target, schedule);
                for kernel in [
                    MessageKernel::FactoredCoefficients,
                    MessageKernel::StructuredEvaluations,
                ] {
                    assert_eq!(
                        kernel.message(&columns, &eq, &weights, 2, 0, target, schedule),
                        reference
                    );
                }
            }
        }
    }
}
