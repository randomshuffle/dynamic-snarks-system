//! Opening arithmetic for points that select columns of an interleaved table.
//!
//! Plonky3 points are big-endian: a Boolean suffix selects one column, and the
//! remaining prefix is the row point. Keep the original claims and their order;
//! only their evaluations and the combined equality table are computed here.

use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::eq_batch::eval_eq_batch;

use super::{F, Point, Poly, PrimeCharacteristicRing};

/// Cache only the most recent row point, bounding storage independently of the
/// number of claims. Column claims at a common row point occur consecutively.
#[derive(Debug, Clone, Default)]
pub(super) struct RowWeights {
    point: Vec<F>,
    weights: Vec<F>,
}

impl RowWeights {
    fn at(&mut self, point: &[F]) -> &[F] {
        if self.weights.is_empty() || self.point != point {
            self.point = point.to_vec();
            self.weights = Poly::new_from_point(point, F::ONE).into_evals();
        }
        &self.weights
    }

    pub(super) fn evaluate(&mut self, poly: &Poly<F>, point: &Point<F>) -> F {
        assert_eq!(poly.num_variables(), point.num_variables());
        let Some((row_point, column, stride)) = column_selection(point) else {
            return poly.eval_ext::<F>(point);
        };
        let weights = self.at(row_point);
        evaluate_column(poly, weights, column, stride)
    }

    /// Column claims share their row weights and can be evaluated independently
    /// before their values are absorbed in the original transcript order.
    pub(super) fn evaluate_batch(&mut self, poly: &Poly<F>, points: &[Point<F>]) -> Vec<F> {
        assert!(
            points
                .iter()
                .all(|point| point.num_variables() == poly.num_variables())
        );
        let mut result = vec![F::ZERO; points.len()];
        let mut index = 0;
        while index < points.len() {
            let Some((row_point, _, stride)) = column_selection(&points[index]) else {
                result[index] = self.evaluate(poly, &points[index]);
                index += 1;
                continue;
            };
            let start = index;
            let mut columns = Vec::new();
            while index < points.len() {
                match column_selection(&points[index]) {
                    Some((next_row, column, next_stride))
                        if row_point == next_row && stride == next_stride =>
                    {
                        columns.push(column);
                        index += 1;
                    }
                    _ => break,
                }
            }
            let weights = self.at(row_point);
            result[start..index]
                .par_iter_mut()
                .zip(columns.par_iter())
                .for_each(|(value, &column)| {
                    *value = evaluate_column(poly, weights, column, stride)
                });
        }
        result
    }

    /// Construct exactly sum_j alpha^j eq(point_j, X), including duplicate
    /// points. Dense/OOD claims use the general kernel with their ORIGINAL
    /// powers of alpha, even when column claims precede or separate them.
    pub(super) fn combine_claims(
        &mut self,
        num_variables: usize,
        claims: &[(Point<F>, F)],
        alpha: F,
    ) -> (Poly<F>, F) {
        let mut weights = Poly::zero(num_variables);
        let mut claimed_sum = F::ZERO;
        let mut dense_points = Vec::new();
        let mut dense_scales = Vec::new();
        let scales = alpha.powers().take(claims.len()).collect();
        let mut index = 0;
        while index < claims.len() {
            let (point, _) = &claims[index];
            assert_eq!(point.num_variables(), num_variables);
            if let Some((row_point, _, stride)) = column_selection(point) {
                let mut columns = Vec::new();
                while index < claims.len() {
                    let (point, evaluation) = &claims[index];
                    assert_eq!(point.num_variables(), num_variables);
                    match column_selection(point) {
                        Some((next_row, column, next_stride))
                            if next_row == row_point && next_stride == stride =>
                        {
                            columns.push((column, scales[index]));
                            claimed_sum += scales[index] * *evaluation;
                            index += 1;
                        }
                        _ => break,
                    }
                }
                let row_weights = self.at(row_point);
                let chunk =
                    crate::parallel::grain(row_weights.len(), 512usize.div_ceil(columns.len()));
                weights
                    .as_mut_slice()
                    .par_chunks_mut(chunk * stride)
                    .enumerate()
                    .for_each(|(task, block)| {
                        for &(column, scale) in &columns {
                            for (offset, row) in block.chunks_exact_mut(stride).enumerate() {
                                row[column] += scale * row_weights[task * chunk + offset];
                            }
                        }
                    });
            } else {
                claimed_sum += scales[index] * claims[index].1;
                dense_points.push(point.clone());
                dense_scales.push(scales[index]);
                index += 1;
            }
        }
        if !dense_points.is_empty() {
            let points = Point::transpose(&dense_points, false);
            if dense_points.len() == claims.len() {
                // Preserve the original overwrite kernel for entirely dense batches.
                eval_eq_batch::<F, F, false>(
                    points.as_view(),
                    weights.as_mut_slice(),
                    &dense_scales,
                );
            } else {
                eval_eq_batch::<F, F, true>(
                    points.as_view(),
                    weights.as_mut_slice(),
                    &dense_scales,
                );
            }
        }
        (weights, claimed_sum)
    }
}

fn evaluate_column(poly: &Poly<F>, weights: &[F], column: usize, stride: usize) -> F {
    let chunk = crate::parallel::grain(weights.len(), 256);
    let evaluate = |offset: usize, weights: &[F]| {
        weights
            .iter()
            .enumerate()
            .fold(F::ZERO, |sum, (row, &weight)| {
                sum + poly.as_slice()[(offset + row) * stride + column] * weight
            })
    };
    if weights.len() <= chunk {
        return evaluate(0, weights);
    }
    weights
        .par_chunks(chunk)
        .enumerate()
        .map(|(task, weights)| evaluate(task * chunk, weights))
        .par_fold_reduce(|| F::ZERO, |sum, value| sum + value, |a, b| a + b)
}

/// Return the remaining row prefix, selected column, and interleaving stride.
/// The prefix itself can contain Boolean coordinates; only a trailing run is
/// removed, so no table-layout metadata or assumptions about row points enter.
fn column_selection(point: &Point<F>) -> Option<(&[F], usize, usize)> {
    let coordinates = point.as_slice();
    let mut prefix_len = coordinates.len();
    let mut column = 0;
    let mut stride = 1;
    while prefix_len > 0 {
        let coordinate = coordinates[prefix_len - 1];
        if coordinate == F::ONE {
            column += stride;
        } else if coordinate != F::ZERO {
            break;
        }
        stride *= 2;
        prefix_len -= 1;
    }
    (stride > 1).then_some((&coordinates[..prefix_len], column, stride))
}

#[cfg(test)]
mod tests {
    use super::super::{Constraint, EqStatement};
    use super::*;

    fn table(variables: usize) -> Poly<F> {
        Poly::new(
            (0..1 << variables)
                .map(|i| F::from_usize(i * i + 3 * i + 7))
                .collect(),
        )
    }

    #[test]
    fn column_evaluation_matches_dense_for_every_small_coordinate_pattern() {
        let coordinates = [F::ZERO, F::ONE, F::from_u64(7), -F::from_u64(11)];
        let mut cache = RowWeights::default();
        for variables in 0..=6 {
            let poly = table(variables);
            for encoding in 0..4usize.pow(variables as u32) {
                let point = Point::new(
                    (0..variables)
                        .map(|i| coordinates[(encoding >> (2 * i)) & 3])
                        .collect(),
                );
                assert_eq!(cache.evaluate(&poly, &point), poly.eval_ext::<F>(&point));
            }
        }
    }

    #[test]
    fn real_transition_dimensions_and_shared_row_points_match_dense() {
        let poly = table(15); // 256 rows by 128 columns.
        let mut cache = RowWeights::default();
        for row_seed in [3, 17, 3] {
            for column in [0, 1, 49, 64, 114, 127] {
                let mut coordinates = (0..8)
                    .map(|i| F::from_usize(row_seed + 2 * i))
                    .collect::<Vec<_>>();
                coordinates.extend_from_slice(Point::hypercube(column, 7).as_slice());
                let point = Point::new(coordinates);
                assert_eq!(cache.evaluate(&poly, &point), poly.eval_ext::<F>(&point));
            }
        }
    }

    fn check_combination(variables: usize, points: Vec<Point<F>>) {
        let poly = table(variables);
        let batched = RowWeights::default().evaluate_batch(&poly, &points);
        let claims = points
            .into_iter()
            .map(|point| {
                let value = poly.eval_ext::<F>(&point);
                (point, value)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            batched,
            claims.iter().map(|(_, value)| *value).collect::<Vec<_>>()
        );
        let mut cache = RowWeights::default();
        for alpha in [F::ZERO, F::ONE, F::from_u64(13), -F::ONE] {
            let mut statement = EqStatement::initialize(variables);
            for (point, value) in &claims {
                statement.add_evaluated_constraint(point.clone(), *value);
            }
            let expected = Constraint::new_eq_only(alpha, statement).combine_new();
            let actual = cache.combine_claims(variables, &claims, alpha);
            assert_eq!(actual, expected);
            let inner_product = poly
                .iter()
                .zip(actual.0.iter())
                .fold(F::ZERO, |sum, (&value, &weight)| sum + value * weight);
            assert_eq!(inner_product, actual.1);
        }
    }

    #[test]
    fn mixed_claim_weights_preserve_original_batching_powers() {
        check_combination(0, vec![Point::new(vec![]), Point::new(vec![])]);
        for variables in [1, 5, 12, 15] {
            let dense = Point::new((0..variables).map(|i| F::from_usize(i + 3)).collect());
            let mut points = vec![dense.clone()]; // OOD claim first.
            let column_bits = variables.min(7);
            for column in [0, 1, (1 << column_bits) - 1] {
                let mut coordinates = dense.as_slice()[..variables - column_bits].to_vec();
                coordinates.extend_from_slice(Point::hypercube(column, column_bits).as_slice());
                points.push(Point::new(coordinates));
            }
            points.push(dense.clone()); // Dense claim after sparse claims.
            points.push(points[1].clone()); // Duplicate, nonconsecutive row point.
            points.push(Point::hypercube((1 << variables) - 1, variables));
            let mut mixed = dense.as_slice().to_vec();
            mixed[0] = F::ZERO;
            mixed[variables - 1] = F::ONE;
            points.push(Point::new(mixed));
            check_combination(variables, points);
            check_combination(variables, vec![dense.clone(), dense]);
            check_combination(variables, vec![Point::hypercube(0, variables)]);
            check_combination(variables, vec![]);
        }
    }

    #[test]
    fn optimized_layout_preserves_sumcheck_messages_and_transcript() {
        use super::super::{ExplicitLayout, ExplicitWhir};
        use p3_challenger::FieldChallenger;
        use p3_sumcheck::SumcheckData;
        use p3_sumcheck::layout::Layout;
        use p3_sumcheck::product_polynomial::ProductPolynomial;
        use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};

        let variables = 8;
        let poly = table(variables);
        let whir = ExplicitWhir::new(variables).unwrap();
        let seed = [F::from_u64(31)];
        let mut reference_challenger = whir.seeded_challenger(&seed);
        let mut optimized_challenger = whir.seeded_challenger(&seed);
        let mut layout = ExplicitLayout {
            poly: poly.clone(),
            num_variables: variables,
            folding: 4,
            claims: vec![],
            row_weights: RowWeights::default(),
        };
        let mut statement = EqStatement::initialize(variables);
        let ood_point =
            Point::expand_from_univariate(reference_challenger.sample_algebra_element(), variables);
        let ood_value = poly.eval_ext::<F>(&ood_point);
        reference_challenger.observe_algebra_element(ood_value);
        statement.add_evaluated_constraint(ood_point, ood_value);
        assert_eq!(
            layout.add_virtual_eval(&mut optimized_challenger),
            ood_value
        );
        for column in [0, 7, 3, 0] {
            let mut point = (2..7).map(F::from_usize).collect::<Vec<_>>();
            point.extend_from_slice(Point::hypercube(column, 3).as_slice());
            let point = Point::new(point);
            let value = poly.eval_ext::<F>(&point);
            reference_challenger.observe_algebra_element(value);
            statement.add_evaluated_constraint(point.clone(), value);
            assert_eq!(layout.add_claim(point, &mut optimized_challenger), value);
        }
        let alpha = reference_challenger.sample_algebra_element();
        let (weights, sum) = Constraint::new_eq_only(alpha, statement).combine_new();
        let product = ProductPolynomial::new_unpacked(VariableOrder::Prefix, poly, weights);
        let mut prover = SumcheckProver::new(product, sum);
        let mut reference_data = SumcheckData::default();
        let reference_point = prover.compute_sumcheck_polynomials(
            &mut reference_data,
            &mut reference_challenger,
            4,
            0,
            None,
        );
        let mut optimized_data = SumcheckData::default();
        let (_, optimized_point) =
            layout.into_sumcheck(&mut optimized_data, 0, &mut optimized_challenger);
        assert_eq!(optimized_point, reference_point);
        assert_eq!(
            optimized_data.polynomial_evaluations,
            reference_data.polynomial_evaluations
        );
        assert_eq!(optimized_data.pow_witnesses, reference_data.pow_witnesses);
        let expected: F = reference_challenger.sample_algebra_element();
        let actual: F = optimized_challenger.sample_algebra_element();
        assert_eq!(actual, expected);
    }
}
