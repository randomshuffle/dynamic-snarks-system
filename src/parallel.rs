//! Shared scheduling for exact field arithmetic; no protocol or machine-specific choices.

use std::ops::Range;

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;

/// Keep several chunks available per worker for work stealing. The minimum
/// grain expresses work per item, rather than assuming a particular CPU count.
pub(crate) fn grain(len: usize, minimum: usize) -> usize {
    if current_num_threads() == 1 {
        return len.max(1);
    }
    len.div_ceil(current_num_threads().saturating_mul(4))
        .max(minimum)
        .max(1)
}

/// Evaluate a sumcheck message with independent, reusable scratch per task.
/// Field addition is exact, so regrouping sums preserves every transcript byte.
pub(crate) fn sumcheck<S: Send>(
    pairs: usize,
    evaluations: usize,
    fields_per_pair: usize,
    scratch: impl Fn() -> S + Sync + Send,
    evaluate: impl Fn(&mut S, usize, Bn254) -> Bn254 + Sync + Send,
) -> Vec<Bn254> {
    assert!(evaluations > 0);
    // Split across message points as well as rows. In the last rounds there
    // may be only one pair, but its different evaluation points are independent.
    let fields_per_point = (fields_per_pair / evaluations).max(1);
    let chunk = grain(pairs * evaluations, 512usize.div_ceil(fields_per_point)).min(pairs.max(1));
    let chunks_per_point = pairs.div_ceil(chunk);
    let points = (0..evaluations).map(Bn254::from_usize).collect::<Vec<_>>();
    (0..evaluations * chunks_per_point)
        .into_par_iter()
        .par_fold_reduce(
            || (scratch(), vec![Bn254::ZERO; evaluations]),
            |(mut scratch, mut sums), task| {
                let evaluation = task / chunks_per_point;
                let block = task % chunks_per_point;
                for pair in block * chunk..((block + 1) * chunk).min(pairs) {
                    sums[evaluation] += evaluate(&mut scratch, pair, points[evaluation]);
                }
                (scratch, sums)
            },
            |(scratch, mut left), (_, right)| {
                for (left, right) in left.iter_mut().zip(right) {
                    *left += right;
                }
                (scratch, left)
            },
        )
        .1
}

/// Disjoint row blocks across column-major buffers. Only slice descriptors are
/// allocated per task; the witness is neither copied nor transposed.
pub(crate) fn rows_mut(
    columns: &mut [&mut [Bn254]],
    range: Range<usize>,
    minimum_rows: usize,
    apply: impl Fn(usize, &mut [&mut [Bn254]]) + Sync + Send,
) {
    let chunk = grain(range.len(), minimum_rows);
    let mut tasks = (0..range.len().div_ceil(chunk))
        .map(|_| Vec::with_capacity(columns.len()))
        .collect::<Vec<_>>();
    for column in columns {
        for (task, slice) in tasks
            .iter_mut()
            .zip(column[range.clone()].chunks_mut(chunk))
        {
            task.push(slice);
        }
    }
    tasks
        .into_par_iter()
        .enumerate()
        .for_each(|(task, mut columns)| {
            apply(range.start + task * chunk, &mut columns);
        });
}

/// Fold adjacent entries in bounded, disjoint blocks, then compact in place.
/// This avoids allocating another half-witness while many columns fold at once.
pub(crate) fn fold(values: &mut Vec<Bn254>, point: Bn254) {
    let pairs = values.len() / 2;
    let chunk = grain(pairs, 256);
    values.par_chunks_mut(2 * chunk).for_each(|block| {
        for pair in 0..block.len() / 2 {
            block[pair] = block[2 * pair] + (block[2 * pair + 1] - block[2 * pair]) * point;
        }
    });
    for task in 1..pairs.div_ceil(chunk) {
        let start = 2 * task * chunk;
        let count = chunk.min(pairs - task * chunk);
        values.copy_within(start..start + count, task * chunk);
    }
    values.truncate(pairs);
}

pub(crate) fn fold_columns(columns: &mut [Vec<Bn254>], point: Bn254) {
    columns
        .par_iter_mut()
        .for_each(|column| fold(column, point));
}

pub(crate) fn eq_evaluations(point: &[Bn254]) -> Vec<Bn254> {
    let mut result = vec![Bn254::ZERO; 1 << point.len()];
    result[0] = Bn254::ONE;
    for (bit, &coordinate) in point.iter().enumerate() {
        let size = 1 << bit;
        let (left, right) = result[..2 * size].split_at_mut(size);
        let chunk = grain(size, 256);
        left.par_chunks_mut(chunk)
            .zip(right.par_chunks_mut(chunk))
            .for_each(|(left, right)| {
                for (left, right) in left.iter_mut().zip(right) {
                    *right = *left * coordinate;
                    *left -= *right;
                }
            });
    }
    result
}

pub(crate) fn pack_columns(rows: usize, width: usize, columns: &[&[Bn254]]) -> Vec<Bn254> {
    assert!(columns.len() <= width);
    assert!(columns.iter().all(|column| column.len() == rows));
    let mut result = vec![Bn254::ZERO; rows * width];
    let chunk = grain(rows, 1024usize.div_ceil(width));
    result
        .par_chunks_mut(chunk * width)
        .enumerate()
        .for_each(|(task, block)| {
            // Keep the transpose tile bounded even when a large input gives
            // each worker a very large range. This also limits cache-line traffic.
            let tile_rows = 1024usize.div_ceil(width);
            for (tile, output) in block.chunks_mut(tile_rows * width).enumerate() {
                for (column, values) in columns.iter().enumerate() {
                    for (offset, row) in output.chunks_exact_mut(width).enumerate() {
                        row[column] = values[task * chunk + tile * tile_rows + offset];
                    }
                }
            }
        });
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_stir_weights_match_direct_powers_with_duplicates_and_zero_challenges() {
        use p3_multilinear_util::poly::Poly;
        use p3_sumcheck::constraints::statement::SelectStatement;
        for (variables, queries) in [(0, 0), (0, 3), (3, 3), (8, 137), (11, 5)] {
            let vars = (0..queries)
                .map(|j| match j % 5 {
                    0 => Bn254::ZERO,
                    1 => Bn254::ONE,
                    2 => -Bn254::ONE,
                    _ => Bn254::from_usize(j % 7 + 2),
                })
                .collect::<Vec<_>>();
            let evals = (0..queries)
                .map(|j| Bn254::from_usize(j + 3))
                .collect::<Vec<_>>();
            let statement = SelectStatement::new(variables, vars.clone(), evals.clone());
            for challenge in [Bn254::ZERO, Bn254::ONE, Bn254::from_u64(13)] {
                for shift in [0, 7] {
                    let scales = (0..queries)
                        .map(|j| challenge.exp_u64((shift + j) as u64))
                        .collect::<Vec<_>>();
                    let expected = (0..1 << variables)
                        .map(|b| {
                            vars.iter()
                                .zip(&scales)
                                .fold(Bn254::from_u64(5), |sum, (&var, &scale)| {
                                    sum + scale * var.exp_u64(b)
                                })
                        })
                        .collect::<Vec<_>>();
                    let expected_sum = evals
                        .iter()
                        .zip(&scales)
                        .fold(Bn254::from_u64(17), |sum, (&value, &scale)| {
                            sum + value * scale
                        });
                    let mut weights = Poly::new(vec![Bn254::from_u64(5); 1 << variables]);
                    let mut sum = Bn254::from_u64(17);
                    statement.combine(&mut weights, &mut sum, challenge, shift);
                    assert_eq!(weights.as_slice(), expected);
                    assert_eq!(sum, expected_sum);
                }
            }
        }
    }

    #[test]
    fn whir_coefficient_kernels_match_scalar_reference_at_grain_and_tile_boundaries() {
        use p3_sumcheck::strategy::{sumcheck_coefficients_prefix, sumcheck_coefficients_suffix};
        for len in [0, 2, 14, 16, 30, 254, 256, 258, 4096, 32768] {
            let evals = (0..len)
                .map(|i| Bn254::from_usize(i * i + 3))
                .collect::<Vec<_>>();
            let weights = (0..len)
                .map(|i| Bn254::from_usize(7 * i + 11))
                .collect::<Vec<_>>();
            let expected = |suffix| {
                (0..len / 2).fold((Bn254::ZERO, Bn254::ZERO), |(c0, c2), i| {
                    let (a, b) = if suffix {
                        (2 * i, 2 * i + 1)
                    } else {
                        (i, i + len / 2)
                    };
                    (
                        c0 + evals[a] * weights[a],
                        c2 + (evals[b] - evals[a]) * (weights[b] - weights[a]),
                    )
                })
            };
            assert_eq!(
                sumcheck_coefficients_prefix(&evals, &weights),
                expected(false)
            );
            assert_eq!(
                sumcheck_coefficients_suffix(&evals, &weights),
                expected(true)
            );
        }
    }

    #[test]
    fn blocked_fold_matches_adjacent_fold() {
        for size in [2, 16, 512, 1024, 4096, 32768] {
            let input = (0..size)
                .map(|i| Bn254::from_usize(i * i + 7))
                .collect::<Vec<_>>();
            for point in [Bn254::ZERO, Bn254::ONE, Bn254::from_u64(17)] {
                let expected = input
                    .chunks_exact(2)
                    .map(|p| p[0] + (p[1] - p[0]) * point)
                    .collect::<Vec<_>>();
                let mut actual = input.clone();
                fold(&mut actual, point);
                assert_eq!(actual, expected);
            }
        }
    }
}

pub(crate) fn clone_columns(columns: &[Vec<Bn254>]) -> Vec<Vec<Bn254>> {
    columns.par_iter().cloned().collect()
}
