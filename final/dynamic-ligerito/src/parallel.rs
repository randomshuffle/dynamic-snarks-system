//! Shared scheduling for exact field arithmetic; no protocol or machine-specific choices.

use std::ops::Range;

use crate::field::F;

use rayon::current_num_threads;
use rayon::prelude::*;

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
    evaluate: impl Fn(&mut S, usize, F) -> F + Sync + Send,
) -> Vec<F> {
    assert!(evaluations > 0);
    // Split across message points as well as rows. In the last rounds there
    // may be only one pair, but its different evaluation points are independent.
    let fields_per_point = (fields_per_pair / evaluations).max(1);
    let chunk = grain(pairs * evaluations, 512usize.div_ceil(fields_per_point)).min(pairs.max(1));
    let chunks_per_point = pairs.div_ceil(chunk);
    let points = (0..evaluations).map(F::from_usize).collect::<Vec<_>>();
    (0..evaluations * chunks_per_point)
        .into_par_iter()
        .fold(
            || (scratch(), vec![F::ZERO; evaluations]),
            |(mut scratch, mut sums), task| {
                let evaluation = task / chunks_per_point;
                let block = task % chunks_per_point;
                for pair in block * chunk..((block + 1) * chunk).min(pairs) {
                    sums[evaluation] += evaluate(&mut scratch, pair, points[evaluation]);
                }
                (scratch, sums)
            },
        )
        .reduce(
            || (scratch(), vec![F::ZERO; evaluations]),
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
    columns: &mut [&mut [F]],
    range: Range<usize>,
    minimum_rows: usize,
    apply: impl Fn(usize, &mut [&mut [F]]) + Sync + Send,
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
pub(crate) fn fold(values: &mut Vec<F>, point: F) {
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

pub(crate) fn fold_columns(columns: &mut [Vec<F>], point: F) {
    columns
        .par_iter_mut()
        .for_each(|column| fold(column, point));
}

pub(crate) fn eq_evaluations(point: &[F]) -> Vec<F> {
    let mut result = vec![F::ZERO; 1 << point.len()];
    result[0] = F::ONE;
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

pub(crate) fn pack_columns(rows: usize, width: usize, columns: &[&[F]]) -> Vec<F> {
    assert!(columns.len() <= width);
    assert!(columns.iter().all(|column| column.len() == rows));
    let mut result = vec![F::ZERO; rows * width];
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

pub(crate) mod prelude {
    pub use rayon::join;
    pub use rayon::prelude::*;
}
