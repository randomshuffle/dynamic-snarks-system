//! Prover-only scheduling: bounds apply to field work, never to proof parameters.
use super::{Columns, F, State, WIDTH, hash, math};
use rayon::prelude::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Schedule {
    /// Segment/pair contributions, each producing nine message coefficients.
    pub coefficient_min: usize,
    pub coefficient_grain: usize,
    /// Adjacent field pairs across all columns.
    pub fold_min: usize,
    pub fold_grain: usize,
    /// Maximum hashes per trace tile; smaller batches expose up to four tiles
    /// per worker, with a floor of 32 hashes to amortize task setup.
    pub trace_tile: usize,
    pub trace_min: usize,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            coefficient_min: 1024,
            coefficient_grain: 128,
            fold_min: 8192,
            fold_grain: 1024,
            trace_tile: 512,
            trace_min: 128,
        }
    }
}

impl Schedule {
    /// Sequential inner reductions amortize scheduling and avoid a nine-field
    /// accumulator/reduction tree for each individual pair. Field addition is
    /// exact, so this preserves all transcript bytes.
    pub fn coefficients<const N: usize>(
        self,
        count: usize,
        contribution: impl Fn(usize) -> [F; N] + Sync,
    ) -> [F; N] {
        let add = |mut a: [F; N], b: [F; N]| {
            for i in 0..N {
                a[i] += b[i];
            }
            a
        };
        let serial =
            |start: usize, end: usize| (start..end).map(&contribution).fold([F::ZERO; N], add);
        let workers = rayon::current_num_threads();
        if workers == 1 || count < self.coefficient_min {
            return serial(0, count);
        }
        let grain = count.div_ceil(4 * workers).max(self.coefficient_grain);
        (0..count.div_ceil(grain))
            .into_par_iter()
            .map(|chunk| serial(chunk * grain, ((chunk + 1) * grain).min(count)))
            .reduce(|| [F::ZERO; N], add)
    }

    /// Fold disjoint adjacent-pair blocks in place before compacting. Large
    /// columns expose multiple chunks per worker; small terminal tables stay
    /// serial instead of launching a Rayon job for each of eight tiny columns.
    pub fn fold_columns(self, columns: &mut [Vec<F>], point: F) {
        let pairs = columns[0].len() / 2;
        let count = columns.len() * pairs;
        let workers = rayon::current_num_threads();
        if workers == 1 || count < self.fold_min {
            for column in columns {
                math::fold(column, point);
            }
            return;
        }
        let grain = count.div_ceil(4 * workers).max(self.fold_grain);
        columns.par_iter_mut().for_each(|column| {
            column.par_chunks_mut(2 * grain).for_each(|block| {
                for i in 0..block.len() / 2 {
                    block[i] = block[2 * i] + (block[2 * i] + block[2 * i + 1]) * point;
                }
            });
            for task in 1..pairs.div_ceil(grain) {
                let start = 2 * task * grain;
                let count = grain.min(pairs - task * grain);
                column.copy_within(start..start + count, task * grain);
            }
            column.truncate(pairs);
        });
    }

    /// Advance a cache-sized tile through an entire round interval inside one
    /// task. Output slices are disjoint between tiles. This writes only retained
    /// rounds and avoids a global barrier and full-state transpose per round.
    pub fn trace(
        self,
        rows: usize,
        start: usize,
        end: usize,
        retained: &[usize],
        outputs: &mut [&mut [F]],
        initialize: impl Fn(usize) -> State + Sync,
        feed_forward: bool,
    ) {
        debug_assert_eq!(
            outputs.len(),
            WIDTH * retained.len() + 2 * usize::from(feed_forward)
        );
        debug_assert!(retained.windows(2).all(|p| p[0] < p[1]));
        debug_assert!(retained.iter().all(|&r| (start..=end).contains(&r)));
        debug_assert!(!feed_forward || retained.first() == Some(&0));
        let tile = rows
            .div_ceil(4 * rayon::current_num_threads())
            .max(32)
            .min(self.trace_tile);
        let mut tasks: Vec<Vec<&mut [F]>> = (0..rows.div_ceil(tile))
            .map(|_| Vec::with_capacity(outputs.len()))
            .collect();
        for column in outputs {
            for (task, chunk) in tasks.iter_mut().zip(column.chunks_mut(tile)) {
                task.push(chunk);
            }
        }
        let run = |(task, mut outputs): (usize, Vec<&mut [F]>)| {
            let n = outputs[0].len();
            let mut states: Vec<State> = (task * tile..task * tile + n).map(&initialize).collect();
            let mut cursor = 0;
            for round in start..=end {
                if retained.get(cursor) == Some(&round) {
                    for w in 0..WIDTH {
                        for (out, state) in outputs[WIDTH * cursor + w].iter_mut().zip(&states) {
                            *out = state[w];
                        }
                    }
                    cursor += 1;
                }
                if round != end {
                    for state in &mut states {
                        *state = hash::round(round, *state);
                    }
                }
            }
            debug_assert_eq!(cursor, retained.len());
            if feed_forward {
                for w in 0..2 {
                    for (i, state) in states.iter().enumerate() {
                        outputs[WIDTH * retained.len() + w][i] = state[w] + outputs[w][i];
                    }
                }
            }
        };
        if rayon::current_num_threads() == 1 || rows < self.trace_min {
            tasks.into_iter().enumerate().for_each(run);
        } else {
            tasks.into_par_iter().enumerate().for_each(run);
        }
    }

    pub fn recompute(self, input: &Columns, start: usize, end: usize) -> Vec<Columns> {
        let rows = input[0].len();
        let retained: Vec<_> = (start + 1..=end).collect();
        let mut result: Vec<Columns> = retained
            .iter()
            .map(|_| std::array::from_fn(|_| vec![F::ZERO; rows]))
            .collect();
        let mut outputs: Vec<_> = result.iter_mut().flatten().map(Vec::as_mut_slice).collect();
        self.trace(
            rows,
            start,
            end,
            &retained,
            &mut outputs,
            |i| std::array::from_fn(|w| input[w][i]),
            false,
        );
        result
    }
}
