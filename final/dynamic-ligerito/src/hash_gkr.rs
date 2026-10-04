//! Checkpoint-batched GKR for Poseidon2b t=4 compression, including feed-forward.
//! Coefficient-form degree-eight sumchecks avoid characteristic-two collisions
//! in the prime-field evaluation grid (0,1,-1,2,-2,...).
use flock_core::{challenger::Challenger, field::F128 as F};
use poseidon2b_compress_ligerito_experiment::{
    hash::{self, HASH_ROUNDS, State, WIDTH},
    math,
};
#[path = "hash_gkr/scheduling.rs"]
mod scheduling;
pub(crate) use scheduling::Schedule;
#[path = "hash_gkr/message.rs"]
mod message;
pub(crate) use message::MessageKernel;
#[path = "hash_gkr/frobenius.rs"]
pub(crate) mod frobenius;
use serde::{Deserialize, Serialize};
pub type Columns = [Vec<F>; WIDTH];
#[derive(Clone, Serialize, Deserialize)]
pub struct Layer {
    pub messages: Vec<[F; 9]>,
    pub inputs: Vec<State>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub outputs: Vec<F>,
    pub feed_forward: [F; 2],
    pub layers: Vec<Layer>,
}
#[derive(Clone, Debug)]
pub struct Claim {
    pub column: usize,
    pub point: Vec<F>,
    pub value: F,
}
pub struct Witness {
    pub trace: Vec<Option<Columns>>,
    pub columns: Vec<Vec<F>>,
}
fn valid_segments(s: usize) -> bool {
    // Segment claims are batched explicitly; their count is not an MLE axis
    // and need not be a power of two. Only the PCS column table is padded.
    (1..=HASH_ROUNDS).contains(&s)
}
/// Near-equal contiguous segments; shorter segments start with an identity layer.
pub fn boundary(segments: usize, s: usize) -> usize {
    (s * HASH_ROUNDS).div_ceil(segments)
}
pub fn layer_count(segments: usize) -> usize {
    HASH_ROUNDS.div_ceil(segments)
}
/// Short segments have an identity step at their output end to share a depth.
pub fn round_at(segments: usize, segment: usize, depth: usize) -> Option<usize> {
    let end = boundary(segments, segment + 1);
    let length = end - boundary(segments, segment);
    let pad = layer_count(segments) - length;
    if depth < pad {
        None
    } else {
        Some(end - 1 - (depth - pad))
    }
}
fn step(round: Option<usize>, input: State) -> State {
    round.map_or(input, |r| hash::round(r, input))
}
/// Retain eight-round recomputation checkpoints above 32K hashes. This changes
/// prover memory scheduling only; proof bytes and verifier equations are identical.
pub fn witness(messages: &[[u8; 64]], segments: usize) -> Result<Witness, String> {
    witness_with_schedule(messages, segments, Schedule::default())
}
pub(crate) fn witness_with_schedule(
    messages: &[[u8; 64]],
    segments: usize,
    schedule: Schedule,
) -> Result<Witness, String> {
    witness_with_stride(
        messages,
        segments,
        if messages.len() > 32768 { 8 } else { 1 },
        schedule,
    )
}
fn witness_with_stride(
    messages: &[[u8; 64]],
    segments: usize,
    stride: usize,
    schedule: Schedule,
) -> Result<Witness, String> {
    if !valid_segments(segments) || messages.len() < 2 || !messages.len().is_power_of_two() {
        return Err("invalid witness shape".into());
    }
    let rows = messages.len();
    let padded_output =
        boundary(segments, segments) - boundary(segments, segments - 1) < layer_count(segments);
    let retained: Vec<_> = (0..=HASH_ROUNDS)
        .filter(|&i| {
            (i == HASH_ROUNDS && padded_output)
                || (0..segments).any(|s| {
                    let start = boundary(segments, s);
                    (start..boundary(segments, s + 1)).contains(&i) && (i - start) % stride == 0
                })
        })
        .collect();
    let mut trace: Vec<Option<Columns>> = (0..=HASH_ROUNDS)
        .map(|r| {
            retained
                .contains(&r)
                .then(|| std::array::from_fn(|_| vec![F::ZERO; rows]))
        })
        .collect();
    let mut digests: [Vec<F>; 2] = std::array::from_fn(|_| vec![F::ZERO; rows]);
    {
        let mut outputs: Vec<_> = trace
            .iter_mut()
            .flatten()
            .flatten()
            .chain(digests.iter_mut())
            .map(Vec::as_mut_slice)
            .collect();
        schedule.trace(
            rows,
            0,
            HASH_ROUNDS,
            &retained,
            &mut outputs,
            |i| hash::input(&messages[i]),
            true,
        );
    }
    let mut columns = Vec::new();
    for s in 0..segments {
        columns.extend(
            trace[boundary(segments, s)]
                .as_ref()
                .unwrap()
                .iter()
                .cloned(),
        );
    }
    columns.extend(digests);
    Ok(Witness { trace, columns })
}
fn take_round(trace: &mut [Option<Columns>], r: usize, schedule: Schedule) -> Columns {
    if trace[r].is_none() {
        let base = (0..r)
            .rev()
            .find(|&i| trace[i].is_some())
            .expect("retained checkpoint");
        let regenerated = schedule.recompute(trace[base].as_ref().unwrap(), base, r);
        for (i, columns) in (base + 1..=r).zip(regenerated) {
            trace[i] = Some(columns);
        }
    }
    trace[r].take().unwrap()
}
fn start(t: &mut impl Challenger, variables: usize, segments: usize) -> Vec<F> {
    t.observe_label(b"poseidon2b-compress64-ghash-gkr-v1");
    t.observe_bytes(&(variables as u64).to_le_bytes());
    t.observe_bytes(&(segments as u64).to_le_bytes());
    t.sample_f128_vec(variables)
}
fn weights(t: &mut impl Challenger, depth: usize, segments: usize) -> Vec<State> {
    (0..segments)
        .map(|s| {
            std::array::from_fn(|w| {
                if depth == 0 && s == segments - 1 && w >= 2 {
                    F::ZERO
                } else {
                    t.sample_f128()
                }
            })
        })
        .collect()
}
fn initial(outputs: &[F], feed_forward: [F; 2], segments: usize) -> Vec<State> {
    (0..segments)
        .map(|s| {
            std::array::from_fn(|w| {
                if s == segments - 1 && w >= 2 {
                    F::ZERO
                } else {
                    outputs[WIDTH * s + w]
                        + if s == segments - 1 {
                            feed_forward[w]
                        } else {
                            F::ZERO
                        }
                }
            })
        })
        .collect()
}
fn dot(w: State, v: State) -> F {
    w.iter().zip(v).fold(F::ZERO, |a, (&x, y)| a + x * y)
}
fn absorb_inputs(t: &mut impl Challenger, inputs: &[State]) {
    t.observe_label(b"gkr-layer-inputs");
    for row in inputs {
        t.observe_f128_slice(row);
    }
}
fn frame(t: &mut impl Challenger, d: usize, v: usize) {
    t.observe_bytes(&(d as u64).to_le_bytes());
    t.observe_bytes(&(v as u64).to_le_bytes());
}
fn claims(
    output_point: Vec<F>,
    outputs: &[F],
    feed_forward: [F; 2],
    input_point: Vec<F>,
    inputs: &[State],
) -> Result<Vec<Claim>, String> {
    let mut out = Vec::new();
    for (col, &value) in inputs.iter().flatten().enumerate() {
        out.push(Claim {
            column: col,
            point: input_point.clone(),
            value,
        });
    }
    for (col, &value) in outputs.iter().enumerate() {
        out.push(Claim {
            column: WIDTH + col,
            point: output_point.clone(),
            value,
        });
    }
    // Feed-forward inputs must be authenticated at the output row point too.
    for (column, value) in feed_forward.into_iter().enumerate() {
        out.push(Claim {
            column,
            point: output_point.clone(),
            value,
        });
    }
    Ok(out)
}
fn line(round: Option<usize>, mut zero: State, mut one: State, sw: State) -> [F; 8] {
    if let Some(r) = round {
        hash::before_sbox(r, &mut zero);
        hash::before_sbox(r, &mut one);
    }
    let mut out = [F::ZERO; 8];
    for w in 0..WIDTH {
        let b = zero[w] + one[w];
        if round.is_some_and(|r| w == 0 || hash::full(r)) {
            let p = math::seventh_line(zero[w], b);
            for k in 0..8 {
                out[k] += sw[w] * p[k];
            }
        } else {
            out[0] += sw[w] * zero[w];
            out[1] += sw[w] * b;
        }
    }
    out
}
pub fn prove(
    witness: Witness,
    segments: usize,
    t: &mut impl Challenger,
) -> Result<(Proof, Vec<Claim>), String> {
    prove_with_kernel(
        witness,
        segments,
        t,
        Schedule::default(),
        MessageKernel::configured()?,
    )
}
pub(crate) fn prove_with_schedule(
    witness: Witness,
    segments: usize,
    t: &mut impl Challenger,
    schedule: Schedule,
) -> Result<(Proof, Vec<Claim>), String> {
    prove_with_kernel(witness, segments, t, schedule, MessageKernel::Coefficients)
}
pub(crate) fn prove_with_kernel(
    witness: Witness,
    segments: usize,
    t: &mut impl Challenger,
    schedule: Schedule,
    kernel: MessageKernel,
) -> Result<(Proof, Vec<Claim>), String> {
    if !valid_segments(segments)
        || witness.trace.len() != HASH_ROUNDS + 1
        || witness.columns.len() != WIDTH * segments + 2
    {
        return Err("invalid GKR shape".into());
    }
    let rows = witness.columns[0].len();
    let variables = rows.ilog2() as usize;
    let length = layer_count(segments);
    let output_point = start(t, variables, segments);
    let outputs: Vec<_> = witness.columns[WIDTH..]
        .iter()
        .map(|v| math::evaluate(v, &output_point))
        .collect();
    let feed_forward = std::array::from_fn(|w| math::evaluate(&witness.columns[w], &output_point));
    t.observe_f128_slice(&outputs);
    t.observe_f128_slice(&feed_forward);
    let mut current = initial(&outputs, feed_forward, segments);
    let mut target = output_point.clone();
    let mut trace = witness.trace;
    let mut layers = Vec::new();
    for depth in 0..length {
        let weights = weights(t, depth, segments);
        let sw: Vec<_> = (0..segments)
            .map(|s| {
                round_at(segments, s, depth)
                    .map_or(weights[s], |r| hash::sbox_weights(r, weights[s]))
            })
            .collect();
        let mut claim = weights
            .iter()
            .zip(&current)
            .fold(F::ZERO, |a, (&w, &v)| a + dot(w, v));
        let mut cols: Vec<_> = (0..segments)
            .flat_map(|s| match round_at(segments, s, depth) {
                Some(r) => take_round(&mut trace, r, schedule),
                None => trace[boundary(segments, s + 1)].as_ref().unwrap().clone(),
            })
            .collect();
        let mut eq = math::eq_table(&target);
        let mut point = Vec::new();
        let mut messages = Vec::new();
        for variable in 0..variables {
            let message =
                kernel.message(&cols, &eq, &sw, segments, depth, target[variable], schedule);
            if message[1..].iter().fold(F::ZERO, |a, &v| a + v) != claim {
                return Err(format!(
                    "sumcheck failure depth={depth} variable={variable}"
                ));
            }
            frame(t, depth, variable);
            t.observe_f128_slice(&message);
            let r = t.sample_f128();
            claim = math::poly_eval(&message, r);
            math::fold(&mut eq, r);
            schedule.fold_columns(&mut cols, r);
            point.push(r);
            messages.push(message);
        }
        current = (0..segments)
            .map(|s| std::array::from_fn(|w| cols[WIDTH * s + w][0]))
            .collect();
        let expected = (0..segments).fold(F::ZERO, |a, s| {
            a + dot(weights[s], step(round_at(segments, s, depth), current[s]))
        });
        if claim != math::eq(&target, &point) * expected {
            return Err("GKR terminal relation".into());
        }
        absorb_inputs(t, &current);
        target = point;
        layers.push(Layer {
            messages,
            inputs: current.clone(),
        });
    }
    let c = claims(output_point, &outputs, feed_forward, target, &current)?;
    Ok((
        Proof {
            outputs,
            feed_forward,
            layers,
        },
        c,
    ))
}
pub fn verify(
    p: &Proof,
    variables: usize,
    segments: usize,
    t: &mut impl Challenger,
) -> Result<Vec<Claim>, String> {
    if !valid_segments(segments)
        || variables == 0
        || p.outputs.len() != WIDTH * (segments - 1) + 2
        || p.layers.len() != layer_count(segments)
    {
        return Err("GKR proof shape".into());
    }
    let output_point = start(t, variables, segments);
    t.observe_f128_slice(&p.outputs);
    t.observe_f128_slice(&p.feed_forward);
    let mut current = initial(&p.outputs, p.feed_forward, segments);
    let mut target = output_point.clone();
    for (d, layer) in p.layers.iter().enumerate() {
        if layer.messages.len() != variables || layer.inputs.len() != segments {
            return Err("GKR layer shape".into());
        }
        let weights = weights(t, d, segments);
        let mut claim = weights
            .iter()
            .zip(&current)
            .fold(F::ZERO, |a, (&w, &v)| a + dot(w, v));
        let mut point = Vec::new();
        for (v, msg) in layer.messages.iter().enumerate() {
            if msg[1..].iter().fold(F::ZERO, |a, &v| a + v) != claim {
                return Err("sumcheck claim".into());
            }
            frame(t, d, v);
            t.observe_f128_slice(msg);
            let r = t.sample_f128();
            claim = math::poly_eval(msg, r);
            point.push(r);
        }
        current = layer.inputs.clone();
        let expected = (0..segments).fold(F::ZERO, |a, s| {
            a + dot(weights[s], step(round_at(segments, s, d), current[s]))
        });
        if claim != math::eq(&target, &point) * expected {
            return Err("GKR terminal relation".into());
        }
        absorb_inputs(t, &current);
        target = point;
    }
    claims(output_point, &p.outputs, p.feed_forward, target, &current)
}

#[cfg(test)]
#[path = "hash_gkr/reference.rs"]
mod reference;
#[cfg(test)]
mod tests {
    use super::*;
    use flock_core::challenger::FsChallenger;
    #[test]
    fn message_kernels_preserve_proofs_and_claims() {
        for segments in [1, 2, 3, 4, 7, 8] {
            for rows in [2, 256, 2048] {
                let messages: Vec<_> = (0..rows).map(hash::dataset).collect();
                let mut reference = None;
                for kernel in [
                    MessageKernel::Coefficients,
                    MessageKernel::FactoredCoefficients,
                    MessageKernel::StructuredEvaluations,
                ] {
                    for stride in [1, 8] {
                        let w =
                            witness_with_stride(&messages, segments, stride, Schedule::default())
                                .unwrap();
                        let (proof, claims) = prove_with_kernel(
                            w,
                            segments,
                            &mut FsChallenger::new(b"message-kernel-test"),
                            Schedule::default(),
                            kernel,
                        )
                        .unwrap();
                        let verified = verify(
                            &proof,
                            rows.ilog2() as usize,
                            segments,
                            &mut FsChallenger::new(b"message-kernel-test"),
                        )
                        .unwrap();
                        let bytes = bincode::serialize(&proof).unwrap();
                        if let Some(previous) = &reference {
                            assert_eq!(
                                &bytes, previous,
                                "{kernel:?}, {rows}, {segments}, stride={stride}"
                            );
                        } else {
                            reference = Some(bytes);
                        }
                        for (a, b) in claims.iter().zip(verified) {
                            assert_eq!(
                                (a.column, &a.point, a.value),
                                (b.column, &b.point, b.value)
                            );
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn multiple_checkpoints_bind_native_states_and_padded_segments() {
        for segments in [1, 2, 3, 4, 7, 8] {
            for rows in [8, 256] {
                let messages: Vec<_> = (0..rows).map(hash::dataset).collect();
                let mut expected = vec![vec![F::ZERO; rows]; 4 * segments + 2];
                for (row, message) in messages.iter().enumerate() {
                    let input = hash::input(message);
                    let mut state = input;
                    for r in 0..=HASH_ROUNDS {
                        for s in 0..segments {
                            if r == boundary(segments, s) {
                                for w in 0..4 {
                                    expected[4 * s + w][row] = state[w];
                                }
                            }
                        }
                        if r < HASH_ROUNDS {
                            state = hash::round(r, state);
                        }
                    }
                    for w in 0..2 {
                        expected[4 * segments + w][row] = state[w] + input[w];
                    }
                }
                let mut encoded = None;
                for stride in [1, 8] {
                    let witness =
                        witness_with_stride(&messages, segments, stride, Schedule::default())
                            .unwrap();
                    assert_eq!(witness.columns, expected);
                    let (proof, claims) = prove(
                        witness,
                        segments,
                        &mut FsChallenger::new(b"multi-checkpoint-test"),
                    )
                    .unwrap();
                    let verified = verify(
                        &proof,
                        rows.ilog2() as usize,
                        segments,
                        &mut FsChallenger::new(b"multi-checkpoint-test"),
                    )
                    .unwrap();
                    for (a, b) in claims.iter().zip(&verified) {
                        assert_eq!((a.column, &a.point, a.value), (b.column, &b.point, b.value));
                        assert_eq!(a.value, math::evaluate(&expected[a.column], &a.point));
                    }
                    let bytes = bincode::serialize(&proof).unwrap();
                    if let Some(previous) = &encoded {
                        assert_eq!(&bytes, previous);
                    }
                    encoded = Some(bytes);
                }
            }
        }
    }
    #[test]
    fn every_segment_count_preserves_hash_boundaries() {
        let messages: Vec<_> = (0..2).map(hash::dataset).collect();
        for segments in 1..=HASH_ROUNDS {
            let witness = witness(&messages, segments).unwrap();
            let columns = witness.columns.clone();
            let (proof, _) = prove(
                witness,
                segments,
                &mut FsChallenger::new(b"arbitrary-segments"),
            )
            .unwrap();
            let claims = verify(
                &proof,
                1,
                segments,
                &mut FsChallenger::new(b"arbitrary-segments"),
            )
            .unwrap();
            for claim in claims {
                assert_eq!(
                    claim.value,
                    math::evaluate(&columns[claim.column], &claim.point)
                );
            }
            for (i, message) in messages.iter().enumerate() {
                let digest = hash::hash64(message);
                assert_eq!(
                    [columns[4 * segments][i], columns[4 * segments + 1][i]],
                    digest
                );
            }
            let mut bad = proof.clone();
            bad.outputs[0] += F::ONE;
            assert!(
                verify(
                    &bad,
                    1,
                    segments,
                    &mut FsChallenger::new(b"arbitrary-segments")
                )
                .is_err()
            );
        }
        for invalid in [0, HASH_ROUNDS + 1] {
            assert!(witness(&messages, invalid).is_err());
        }
    }
    #[test]
    fn recomputation_is_byte_identical() {
        let messages: Vec<_> = (0..16).map(hash::dataset).collect();
        let run = |stride| {
            let w = witness_with_stride(&messages, 2, stride, Schedule::default()).unwrap();
            let mut t = FsChallenger::new(b"recompute-test");
            let (p, _) = prove(w, 2, &mut t).unwrap();
            bincode::serialize(&p).unwrap()
        };
        assert_eq!(run(1), run(8));
    }

    #[test]
    fn schedules_preserve_reference_proofs_and_claims() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        pool.install(|| {
            for rows in [2, 256, 2048] {
                let messages: Vec<_> = (0..rows).map(hash::dataset).collect();
                let (expected, expected_claims) = reference::prove(
                    reference::witness(&messages, 2).unwrap(),
                    2,
                    &mut FsChallenger::new(b"scheduling-compatibility"),
                )
                .unwrap();
                let expected = bincode::serialize(&expected).unwrap();
                for schedule in [
                    Schedule::default(),
                    Schedule {
                        coefficient_min: usize::MAX,
                        fold_min: usize::MAX,
                        trace_min: usize::MAX,
                        ..Schedule::default()
                    },
                    Schedule {
                        coefficient_min: 0,
                        coefficient_grain: 13,
                        fold_min: 0,
                        fold_grain: 123,
                        trace_tile: 57,
                        trace_min: 0,
                    },
                ] {
                    for stride in [1, 8] {
                        let witness = witness_with_stride(&messages, 2, stride, schedule).unwrap();
                        let (p, claims) = prove_with_schedule(
                            witness,
                            2,
                            &mut FsChallenger::new(b"scheduling-compatibility"),
                            schedule,
                        )
                        .unwrap();
                        assert_eq!(
                            bincode::serialize(&p).unwrap(),
                            expected,
                            "rows={rows} stride={stride} schedule={schedule:?}"
                        );
                        verify(
                            &p,
                            rows.ilog2() as usize,
                            2,
                            &mut FsChallenger::new(b"scheduling-compatibility"),
                        )
                        .unwrap();
                        for (a, b) in claims.iter().zip(&expected_claims) {
                            assert_eq!(
                                (a.column, &a.point, a.value),
                                (b.column, &b.point, b.value)
                            );
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn chunked_folds_match_reference_with_partial_tail_blocks() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        pool.install(|| {
            for rows in [2, 16, 2048, 8192, 32768] {
                let columns: Vec<Vec<F>> = (0..8)
                    .map(|c| {
                        (0..rows)
                            .map(|i| F::new((i * 65537 + c) as u64, (i + 7 * c) as u64))
                            .collect()
                    })
                    .collect();
                let mut expected = columns.clone();
                let point = F::new(0x123456789abc, 0x987654321);
                for column in &mut expected {
                    math::fold(column, point);
                }
                for grain in [123, 1024] {
                    let mut actual = columns.clone();
                    Schedule {
                        fold_min: 0,
                        fold_grain: grain,
                        ..Schedule::default()
                    }
                    .fold_columns(&mut actual, point);
                    assert_eq!(actual, expected);
                }
            }
        });
    }
}
