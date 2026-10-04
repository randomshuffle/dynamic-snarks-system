//! Frozen pre-granularity reference, compiled only for compatibility tests and tuning.
//! Checkpoint-batched GKR for Poseidon2b t=4 compression, including feed-forward.
//! Coefficient-form degree-eight sumchecks avoid characteristic-two collisions
//! in the prime-field evaluation grid (0,1,-1,2,-2,...).
use flock_core::{challenger::Challenger, field::F128 as F};
use poseidon2b_compress_ligerito_experiment::{
    hash::{self, HASH_ROUNDS, State, WIDTH},
    math,
};
use rayon::prelude::*;
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
    [1, 2, 4].contains(&s)
}
/// Boundaries [0,66], [0,33,66], or [0,17,33,50,66].
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
    witness_with_stride(
        messages,
        segments,
        if messages.len() > 32768 { 8 } else { 1 },
    )
}
fn advance(previous: &Columns, r: usize) -> Columns {
    let rows = previous[0].len();
    let apply = |i| hash::round(r, std::array::from_fn(|w| previous[w][i]));
    let states: Vec<_> = if rows < 128 || rayon::current_num_threads() == 1 {
        (0..rows).map(apply).collect()
    } else {
        (0..rows).into_par_iter().map(apply).collect()
    };
    std::array::from_fn(|w| states.iter().map(|s| s[w]).collect())
}
fn witness_with_stride(
    messages: &[[u8; 64]],
    segments: usize,
    stride: usize,
) -> Result<Witness, String> {
    if segments != 2 || messages.len() < 2 || !messages.len().is_power_of_two() {
        return Err("invalid witness shape".into());
    }
    let inputs: Vec<_> = messages.par_iter().map(hash::input).collect();
    let mut current: Columns = std::array::from_fn(|w| inputs.iter().map(|s| s[w]).collect());
    drop(inputs);
    let mut trace: Vec<Option<Columns>> = (0..=HASH_ROUNDS).map(|_| None).collect();
    trace[0] = Some(current.clone());
    for r in 0..HASH_ROUNDS {
        let next = advance(&current, r);
        current = next;
        let i = r + 1;
        if i < HASH_ROUNDS && ((i % 33) % stride == 0) {
            trace[i] = Some(current.clone());
        }
    }
    let mut columns = Vec::new();
    columns.extend(trace[0].as_ref().unwrap().iter().cloned());
    columns.extend(trace[33].as_ref().unwrap().iter().cloned());
    columns.extend(
        (0..2)
            .map(|w| {
                current[w]
                    .iter()
                    .zip(&columns[w])
                    .map(|(&a, &b)| a + b)
                    .collect()
            })
            .collect::<Vec<Vec<F>>>(),
    );
    Ok(Witness { trace, columns })
}
fn take_round(trace: &mut [Option<Columns>], r: usize) -> Columns {
    if trace[r].is_none() {
        let base = (0..r)
            .rev()
            .find(|&i| trace[i].is_some())
            .expect("retained checkpoint");
        for j in base..r {
            trace[j + 1] = Some(advance(trace[j].as_ref().unwrap(), j));
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
                Some(r) => take_round(&mut trace, r),
                None => trace[boundary(segments, s + 1)].as_ref().unwrap().clone(),
            })
            .collect();
        let mut eq = math::eq_table(&target);
        let mut point = Vec::new();
        let mut messages = Vec::new();
        for variable in 0..variables {
            let pairs = eq.len() / 2;
            let contribution = |i: usize| {
                let s = i / pairs;
                let p = i % pairs;
                let h = line(
                    round_at(segments, s, depth),
                    std::array::from_fn(|w| cols[WIDTH * s + w][2 * p]),
                    std::array::from_fn(|w| cols[WIDTH * s + w][2 * p + 1]),
                    sw[s],
                );
                let a = eq[2 * p];
                let b = a + eq[2 * p + 1];
                let mut c = [F::ZERO; 9];
                for k in 0..8 {
                    c[k] += a * h[k];
                    c[k + 1] += b * h[k];
                }
                c
            };
            let add = |mut a: [F; 9], b: [F; 9]| {
                for i in 0..9 {
                    a[i] += b[i];
                }
                a
            };
            let message = if rayon::current_num_threads() == 1 || segments * pairs < 32 {
                (0..segments * pairs)
                    .map(contribution)
                    .fold([F::ZERO; 9], add)
            } else {
                (0..segments * pairs)
                    .into_par_iter()
                    .map(contribution)
                    .reduce(|| [F::ZERO; 9], add)
            };
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
            math::fold_columns(&mut cols, r);
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
