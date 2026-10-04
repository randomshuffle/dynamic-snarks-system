//! Experimental degree-four GKR: virtual square/fourth-power tables.
//!
//! If A_j is the MLE of the Boolean table A(b)^(2^j), then
//! A_j(r) = A(r^(2^(128-j)))^(2^j). Thus a cubic product of three MLEs
//! checks x^7 on the Boolean cube and reduces to three claims on A.
//! All three points are propagated into the next GKR layer, or authenticated
//! by the PCS at a checkpoint. No square-table commitment is trusted.
//!
//! To share one equality table, batching uses independently random state
//! weights and point weights (a degree-two rank-one batching polynomial).
//! We supply all state coordinates at each of the three points; the resulting
//! extra folding work is charged to this experimental prover.
use super::*;
use rayon::prelude::*;
use std::sync::OnceLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct Layer {
    pub messages: Vec<[F; 5]>,
    pub inputs: [Vec<State>; 3],
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub outputs: Vec<F>,
    pub feed_forward: [F; 2],
    pub layers: Vec<Layer>,
}

fn power(mut x: F, count: usize) -> F {
    for _ in 0..count {
        x = x * x;
    }
    x
}
fn points(r: &[F]) -> [Vec<F>; 3] {
    [
        r.to_vec(),
        r.iter().map(|&x| power(x, 127)).collect(),
        r.iter().map(|&x| power(x, 126)).collect(),
    ]
}
fn start(t: &mut impl Challenger, variables: usize, segments: usize) -> Vec<F> {
    t.observe_label(b"poseidon2b-frobenius-gkr-v1");
    t.observe_bytes(&(variables as u64).to_le_bytes());
    t.observe_bytes(&(segments as u64).to_le_bytes());
    t.sample_f128_vec(variables)
}

fn inverse_external() -> &'static [State; WIDTH] {
    static INV: OnceLock<[State; WIDTH]> = OnceLock::new();
    INV.get_or_init(|| {
        let mut a = [[F::ZERO; 2 * WIDTH]; WIDTH];
        for col in 0..WIDTH {
            let mut e = [F::ZERO; WIDTH];
            e[col] = F::ONE;
            hash::external(&mut e);
            for row in 0..WIDTH {
                a[row][col] = e[row];
            }
            a[col][WIDTH + col] = F::ONE;
        }
        for col in 0..WIDTH {
            let pivot = (col..WIDTH).find(|&row| a[row][col] != F::ZERO).unwrap();
            a.swap(pivot, col);
            let inv = a[col][col].inv();
            for x in &mut a[col] {
                *x *= inv;
            }
            for row in 0..WIDTH {
                if row == col {
                    continue;
                }
                let factor = a[row][col];
                for j in 0..2 * WIDTH {
                    a[row][j] += factor * a[col][j];
                }
            }
        }
        std::array::from_fn(|i| std::array::from_fn(|j| a[i][WIDTH + j]))
    })
}
fn undo_before_sbox(round: Option<usize>, mut state: State) -> State {
    if let Some(r) = round {
        let rc = &hash::constants()[r];
        if hash::full(r) {
            for w in 0..WIDTH {
                state[w] += rc[w];
            }
        } else {
            state[0] += rc[0];
        }
        if r == 0 {
            state = std::array::from_fn(|i| dot(inverse_external()[i], state));
        }
    }
    state
}

/// Cubic product using Karatsuba for the first two affine factors.
fn cubic(a: [F; 2], b: [F; 2], c: [F; 2]) -> [F; 4] {
    let lo = a[0] * b[0];
    let hi = a[1] * b[1];
    let mid = (a[0] + a[1]) * (b[0] + b[1]) + lo + hi;
    [
        lo * c[0],
        lo * c[1] + mid * c[0],
        mid * c[1] + hi * c[0],
        hi * c[1],
    ]
}
fn line(
    columns: &[Vec<F>],
    segments: usize,
    s: usize,
    pair: usize,
    depth: usize,
    sw: State,
) -> [F; 4] {
    let round = round_at(segments, s, depth);
    let mut out = [F::ZERO; 4];
    for w in 0..WIDTH {
        let affine = |group: usize| {
            let c = &columns[(group * segments + s) * WIDTH + w];
            [c[2 * pair], c[2 * pair] + c[2 * pair + 1]]
        };
        let a = affine(0);
        if round.is_some_and(|r| w == 0 || hash::full(r)) {
            let h = cubic(a, affine(1), affine(2));
            for k in 0..4 {
                out[k] += sw[w] * h[k];
            }
        } else {
            out[0] += sw[w] * a[0];
            out[1] += sw[w] * a[1];
        }
    }
    out
}
fn message(
    columns: &[Vec<F>],
    eq: &[F],
    sw: &[State],
    segments: usize,
    depth: usize,
    single_target: Option<F>,
    schedule: Schedule,
) -> [F; 5] {
    let pairs = eq.len() / 2;
    if let Some(target) = single_target {
        let h = schedule.coefficients(segments * pairs, |i| {
            let pair = i % pairs;
            let tail = eq[2 * pair] + eq[2 * pair + 1];
            line(columns, segments, i / pairs, pair, depth, sw[i / pairs]).map(|x| x * tail)
        });
        let mut out = [F::ZERO; 5];
        for k in 0..4 {
            out[k] += (F::ONE + target) * h[k];
            out[k + 1] += h[k];
        }
        out
    } else {
        schedule.coefficients(segments * pairs, |i| {
            let pair = i % pairs;
            let a = eq[2 * pair];
            let b = a + eq[2 * pair + 1];
            let h = line(columns, segments, i / pairs, pair, depth, sw[i / pairs]);
            let mut out = [F::ZERO; 5];
            for k in 0..4 {
                out[k] += a * h[k];
                out[k + 1] += b * h[k];
            }
            out
        })
    }
}
fn point_weights(t: &mut impl Challenger, n: usize) -> Vec<F> {
    if n == 1 {
        vec![F::ONE]
    } else {
        t.sample_f128_vec(n)
    }
}
fn combined_eq(targets: &[Vec<F>], beta: &[F]) -> Vec<F> {
    let mut out = math::eq_table(&targets[0]);
    if targets.len() == 1 {
        return out;
    }
    out.par_iter_mut().for_each(|x| *x *= beta[0]);
    for (target, &weight) in targets.iter().zip(beta).skip(1) {
        let e = math::eq_table(target);
        out.par_iter_mut()
            .zip(e)
            .for_each(|(x, e)| *x += weight * e);
    }
    out
}
fn initial_claim(current: &[Vec<State>], weights: &[State], beta: &[F]) -> F {
    current.iter().zip(beta).fold(F::ZERO, |a, (states, &b)| {
        a + b * states
            .iter()
            .zip(weights)
            .fold(F::ZERO, |a, (&x, &w)| a + dot(w, x))
    })
}
fn expected(inputs: &[Vec<State>; 3], sw: &[State], segments: usize, depth: usize) -> F {
    (0..segments).fold(F::ZERO, |sum, s| {
        let round = round_at(segments, s, depth);
        let a: [State; 3] = std::array::from_fn(|j| {
            let mut x = inputs[j][s];
            if let Some(r) = round {
                hash::before_sbox(r, &mut x);
            }
            x
        });
        sum + (0..WIDTH).fold(F::ZERO, |sum, w| {
            let v = if round.is_some_and(|r| w == 0 || hash::full(r)) {
                a[0][w] * power(a[1][w], 1) * power(a[2][w], 2)
            } else {
                a[0][w]
            };
            sum + sw[s][w] * v
        })
    })
}
fn absorb_inputs(t: &mut impl Challenger, inputs: &[Vec<State>; 3]) {
    t.observe_label(b"frobenius-layer-inputs");
    for group in inputs {
        for state in group {
            t.observe_f128_slice(state);
        }
    }
}
fn terminal_claims(
    output_point: Vec<F>,
    outputs: &[F],
    feed_forward: [F; 2],
    targets: &[Vec<F>],
    current: &[Vec<State>],
) -> Result<Vec<Claim>, String> {
    let mut c = super::claims(
        output_point,
        outputs,
        feed_forward,
        targets[0].clone(),
        &current[0],
    )?;
    for j in 1..3 {
        c.extend(
            current[j]
                .iter()
                .flatten()
                .enumerate()
                .map(|(column, &value)| Claim {
                    column,
                    point: targets[j].clone(),
                    value,
                }),
        );
    }
    Ok(c)
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
        return Err("invalid Frobenius witness shape".into());
    }
    let rows = witness.columns[0].len();
    let variables = rows.ilog2() as usize;
    let schedule = Schedule::default();
    let output_point = start(t, variables, segments);
    let outputs: Vec<_> = witness.columns[WIDTH..]
        .iter()
        .map(|v| math::evaluate(v, &output_point))
        .collect();
    let feed_forward = std::array::from_fn(|w| math::evaluate(&witness.columns[w], &output_point));
    t.observe_f128_slice(&outputs);
    t.observe_f128_slice(&feed_forward);
    let mut current = vec![initial(&outputs, feed_forward, segments)];
    let mut targets = vec![output_point.clone()];
    let mut trace = witness.trace;
    let mut layers = Vec::new();
    for depth in 0..layer_count(segments) {
        let beta = point_weights(t, targets.len());
        let weights = weights(t, depth, segments);
        let sw: Vec<_> = (0..segments)
            .map(|s| {
                round_at(segments, s, depth)
                    .map_or(weights[s], |r| hash::sbox_weights(r, weights[s]))
            })
            .collect();
        let mut claim = initial_claim(&current, &weights, &beta);
        let mut columns: Vec<_> = (0..segments)
            .flat_map(|s| match round_at(segments, s, depth) {
                Some(r) => take_round(&mut trace, r, schedule),
                None => trace[boundary(segments, s + 1)].as_ref().unwrap().clone(),
            })
            .collect();
        // Affine preprocessing commutes with MLE evaluation. Its inverse is
        // applied below so the next layer still receives original-state claims.
        columns
            .par_chunks_mut(WIDTH)
            .enumerate()
            .for_each(|(s, cols)| {
                if let Some(r) = round_at(segments, s, depth) {
                    for i in 0..rows {
                        let mut x = std::array::from_fn(|w| cols[w][i]);
                        hash::before_sbox(r, &mut x);
                        for w in 0..WIDTH {
                            cols[w][i] = x[w];
                        }
                    }
                }
            });
        let squares: Vec<Vec<F>> = columns
            .par_iter()
            .map(|c| c.iter().map(|&x| x * x).collect())
            .collect();
        let fourths: Vec<Vec<F>> = squares
            .par_iter()
            .map(|c| c.iter().map(|&x| x * x).collect())
            .collect();
        columns.extend(squares);
        columns.extend(fourths);
        let mut eq = combined_eq(&targets, &beta);
        let mut point = Vec::new();
        let mut messages = Vec::new();
        for variable in 0..variables {
            let msg = message(
                &columns,
                &eq,
                &sw,
                segments,
                depth,
                (targets.len() == 1).then(|| targets[0][variable]),
                schedule,
            );
            if msg[1..].iter().fold(F::ZERO, |a, &x| a + x) != claim {
                return Err(format!(
                    "Frobenius sumcheck depth={depth} variable={variable}"
                ));
            }
            frame(t, depth, variable);
            t.observe_f128_slice(&msg);
            let r = t.sample_f128();
            claim = math::poly_eval(&msg, r);
            math::fold(&mut eq, r);
            schedule.fold_columns(&mut columns, r);
            point.push(r);
            messages.push(msg);
        }
        let inputs = std::array::from_fn(|j| {
            (0..segments)
                .map(|s| {
                    let x = std::array::from_fn(|w| {
                        let v = columns[(j * segments + s) * WIDTH + w][0];
                        if j == 0 { v } else { power(v, 128 - j) }
                    });
                    undo_before_sbox(round_at(segments, s, depth), x)
                })
                .collect()
        });
        let e = targets
            .iter()
            .zip(&beta)
            .fold(F::ZERO, |a, (target, &b)| a + b * math::eq(target, &point));
        if claim != e * expected(&inputs, &sw, segments, depth) {
            return Err("Frobenius terminal relation".into());
        }
        absorb_inputs(t, &inputs);
        targets = points(&point).into();
        current = inputs.clone().into();
        layers.push(Layer { messages, inputs });
    }
    let claims = terminal_claims(output_point, &outputs, feed_forward, &targets, &current)?;
    Ok((
        Proof {
            outputs,
            feed_forward,
            layers,
        },
        claims,
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
        || p.layers
            .iter()
            .any(|l| l.messages.len() != variables || l.inputs.iter().any(|x| x.len() != segments))
    {
        return Err("Frobenius GKR shape".into());
    }
    let output_point = start(t, variables, segments);
    t.observe_f128_slice(&p.outputs);
    t.observe_f128_slice(&p.feed_forward);
    let mut current = vec![initial(&p.outputs, p.feed_forward, segments)];
    let mut targets = vec![output_point.clone()];
    for (depth, layer) in p.layers.iter().enumerate() {
        let beta = point_weights(t, targets.len());
        let weights = weights(t, depth, segments);
        let sw: Vec<_> = (0..segments)
            .map(|s| {
                round_at(segments, s, depth)
                    .map_or(weights[s], |r| hash::sbox_weights(r, weights[s]))
            })
            .collect();
        let mut claim = initial_claim(&current, &weights, &beta);
        let mut point = Vec::new();
        for (variable, msg) in layer.messages.iter().enumerate() {
            if msg[1..].iter().fold(F::ZERO, |a, &x| a + x) != claim {
                return Err("Frobenius GKR sumcheck".into());
            }
            frame(t, depth, variable);
            t.observe_f128_slice(msg);
            let r = t.sample_f128();
            claim = math::poly_eval(msg, r);
            point.push(r);
        }
        let e = targets
            .iter()
            .zip(&beta)
            .fold(F::ZERO, |a, (target, &b)| a + b * math::eq(target, &point));
        if claim != e * expected(&layer.inputs, &sw, segments, depth) {
            return Err("Frobenius GKR terminal relation".into());
        }
        absorb_inputs(t, &layer.inputs);
        targets = points(&point).into();
        current = layer.inputs.clone().into();
    }
    terminal_claims(output_point, &p.outputs, p.feed_forward, &targets, &current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flock_core::challenger::FsChallenger;
    #[test]
    fn virtual_power_mles_and_affine_inverse() {
        let mut t = FsChallenger::new(b"frobenius-identity-test");
        for n in [1, 3, 7] {
            let a = t.sample_f128_vec(1 << n);
            let r = t.sample_f128_vec(n);
            for (j, q) in points(&r).iter().enumerate() {
                let table: Vec<_> = a.iter().map(|&x| power(x, j)).collect();
                assert_eq!(math::evaluate(&table, &r), power(math::evaluate(&a, q), j));
            }
        }
        for round in (0..HASH_ROUNDS).map(Some).chain([None]) {
            let x = std::array::from_fn(|_| t.sample_f128());
            let mut y = x;
            if let Some(r) = round {
                hash::before_sbox(r, &mut y);
            }
            assert_eq!(undo_before_sbox(round, y), x);
        }
    }
    #[test]
    fn reductions_bind_original_tables_and_reject_mutations() {
        for segments in [1, 2, 4, 5, 7, 8, 9] {
            let messages: Vec<_> = (0..16).map(hash::dataset).collect();
            let w = witness(&messages, segments).unwrap();
            let originals = w.columns.clone();
            let (proof, claims) = prove(w, segments, &mut FsChallenger::new(b"frob-test")).unwrap();
            let check = |p: &Proof| verify(p, 4, segments, &mut FsChallenger::new(b"frob-test"));
            let verified = check(&proof).unwrap();
            assert_eq!(claims.len(), verified.len());
            for (a, b) in claims.iter().zip(&verified) {
                assert_eq!(a.column, b.column);
                assert_eq!(a.point, b.point);
                assert_eq!(a.value, b.value);
                assert_eq!(a.value, math::evaluate(&originals[a.column], &a.point));
            }
            let mut bad = proof.clone();
            bad.layers[0].messages[0][4] += F::ONE;
            assert!(check(&bad).is_err());
            for group in 0..3 {
                let mut bad = proof.clone();
                bad.layers[0].inputs[group][0][0] += F::ONE;
                assert!(check(&bad).is_err());
            }
            let mut bad = proof.clone();
            bad.feed_forward[0] += F::ONE;
            assert!(check(&bad).is_err());
            let mut bad = proof.clone();
            bad.layers[0].inputs[2].pop();
            assert!(check(&bad).is_err());
            let mut bad_w = witness(&messages, segments).unwrap();
            bad_w.columns[4 * segments][0] += F::ONE;
            assert!(prove(bad_w, segments, &mut FsChallenger::new(b"frob-test")).is_err());
        }
    }
    #[test]
    fn parallel_reduction_is_byte_identical() {
        let messages: Vec<_> = (0..2048).map(hash::dataset).collect();
        let mut encoded = Vec::new();
        for threads in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            encoded.push(pool.install(|| {
                let w = witness(&messages, 7).unwrap();
                let (p, c) = prove(w, 7, &mut FsChallenger::new(b"frob-parallel")).unwrap();
                let v = verify(&p, 11, 7, &mut FsChallenger::new(b"frob-parallel")).unwrap();
                assert_eq!(c.len(), v.len());
                bincode::serialize(&p).unwrap()
            }));
        }
        assert_eq!(encoded[0], encoded[1]);
    }
}
