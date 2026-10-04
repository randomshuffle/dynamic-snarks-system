//! Uncommitted multiplication trees; terminal claims are bound to route oracles.
use super::*;
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Layer {
    sc: SumcheckProof,
    values: [F; 4],
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Proof {
    pub roots: [F; 2],
    layers: Vec<Layer>,
}
pub(super) struct Witness {
    levels: Vec<[Vec<F>; 2]>,
}
impl Witness {
    pub fn new(p: Vec<F>, q: Vec<F>) -> Self {
        assert!(p.len().is_power_of_two() && p.len() == q.len());
        let mut levels = vec![[p, q]];
        while levels.last().unwrap()[0].len() > 1 {
            let previous = levels.last().unwrap();
            levels.push(std::array::from_fn(|s| {
                previous[s]
                    .par_chunks_exact(2)
                    .map(|c| c[0] * c[1])
                    .collect()
            }));
        }
        Self { levels }
    }
    pub fn roots(&self) -> [F; 2] {
        std::array::from_fn(|s| self.levels.last().unwrap()[s][0])
    }
}
pub(super) fn prove_sc(
    mut columns: Vec<Vec<F>>,
    degree: usize,
    mut claim: F,
    t: &mut RawTranscript,
    f: impl Fn(&[F]) -> F + Sync,
) -> Result<(SumcheckProof, Vec<F>, Vec<F>), Error> {
    let variables = columns[0].len().ilog2() as usize;
    let mut point = Vec::new();
    let mut rounds = Vec::new();
    for round in 0..variables {
        let e = crate::parallel::sumcheck(
            columns[0].len() / 2,
            degree + 1,
            (degree + 1) * columns.len(),
            || vec![F::ZERO; columns.len()],
            |v, p, x| {
                for (a, c) in v.iter_mut().zip(&columns) {
                    *a = c[2 * p] + x * (c[2 * p + 1] + c[2 * p]);
                }
                f(v)
            },
        );
        finish_prover_round(
            &e,
            &mut claim,
            &mut point,
            round,
            0x534353,
            0x534352,
            interpolate,
            t,
        )?;
        crate::parallel::fold_columns(&mut columns, point[round]);
        rounds.push(e);
    }
    Ok((
        SumcheckProof { rounds },
        point,
        columns.iter().map(|c| c[0]).collect(),
    ))
}
pub(super) fn verify_sc(
    p: &SumcheckProof,
    degree: usize,
    variables: usize,
    mut claim: F,
    t: &mut RawTranscript,
) -> Result<(F, Vec<F>), Error> {
    if p.rounds.len() != variables {
        return Err(Error::Sumcheck);
    }
    let mut point = Vec::new();
    for (i, e) in p.rounds.iter().enumerate() {
        if e.len() != degree + 1 || e[0] + e[1] != claim {
            return Err(Error::Sumcheck);
        }
        t.absorb_message(0x534353 + i as u64, e);
        let r = t.challenge(0x534352 + i as u64);
        claim = interpolate(e, r);
        point.push(r);
    }
    Ok((claim, point))
}
pub(super) fn prove(w: Witness, t: &mut RawTranscript) -> Result<(Proof, Vec<F>, [F; 2]), Error> {
    let roots = w.roots();
    let mut claims = roots;
    let mut target = Vec::new();
    let mut layers = Vec::new();
    t.absorb_message(0x50524f44, &roots);
    let log = w.levels.len() - 1;
    for depth in 0..log {
        let child = &w.levels[log - depth - 1];
        let beta = t.challenge(0x42455441);
        let mut columns: Vec<_> = (0..4)
            .map(|j| {
                child[j / 2]
                    .iter()
                    .skip(j % 2)
                    .step_by(2)
                    .copied()
                    .collect()
            })
            .collect();
        columns.push(eq_evaluations(&target));
        let (sc, point, v) = prove_sc(columns, 3, claims[0] + beta * claims[1], t, |v| {
            v[4] * (v[0] * v[1] + beta * v[2] * v[3])
        })?;
        let values = [v[0], v[1], v[2], v[3]];
        t.absorb_message(0x56414c, &values);
        let mix = t.challenge(0x4d4958);
        claims = [v[0] + mix * (v[0] + v[1]), v[2] + mix * (v[2] + v[3])];
        target = vec![mix];
        target.extend(point);
        layers.push(Layer { sc, values });
    }
    Ok((Proof { roots, layers }, target, claims))
}
pub(super) fn verify(
    p: &Proof,
    log: usize,
    t: &mut RawTranscript,
) -> Result<(Vec<F>, [F; 2]), Error> {
    if p.layers.len() != log {
        return Err(Error::TableShape);
    }
    t.absorb_message(0x50524f44, &p.roots);
    let mut claims = p.roots;
    let mut target = Vec::new();
    for (depth, l) in p.layers.iter().enumerate() {
        let beta = t.challenge(0x42455441);
        let (claim, point) = verify_sc(&l.sc, 3, depth, claims[0] + beta * claims[1], t)?;
        let v = l.values;
        if claim != eq_eval(&target, &point) * (v[0] * v[1] + beta * v[2] * v[3]) {
            return Err(Error::Terminal);
        }
        t.absorb_message(0x56414c, &v);
        let mix = t.challenge(0x4d4958);
        claims = [v[0] + mix * (v[0] + v[1]), v[2] + mix * (v[2] + v[3])];
        target = vec![mix];
        target.extend(point);
    }
    Ok((target, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn product_tree_reduces_to_exact_leaf_evaluations() {
        for log in [2, 3, 8] {
            let p = (0..1 << log)
                .map(|i| F::from_usize(i + 1))
                .collect::<Vec<_>>();
            let q = (0..1 << log)
                .map(|i| F::from_usize(i + 5))
                .collect::<Vec<_>>();
            let w = Witness::new(p.clone(), q.clone());
            let (proof, point, values) = prove(w, &mut RawTranscript::new(9)).unwrap();
            let (vp, vv) = verify(&proof, log, &mut RawTranscript::new(9)).unwrap();
            assert_eq!(point, vp);
            assert_eq!(values, vv);
            let eq = eq_evaluations(&point);
            assert_eq!(
                values,
                [
                    p.iter().zip(&eq).map(|(&a, &b)| a * b).sum(),
                    q.iter().zip(&eq).map(|(&a, &b)| a * b).sum()
                ]
            );
            let mut bad = proof.clone();
            bad.roots[0] += F::ONE;
            assert!(verify(&bad, log, &mut RawTranscript::new(9)).is_err());
            let mut bad = proof.clone();
            bad.layers[log - 1].values[0] += F::ONE;
            assert!(verify(&bad, log, &mut RawTranscript::new(9)).is_err());
        }
    }
}
