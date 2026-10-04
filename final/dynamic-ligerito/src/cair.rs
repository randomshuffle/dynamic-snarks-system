//! Initial Merkle PIOP, linked to the arithmetic assignment at two MLE points.
use crate::{
    endpoint_gkr,
    field::F,
    hash::{self, Digest},
    static_snark::{MleOpeningProof, commit_mle, commitment_seed, verify_mle_opening},
    transcript::RawTranscript,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, thiserror::Error)]
#[error("initial Merkle proof: {0}")]
pub(crate) struct Error(String);
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    rows: usize,
    poseidon: endpoint_gkr::Proof,
    table: MleOpeningProof,
}
pub(crate) struct StaticLink {
    pub points: Vec<Vec<F>>,
    pub transcript_binding: Vec<F>,
}
fn seed(k: usize, root: Digest, static_seed: &[F], table: &[u8; 32]) -> Vec<F> {
    let mut s = vec![
        F::from_usize(k),
        root[0],
        root[1],
        F::from_usize(static_seed.len()),
    ];
    s.extend_from_slice(static_seed);
    s.extend(commitment_seed(table));
    s
}
fn transcript(s: &[F]) -> RawTranscript {
    let mut t = RawTranscript::new(0x494e495444494732);
    t.absorb_message(1, s);
    t
}
fn table_point(word: usize, p: &[F]) -> Vec<F> {
    let mut out = vec![F::from_usize(word)];
    out.extend_from_slice(p);
    out
}
fn points(c: &endpoint_gkr::Claims) -> Vec<Vec<F>> {
    let vars = c.input_point.len();
    let mut p = vec![
        table_point(0, &c.output_point),
        table_point(1, &c.output_point),
    ];
    for source in [&c.input_point, &c.output_point] {
        for child in 0..2 {
            let mut q = vec![F::from_usize(child)];
            q.extend_from_slice(&source[..vars - 1]);
            for word in 0..2 {
                p.push(table_point(word, &q));
            }
        }
    }
    let mut root = vec![F::ZERO; vars];
    root[0] = F::ONE;
    for word in 0..2 {
        p.push(table_point(word, &root));
    }
    for word in 0..2 {
        p.push(table_point(word, &vec![F::ZERO; vars]));
    }
    p
}
fn derived(p: &[F], d: &[F], assignment: F, root: Digest) -> [F; 4] {
    let h = p.len() - 1;
    let b = p[h];
    let delta = p.iter().map(|&x| F::ONE + x).product::<F>();
    let index = p[..h]
        .iter()
        .enumerate()
        .map(|(i, &x)| F::from_usize(1 << i) * x)
        .sum::<F>();
    let dummy = hash::compress([F::ZERO; 4]);
    [
        (F::ONE + b) * d[0] + b * assignment + delta * dummy[0],
        (F::ONE + b) * d[1] + b * index + delta * dummy[1],
        (F::ONE + b) * d[2] + delta * root[0],
        (F::ONE + b) * d[3] + delta * root[1],
    ]
}
fn link(c: &endpoint_gkr::Claims, s: Vec<F>) -> StaticLink {
    let h = c.input_point.len() - 1;
    StaticLink {
        points: vec![c.input_point[..h].to_vec(), c.output_point[..h].to_vec()],
        transcript_binding: s,
    }
}
pub(crate) fn prove(
    a: &[F],
    root: Digest,
    static_seed: &[F],
    trace_len: usize,
    main: Vec<F>,
) -> Result<(Proof, StaticLink), Error> {
    let k = a.len();
    if k < 2 || !k.is_power_of_two() || trace_len != k || a != main {
        return Err(Error("assignment link".into()));
    }
    drop(main);
    let mut d = vec![[F::ZERO; 2]; 2 * k];
    d[0] = hash::compress([F::ZERO; 4]);
    d[k..]
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, x)| *x = hash::hash_leaf(i, a[i]));
    let mut start = k / 2;
    while start > 0 {
        let (left, right) = d.split_at_mut(2 * start);
        left[start..]
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = hash::hash_node(0, right[2 * i], right[2 * i + 1]));
        start /= 2;
    }
    if d[1] != root {
        return Err(Error("root".into()));
    }
    let inputs = std::array::from_fn(|word| {
        (0..2 * k)
            .map(|i| {
                if i == 0 {
                    F::ZERO
                } else if i >= k {
                    [a[i - k], F::from_usize(i - k), F::ZERO, F::ZERO][word]
                } else {
                    [d[2 * i][0], d[2 * i][1], d[2 * i + 1][0], d[2 * i + 1][1]][word]
                }
            })
            .collect::<Vec<_>>()
    });
    let digests = std::array::from_fn(|word| d.iter().map(|x| x[word]).collect::<Vec<_>>());
    let committed =
        commit_mle(d.into_iter().flatten().collect()).map_err(|e| Error(e.to_string()))?;
    let mut s = seed(k, root, static_seed, committed.commitment());
    let (poseidon, c) =
        endpoint_gkr::prove(inputs, &digests, &mut transcript(&s)).map_err(Error)?;
    drop(digests);
    poseidon.append_transcript(&mut s);
    let p = points(&c);
    let table = committed.open(&p.iter().map(Vec::as_slice).collect::<Vec<_>>(), &s);
    let link = link(&c, s);
    Ok((
        Proof {
            rows: 2 * k,
            poseidon,
            table,
        },
        link,
    ))
}
pub(crate) fn verify(
    k: usize,
    root: Digest,
    static_seed: &[F],
    trace_len: usize,
    proof: &Proof,
    static_values: &[F],
) -> Result<StaticLink, Error> {
    if k < 2
        || !k.is_power_of_two()
        || trace_len != k
        || proof.rows != 2 * k
        || static_values.len() != 2
    {
        return Err(Error("shape".into()));
    }
    let mut s = seed(k, root, static_seed, &proof.table.commitment);
    let c = endpoint_gkr::verify(
        &proof.poseidon,
        (2 * k).ilog2() as usize,
        &mut transcript(&s),
    )
    .map_err(Error)?;
    proof.poseidon.append_transcript(&mut s);
    let p = points(&c);
    verify_mle_opening(
        4 * k,
        &p.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        &proof.table,
        &s,
    )
    .map_err(|e| Error(e.to_string()))?;
    let v = &proof.table.opening.evaluations;
    if v.len() != 14
        || v[10..12] != root
        || v[12..14] != hash::compress([F::ZERO; 4])
        || v[..2] != c.outputs
        || derived(&c.input_point, &v[2..6], static_values[0], root) != c.inputs
        || derived(&c.output_point, &v[6..10], static_values[1], root)[..2] != c.feed_forward
    {
        return Err(Error("terminal or assignment binding".into()));
    }
    Ok(link(&c, s))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assignment_and_both_digest_limbs_bound() {
        let a: Vec<_> = (0..16).map(F::from_usize).collect();
        let root = crate::merkle::MerkleTree::new(a.clone())
            .unwrap()
            .commitment()
            .root;
        let (p, link) = prove(&a, root, &[F::ONE], 16, a.clone()).unwrap();
        let values: Vec<_> = link
            .points
            .iter()
            .map(|q| {
                let mut v = a.clone();
                for &r in q {
                    crate::parallel::fold(&mut v, r);
                }
                v[0]
            })
            .collect();
        verify(16, root, &[F::ONE], 16, &p, &values).unwrap();
        for i in 0..2 {
            let mut bad = values.clone();
            bad[i] += F::ONE;
            assert!(verify(16, root, &[F::ONE], 16, &p, &bad).is_err());
            let mut bad = root;
            bad[i] += F::ONE;
            assert!(verify(16, bad, &[F::ONE], 16, &p, &values).is_err());
        }
        let mut bad = p.clone();
        bad.table.opening.evaluations[5] += F::ONE;
        assert!(verify(16, root, &[F::ONE], 16, &bad, &values).is_err());
    }
}
