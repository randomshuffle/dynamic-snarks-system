//! One, three, or seven committed checkpoints, packed into a single PCS oracle.
use crate::hash_gkr as gkr;
use crate::{
    field::F,
    static_snark::{MleOpeningProof, commitment_seed, verify_mle_opening},
    transcript::RawTranscript,
};
use flock_core::challenger::{Challenger, FsChallenger};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    gkr: gkr::Proof,
    middle: MleOpeningProof,
}
pub(crate) struct Claims {
    pub input_point: Vec<F>,
    pub output_point: Vec<F>,
    pub inputs: [F; 4],
    pub outputs: [F; 2],
    pub feed_forward: [F; 2],
}
impl Proof {
    pub(crate) fn statistics(&self, rows: usize) -> serde_json::Value {
        let segments = (self.gkr.outputs.len() + 2) / 4;
        let logical = rows * checkpoint_width(segments);
        let plain = self.plaintext_bytes();
        serde_json::json!({"role":"hash_midpoint","rows":rows,"logical_elements":logical,"pcs_elements":if plain>0{0}else{logical.max(8192)},"plaintext_bytes":plain})
    }

    pub(crate) fn plaintext_bytes(&self) -> usize {
        self.middle.opening.plaintext_bytes()
    }

    pub fn append_transcript(&self, out: &mut Vec<F>) {
        let h = blake3::hash(&bincode::serialize(self).unwrap());
        out.extend(
            h.as_bytes()
                .chunks_exact(16)
                .map(|c| F::from_u128(u128::from_le_bytes(c.try_into().unwrap()))),
        );
    }
}
fn transcript(parent: &RawTranscript, root: &[u8; 32], segments: usize) -> FsChallenger {
    let mut t = FsChallenger::new(b"dynamic-poseidon2b-33-checkpoint-v1");
    t.observe_bytes(&parent.challenge(0x504f534549444f4e).bytes());
    t.observe_bytes(root);
    // Preserve the existing one-checkpoint transcript exactly.
    if segments != 2 {
        t.observe_bytes(b"multi-checkpoint-v1");
        t.observe_bytes(&(segments as u64).to_le_bytes());
    }
    t
}
fn unpack(c: &[gkr::Claim], segments: usize) -> Claims {
    Claims {
        input_point: c[0].point.iter().copied().map(F).collect(),
        output_point: c[4 * segments].point.iter().copied().map(F).collect(),
        inputs: std::array::from_fn(|i| F(c[i].value)),
        outputs: [F(c[8 * segments - 4].value), F(c[8 * segments - 3].value)],
        feed_forward: [F(c[8 * segments - 2].value), F(c[8 * segments - 1].value)],
    }
}
fn checkpoint_width(segments: usize) -> usize {
    (4 * (segments - 1)).next_power_of_two()
}
fn middle_points(c: &[gkr::Claim], segments: usize) -> Vec<Vec<F>> {
    c.iter()
        .filter(|c| (4..4 * segments).contains(&c.column))
        .map(|c| {
            let mut p: Vec<_> = (0..checkpoint_width(segments).ilog2())
                .map(|bit| F::from_bool((c.column - 4) & (1 << bit) != 0))
                .collect();
            p.extend(c.point.iter().copied().map(F));
            p
        })
        .collect()
}
fn seed(parent: &RawTranscript, p: &gkr::Proof, root: &[u8; 32]) -> Vec<F> {
    let mut out = commitment_seed(root);
    out.push(parent.challenge(0x504f534549444f4e));
    let h = blake3::hash(&bincode::serialize(p).unwrap());
    out.extend(
        h.as_bytes()
            .chunks_exact(16)
            .map(|c| F::from_u128(u128::from_le_bytes(c.try_into().unwrap()))),
    );
    out
}
pub(crate) fn prove(
    inputs: [Vec<F>; 4],
    digests: &[Vec<F>; 2],
    parent: &mut RawTranscript,
) -> Result<(Proof, Claims), String> {
    prove_with_checkpoints(inputs, digests, parent, 1)
}
pub(crate) fn prove_with_checkpoints(
    inputs: [Vec<F>; 4],
    digests: &[Vec<F>; 2],
    parent: &mut RawTranscript,
    checkpoints: usize,
) -> Result<(Proof, Claims), String> {
    prove_with_policy(inputs, digests, parent, checkpoints, false)
}
pub(crate) fn prove_with_policy(
    inputs: [Vec<F>; 4],
    digests: &[Vec<F>; 2],
    parent: &mut RawTranscript,
    checkpoints: usize,
    plain: bool,
) -> Result<(Proof, Claims), String> {
    if ![1, 3, 7].contains(&checkpoints) {
        return Err("unsupported checkpoint count".into());
    }
    let segments = checkpoints + 1;
    let width = checkpoint_width(segments);
    let rows = inputs[0].len();
    let messages: Vec<[u8; 64]> = (0..rows)
        .map(|i| {
            let mut b = [0; 64];
            for j in 0..4 {
                b[16 * j..16 * j + 16].copy_from_slice(&inputs[j][i].bytes());
            }
            b
        })
        .collect();
    drop(inputs);
    let witness = gkr::witness(&messages, segments)?;
    drop(messages);
    for j in 0..2 {
        if witness.columns[4 * segments + j]
            .iter()
            .zip(&digests[j])
            .any(|(a, b)| *a != b.0)
        {
            return Err("hash output mismatch".into());
        }
    }
    let middle: Vec<_> = (0..rows)
        .flat_map(|i| {
            (0..width).map({
                let c = &witness.columns;
                move |j| {
                    if j < 4 * checkpoints {
                        F(c[4 + j][i])
                    } else {
                        F::ZERO
                    }
                }
            })
        })
        .collect();
    let committed =
        crate::static_snark::commit_mle_with_plain(middle, plain).map_err(|e| e.to_string())?;
    let root = *committed.commitment();
    let mut t = transcript(parent, &root, segments);
    let (p, c) = gkr::prove(witness, segments, &mut t)?;
    let points = middle_points(&c, segments);
    let s = seed(parent, &p, &root);
    let middle = committed.open(&points.iter().map(Vec::as_slice).collect::<Vec<_>>(), &s);
    let proof = Proof { gkr: p, middle };
    let claims = unpack(&c, segments);
    let mut binding = Vec::new();
    proof.append_transcript(&mut binding);
    parent.absorb_message(0x504f534549444f4e, &binding);
    Ok((proof, claims))
}
pub(crate) fn verify(
    proof: &Proof,
    variables: usize,
    parent: &mut RawTranscript,
) -> Result<Claims, String> {
    let segments = (proof.gkr.outputs.len() + 2) / 4;
    if ![2, 4, 8].contains(&segments) || proof.gkr.outputs.len() != 4 * (segments - 1) + 2 {
        return Err("unsupported checkpoint proof shape".into());
    }
    let mut t = transcript(parent, &proof.middle.commitment, segments);
    let c = gkr::verify(&proof.gkr, variables, segments, &mut t)?;
    let points = middle_points(&c, segments);
    let s = seed(parent, &proof.gkr, &proof.middle.commitment);
    verify_mle_opening(
        checkpoint_width(segments) << variables,
        &points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        &proof.middle,
        &s,
    )
    .map_err(|e| e.to_string())?;
    let expected: Vec<_> = c
        .iter()
        .filter(|c| (4..4 * segments).contains(&c.column))
        .map(|c| F(c.value))
        .collect();
    if expected != proof.middle.opening.evaluations {
        return Err("checkpoint link".into());
    }
    let mut binding = Vec::new();
    proof.append_transcript(&mut binding);
    parent.absorb_message(0x504f534549444f4e, &binding);
    Ok(unpack(&c, segments))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_and_feed_forward_tampering() {
        let input: [Vec<F>; 4] =
            std::array::from_fn(|w| (0..8).map(|i| F::from_usize(i * 7 + w + 2)).collect());
        let d = std::array::from_fn(|w| {
            (0..8)
                .map(|i| crate::hash::compress(std::array::from_fn(|j| input[j][i]))[w])
                .collect()
        });
        for checkpoints in [1, 3, 7] {
            let (p, _) =
                prove_with_checkpoints(input.clone(), &d, &mut RawTranscript::new(77), checkpoints)
                    .unwrap();
            let check = |p: &Proof| verify(p, 3, &mut RawTranscript::new(77));
            check(&p).unwrap();
            // Bind every intermediate state at both its input and output points.
            for state in 0..checkpoints {
                for occurrence in [0, 4 * checkpoints] {
                    let mut bad = p.clone();
                    bad.middle.opening.evaluations[occurrence + 4 * state] += F::ONE;
                    assert!(check(&bad).is_err());
                }
            }
            let mut bad = p.clone();
            bad.middle.commitment[0] ^= 1;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.gkr.feed_forward[0] += flock_core::field::F128::ONE;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            let layer = bad.gkr.layers.len() / 2;
            bad.gkr.layers[layer].messages[1][3] += flock_core::field::F128::ONE;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.gkr.outputs.pop();
            assert!(check(&bad).is_err());
        }
    }
}
