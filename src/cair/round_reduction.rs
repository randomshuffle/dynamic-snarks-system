//! Initial Merkle PIOP with one digest oracle and no routing sumcheck.
//!
//! The caller supplies a complete power-of-two physical assignment table W.
//! O[1..2K] is its Merkle digest heap and O[0] = Poseidon2(0,0,0)[0].
//! Hash inputs are affine restrictions of O and W, with a correction at row
//! zero. They are authenticated after the 64-round endpoint GKR reduction.

use super::{Error, StaticLink, domain_mle, profile_checkpoint};
use crate::poseidon_scalar::round_reduction as endpoint_gkr;
use crate::static_snark::{MleOpeningProof, commit_mle, commitment_seed, verify_mle_opening};
use crate::transcript::RawTranscript;
use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use std::time::Instant;

const DOMAIN: u64 = 0x494e_4954_454e_4431;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    table_rows: usize,
    poseidon: endpoint_gkr::Proof,
    table_opening: MleOpeningProof,
}

fn table_rows(assignment_len: usize, trace_len: usize) -> Result<usize, Error> {
    // Physical gate-order assignments are already padded by Circuit::encode_assignment.
    // Enforcing this interface makes W itself the leaf-input MLE, including zeros.
    if assignment_len < 2 || !assignment_len.is_power_of_two() || trace_len != assignment_len {
        return Err(Error::TraceLength);
    }
    assignment_len.checked_mul(2).ok_or(Error::TableShape)
}

fn dummy_digest() -> Bn254 {
    let mut state = [Bn254::ZERO; 3];
    crate::hash::poseidon2().permute_mut(&mut state);
    state[0]
}

fn digest_table(assignment: &[Bn254]) -> Vec<Bn254> {
    let k = assignment.len();
    let permutation = crate::hash::poseidon2();
    let mut digests = vec![Bn254::ZERO; 2 * k];
    digests[k..]
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, digest)| {
            let mut state = [assignment[i], Bn254::from_usize(i), Bn254::ONE];
            permutation.permute_mut(&mut state);
            *digest = state[0];
        });
    let mut start = k / 2;
    let mut level = 0;
    while start != 0 {
        let (parents, children) = digests.split_at_mut(2 * start);
        parents[start..]
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, digest)| {
                let mut state = [
                    children[2 * i],
                    children[2 * i + 1],
                    Bn254::from_usize(2 + level),
                ];
                permutation.permute_mut(&mut state);
                *digest = state[0];
            });
        start /= 2;
        level += 1;
    }
    digests[0] = dummy_digest();
    digests
}

fn hash_inputs(assignment: &[Bn254], digests: &[Bn254]) -> [Vec<Bn254>; 3] {
    let k = assignment.len();
    let height = k.ilog2() as usize;
    let mut inputs = std::array::from_fn::<_, 3, _>(|_| vec![Bn254::ZERO; 2 * k]);
    crate::parallel::rows_mut(
        &mut inputs.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
        0..2 * k,
        16,
        |start, columns| {
            for offset in 0..columns[0].len() {
                let row = start + offset;
                let input = if row == 0 {
                    [Bn254::ZERO; 3]
                } else if row < k {
                    [
                        digests[2 * row],
                        digests[2 * row + 1],
                        Bn254::from_usize(1 + height - row.ilog2() as usize),
                    ]
                } else {
                    [assignment[row - k], Bn254::from_usize(row - k), Bn254::ONE]
                };
                for word in 0..3 {
                    columns[word][offset] = input[word];
                }
            }
        },
    );
    inputs
}

fn statement_seed(
    k: usize,
    root: Bn254,
    static_seed: &[Bn254],
    digest_seed: &[Bn254],
) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(DOMAIN),
        Bn254::from_usize(k),
        root,
        Bn254::from_usize(static_seed.len()),
    ];
    seed.extend_from_slice(static_seed);
    seed.push(Bn254::from_usize(digest_seed.len()));
    seed.extend_from_slice(digest_seed);
    seed
}

fn transcript(seed: &[Bn254]) -> RawTranscript {
    let mut transcript = RawTranscript::new(DOMAIN);
    transcript.absorb_message(1, seed);
    transcript
}

fn opening_points(claims: &endpoint_gkr::Claims) -> Vec<Vec<Bn254>> {
    let variables = claims.input_point.len();
    let u = &claims.input_point[..variables - 1];
    let mut points = vec![claims.output_point.clone()];
    for bit in [Bn254::ZERO, Bn254::ONE] {
        let mut child = vec![bit];
        child.extend_from_slice(u);
        points.push(child);
    }
    let mut root = vec![Bn254::ZERO; variables];
    root[0] = Bn254::ONE;
    points.push(root);
    points.push(vec![Bn254::ZERO; variables]);
    points
}

fn derived_inputs(
    point: &[Bn254],
    left: Bn254,
    right: Bn254,
    assignment: Bn254,
    root: Bn254,
) -> [Bn254; 3] {
    let height = point.len() - 1;
    let b = point[height];
    let u = &point[..height];
    let delta_zero = point
        .iter()
        .fold(Bn254::ONE, |acc, &x| acc * (Bn254::ONE - x));
    let index = u.iter().enumerate().fold(Bn254::ZERO, |acc, (bit, &x)| {
        acc + Bn254::from_usize(1usize << bit) * x
    });
    [
        (Bn254::ONE - b) * left + b * assignment - delta_zero * dummy_digest(),
        (Bn254::ONE - b) * right + b * index - delta_zero * root,
        domain_mle(point, height),
    ]
}

pub(crate) fn prove(
    assignment: &[Bn254],
    root: Bn254,
    static_commitment_seed: &[Bn254],
    trace_len: usize,
    committed_main_column: Vec<Bn254>,
) -> Result<(Proof, StaticLink), Error> {
    let rows = table_rows(assignment.len(), trace_len)?;
    if assignment != committed_main_column {
        return Err(Error::StaticLink);
    }
    drop(committed_main_column);
    let phase = Instant::now();
    let digests = digest_table(assignment);
    if digests[1] != root {
        return Err(Error::RootMismatch);
    }
    let inputs = hash_inputs(assignment, &digests);
    profile_checkpoint(
        "initial endpoint: digest heap and derived input tables",
        phase,
    );
    let phase = Instant::now();
    let committed = commit_mle(digests.clone()).map_err(|e| Error::Whir(e.to_string()))?;
    profile_checkpoint("initial endpoint: digest commitment", phase);
    let mut opening_seed = statement_seed(
        assignment.len(),
        root,
        static_commitment_seed,
        &commitment_seed(committed.commitment()),
    );
    let phase = Instant::now();
    let (poseidon, claims) = endpoint_gkr::prove(inputs, &digests, &mut transcript(&opening_seed))
        .map_err(|_| Error::Sumcheck)?;
    profile_checkpoint("initial endpoint: all-round hash reduction", phase);
    poseidon.append_transcript(&mut opening_seed);
    let points = opening_points(&claims);
    let refs = points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let phase = Instant::now();
    let table_opening =
        committed.open_with_checkpoints(&refs, &opening_seed, "initial endpoint checkpoint");
    profile_checkpoint("initial endpoint: digest opening", phase);
    Ok((
        Proof {
            table_rows: rows,
            poseidon,
            table_opening,
        },
        StaticLink {
            point: claims.input_point[..claims.input_point.len() - 1].to_vec(),
            transcript_binding: opening_seed,
        },
    ))
}

pub(crate) fn verify(
    assignment_len: usize,
    root: Bn254,
    static_commitment_seed: &[Bn254],
    trace_len: usize,
    proof: &Proof,
    static_evaluations: &[Bn254],
) -> Result<StaticLink, Error> {
    let rows = table_rows(assignment_len, trace_len)?;
    if proof.table_rows != rows {
        return Err(Error::TableShape);
    }
    if static_evaluations.len() != 1 {
        return Err(Error::StaticLink);
    }
    let mut opening_seed = statement_seed(
        assignment_len,
        root,
        static_commitment_seed,
        &commitment_seed(&proof.table_opening.commitment),
    );
    let claims = endpoint_gkr::verify(
        &proof.poseidon,
        rows.ilog2() as usize,
        &mut transcript(&opening_seed),
    )
    .map_err(|_| Error::Sumcheck)?;
    proof.poseidon.append_transcript(&mut opening_seed);
    let points = opening_points(&claims);
    let refs = points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    verify_mle_opening(rows, &refs, &proof.table_opening, &opening_seed)
        .map_err(|e| Error::Whir(e.to_string()))?;
    let values = &proof.table_opening.opening.evaluations;
    if values.len() != 5 {
        return Err(Error::TableShape);
    }
    if values[3] != root || values[4] != dummy_digest() {
        return Err(Error::RootMismatch);
    }
    if values[0] != claims.output
        || claims.inputs
            != derived_inputs(
                &claims.input_point,
                values[1],
                values[2],
                static_evaluations[0],
                root,
            )
    {
        return Err(Error::Terminal);
    }
    Ok(StaticLink {
        point: claims.input_point[..claims.input_point.len() - 1].to_vec(),
        transcript_binding: opening_seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(values: &[Bn254], point: &[Bn254]) -> Bn254 {
        let mut work = values.to_vec();
        for &r in point {
            crate::parallel::fold(&mut work, r);
        }
        assert_eq!(work.len(), 1);
        work[0]
    }

    #[test]
    fn initial_endpoint_inputs_match_heap_and_off_cube_mles() {
        for k in [2usize, 4, 8, 32] {
            let assignment = (0..k)
                .map(|i| Bn254::from_usize(i * i + 3))
                .collect::<Vec<_>>();
            let digests = digest_table(&assignment);
            let root = crate::merkle::MerkleTree::new(assignment.clone())
                .unwrap()
                .commitment()
                .root;
            assert_eq!(digests[1], root);
            let inputs = hash_inputs(&assignment, &digests);
            for index in 0..2 * k + 3 {
                let point = (0..(2 * k).ilog2())
                    .map(|bit| {
                        if index < 2 * k {
                            Bn254::from_bool(index & (1 << bit) != 0)
                        } else {
                            Bn254::from_usize(index * (bit as usize + 3) + 11)
                        }
                    })
                    .collect::<Vec<_>>();
                let u = &point[..point.len() - 1];
                let child = |b| {
                    let mut p = vec![b];
                    p.extend_from_slice(u);
                    eval(&digests, &p)
                };
                assert_eq!(
                    derived_inputs(
                        &point,
                        child(Bn254::ZERO),
                        child(Bn254::ONE),
                        eval(&assignment, u),
                        root
                    ),
                    std::array::from_fn(|w| eval(&inputs[w], &point))
                );
            }
        }
    }

    #[test]
    fn initial_endpoint_roundtrip_and_tamper_rejection() {
        let assignment = (0..8).map(|i| Bn254::from_usize(i + 5)).collect::<Vec<_>>();
        let root = digest_table(&assignment)[1];
        let seed = [Bn254::from_u64(41), Bn254::from_u64(43)];
        let (proof, link) = prove(&assignment, root, &seed, 8, assignment.clone()).unwrap();
        let value = eval(&assignment, &link.point);
        let check = |p: &Proof| verify(8, root, &seed, 8, p, &[value]);
        let verified_link = check(&proof).unwrap();
        assert_eq!(verified_link.point, link.point);
        assert_eq!(verified_link.transcript_binding, link.transcript_binding);
        let bytes = serde_json::to_vec(&proof).unwrap();
        check(&serde_json::from_slice(&bytes).unwrap()).unwrap();
        assert!(verify(8, root, &seed, 8, &proof, &[value + Bn254::ONE]).is_err());
        assert!(verify(8, root + Bn254::ONE, &seed, 8, &proof, &[value]).is_err());
        assert!(verify(8, root, &[Bn254::ONE], 8, &proof, &[value]).is_err());
        for entry in 0..5 {
            let mut bad = proof.clone();
            bad.table_opening.opening.evaluations[entry] += Bn254::ONE;
            assert!(check(&bad).is_err());
        }
        let mut bad = proof.clone();
        bad.poseidon.tamper_for_test();
        assert!(check(&bad).is_err());
        let mut bad = proof.clone();
        bad.table_rows *= 2;
        assert!(check(&bad).is_err());
        assert!(prove(&assignment, root, &seed, 4, assignment.clone()).is_err());
        assert!(prove(&assignment[..7], root, &seed, 8, assignment.clone()).is_err());
        let mut wrong_assignment = assignment.clone();
        wrong_assignment[0] += Bn254::ONE;
        assert!(prove(&assignment, root, &seed, 8, wrong_assignment).is_err());
        #[cfg(feature = "parallel")]
        for threads in [1, 8] {
            let (other, _) = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| prove(&assignment, root, &seed, 8, assignment.clone()).unwrap());
            assert_eq!(serde_json::to_vec(&other).unwrap(), bytes);
        }
    }
}
