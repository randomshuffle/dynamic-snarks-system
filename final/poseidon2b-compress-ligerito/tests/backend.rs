use flock_core::{
    challenger::{Challenger, FsChallenger},
    field::F128 as F,
};
use poseidon2b_compress_ligerito_experiment::{Backend, digest_bytes, gkr, hash, math};
fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn slow_mul(mut a: u128, mut b: u128) -> u128 {
    let mut out = 0;
    for _ in 0..128 {
        if b & 1 != 0 {
            out ^= a;
        }
        b >>= 1;
        let high = a >> 127;
        a <<= 1;
        if high != 0 {
            a ^= 0x87;
        }
    }
    out
}
#[test]
fn flock_field_and_degree_eight_coefficients_match_independent_arithmetic() {
    let mut t = FsChallenger::new(b"arithmetic-tests");
    for _ in 0..32 {
        let a = t.sample_f128();
        let b = t.sample_f128();
        let x = t.sample_f128();
        assert_eq!(
            hash::integer(a * b),
            slow_mul(hash::integer(a), hash::integer(b))
        );
        let coeffs = math::seventh_line(a, b);
        for x in [F::ZERO, F::ONE, hash::field(2), x] {
            assert_eq!(math::poly_eval(&coeffs, x), hash::pow7(a + b * x));
        }
        let evals: Vec<_> = (0..8).map(|_| t.sample_f128()).collect();
        let p = t.sample_f128_vec(3);
        let sum = evals
            .iter()
            .zip(math::eq_table(&p))
            .fold(F::ZERO, |s, (&x, e)| s + x * e);
        assert_eq!(sum, math::evaluate(&evals, &p));
    }
}
#[test]
fn published_recipe_matches_independent_python_reference() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("reference-vectors.json")).unwrap();
    for r in 0..66 {
        for w in 0..4 {
            assert_eq!(
                hash::integer(hash::constants()[r][w]),
                u128::from_str_radix(data["round_constants"][r][w].as_str().unwrap(), 16).unwrap()
            );
        }
    }
    for case in data["hashes"].as_array().unwrap() {
        let message: [u8; 64] = from_hex(case["input"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            digest_bytes(hash::hash64(&message)).to_vec(),
            from_hex(case["digest"].as_str().unwrap())
        );
    }
}
fn rank(mut m: Vec<Vec<F>>) -> usize {
    let mut row = 0;
    for c in 0..m[0].len() {
        if let Some(p) = (row..m.len()).find(|&i| m[i][c] != F::ZERO) {
            m.swap(row, p);
            let inv = m[row][c].inv();
            for x in &mut m[row] {
                *x *= inv;
            }
            let pivot = m[row].clone();
            for (i, r) in m.iter_mut().enumerate() {
                if i != row {
                    let v = r[c];
                    for (x, &p) in r.iter_mut().zip(&pivot) {
                        *x += v * p;
                    }
                }
            }
            row += 1;
            if row == m.len() {
                break;
            }
        }
    }
    row
}
#[test]
fn ghash_basis_matrices_are_mds_invertible_and_observable() {
    let matrix = |external: bool| {
        let cols: Vec<_> = (0..4)
            .map(|j| {
                let mut e = [F::ZERO; 4];
                e[j] = F::ONE;
                if external {
                    hash::external(&mut e)
                } else {
                    hash::internal(&mut e)
                }
                e
            })
            .collect();
        (0..4)
            .map(|i| (0..4).map(|j| cols[j][i]).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    };
    let ext = matrix(true);
    let int = matrix(false);
    for a in 1u32..16 {
        for b in 1u32..16 {
            if a.count_ones() != b.count_ones() {
                continue;
            }
            let minor: Vec<Vec<F>> = (0..4)
                .filter(|i| a >> i & 1 == 1)
                .map(|i| {
                    (0..4)
                        .filter(|j| b >> j & 1 == 1)
                        .map(|j| ext[i][j])
                        .collect()
                })
                .collect();
            assert_eq!(rank(minor), a.count_ones() as usize);
        }
    }
    assert_eq!(rank(int.clone()), 4);
    let mut row = vec![F::ZERO; 4];
    row[0] = F::ONE;
    let mut observability = Vec::new();
    for _ in 0..4 {
        observability.push(row.clone());
        row = (0..4)
            .map(|j| (0..4).fold(F::ZERO, |s, i| s + row[i] * int[i][j]))
            .collect();
    }
    assert_eq!(rank(observability), 4);
    assert_eq!(u128::MAX % 7, 3); // x^7 is a permutation; x^5 is not.
    assert_eq!(u128::MAX % 5, 0);
}
#[test]
fn all_segment_boundaries_and_feed_forward_round_trip() {
    let messages: Vec<_> = (0..8)
        .map(|i| std::array::from_fn(|j| (17 * i + 13 * j) as u8))
        .collect();
    for segments in [1, 2, 4] {
        let backend = Backend::new(8, segments).unwrap();
        let witness = gkr::witness(&messages, segments).unwrap();
        let columns = witness.columns.clone();
        let (p, claims) = gkr::prove(witness, segments, &mut FsChallenger::new(b"test")).unwrap();
        assert_eq!(p.layers.len(), gkr::layer_count(segments));
        let vc = gkr::verify(&p, 3, segments, &mut FsChallenger::new(b"test")).unwrap();
        for (a, b) in claims.iter().zip(&vc) {
            assert_eq!(a.value, b.value);
            assert_eq!(a.value, math::evaluate(&columns[a.column], &a.point));
        }
        let (proof, _) = backend.prove(&messages).unwrap();
        backend.verify(&proof).unwrap();
        assert!(Backend::new(16, segments).unwrap().verify(&proof).is_err());
        for s in 0..segments {
            for w in 0..4 {
                let mut bad = proof.clone();
                bad.gkr.layers[gkr::layer_count(segments) - 1].inputs[s][w] += F::ONE;
                assert!(backend.verify(&bad).is_err());
            }
        }
        for c in 0..proof.gkr.outputs.len() {
            let mut bad = proof.clone();
            bad.gkr.outputs[c] += F::ONE;
            assert!(backend.verify(&bad).is_err());
        }
        for w in 0..2 {
            let mut bad = proof.clone();
            bad.gkr.feed_forward[w] += F::ONE;
            assert!(backend.verify(&bad).is_err());
        }
        for other in [1, 2, 4] {
            if other != segments {
                assert!(Backend::new(8, other).unwrap().verify(&proof).is_err());
            }
        }
        let mut bad = proof.clone();
        bad.gkr.layers[0].messages[0][0] += F::ONE;
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.gkr.layers.pop();
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.opening.final_proof.yr[0] += F::ONE;
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.opening.recursive_roots[0][0] ^= 1;
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.root[0] ^= 1;
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.opening.final_proof.yr.pop();
        assert!(backend.verify(&bad).is_err());
        let mut bad = proof.clone();
        bad.opening.recursive_roots.pop();
        assert!(backend.verify(&bad).is_err());
        let bytes = bincode::serialize(&proof).unwrap();
        let decoded = bincode::deserialize(&bytes).unwrap();
        backend.verify(&decoded).unwrap();
    }
}
#[test]
fn feed_forward_is_required_and_every_real_round_is_constrained() {
    let messages: Vec<_> = (0..8)
        .map(|i| std::array::from_fn(|j| (17 * i + 13 * j) as u8))
        .collect();
    for segments in [1, 2, 4] {
        let mut schedule: Vec<_> = (0..segments)
            .flat_map(|s| {
                (0..gkr::layer_count(segments)).filter_map(move |d| gkr::round_at(segments, s, d))
            })
            .collect();
        schedule.sort_unstable();
        assert_eq!(schedule, (0..66).collect::<Vec<_>>());
        let mut witness = gkr::witness(&messages, segments).unwrap();
        for w in 0..2 {
            witness.columns[4 * segments + w] = witness.trace[66][w].clone();
        }
        assert!(
            gkr::prove(
                witness,
                segments,
                &mut FsChallenger::new(b"missing-feed-forward")
            )
            .is_err()
        );
        for checkpoint in 1..segments {
            let mut witness = gkr::witness(&messages, segments).unwrap();
            let boundary = gkr::boundary(segments, checkpoint);
            witness.trace[boundary][0][0] += F::ONE;
            // Propagate after a broken transition and update every committed boundary.
            for r in boundary..66 {
                for i in 0..8 {
                    let state = hash::round(r, std::array::from_fn(|w| witness.trace[r][w][i]));
                    for w in 0..4 {
                        witness.trace[r + 1][w][i] = state[w];
                    }
                }
            }
            for s in 0..segments {
                for w in 0..4 {
                    witness.columns[4 * s + w] =
                        witness.trace[gkr::boundary(segments, s)][w].clone();
                }
            }
            for w in 0..2 {
                witness.columns[4 * segments + w] = witness.trace[66][w]
                    .iter()
                    .zip(&witness.trace[0][w])
                    .map(|(&x, &y)| x + y)
                    .collect();
            }
            assert!(
                gkr::prove(
                    witness,
                    segments,
                    &mut FsChallenger::new(b"broken-boundary")
                )
                .is_err()
            );
        }
    }
}

#[test]
fn parallel_and_serial_proofs_are_identical_across_scheduling_thresholds() {
    let messages: Vec<_> = (0..128).map(hash::dataset).collect();
    let backend = Backend::new(128, 4).unwrap();
    let run = |threads| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| backend.prove(&messages).unwrap().0)
    };
    let serial = run(1);
    let parallel = run(4);
    backend.verify(&serial).unwrap();
    backend.verify(&parallel).unwrap();
    assert_eq!(
        bincode::serialize(&serial).unwrap(),
        bincode::serialize(&parallel).unwrap()
    );
}
