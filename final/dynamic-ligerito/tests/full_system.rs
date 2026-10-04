use dynamic_ligerito_experiment::{Field as F, circuit::Circuit, dynamic, static_snark};
fn fixture(n: usize, public: usize, copy: bool) -> (Circuit, Vec<F>) {
    let m = 6 * n + public;
    let mut sigma: Vec<_> = (0..m).collect();
    if copy {
        sigma.swap(1, 4);
    }
    let c = Circuit::new(n, public, sigma).unwrap();
    let mut z = Vec::new();
    for i in 0..n {
        let a = F::from_usize(i + 3);
        let b = F::TWO;
        z.extend([a, b, a + b, a, b, a * b]);
    }
    z.extend(vec![F::from_u64(9); public]);
    (c, z)
}
#[test]
fn arithmetic_baseline_roundtrip_copy_and_public() {
    for (n, p, copy) in [(2, 1, false), (11, 5, true)] {
        let (c, z) = fixture(n, p, copy);
        let program = dynamic::regular_hyperplonk_program(&c, &z).unwrap();
        let (pk, vk) = static_snark::setup(&program).unwrap();
        let public = vec![F::from_u64(9); p];
        let proof = static_snark::prove(&pk, &program, &public).unwrap();
        static_snark::verify(&vk, &public, &proof).unwrap();
        let mut bad = public;
        bad[0] += F::ONE;
        assert!(static_snark::verify(&vk, &bad, &proof).is_err());
    }
}
#[test]
fn initialization_and_twelve_composed_updates() {
    for (n, p, copy) in [(2, 1, false), (11, 5, true)] {
        let (c, z) = fixture(n, p, copy);
        let (pk, vk) = dynamic::index(c).unwrap();
        let mut state = dynamic::initialize(&pk, z).unwrap();
        let mut public = vec![F::from_u64(9); p];
        dynamic::verify(&vk, &public, state.proof()).unwrap();
        for revision in 1..=12 {
            let a = F::from_usize(revision + 8);
            let start = 3 * (revision % (2 * n));
            let out = if start / 3 % 2 == 0 {
                a + F::TWO
            } else {
                a * F::TWO
            };
            let update = vec![(start, a), (start + 1, F::TWO), (start + 2, out)];
            dynamic::update(&pk, &mut state, &update).unwrap();
            dynamic::verify(&vk, &public, state.proof()).unwrap();
            let stats = state.proof().oracle_statistics();
            let plain = stats["total_plaintext_bytes"].as_u64().unwrap();
            assert!(plain <= stats["other_proof_bytes"].as_u64().unwrap());
            assert_eq!(
                plain + stats["other_proof_bytes"].as_u64().unwrap(),
                bincode::serialized_size(state.proof()).unwrap()
            );
        }
        public[0] += F::ONE;
        assert!(dynamic::verify(&vk, &public, state.proof()).is_err());
        let index = 6 * n;
        dynamic::update(&pk, &mut state, &[(index, public[0])]).unwrap();
        dynamic::verify(&vk, &public, state.proof()).unwrap();
    }
}

#[test]
fn trusted_transition_payload_obeys_its_own_plaintext_budget() {
    let (c, z) = fixture(11, 5, true);
    let (pk, vk) = dynamic::index(c).unwrap();
    let mut state = dynamic::initialize_transition_benchmark(&pk, z).unwrap();
    for revision in 1..=12 {
        let a = F::from_usize(revision + 8);
        dynamic::update_transition_benchmark(
            &pk,
            &mut state,
            &[(0, a), (1, F::TWO), (2, a + F::TWO)],
        )
        .unwrap();
        dynamic::verify_transition_benchmark(&vk, &[F::from_u64(9); 5], &state).unwrap();
        let encoded = bincode::serialize(&state.proof_payload()).unwrap();
        let decoded = bincode::deserialize(&encoded).unwrap();
        dynamic::verify_transition_benchmark_proof(&vk, &[F::from_u64(9); 5], &decoded).unwrap();
    }
}

#[test]
fn mixed_checkpoint_counts_preserve_the_transition_chain() {
    let (c, z) = fixture(11, 5, true);
    let (pk, vk) = dynamic::index_with_plaintext_cap(c, 0).unwrap();
    let mut state = dynamic::initialize(&pk, z).unwrap();
    let public = vec![F::from_u64(9); 5];
    let before = bincode::serialize(state.proof()).unwrap();
    assert!(dynamic::update_with_hash_checkpoints(&pk, &mut state, &[(0, F::ONE)], 2).is_err());
    assert_eq!(bincode::serialize(state.proof()).unwrap(), before);
    for revision in 1..=12 {
        let a = F::from_usize(revision + 8);
        let update = [(0, a), (1, F::TWO), (2, a + F::TWO)];
        let checkpoints = [1, 3, 7][(revision - 1) % 3];
        dynamic::update_with_hash_checkpoints(&pk, &mut state, &update, checkpoints).unwrap();
        dynamic::verify(&vk, &public, state.proof()).unwrap();
        let decoded: dynamic::Proof =
            bincode::deserialize(&bincode::serialize(state.proof()).unwrap()).unwrap();
        dynamic::verify(&vk, &public, &decoded).unwrap();
    }
}

#[test]
fn direct_tail_accumulates_without_lower_proofs_and_promotes_on_overflow() {
    let (c, z) = fixture(64, 5, true);
    let cap = 2048;
    let (pk, vk) = dynamic::index_with_plaintext_cap(c.clone(), cap).unwrap();
    let mut state = dynamic::initialize(&pk, z.clone()).unwrap();
    let mut expected = z;
    let mut public = vec![F::from_u64(9); 5];
    let mut directs = 0;
    let mut promotions = 0;
    let mut upper_merge = false;
    for revision in 1..=48 {
        let gate = (revision * 17) % 128;
        let a = F::from_usize(100 + revision);
        let mut u = vec![
            (3 * gate, a),
            (3 * gate + 1, F::TWO),
            (
                3 * gate + 2,
                if gate % 2 == 0 {
                    a + F::TWO
                } else {
                    a * F::TWO
                },
            ),
        ];
        if revision % 7 == 0 {
            public[0] += F::ONE;
            u.push((6 * 64, public[0]));
        }
        for &(i, v) in &u {
            expected[i] = v;
        }
        let expected_credit = state.proof().oracle_statistics()["other_proof_bytes"]
            .as_u64()
            .unwrap();
        dynamic::update(&pk, &mut state, &u).unwrap();
        dynamic::verify(&vk, &public, state.proof()).unwrap();
        assert_eq!(state.current_assignment(), expected);
        let stat = state.last_update_statistics().unwrap();
        assert_eq!(stat.plaintext_credit_bytes, expected_credit);
        let proof = state.proof().oracle_statistics();
        assert!(proof["total_plaintext_bytes"].as_u64().unwrap() <= cap as u64);
        if stat.mode == "direct" {
            assert_eq!(proof["other_proof_bytes"], expected_credit);
            directs += 1;
            assert!(stat.candidate_plaintext_bytes <= cap);
            assert_eq!(stat.polynomial_gates, 0);
            if promotions == 0 {
                assert_eq!(proof["transition_oracles"].as_array().unwrap().len(), 0);
            }
        } else {
            promotions += 1;
            assert!(stat.candidate_plaintext_bytes > cap);
            assert!(proof["direct_tail"].is_null());
            assert_eq!(proof["total_plaintext_bytes"], 0);
            upper_merge |= stat.polynomial_gates > stat.candidate_gates;
        }
        let decoded: dynamic::Proof =
            bincode::deserialize(&bincode::serialize(state.proof()).unwrap()).unwrap();
        dynamic::verify(&vk, &public, &decoded).unwrap();
    }
    assert!(directs > 0 && promotions > 2 && upper_merge);
    // Repeated writes to one gate must stay one direct tail, not force merges
    // based on the revision counter rather than distinct updated positions.
    let (pk, vk) = dynamic::index_with_plaintext_cap(c, 64 * 1024).unwrap();
    let (_, initial) = fixture(64, 5, true);
    let mut state = dynamic::initialize(&pk, initial).unwrap();
    for revision in 0..24 {
        let a = F::from_usize(revision + 10);
        dynamic::update(&pk, &mut state, &[(0, a), (1, F::TWO), (2, a + F::TWO)]).unwrap();
        assert_eq!(state.last_update_statistics().unwrap().candidate_gates, 1);
        assert_eq!(state.last_update_statistics().unwrap().mode, "direct");
        assert!(
            state.proof().oracle_statistics()["transition_oracles"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        dynamic::verify(&vk, &[F::from_u64(9); 5], state.proof()).unwrap();
    }
}

#[test]
fn radix_hierarchies_prove_multiple_slots_carries_and_reject_wrong_geometry() {
    let (c, initial) = fixture(64, 5, true);
    let public = [F::from_u64(9); 5];
    for base in [2, 4, 8] {
        let (pk, vk) = dynamic::index_with_hierarchy(c.clone(), 0, base).unwrap();
        let (_, wrong_vk) =
            dynamic::index_with_hierarchy(c.clone(), 0, if base == 8 { 4 } else { 8 }).unwrap();
        let mut state = dynamic::initialize(&pk, initial.clone()).unwrap();
        let mut saw_full_level = false;
        let mut saw_merge = false;
        for revision in 1..=32 {
            let gate = (revision * 17) % 128;
            let left = F::from_usize(200 + revision);
            let output = if gate % 2 == 0 {
                left + F::TWO
            } else {
                left * F::TWO
            };
            dynamic::update(
                &pk,
                &mut state,
                &[
                    (3 * gate, left),
                    (3 * gate + 1, F::TWO),
                    (3 * gate + 2, output),
                ],
            )
            .unwrap();
            dynamic::verify(&vk, &public, state.proof()).unwrap();
            let encoded = bincode::serialize(state.proof()).unwrap();
            let decoded: dynamic::Proof = bincode::deserialize(&encoded).unwrap();
            dynamic::verify(&vk, &public, &decoded).unwrap();
            assert!(dynamic::verify(&wrong_vk, &public, &decoded).is_err());
            let statistics = state.proof().oracle_statistics();
            let mut counts = vec![0; pk.hierarchy_levels()];
            for transition in statistics["transition_oracles"].as_array().unwrap() {
                counts[transition["level"].as_u64().unwrap() as usize / (base - 1)] += 1;
            }
            assert!(counts.iter().all(|&n| n <= base - 1));
            saw_full_level |= counts.contains(&(base - 1));
            saw_merge |= state.last_update_statistics().unwrap().polynomial_gates > 1;
        }
        assert!(saw_full_level && saw_merge);
    }
}

#[test]
fn thirty_two_gate_updates_follow_nonidentity_wiring() {
    let n = 32;
    let public = 5;
    let mut sigma: Vec<_> = (0..6 * n + public).collect();
    // Two independent cycles through the left inputs of 32 gates.
    for block in [0, 32] {
        for i in 0..32 {
            sigma[3 * (block + i)] = 3 * (block + (i + 1) % 32);
        }
    }
    let c = Circuit::new(n, public, sigma).unwrap();
    let mut z = Vec::new();
    for gate in 0..2 * n {
        let a = F::from_u64(9);
        z.extend([
            a,
            F::TWO,
            if gate % 2 == 0 {
                a + F::TWO
            } else {
                a * F::TWO
            },
        ]);
    }
    z.extend(vec![F::from_u64(9); public]);
    let (pk, vk) = dynamic::index(c).unwrap();
    let mut state = dynamic::initialize(&pk, z).unwrap();
    for revision in 1..=3 {
        let a = F::from_usize(20 + revision);
        let mut u = Vec::new();
        for gate in 0..32 {
            u.extend([
                (3 * gate, a),
                (3 * gate + 1, F::TWO),
                (
                    3 * gate + 2,
                    if gate % 2 == 0 {
                        a + F::TWO
                    } else {
                        a * F::TWO
                    },
                ),
            ]);
        }
        dynamic::update(&pk, &mut state, &u).unwrap();
        dynamic::verify(&vk, &vec![F::from_u64(9); public], state.proof()).unwrap();
        let stats = state.proof().oracle_statistics();
        assert!(
            stats["total_plaintext_bytes"].as_u64().unwrap() * 2
                <= stats["total_serialized_bytes"].as_u64().unwrap()
        );
    }
}
