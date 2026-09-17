//! Exact transcript/proof equivalence across Rayon pool sizes.

#![cfg(feature = "parallel")]

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic, static_snark};
use p3_field::PrimeCharacteristicRing;

fn proofs(threads: usize) -> Vec<Vec<u8>> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(|| {
            let gates = 64;
            let circuit = Circuit::new(gates / 2, 8, (0..3 * gates + 8).collect()).unwrap();
            let mut assignment = Vec::new();
            for pair in 0..gates / 2 {
                let a = Field::from_usize(pair + 1);
                let b = Field::from_u64(2);
                assignment.extend([a, b, a + b, a, b, a * b]);
            }
            let mut public = vec![Field::from_u64(9); 8];
            assignment.extend_from_slice(&public);
            let (pk, vk) = dynamic::index(circuit.clone()).unwrap();
            let mut state = dynamic::initialize(&pk, assignment.clone()).unwrap();
            dynamic::verify(&vk, &public, state.proof()).unwrap();
            let mut result = vec![serde_json::to_vec(state.proof()).unwrap()];
            // A public leaf followed by distinct full gate tuples exercises hierarchy merges.
            for update in [
                vec![(3 * gates, Field::from_u64(10))],
                vec![
                    (0, Field::from_u64(4)),
                    (1, Field::from_u64(5)),
                    (2, Field::from_u64(9)),
                ],
                vec![
                    (3, Field::from_u64(7)),
                    (4, Field::from_u64(8)),
                    (5, Field::from_u64(56)),
                ],
            ] {
                for &(index, value) in &update {
                    assignment[index] = value;
                    if index >= 3 * gates {
                        public[index - 3 * gates] = value;
                    }
                }
                dynamic::update(&pk, &mut state, &update).unwrap();
                dynamic::verify(&vk, &public, state.proof()).unwrap();
                result.push(serde_json::to_vec(state.proof()).unwrap());
                let program = dynamic::regular_hyperplonk_program(&circuit, &assignment).unwrap();
                let (baseline_pk, baseline_vk) = static_snark::setup(&program).unwrap();
                let proof = static_snark::prove(&baseline_pk, &program, &public).unwrap();
                static_snark::verify(&baseline_vk, &public, &proof).unwrap();
                result.push(serde_json::to_vec(&proof).unwrap());
            }
            result
        })
}

#[test]
fn initial_update_and_baseline_proofs_are_identical_with_1_8_and_96_workers() {
    let serial = proofs(1);
    for threads in [8, 96] {
        assert_eq!(
            proofs(threads),
            serial,
            "proof changed with {threads} workers"
        );
    }
}
