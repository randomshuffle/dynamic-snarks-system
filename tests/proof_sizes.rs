//! Audit payload counts and verify proofs after binary serialization.

#[path = "../benches/support/proof_size.rs"]
mod proof_size;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic, static_snark};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

#[test]
fn counts_fields_roots_paths_and_serialization_framing() {
    #[derive(Serialize, Deserialize)]
    struct Fixture {
        claim: Field,
        root: Field,
        cap: Vec<[u8; 32]>,
        proof: Vec<[u8; 32]>,
        index: usize,
    }
    let fixture = Fixture {
        claim: Field::ONE,
        root: Field::from_u64(8),
        cap: vec![[9; 32]],
        proof: vec![[200; 32]],
        index: 65536,
    };
    let encoded = proof_size::encode(&fixture).unwrap();
    assert_eq!(encoded.metrics.field_elements, 2);
    assert_eq!(encoded.metrics.poseidon_hashes, 1);
    assert_eq!(encoded.metrics.blake3_hashes, 2);
    assert_eq!(encoded.metrics.payload_bytes(), 128);
    assert!(encoded.metrics.overhead_bytes() > 0);
    assert_eq!(encoded.metrics.serialized_bytes, encoded.bytes.len());
    assert_eq!(
        encoded
            .components
            .iter()
            .map(|(_, m)| m.serialized_bytes)
            .sum::<usize>(),
        encoded.bytes.len()
    );
    let recovered: Fixture = proof_size::decode(&encoded.bytes).unwrap();
    assert_eq!(recovered.claim, fixture.claim);
    assert_eq!(recovered.proof, fixture.proof);
    assert_eq!(recovered.index, fixture.index);
    let mut trailing = encoded.bytes.clone();
    trailing.push(0);
    assert!(proof_size::decode::<Fixture>(&trailing).is_err());
}

#[test]
fn complete_baseline_initial_and_fortieth_update_round_trip_drops_composed_levels() {
    let circuit = Circuit::new(8, 1, (0..49).collect()).unwrap();
    let (pk, vk) = dynamic::index(circuit.clone()).unwrap();
    let mut state = dynamic::initialize(&pk, vec![Field::ZERO; 49]).unwrap();
    let initial = proof_size::encode(state.proof()).unwrap();
    let decoded: dynamic::Proof = proof_size::decode(&initial.bytes).unwrap();
    dynamic::verify(&vk, &[Field::ZERO], &decoded).unwrap();
    for revision in 1usize..=40 {
        let left = Field::from_usize(revision);
        // Cycle through sixteen distinct gates. At revisions 4, 8, 16, ...,
        // several occupied levels collapse into one composed transition.
        let gate = (revision - 1) % 16;
        let start = 3 * gate;
        let output = if gate % 2 == 0 {
            left + Field::ONE
        } else {
            left
        };
        dynamic::update(
            &pk,
            &mut state,
            &[(start, left), (start + 1, Field::ONE), (start + 2, output)],
        )
        .unwrap();
        let encoded = proof_size::encode(state.proof()).unwrap();
        let value: ciborium::Value = ciborium::from_reader(encoded.bytes.as_slice()).unwrap();
        let transitions = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| key.as_text() == Some("transition_proofs"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(transitions.len(), circuit.hierarchy_depth());
        let occupied = transitions
            .iter()
            .enumerate()
            .filter_map(|(level, value)| (!value.is_null()).then_some(level))
            .collect::<Vec<_>>();
        // Three positions per gate: partial blocks of 1, 2, 4, 8 gates
        // occupy indices 4, 3, 2, 1; a full block of 16 occupies index 0.
        let mut expected = Vec::new();
        if revision >= 16 {
            expected.push(0);
        }
        for bit in (0..4).rev() {
            if (revision % 16) & (1 << bit) != 0 {
                expected.push(4 - bit);
            }
        }
        assert_eq!(
            occupied, expected,
            "stale or missing proof at revision {revision}"
        );
        let decoded: dynamic::Proof = proof_size::decode(&encoded.bytes).unwrap();
        dynamic::verify(&vk, &[Field::ZERO], &decoded).unwrap();
    }
    let updated = proof_size::encode(state.proof()).unwrap();
    let decoded: dynamic::Proof = proof_size::decode(&updated.bytes).unwrap();
    dynamic::verify(&vk, &[Field::ZERO], &decoded).unwrap();
    assert!(updated.metrics.serialized_bytes > initial.metrics.serialized_bytes);
    for name in ["initial_proof", "initial_cair"] {
        let component =
            |p: &proof_size::EncodedProof| p.components.iter().find(|(n, _)| n == name).unwrap().1;
        assert_eq!(
            component(&initial).serialized_bytes,
            component(&updated).serialized_bytes
        );
        assert!(component(&updated).payload_bytes() > 0);
    }
    assert!(
        updated
            .components
            .iter()
            .find(|(n, _)| n == "transition_proofs")
            .unwrap()
            .1
            .payload_bytes()
            > 0
    );
    let program =
        dynamic::regular_hyperplonk_program(&circuit, state.current_assignment()).unwrap();
    let (baseline_pk, baseline_vk) = static_snark::setup(&program).unwrap();
    let baseline = static_snark::prove(&baseline_pk, &program, &[Field::ZERO]).unwrap();
    let encoded = proof_size::encode(&baseline).unwrap();
    let decoded: static_snark::Proof = proof_size::decode(&encoded.bytes).unwrap();
    static_snark::verify(&baseline_vk, &[Field::ZERO], &decoded).unwrap();
    assert!(encoded.metrics.field_elements > 0);
    assert!(encoded.metrics.blake3_hashes > 0);
    assert_eq!(
        serde_json::to_vec(&baseline).unwrap(),
        serde_json::to_vec(&decoded).unwrap()
    );
}
