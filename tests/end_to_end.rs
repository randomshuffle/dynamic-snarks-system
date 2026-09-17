//! Full initialize/update/verify tests for the public dynamic-SNARK API.

use dynamic_snarks_system::Field;
use dynamic_snarks_system::circuit::Circuit;
use dynamic_snarks_system::dynamic::{index, initialize, update, verify};
use p3_field::PrimeCharacteristicRing;

#[test]
fn initialize_update_and_verify_end_to_end() {
    let circuit = Circuit::new(1, 1, (0..7).collect()).unwrap();
    let assignment = [1, 2, 3, 3, 4, 12, 9].map(Field::from_u64).to_vec();
    let (proving_key, verifying_key) = index(circuit).unwrap();
    assert_eq!(proving_key.initial_preprocessed_width(), 4);
    assert_eq!(verifying_key.initial_preprocessed_width(), 4);
    let mut state = initialize(&proving_key, assignment).unwrap();

    update(
        &proving_key,
        &mut state,
        &[
            (0, Field::from_u64(5)),
            (1, Field::from_u64(6)),
            (2, Field::from_u64(11)),
        ],
    )
    .unwrap();

    assert_eq!(state.current_assignment()[2], Field::from_u64(11));
    verify(&verifying_key, &[Field::from_u64(9)], state.proof()).unwrap();
    assert!(verify(&verifying_key, &[Field::from_u64(10)], state.proof()).is_err());
}

#[test]
fn non_power_of_two_transition_updates_gate_and_public_input() {
    let n = 3;
    let n0 = 2;
    let m = 6 * n + n0;
    let circuit = Circuit::new(n, n0, (0..m).collect()).unwrap();
    let mut assignment = vec![Field::ZERO; m];
    for pair in 0..n {
        assignment[6 * pair] = Field::from_usize(pair + 2);
        assignment[6 * pair + 1] = Field::from_usize(pair + 3);
        assignment[6 * pair + 2] = assignment[6 * pair] + assignment[6 * pair + 1];
        assignment[6 * pair + 3] = Field::from_usize(pair + 4);
        assignment[6 * pair + 4] = Field::from_usize(pair + 5);
        assignment[6 * pair + 5] = assignment[6 * pair + 3] * assignment[6 * pair + 4];
    }
    let (proving_key, verifying_key) = index(circuit).unwrap();
    let mut state = initialize(&proving_key, assignment).unwrap();
    update(
        &proving_key,
        &mut state,
        &[
            (0, Field::from_u64(9)),
            (1, Field::from_u64(10)),
            (2, Field::from_u64(19)),
            (18, Field::from_u64(77)),
        ],
    )
    .unwrap();
    verify(
        &verifying_key,
        &[Field::from_u64(77), Field::ZERO],
        state.proof(),
    )
    .unwrap();

    update(&proving_key, &mut state, &[(18, Field::from_u64(88))]).unwrap();
    verify(
        &verifying_key,
        &[Field::from_u64(88), Field::ZERO],
        state.proof(),
    )
    .unwrap();

    update(
        &proving_key,
        &mut state,
        &[
            (3, Field::from_u64(7)),
            (4, Field::from_u64(8)),
            (5, Field::from_u64(56)),
        ],
    )
    .unwrap();
    verify(
        &verifying_key,
        &[Field::from_u64(88), Field::ZERO],
        state.proof(),
    )
    .unwrap();

    let error = update(
        &proving_key,
        &mut state,
        &[(6, Field::ONE), (7, Field::ONE)],
    )
    .unwrap_err();
    assert!(error.to_string().contains("not closed"));
}

#[test]
fn aligned_tree_preserves_nontrivial_wiring_and_reorders_mixed_updates() {
    // This shape needs 64 physical leaves, versus 32 for the previous dense encoding.
    let mut sigma = (0..31).collect::<Vec<_>>();
    sigma[2] = 6;
    sigma[6] = 30;
    sigma[30] = 2;
    let circuit = Circuit::new(5, 1, sigma).unwrap();
    let mut z = [1, 2, 3, 4, 5, 20].repeat(5);
    z[6] = 3;
    z[8] = 5;
    z.push(3);
    let z = z.into_iter().map(Field::from_u64).collect::<Vec<_>>();
    let (pk, vk) = index(circuit).unwrap();
    assert_eq!(pk.initial_trace_len(), 16);
    let mut state = initialize(&pk, z.clone()).unwrap();
    verify(&vk, &[Field::from_u64(3)], state.proof()).unwrap();
    assert_eq!(state.current_commitment().len, 64);

    let updates = [(0, 2), (1, 3), (2, 5), (6, 5), (7, 2), (8, 7), (30, 5)]
        .map(|(index, value)| (index, Field::from_u64(value)));
    update(&pk, &mut state, &updates).unwrap();
    verify(&vk, &[Field::from_u64(5)], state.proof()).unwrap();
    assert!(verify(&vk, &[Field::from_u64(3)], state.proof()).is_err());

    // Independently rebuild the specified four-column table and its Merkle root.
    let z = state.current_assignment();
    let mut table = vec![Field::ZERO; 64];
    for row in 0..10 {
        table[4 * row..4 * row + 3].copy_from_slice(&z[3 * row..3 * row + 3]);
    }
    table[3] = z[30];
    let expected = dynamic_snarks_system::merkle::MerkleTree::new(table).unwrap();
    assert_eq!(state.current_commitment(), expected.commitment());
}
