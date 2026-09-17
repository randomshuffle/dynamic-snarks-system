//! Check the benchmark's random workloads against the actual dynamic prover.

#[path = "../benches/support/update_workload.rs"]
mod update_workload;

use std::collections::BTreeSet;

use dynamic_snarks_system::{Field, circuit::Circuit, dynamic};
use p3_field::PrimeCharacteristicRing;
use update_workload::{Pattern, fingerprint, maximal_composed_supports, revisions};

#[test]
fn seeded_random_updates_remain_valid_through_hierarchy_compositions() {
    let gates = 32;
    let count = 4;
    let seed = 20_260_909;
    let workload = revisions(gates, count, 8, seed, Pattern::Random);
    assert_eq!(workload, revisions(gates, count, 8, seed, Pattern::Random));
    assert_ne!(
        fingerprint(&workload),
        fingerprint(&revisions(gates, count, 8, seed + 1, Pattern::Random))
    );
    assert_eq!(Pattern::parse("random").unwrap(), Pattern::Random);
    assert!(Pattern::parse("invalid").is_err());
    assert!(!Pattern::Random.label().is_empty());
    let circuit = Circuit::new(gates / 2, 1, (0..3 * gates + 1).collect()).unwrap();
    let mut values = vec![Field::ZERO; circuit.assignment_len()];
    values[3 * gates] = Field::from_u64(9);
    let (pk, vk) = dynamic::index(circuit.clone()).unwrap();
    let mut state = dynamic::initialize(&pk, values.clone()).unwrap();
    let mut visited = BTreeSet::new();
    let maximal = maximal_composed_supports(&workload);
    // Every prefix's live supports must fit within a final support, so their
    // authentication DAGs are bounded by the benchmark's memory preflight.
    for length in 1..=workload.len() {
        for support in maximal_composed_supports(&workload[..length]) {
            assert!(maximal.iter().any(|bound| {
                support
                    .iter()
                    .all(|index| bound.binary_search(index).is_ok())
            }));
        }
    }
    for batch in &workload {
        assert_eq!(batch.len(), 3 * count);
        let indices = batch.iter().map(|&(index, _)| index).collect::<Vec<_>>();
        assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
        circuit.check_update_indices(&indices).unwrap();
        for &(index, value) in batch {
            assert!(index < 3 * gates);
            values[index] = value;
            visited.insert(index / 3);
        }
        circuit.check_assignment(&values).unwrap();
        dynamic::update(&pk, &mut state, batch).unwrap();
        dynamic::verify(&vk, &[Field::from_u64(9)], state.proof()).unwrap();
        assert_eq!(state.current_assignment(), values);
    }
    assert!(visited.len() > 3 * count);
    assert!(workload.windows(2).all(|pair| {
        pair[0]
            .iter()
            .map(|&(i, _)| i)
            .ne(pair[1].iter().map(|&(i, _)| i))
    }));

    let contiguous = revisions(gates, count, 2, seed, Pattern::Contiguous);
    for batch in contiguous {
        assert!(batch.iter().map(|&(index, _)| index).eq(0..3 * count));
    }
    assert_eq!(
        maximal_composed_supports(&revisions(gates, count, 8, seed, Pattern::Contiguous)),
        vec![(0..3 * count).collect::<Vec<_>>()]
    );
}
