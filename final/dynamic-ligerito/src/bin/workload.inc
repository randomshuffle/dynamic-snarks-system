//! Reproducible gate-closed workloads shared by the benchmark and its validation.

use dynamic_ligerito_experiment::Field;

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::index::sample;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pattern {
    Random,
    Contiguous,
}

impl Pattern {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "random" => Ok(Self::Random),
            "contiguous" => Ok(Self::Contiguous),
            _ => Err("DYNAMIC_SNARK_UPDATE_PATTERN must be random or contiguous"),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Random => "fresh uniform gate subset without replacement on every revision",
            Self::Contiguous => "the same contiguous prefix of gates on every revision",
        }
    }
}

pub fn revisions(
    gate_count: usize,
    changed_gates: usize,
    sequence_len: usize,
    seed: u64,
    pattern: Pattern,
) -> Vec<Vec<(usize, Field)>> {
    assert!(changed_gates > 0 && changed_gates <= gate_count);
    let mut rng = StdRng::seed_from_u64(seed);
    (1..=sequence_len)
        .map(|revision| {
            let mut gates = match pattern {
                Pattern::Random => sample(&mut rng, gate_count, changed_gates).into_vec(),
                Pattern::Contiguous => (0..changed_gates).collect(),
            };
            gates.sort_unstable();
            let mut updates = Vec::with_capacity(3 * changed_gates);
            for gate in gates {
                let pair = gate / 2;
                let is_multiplication = gate % 2 == 1;
                let start = 3 * gate;
                // Preserve the previous workload's values; only positions change.
                // Revision-dependent left values ensure every selected gate changes,
                // including gates sampled again after an intervening revision.
                let left = Field::from_usize(pair + revision + 1 + usize::from(is_multiplication));
                let right = Field::from_u64(2);
                let output = if is_multiplication {
                    left * right
                } else {
                    left + right
                };
                updates.extend([(start, left), (start + 1, right), (start + 2, output)]);
            }
            updates
        })
        .collect()
}

pub fn fingerprint(revisions: &[Vec<(usize, Field)>]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"dynamic-snark-update-positions-v1");
    hash.update(&(revisions.len() as u64).to_le_bytes());
    for revision in revisions {
        hash.update(&(revision.len() as u64).to_le_bytes());
        for &(index, _) in revision {
            hash.update(&(index as u64).to_le_bytes());
        }
    }
    hash.finalize().to_hex().to_string()
}

/// Final hierarchy supports, each containing all earlier supports merged into it.
/// Buckets are indexed by floor(log2(size)); this is the reverse of the
/// prover's level numbering. Values do not affect its union-based composition.
pub fn maximal_composed_supports(revisions: &[Vec<(usize, Field)>]) -> Vec<Vec<usize>> {
    let mut buckets = BTreeMap::<u32, BTreeSet<usize>>::new();
    for revision in revisions {
        let mut incoming = revision
            .iter()
            .map(|&(index, _)| index)
            .collect::<BTreeSet<_>>();
        loop {
            let bucket = incoming.len().ilog2();
            let affected = buckets
                .range(..=bucket)
                .map(|(&key, _)| key)
                .collect::<Vec<_>>();
            if affected.is_empty() {
                buckets.insert(bucket, incoming);
                break;
            }
            for key in affected {
                incoming.extend(buckets.remove(&key).unwrap());
            }
        }
    }
    buckets
        .into_values()
        .map(|indices| indices.into_iter().collect())
        .collect()
}
