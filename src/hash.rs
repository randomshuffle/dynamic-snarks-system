//! Domain-separated Poseidon2 hashing over BN254.

use p3_bn254::{
    BN254_POSEIDON2_HALF_FULL_ROUNDS, BN254_POSEIDON2_PARTIAL_ROUNDS_3, Bn254, Poseidon2Bn254,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::Permutation;
use rand::RngExt;
use rand::SeedableRng;
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;

/// A 32-byte-encoded, single-field-element Poseidon2 digest.
pub type Digest = Bn254;

const PARAMETER_SEED: u64 = 0x4459_4e53_4e41_524b;
const LEAF_DOMAIN: u64 = 1;
const NODE_DOMAIN: u64 = 2;
const ROOT_DOMAIN: u64 = 3;

/// Deterministic BN254 Poseidon2 parameters used throughout this crate.
///
/// Plonky3's BN254 instantiation has width three, eight full rounds, and 56
/// partial rounds, matching its 128-bit-security parameter set. A fixed seed
/// makes the public parameters reproducible.
#[must_use]
pub fn poseidon2() -> Poseidon2Bn254<3> {
    let (external, internal) = poseidon2_constants();
    Poseidon2Bn254::<3>::new(external, internal)
}

/// Recreate the fixed round constants used by [`poseidon2`].
#[must_use]
pub fn poseidon2_constants() -> (ExternalLayerConstants<Bn254, 3>, Vec<Bn254>) {
    let mut rng = SmallRng::seed_from_u64(PARAMETER_SEED);
    let external =
        ExternalLayerConstants::new_from_rng(2 * BN254_POSEIDON2_HALF_FULL_ROUNDS, &mut rng);
    let internal = rng
        .sample_iter(StandardUniform)
        .take(BN254_POSEIDON2_PARTIAL_ROUNDS_3)
        .collect();
    (external, internal)
}

/// Hash a vector element into a position-bound Merkle leaf.
pub fn hash_leaf(index: usize, value: Bn254) -> Digest {
    permute_first([
        value,
        Bn254::from_usize(index),
        Bn254::from_u64(LEAF_DOMAIN),
    ])
}

/// Compress two children at a specified Merkle level.
pub fn hash_node(level: usize, left: Digest, right: Digest) -> Digest {
    permute_first([
        left,
        right,
        Bn254::from_u64(NODE_DOMAIN) + Bn254::from_usize(level),
    ])
}

/// Bind two subtree roots and their logical lengths into one vector root.
pub fn hash_roots(left_len: usize, left: Digest, right_len: usize, right: Digest) -> Digest {
    let lengths = Bn254::from_usize(left_len) + Bn254::from_usize(right_len).double();
    permute_first([left, right, Bn254::from_u64(ROOT_DOMAIN) + lengths])
}

#[inline]
fn permute_first(mut state: [Bn254; 3]) -> Bn254 {
    poseidon2().permute_mut(&mut state);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_deterministic_and_domain_separated() {
        let value = Bn254::from_u64(7);
        assert_eq!(hash_leaf(3, value), hash_leaf(3, value));
        assert_ne!(hash_leaf(3, value), hash_leaf(4, value));
        assert_ne!(hash_node(1, value, value), hash_leaf(1, value));
        assert_ne!(hash_node(1, value, value), hash_node(2, value, value));
    }
}
