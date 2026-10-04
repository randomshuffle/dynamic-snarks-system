//! Fixed-shape 64-byte Poseidon2b compression. Two GF128 words per digest.
use crate::field::F;
pub type Digest = [F; 2];
pub fn compress(state: [F; 4]) -> Digest {
    let mut bytes = [0; 64];
    for (i, x) in state.iter().enumerate() {
        bytes[16 * i..16 * i + 16].copy_from_slice(&x.bytes());
    }
    poseidon2b_compress_ligerito_experiment::hash::hash64(&bytes).map(F)
}
pub fn hash_leaf(index: usize, value: F) -> Digest {
    compress([value, F::from_usize(index), F::ZERO, F::ZERO])
}
pub fn hash_node(_level: usize, left: Digest, right: Digest) -> Digest {
    compress([left[0], left[1], right[0], right[1]])
}
