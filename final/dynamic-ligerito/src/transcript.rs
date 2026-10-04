//! Raw-message transcript with uniform full GF(2^128) challenges.
use crate::field::F;
#[derive(Clone, Debug)]
pub(crate) struct RawTranscript {
    hasher: blake3::Hasher,
}
impl RawTranscript {
    pub(crate) fn new(domain: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"dynamic-snarks/gf128-ligerito-fast100-p2b64-s33/v1");
        h.update(&domain.to_le_bytes());
        Self { hasher: h }
    }
    pub(crate) fn absorb(&mut self, v: F) {
        self.hasher.update(&v.bytes());
    }
    pub(crate) fn absorb_message(&mut self, tag: u64, v: &[F]) {
        self.absorb(F::from_u64(tag));
        self.absorb(F::from_usize(v.len()));
        for &x in v {
            self.absorb(x);
        }
    }
    pub(crate) fn challenge(&self, label: u64) -> F {
        let mut q = self.hasher.clone();
        q.update(b"challenge");
        q.update(&label.to_le_bytes());
        F::from_u128(u128::from_le_bytes(
            q.finalize().as_bytes()[..16].try_into().unwrap(),
        ))
    }
}
