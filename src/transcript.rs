//! Raw-message Fiat--Shamir transcript helpers.

use num_bigint::BigUint;
use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField};

/// A domain-separated transcript that retains only protocol messages.
///
/// Challenges are independent labelled random-oracle queries over the raw
/// message prefix. In particular, producing a challenge does not append that
/// challenge to the transcript. This keeps later queries from treating an
/// earlier Fiat--Shamir output as though it were a prover message.
#[derive(Clone, Debug)]
pub(crate) struct RawTranscript {
    hasher: blake3::Hasher,
    message_count: usize,
}

impl RawTranscript {
    pub(crate) fn new(domain: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"dynamic-snarks/raw-transcript/v1");
        hasher.update(&domain.to_le_bytes());
        Self {
            hasher,
            message_count: 0,
        }
    }

    pub(crate) fn absorb(&mut self, value: Bn254) {
        let mut bytes = value.as_canonical_biguint().to_bytes_le();
        bytes.resize(32, 0);
        self.hasher.update(&bytes);
        self.message_count += 1;
    }

    /// Absorb a length-delimited raw protocol message.
    pub(crate) fn absorb_message(&mut self, tag: u64, values: &[Bn254]) {
        self.absorb(Bn254::from_u64(tag));
        self.absorb(Bn254::from_usize(values.len()));
        for &value in values {
            self.absorb(value);
        }
    }

    /// Make a labelled random-oracle query without modifying the transcript.
    pub(crate) fn challenge(&self, label: u64) -> Bn254 {
        let mut query = self.hasher.clone();
        query.update(b"challenge");
        query.update(&label.to_le_bytes());
        let mut uniform = [0u8; 64];
        query.finalize_xof().fill(&mut uniform);
        Bn254::from_biguint(BigUint::from_bytes_le(&uniform) % Bn254::order())
            .expect("a reduced 512-bit integer fits BN254")
    }

    #[cfg(test)]
    pub(crate) const fn message_count(&self) -> usize {
        self.message_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_labelled_queries_over_raw_messages_only() {
        let mut transcript = RawTranscript::new(17);
        transcript.absorb_message(1, &[Bn254::from_u64(3), Bn254::from_u64(5)]);
        let count = transcript.message_count();
        let alpha = transcript.challenge(10);
        assert_eq!(transcript.message_count(), count);
        assert_eq!(alpha, transcript.challenge(10));
        assert_ne!(alpha, transcript.challenge(11));

        transcript.absorb_message(2, &[Bn254::from_u64(7)]);
        assert_ne!(alpha, transcript.challenge(10));
    }
}
