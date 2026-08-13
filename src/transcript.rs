//! Raw-message Fiat--Shamir transcript helpers.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;

use crate::hash::hash_node;

/// A domain-separated transcript that retains only protocol messages.
///
/// Challenges are independent labelled random-oracle queries over the raw
/// message prefix. In particular, producing a challenge does not append that
/// challenge to the transcript. This keeps later queries from treating an
/// earlier Fiat--Shamir output as though it were a prover message.
#[derive(Clone, Debug)]
pub(crate) struct RawTranscript {
    domain: u64,
    messages: Vec<Bn254>,
}

impl RawTranscript {
    pub(crate) fn new(domain: u64) -> Self {
        Self {
            domain,
            messages: Vec::new(),
        }
    }

    pub(crate) fn absorb(&mut self, value: Bn254) {
        self.messages.push(value);
    }

    /// Absorb a length-delimited raw protocol message.
    pub(crate) fn absorb_message(&mut self, tag: u64, values: &[Bn254]) {
        self.absorb(Bn254::from_u64(tag));
        self.absorb(Bn254::from_usize(values.len()));
        self.messages.extend_from_slice(values);
    }

    /// Make a labelled random-oracle query without modifying the transcript.
    pub(crate) fn challenge(&self, label: u64) -> Bn254 {
        let mut state = hash_node(
            240,
            Bn254::from_u64(self.domain),
            Bn254::from_usize(self.messages.len()),
        );
        for &message in &self.messages {
            state = hash_node(241, state, message);
        }
        hash_node(242, state, Bn254::from_u64(label))
    }

    #[cfg(test)]
    pub(crate) const fn message_count(&self) -> usize {
        self.messages.len()
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
