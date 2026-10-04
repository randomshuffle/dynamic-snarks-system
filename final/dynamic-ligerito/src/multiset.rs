use crate::{
    field::F,
    static_snark::{TraceCommitment, commitment_seed},
    transcript::RawTranscript,
};
#[derive(Clone, Copy)]
pub(crate) struct RoutingChallenges {
    pub theta: F,
    pub gamma: F,
}
impl RoutingChallenges {
    pub fn derive(seed: &[F], table: &TraceCommitment) -> Self {
        let mut t = RawTranscript::new(0x524f_5554_455f_4d53);
        t.absorb_message(1, seed);
        t.absorb_message(2, &commitment_seed(table));
        Self {
            theta: t.challenge(1),
            gamma: t.challenge(2),
        }
    }
}
pub(crate) fn compress_fields(tuple: [F; 8], theta: F) -> F {
    tuple.into_iter().rev().fold(F::ZERO, |a, x| a * theta + x)
}
