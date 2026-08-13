//! Arbitrary-point multilinear openings over the WHIR IOPP.
//!
//! Plonky3's high-level WHIR adapter samples points internally. This module
//! uses the public lower-level prover/verifier to register the externally
//! sampled sumcheck terminal points used by the static relation and CAIR.

use p3_bn254::{Bn254, Poseidon2Bn254};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_commit::{Mmcs, MultilinearPcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckData;
use p3_sumcheck::constraints::Constraint;
use p3_sumcheck::constraints::statement::EqStatement;
use p3_sumcheck::layout::{Layout, LayoutStrategy, Table, Witness};
use p3_sumcheck::product_polynomial::ProductPolynomial;
use p3_sumcheck::strategy::{SumcheckProver, VariableOrder};
use p3_symmetric::{MerkleCap, PaddingFreeSponge, TruncatedPermutation};
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::WhirProverData;
use p3_whir::pcs::proof::{WhirProof, WhirRoundProof};
use p3_whir::pcs::prover::WhirProver;
use p3_whir::pcs::verifier::WhirVerifier;
use p3_whir::pcs::verifier::errors::VerifierError;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::hash::poseidon2;

type F = Bn254;
type Perm = Poseidon2Bn254<3>;
type LeafHash = PaddingFreeSponge<Perm, 3, 2, 1>;
type Compress = TruncatedPermutation<Perm, 2, 1, 3>;
type InnerChallenger = p3_challenger::DuplexChallenger<F, Perm, 3, 2>;
type Challenger = Bn254Challenger;
type PackedF = <F as Field>::Packing;
type TreeMmcs = MerkleTreeMmcs<PackedF, PackedF, LeafHash, Compress, 2, 1>;
type Dft = Radix2DFTSmallBatch<F>;
type Pcs = WhirProver<F, F, Dft, TreeMmcs, Challenger, ExplicitLayout>;
pub(crate) type Commitment = <TreeMmcs as Mmcs<F>>::Commitment;

/// Prover-only data for one committed polynomial batch.
pub(crate) struct CommittedBatch {
    pub(crate) commitment: Commitment,
    data: WhirProverData<F, F, TreeMmcs, ExplicitLayout>,
}

/// A WHIR proximity proof and its claimed polynomial evaluations.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OpeningProof {
    pub(crate) whir: WhirProof<F, F, TreeMmcs>,
    pub(crate) evaluations: Vec<F>,
}

/// A configured WHIR PCS for a particular stacked arity.
pub(crate) struct ExplicitWhir {
    pcs: Pcs,
}

impl ExplicitWhir {
    pub(crate) fn new(stacked_num_variables: usize) -> Result<Self, String> {
        let folding_factor = FoldingFactor::Constant(1);
        let schedule = folding_factor
            .compute_folding_schedule(stacked_num_variables)
            .map_err(|error| error.to_string())?;
        let mut rate = 1;
        let round_log_inv_rates = schedule
            .iter()
            .take(schedule.len().saturating_sub(1))
            .map(|&folding| {
                rate += folding.saturating_sub(1);
                rate
            })
            .collect();
        let params = ProtocolParameters {
            security_level: 127,
            pow_bits: 0,
            folding_factor,
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            round_log_inv_rates,
        };
        let config = WhirConfig::<F, F, Challenger>::new(stacked_num_variables, params)
            .map_err(|error| error.to_string())?;
        let perm = poseidon2();
        let mmcs = TreeMmcs::new(LeafHash::new(perm.clone()), Compress::new(perm), 0);
        Ok(Self {
            pcs: Pcs::new(config, Dft::default(), mmcs),
        })
    }

    /// Commit directly to a Boolean-hypercube evaluation table.
    pub(crate) fn commit_evaluations(&self, evaluations: Vec<F>) -> Result<CommittedBatch, String> {
        if !evaluations.len().is_power_of_two() {
            return Err("WHIR MLE table length must be a power of two".to_string());
        }
        let table = Table::new(vec![Poly::new(evaluations)]);
        let witness = ExplicitLayout::new_witness(vec![table], 1);
        if witness.num_variables() != self.pcs.config.num_variables {
            return Err("WHIR MLE arity does not match configured arity".to_string());
        }
        let mut challenger = challenger();
        let (commitment, data) =
            <Pcs as MultilinearPcs<F, Challenger>>::commit(&self.pcs, witness, &mut challenger);
        Ok(CommittedBatch { commitment, data })
    }

    pub(crate) fn open(
        &self,
        batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
    ) -> OpeningProof {
        self.open_inner(batch, points, transcript_seed, None)
    }

    pub(crate) fn open_with_checkpoints(
        &self,
        batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
        checkpoint_label: &str,
    ) -> OpeningProof {
        self.open_inner(batch, points, transcript_seed, Some(checkpoint_label))
    }

    fn open_inner(
        &self,
        mut batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
        checkpoint_label: Option<&str>,
    ) -> OpeningProof {
        let started = Instant::now();
        let mut challenger = self.seeded_challenger(transcript_seed);
        challenger.observe(batch.commitment.clone());
        let mut whir = empty_proof(&self.pcs.config);

        let ood_count = self.pcs.config.commitment_ood_samples;
        whir.initial_ood_answers = (0..ood_count)
            .map(|index| {
                let evaluation = batch.data.layout.add_virtual_eval(&mut challenger);
                if let Some(label) = checkpoint_label {
                    eprintln!(
                        "{label}: WHIR OOD polynomial evaluation {}/{} complete ({:.3}s opening elapsed)",
                        index + 1,
                        ood_count,
                        started.elapsed().as_secs_f64(),
                    );
                }
                evaluation
            })
            .collect();
        let evaluations = points
            .iter()
            .enumerate()
            .map(|(index, point)| {
                let evaluation = batch.data.layout.add_claim(point.clone(), &mut challenger);
                if let Some(label) = checkpoint_label {
                    eprintln!(
                        "{label}: opening polynomial evaluation {}/{} complete ({:.3}s opening elapsed)",
                        index + 1,
                        points.len(),
                        started.elapsed().as_secs_f64(),
                    );
                }
                evaluation
            })
            .collect();

        self.pcs.prove(
            &mut whir,
            &mut challenger,
            batch.data.layout,
            batch.data.merkle_data,
        );
        if let Some(label) = checkpoint_label {
            eprintln!(
                "{label}: WHIR opening proof complete ({:.3}s opening elapsed)",
                started.elapsed().as_secs_f64(),
            );
        }
        OpeningProof { whir, evaluations }
    }

    pub(crate) fn verify(
        &self,
        commitment: &Commitment,
        points: &[Point<F>],
        proof: &OpeningProof,
        transcript_seed: &[F],
    ) -> Result<(), VerifierError> {
        if proof.evaluations.len() != points.len()
            || proof.whir.initial_ood_answers.len() != self.pcs.config.commitment_ood_samples
        {
            return Err(VerifierError::OpeningBatchCountMismatch {
                expected: points.len(),
                actual: proof.evaluations.len(),
            });
        }

        let mut challenger = self.seeded_challenger(transcript_seed);
        challenger.observe(commitment.clone());
        let mut eq = EqStatement::initialize(self.pcs.config.num_variables);

        for &evaluation in &proof.whir.initial_ood_answers {
            let point = Point::expand_from_univariate(
                challenger.sample_algebra_element(),
                self.pcs.config.num_variables,
            );
            challenger.observe_algebra_element(evaluation);
            eq.add_evaluated_constraint(point, evaluation);
        }
        for (point, &evaluation) in points.iter().zip(&proof.evaluations) {
            challenger.observe_algebra_element(evaluation);
            eq.add_evaluated_constraint(point.clone(), evaluation);
        }

        let alpha = challenger.sample_algebra_element();
        let constraint = Constraint::new_eq_only(alpha, eq);
        let mut claimed_eval = F::ZERO;
        constraint.combine_evals(&mut claimed_eval);
        WhirVerifier::new(&self.pcs.config, &self.pcs.mmcs, VariableOrder::Prefix)
            .verify(
                &proof.whir,
                &mut challenger,
                commitment,
                constraint,
                claimed_eval,
            )
            .map(|_| ())
    }

    fn seeded_challenger(&self, transcript_seed: &[F]) -> Challenger {
        let mut challenger = challenger();
        let mut domain_separator = DomainSeparator::new(vec![]);
        self.pcs.add_domain_separator::<1>(&mut domain_separator);
        domain_separator.observe_domain_separator(&mut challenger);
        challenger.observe_slice(transcript_seed);
        challenger
    }
}

fn challenger() -> Challenger {
    // The permutation itself is deterministically parameterized; the extra RNG
    // is retained as an explicit transcript-version marker.
    let _marker = SmallRng::seed_from_u64(0x5748_4952);
    Bn254Challenger::new(poseidon2())
}

/// Poseidon2 Fiat--Shamir transcript specialized to the 254-bit BN254 scalar
/// field. Plonky3's duplex sponge is generic over prime fields, but its bit
/// sampling trait implementations are intentionally limited to 64-bit fields.
/// WHIR only needs at most `usize::BITS - 1` bits for query indices, so this
/// adapter extracts them from the canonical big-integer representation.
#[derive(Clone, Debug)]
struct Bn254Challenger(InnerChallenger);

impl Bn254Challenger {
    fn new(permutation: Perm) -> Self {
        Self(InnerChallenger::new(permutation))
    }

    fn low_bits(value: &F, bits: usize) -> usize {
        if bits == 0 {
            return 0;
        }
        let digit = value
            .as_canonical_biguint()
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);
        (digit as usize) & ((1usize << bits) - 1)
    }
}

impl CanObserve<F> for Bn254Challenger {
    fn observe(&mut self, value: F) {
        self.0.observe(value);
    }
}

impl<const N: usize> CanObserve<[F; N]> for Bn254Challenger {
    fn observe(&mut self, value: [F; N]) {
        self.0.observe(value);
    }
}

impl<const N: usize> CanObserve<MerkleCap<F, [F; N]>> for Bn254Challenger {
    fn observe(&mut self, value: MerkleCap<F, [F; N]>) {
        self.0.observe(value);
    }
}

impl CanSample<F> for Bn254Challenger {
    fn sample(&mut self) -> F {
        self.0.sample()
    }
}

impl CanSampleBits<usize> for Bn254Challenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize, "bit count must fit usize");
        let value: F = self.sample();
        Self::low_bits(&value, bits)
    }
}

impl CanSampleUniformBits<F> for Bn254Challenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        assert!(bits < usize::BITS as usize, "bit count must fit usize");
        if bits == 0 {
            return Ok(0);
        }

        // Rejection threshold floor(p / 2^bits) * 2^bits. WHIR requests the
        // RESAMPLE=true mode. For completeness, the false mode is also made
        // total by resampling; it preserves the promised uniform distribution.
        let threshold = (F::order() >> bits) << bits;
        loop {
            let value: F = self.sample();
            if value.as_canonical_biguint() < threshold {
                return Ok(Self::low_bits(&value, bits));
            }
            let _ = RESAMPLE;
        }
    }
}

impl FieldChallenger<F> for Bn254Challenger {}

impl GrindingChallenger for Bn254Challenger {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < usize::BITS as usize, "bit count must fit usize");
        if bits == 0 {
            return F::ZERO;
        }
        for candidate in 0u64.. {
            let witness = F::from_u64(candidate);
            let mut trial = self.clone();
            if trial.check_witness(bits, witness) {
                return witness;
            }
        }
        unreachable!("the finite proof-of-work search must find a witness")
    }
}

fn empty_proof(config: &WhirConfig<F, F, Challenger>) -> WhirProof<F, F, TreeMmcs> {
    WhirProof {
        initial_ood_answers: Vec::new(),
        initial_sumcheck: SumcheckData::default(),
        rounds: (0..config.round_parameters.len())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: F::ZERO,
        final_queries: Vec::new(),
        final_sumcheck: None,
    }
}

#[derive(Debug, Clone)]
struct ExplicitLayout {
    poly: Poly<F>,
    num_variables: usize,
    folding: usize,
    claims: Vec<(Point<F>, F)>,
}

impl ExplicitLayout {
    fn add_claim<Ch>(&mut self, point: Point<F>, challenger: &mut Ch) -> F
    where
        Ch: FieldChallenger<F>,
    {
        assert_eq!(point.num_variables(), self.num_variables);
        let evaluation = self.poly.eval_ext::<F>(&point);
        challenger.observe_algebra_element(evaluation);
        self.claims.push((point, evaluation));
        evaluation
    }
}

impl Layout<F, F> for ExplicitLayout {
    fn from_witness(witness: Witness<F>) -> Self {
        Self {
            poly: witness.poly().clone(),
            num_variables: witness.num_variables(),
            folding: 1,
            claims: Vec::new(),
        }
    }

    fn new_witness(tables: Vec<Table<F>>, folding: usize) -> Witness<F> {
        Witness::new_interleaved(tables, folding)
    }

    fn commit<D, MT, Ch>(
        dft: &D,
        mmcs: &MT,
        challenger: &mut Ch,
        witness: Witness<F>,
        folding: usize,
        starting_log_inv_rate: usize,
    ) -> (Self, MT::Commitment, MT::ProverData<DenseMatrix<F>>)
    where
        D: p3_dft::TwoAdicSubgroupDft<F>,
        MT: Mmcs<F>,
        Ch: CanObserve<MT::Commitment>,
    {
        let (root, data) = p3_sumcheck::commit::commit_base(
            VariableOrder::Prefix,
            dft,
            mmcs,
            challenger,
            witness.poly(),
            folding,
            starting_log_inv_rate,
        );
        let mut layout = Self::from_witness(witness);
        layout.folding = folding;
        (layout, root, data)
    }

    fn num_claims(&self) -> usize {
        self.claims.len()
    }

    fn strategy() -> LayoutStrategy {
        LayoutStrategy::new(true, VariableOrder::Prefix)
    }

    fn folding(&self) -> usize {
        self.folding
    }

    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn num_variables_table(&self, _id: usize) -> usize {
        self.num_variables
    }

    fn eval<Ch>(&mut self, _table_idx: usize, _polys: &[usize], _challenger: &mut Ch) -> Vec<F>
    where
        Ch: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    {
        panic!("explicit layout uses add_claim instead of scheduled evaluations")
    }

    fn add_virtual_eval<Ch>(&mut self, challenger: &mut Ch) -> F
    where
        Ch: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), self.num_variables);
        self.add_claim(point, challenger)
    }

    fn into_sumcheck<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, F>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, F>, Point<F>)
    where
        Ch: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    {
        let alpha = challenger.sample_algebra_element();
        let mut eq = EqStatement::initialize(self.num_variables);
        for (point, evaluation) in self.claims {
            eq.add_evaluated_constraint(point, evaluation);
        }
        let constraint = Constraint::new_eq_only(alpha, eq);
        let (weights, claimed_sum) = constraint.combine_new();
        let evals = Poly::new(self.poly.as_slice().to_vec());
        let product = ProductPolynomial::new_unpacked(VariableOrder::Prefix, evals, weights);
        let mut prover = SumcheckProver::new(product, claimed_sum);
        let randomness = prover.compute_sumcheck_polynomials(
            sumcheck_data,
            challenger,
            self.folding,
            pow_bits,
            None,
        );
        (prover, randomness)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn arbitrary_points_round_trip_through_whir() {
        let local_vars = 3;
        let width = 2;
        let whir = ExplicitWhir::new(local_vars + 1).unwrap();
        let columns = vec![
            (0..8).map(F::from_usize).collect::<Vec<_>>(),
            (8..16).map(F::from_usize).collect::<Vec<_>>(),
        ];
        let table = (0..8)
            .flat_map(|row| [columns[0][row], columns[1][row]])
            .collect();
        let batch = whir.commit_evaluations(table).unwrap();
        let row_point = [F::from_u64(17), F::from_u64(19), F::from_u64(23)];
        let points = (0..width)
            .map(|column| {
                let mut low = vec![F::from_usize(column)];
                low.extend(row_point);
                Point::new(low.into_iter().rev().collect())
            })
            .collect::<Vec<_>>();
        let seed = [F::from_u64(99)];
        let commitment = batch.commitment.clone();
        let proof = whir.open(batch, &points, &seed);
        whir.verify(&commitment, &points, &proof, &seed).unwrap();
        let expected = |column: usize| {
            let mut values = columns[column].clone();
            for &coordinate in &row_point {
                for pair in 0..values.len() / 2 {
                    values[pair] =
                        values[2 * pair] + coordinate * (values[2 * pair + 1] - values[2 * pair]);
                }
                values.truncate(values.len() / 2);
            }
            values[0]
        };
        assert_eq!(proof.evaluations, vec![expected(0), expected(1)]);

        let mut forged_evaluation = proof.clone();
        forged_evaluation.evaluations[0] += F::ONE;
        assert!(
            whir.verify(&commitment, &points, &forged_evaluation, &seed)
                .is_err()
        );

        let mut missing_evaluation = proof.clone();
        missing_evaluation.evaluations.pop();
        assert!(
            whir.verify(&commitment, &points, &missing_evaluation, &seed)
                .is_err()
        );

        let mut forged_ood = proof;
        assert!(!forged_ood.whir.initial_ood_answers.is_empty());
        forged_ood.whir.initial_ood_answers[0] += F::ONE;
        assert!(
            whir.verify(&commitment, &points, &forged_ood, &seed)
                .is_err()
        );
    }
}
