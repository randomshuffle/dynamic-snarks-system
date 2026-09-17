//! Arbitrary-point multilinear openings over the WHIR IOPP.
//!
//! Plonky3's high-level WHIR adapter samples points internally. This module
//! uses the public lower-level prover/verifier to register the externally
//! sampled sumcheck terminal points used by the static relation and CAIR.

#[path = "pcs/structured_openings.rs"]
mod structured_openings;

use num_bigint::BigUint;
use p3_blake3::Blake3;
use p3_bn254::Bn254;
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
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::WhirProverData;
use p3_whir::pcs::proof::{QueryOpening, WhirProof, WhirRoundProof};
use p3_whir::pcs::prover::WhirProver;
use p3_whir::pcs::verifier::WhirVerifier;
use p3_whir::pcs::verifier::errors::VerifierError;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type F = Bn254;
type LeafHash = SerializingHasher<Blake3>;
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
type Challenger = Bn254Challenger;
type PackedF = <F as Field>::Packing;
type TreeMmcs = MerkleTreeMmcs<PackedF, u8, LeafHash, Compress, 2, 32>;
type Dft = Radix2DFTSmallBatch<F>;
type Pcs = WhirProver<F, F, Dft, TreeMmcs, Challenger, ExplicitLayout>;
pub(crate) type Commitment = <TreeMmcs as Mmcs<F>>::Commitment;

const PRODUCTION_FOLDING_FACTOR: usize = 4;

/// Number of variables folded in the first production WHIR round.
pub const WHIR_INITIAL_FOLDING_FACTOR: usize = if cfg!(feature = "whir-initial-64") {
    6
} else {
    PRODUCTION_FOLDING_FACTOR
};

/// Number of variables folded in later production WHIR rounds.
pub const WHIR_SUBSEQUENT_FOLDING_FACTOR: usize = PRODUCTION_FOLDING_FACTOR;

/// Rate schedules compared by the standalone PCS benchmark. Production keeps
/// the existing fixed-half-rate schedule until a separate choice is made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RateSchedule {
    FixedHalf,
    WhirDefault,
}

impl RateSchedule {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::FixedHalf => "fixed",
            Self::WhirDefault => "default",
        }
    }
}

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

impl OpeningProof {
    /// Bytes of all field elements and hashes stored in this opening proof,
    /// including Merkle paths, intermediate commitments, OOD answers, folding
    /// sumchecks, and the final polynomial. Excludes container lengths/tags and
    /// the initial commitment, which is reported separately by the benchmark.
    pub(crate) fn payload_size_bytes(&self) -> usize {
        fn sumcheck(data: &SumcheckData<F, F>) -> usize {
            32 * (2 * data.polynomial_evaluations.len() + data.pow_witnesses.len())
        }
        fn queries(openings: &[QueryOpening<F, F, Vec<[u8; 32]>>]) -> usize {
            openings
                .iter()
                .map(|opening| match opening {
                    QueryOpening::Base { values, proof }
                    | QueryOpening::Extension { values, proof } => {
                        32 * (values.len() + proof.len())
                    }
                })
                .sum()
        }
        let proof = &self.whir;
        let mut bytes = 32 * (self.evaluations.len() + proof.initial_ood_answers.len());
        bytes += sumcheck(&proof.initial_sumcheck);
        for round in &proof.rounds {
            bytes += round
                .commitment
                .as_ref()
                .map_or(0, |commitment| 32 * commitment.num_roots());
            bytes += 32 * (round.ood_answers.len() + 1); // Stored PoW witness, including zero.
            bytes += queries(&round.queries) + sumcheck(&round.sumcheck);
        }
        bytes += proof
            .final_poly
            .as_ref()
            .map_or(0, |poly| 32 * poly.as_slice().len());
        bytes += 32 + queries(&proof.final_queries); // Stored final PoW witness.
        bytes += proof.final_sumcheck.as_ref().map_or(0, sumcheck);
        bytes
    }
}

/// A configured WHIR PCS for a particular stacked arity.
pub(crate) struct ExplicitWhir {
    pcs: Pcs,
}

/// Derived WHIR parameters exposed to the standalone PCS microbenchmark.
#[derive(Clone, Debug)]
pub(crate) struct ParameterSummary {
    pub(crate) folding_schedule: Vec<usize>,
    pub(crate) round_log_inv_rates: Vec<usize>,
    pub(crate) round_queries: Vec<usize>,
    pub(crate) final_queries: usize,
    pub(crate) final_sumcheck_rounds: usize,
    pub(crate) starting_domain_size: usize,
    pub(crate) codeword_domain_sizes: Vec<usize>,
}

/// Wall-clock subdivision of an arbitrary-point WHIR opening.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OpeningTimings {
    /// Time spent evaluating the committed MLE at OOD and requested points.
    pub(crate) evaluations: Duration,
    /// Time spent constructing the batched sumcheck and WHIR proximity proof.
    pub(crate) proof: Duration,
}

impl ExplicitWhir {
    pub(crate) fn new(stacked_num_variables: usize) -> Result<Self, String> {
        Self::new_with_schedule(
            stacked_num_variables,
            FoldingFactor::ConstantFromSecondRound(
                WHIR_INITIAL_FOLDING_FACTOR.min(stacked_num_variables),
                WHIR_SUBSEQUENT_FOLDING_FACTOR,
            ),
            RateSchedule::FixedHalf,
        )
    }

    /// Configure WHIR with a fixed folding factor and a rate-1/2 codeword in
    /// every round. Keeping the rate fixed lets the PCS microbenchmark vary
    /// only the folding factor.
    pub(crate) fn new_with_folding_factor(
        stacked_num_variables: usize,
        factor: usize,
    ) -> Result<Self, String> {
        Self::new_with_rate_schedule(stacked_num_variables, factor, RateSchedule::FixedHalf)
    }

    /// Change only the intermediate code rates: `WhirDefault` delegates the
    /// schedule to Plonky3 (log-inverse rate grows by folding_factor - 1).
    pub(crate) fn new_with_rate_schedule(
        stacked_num_variables: usize,
        factor: usize,
        rate_schedule: RateSchedule,
    ) -> Result<Self, String> {
        let folding_factor = FoldingFactor::Constant(factor);
        Self::new_with_schedule(stacked_num_variables, folding_factor, rate_schedule)
    }

    fn new_with_schedule(
        stacked_num_variables: usize,
        folding_factor: FoldingFactor,
        rate_schedule: RateSchedule,
    ) -> Result<Self, String> {
        let schedule = folding_factor
            .compute_folding_schedule(stacked_num_variables)
            .map_err(|error| error.to_string())?;
        let round_log_inv_rates = match rate_schedule {
            RateSchedule::FixedHalf => vec![1; schedule.len().saturating_sub(1)],
            RateSchedule::WhirDefault => Vec::new(),
        };
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
        let mmcs = TreeMmcs::new(LeafHash::new(Blake3 {}), Compress::new(Blake3 {}), 0);
        Ok(Self {
            pcs: Pcs::new(config, shared_dft(), mmcs),
        })
    }

    pub(crate) fn parameter_summary(&self) -> ParameterSummary {
        ParameterSummary {
            folding_schedule: self.pcs.config.folding_schedule.clone(),
            round_log_inv_rates: self
                .pcs
                .config
                .round_parameters
                .iter()
                .map(|round| round.log_inv_rate)
                .collect(),
            round_queries: self
                .pcs
                .config
                .round_parameters
                .iter()
                .map(|round| {
                    round
                        .num_queries
                        .min(round.domain_size >> round.folding_factor)
                })
                .collect(),
            final_queries: self.pcs.config.final_queries.min(
                self.pcs.config.final_round_config().domain_size
                    >> self.pcs.config.final_round_config().folding_factor,
            ),
            final_sumcheck_rounds: self.pcs.config.final_sumcheck_rounds,
            starting_domain_size: self.pcs.config.starting_domain_size(),
            codeword_domain_sizes: self
                .pcs
                .config
                .round_parameters
                .iter()
                .map(|round| round.domain_size)
                .chain([self.pcs.config.final_round_config().domain_size])
                .collect(),
        }
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
        self.open_inner(batch, points, transcript_seed, None).0
    }

    pub(crate) fn open_with_checkpoints(
        &self,
        batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
        checkpoint_label: &str,
    ) -> OpeningProof {
        self.open_inner(batch, points, transcript_seed, Some(checkpoint_label))
            .0
    }

    /// Open while returning the exact evaluation/proximity-proof subdivision.
    pub(crate) fn open_profiled(
        &self,
        batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
    ) -> (OpeningProof, OpeningTimings) {
        self.open_inner(batch, points, transcript_seed, None)
    }

    fn open_inner(
        &self,
        mut batch: CommittedBatch,
        points: &[Point<F>],
        transcript_seed: &[F],
        checkpoint_label: Option<&str>,
    ) -> (OpeningProof, OpeningTimings) {
        let started = Instant::now();
        let mut challenger = self.seeded_challenger(transcript_seed);
        challenger.observe(batch.commitment.clone());
        let mut whir = empty_proof(&self.pcs.config);
        let evaluations_started = Instant::now();

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
        let evaluations = batch.data.layout.add_claims(points, &mut challenger);
        if let Some(label) = checkpoint_label {
            eprintln!(
                "{label}: {} opening polynomial evaluations complete ({:.3}s opening elapsed)",
                points.len(),
                started.elapsed().as_secs_f64(),
            );
        }
        let evaluations_elapsed = evaluations_started.elapsed();

        let proof_started = Instant::now();
        self.pcs.prove(
            &mut whir,
            &mut challenger,
            batch.data.layout,
            batch.data.merkle_data,
        );
        let proof_elapsed = proof_started.elapsed();
        if let Some(label) = checkpoint_label {
            eprintln!(
                "{label}: WHIR opening proof complete ({:.3}s opening elapsed: {:.3}s evaluations, {:.3}s proof)",
                started.elapsed().as_secs_f64(),
                evaluations_elapsed.as_secs_f64(),
                proof_elapsed.as_secs_f64(),
            );
        }
        (
            OpeningProof { whir, evaluations },
            OpeningTimings {
                evaluations: evaluations_elapsed,
                proof: proof_elapsed,
            },
        )
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

fn shared_dft() -> Dft {
    static DFT: OnceLock<Dft> = OnceLock::new();
    DFT.get_or_init(Dft::default).clone()
}

fn challenger() -> Challenger {
    Bn254Challenger::new()
}

/// BLAKE3 Fiat--Shamir transcript specialized to the 254-bit BN254 scalar
/// field. Plonky3's byte-serializing challenger is limited to 32- and 64-bit
/// prime fields, so this adapter uses fixed-width canonical BN254 encodings and
/// rejection sampling.
#[derive(Clone, Debug)]
struct Bn254Challenger {
    hasher: blake3::Hasher,
    counter: u64,
}

impl Bn254Challenger {
    fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"dynamic-snarks/whir-transcript/v1");
        Self { hasher, counter: 0 }
    }

    fn observe_field(&mut self, value: &F) {
        let mut bytes = value.as_canonical_biguint().to_bytes_le();
        bytes.resize(32, 0);
        self.hasher.update(b"field");
        self.hasher.update(&bytes);
    }

    fn query(&mut self, domain: &[u8], output: &mut [u8]) {
        let mut query = self.hasher.clone();
        query.update(domain);
        query.update(&self.counter.to_le_bytes());
        query.finalize_xof().fill(output);
        self.counter += 1;
    }
}

impl CanObserve<F> for Bn254Challenger {
    fn observe(&mut self, value: F) {
        self.observe_field(&value);
    }
}

impl<const N: usize> CanObserve<[F; N]> for Bn254Challenger {
    fn observe(&mut self, value: [F; N]) {
        for element in value {
            self.observe_field(&element);
        }
    }
}

impl CanObserve<MerkleCap<PackedF, [u8; 32]>> for Bn254Challenger {
    fn observe(&mut self, value: MerkleCap<PackedF, [u8; 32]>) {
        self.hasher.update(b"merkle-cap");
        self.hasher.update(&value.num_roots().to_le_bytes());
        for digest in value.roots() {
            self.hasher.update(digest);
        }
    }
}

impl CanSample<F> for Bn254Challenger {
    fn sample(&mut self) -> F {
        let mut uniform = [0u8; 64];
        self.query(b"field-challenge", &mut uniform);
        F::from_biguint(BigUint::from_bytes_le(&uniform) % F::order())
            .expect("a reduced 512-bit integer fits BN254")
    }
}

impl CanSampleBits<usize> for Bn254Challenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize, "bit count must fit usize");
        if bits == 0 {
            return 0;
        }
        let mut uniform = [0u8; 8];
        self.query(b"bit-challenge", &mut uniform);
        u64::from_le_bytes(uniform) as usize & ((1usize << bits) - 1)
    }
}

impl CanSampleUniformBits<F> for Bn254Challenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        assert!(bits < usize::BITS as usize, "bit count must fit usize");
        let _ = RESAMPLE;
        Ok(self.sample_bits(bits))
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
    row_weights: structured_openings::RowWeights,
}

impl ExplicitLayout {
    fn add_claims<Ch>(&mut self, points: &[Point<F>], challenger: &mut Ch) -> Vec<F>
    where
        Ch: FieldChallenger<F>,
    {
        let evaluations = self.row_weights.evaluate_batch(&self.poly, points);
        for (point, &evaluation) in points.iter().zip(&evaluations) {
            challenger.observe_algebra_element(evaluation);
            self.claims.push((point.clone(), evaluation));
        }
        evaluations
    }

    fn add_claim<Ch>(&mut self, point: Point<F>, challenger: &mut Ch) -> F
    where
        Ch: FieldChallenger<F>,
    {
        assert_eq!(point.num_variables(), self.num_variables);
        let evaluation = self.row_weights.evaluate(&self.poly, &point);
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
            row_weights: structured_openings::RowWeights::default(),
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
        mut self,
        sumcheck_data: &mut SumcheckData<F, F>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, F>, Point<F>)
    where
        Ch: FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    {
        let profile = std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some();
        let weights_started = Instant::now();
        let claim_count = self.claims.len();
        let alpha = challenger.sample_algebra_element();
        let (weights, claimed_sum) =
            self.row_weights
                .combine_claims(self.num_variables, &self.claims, alpha);
        if profile {
            eprintln!(
                "profile checkpoint: WHIR initial claim weights (variables={}, claims={claim_count}) complete in {:.6}s",
                self.num_variables,
                weights_started.elapsed().as_secs_f64(),
            );
        }
        let sumcheck_started = Instant::now();
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
        if profile {
            eprintln!(
                "profile checkpoint: WHIR initial folding sumcheck (variables={}) complete in {:.6}s",
                self.num_variables,
                sumcheck_started.elapsed().as_secs_f64(),
            );
        }
        (prover, randomness)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn batched_claims_preserve_evaluations_order_and_transcript() {
        let variables = 12;
        let poly = Poly::new(
            (0..1 << variables)
                .map(|i| F::from_usize(i * i + 19))
                .collect(),
        );
        let dense = Point::new((0..variables).map(|i| F::from_usize(i + 3)).collect());
        let mut points = vec![dense.clone()];
        for row_seed in [3, 17, 3] {
            for column in [0, 1, 7, 63, 127, 7] {
                let mut point = (0..5)
                    .map(|i| F::from_usize(row_seed + i))
                    .collect::<Vec<_>>();
                point.extend_from_slice(Point::hypercube(column, 7).as_slice());
                points.push(Point::new(point));
            }
            points.push(dense.clone());
        }
        for points in [&[][..], points.as_slice()] {
            let mut sequential = ExplicitLayout {
                poly: poly.clone(),
                num_variables: variables,
                folding: 4,
                claims: Vec::new(),
                row_weights: structured_openings::RowWeights::default(),
            };
            let mut batched = sequential.clone();
            let mut sequential_transcript = challenger();
            let mut batch_transcript = challenger();
            let expected = points
                .iter()
                .map(|point| sequential.add_claim(point.clone(), &mut sequential_transcript))
                .collect::<Vec<_>>();
            let actual = batched.add_claims(points, &mut batch_transcript);
            assert_eq!(actual, expected);
            assert_eq!(batched.claims, sequential.claims);
            assert_eq!(
                CanSample::<F>::sample(&mut batch_transcript),
                CanSample::<F>::sample(&mut sequential_transcript)
            );
        }
    }

    #[test]
    fn production_configuration_checks_large_cair_without_allocating_it() {
        let configured = ExplicitWhir::new(33);
        if cfg!(feature = "whir-initial-64") {
            let whir = configured.unwrap();
            let summary = whir.parameter_summary();
            assert_eq!(summary.folding_schedule[0], 6);
            assert!(summary.folding_schedule[1..].iter().all(|&fold| fold == 4));
            assert_eq!(summary.codeword_domain_sizes[0] >> 6, 1 << 28);
        } else {
            assert!(configured.is_err());
        }
    }

    #[test]
    fn production_schedule_round_trip_with_a_subsequent_round() {
        let whir = ExplicitWhir::new(13).unwrap();
        let point = Point::new((0..13).map(|i| F::from_usize(i + 11)).collect());
        let table = (0..1 << 13).map(F::from_usize).collect::<Vec<_>>();
        let expected = Poly::new(table.clone()).eval_ext::<F>(&point);
        let batch = whir.commit_evaluations(table).unwrap();
        let commitment = batch.commitment.clone();
        let seed = [F::from_u64(123)];
        let proof = whir.open(batch, std::slice::from_ref(&point), &seed);
        assert_eq!(proof.evaluations, vec![expected]);
        whir.verify(&commitment, &[point], &proof, &seed).unwrap();
    }

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

    #[test]
    fn folding_factor_sweep_keeps_round_rate_fixed() {
        let expected = [(1, 12, 6), (2, 6, 6), (3, 4, 6), (4, 3, 6)];
        for (factor, schedule_len, final_variables) in expected {
            let whir = ExplicitWhir::new_with_folding_factor(18, factor).unwrap();
            let summary = whir.parameter_summary();
            assert_eq!(summary.folding_schedule.len(), schedule_len);
            assert_eq!(summary.final_sumcheck_rounds, final_variables);
            assert!(summary.round_log_inv_rates.iter().all(|&rate| rate == 1));
            assert_eq!(summary.starting_domain_size, 1 << 19);
        }
    }

    #[test]
    fn default_rate_schedule_halves_domains_and_binds_opening_transcripts() {
        let fixed = ExplicitWhir::new_with_rate_schedule(18, 4, RateSchedule::FixedHalf).unwrap();
        let default =
            ExplicitWhir::new_with_rate_schedule(18, 4, RateSchedule::WhirDefault).unwrap();
        assert_eq!(
            fixed.parameter_summary().codeword_domain_sizes,
            vec![1 << 19, 1 << 15, 1 << 11]
        );
        assert_eq!(
            default.parameter_summary().codeword_domain_sizes,
            vec![1 << 19, 1 << 18, 1 << 17]
        );
        assert_eq!(default.parameter_summary().round_log_inv_rates, vec![4, 7]);
        assert_eq!(
            fixed.parameter_summary().folding_schedule,
            default.parameter_summary().folding_schedule
        );

        let fixed = ExplicitWhir::new_with_rate_schedule(12, 2, RateSchedule::FixedHalf).unwrap();
        let default =
            ExplicitWhir::new_with_rate_schedule(12, 2, RateSchedule::WhirDefault).unwrap();
        let table = (0..1 << 12)
            .map(|i| F::from_usize(i * i + 7))
            .collect::<Vec<_>>();
        let points = [Point::new(
            (0..12).map(|i| F::from_usize(3 * i + 2)).collect(),
        )];
        let seed = [F::from_u64(173)];
        let mut expected = None;
        for (prover, wrong_verifier) in [(&fixed, &default), (&default, &fixed)] {
            let batch = prover.commit_evaluations(table.clone()).unwrap();
            let commitment = batch.commitment.clone();
            let proof = prover.open(batch, &points, &seed);
            prover.verify(&commitment, &points, &proof, &seed).unwrap();
            assert!(
                wrong_verifier
                    .verify(&commitment, &points, &proof, &seed)
                    .is_err()
            );
            if let Some(values) = &expected {
                assert_eq!(&proof.evaluations, values);
            } else {
                expected = Some(proof.evaluations.clone());
            }
        }
    }
}
