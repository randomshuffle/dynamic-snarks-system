//! Transparent preprocessed multilinear SNARK backed by Plonky3's WHIR IOPP.
//!
//! Trace columns are committed directly as Boolean-hypercube evaluations. A
//! degree-eight ZeroCheck checks the local relation.  Wiring uses HyperPlonk's
//! PermCheck -> ProductCheck -> ZeroCheck reduction with one multilinear
//! product oracle. WHIR's Reed--Solomon encoding remains an internal
//! commitment detail; no univariate trace interpolation or quotient
//! polynomial is needed.

mod air;
mod pcs;
pub(crate) mod program;

use air::{
    GATE_WIDTH, LOCAL_CONSTRAINT_COUNT, LOCAL_PRE_WIDTH, MainTrace, PRE_WIDTH, PreprocessingLayout,
    RelationShape, evaluate_local_constraints,
};
use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use p3_maybe_rayon::prelude::*;
use p3_multilinear_util::point::Point;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

use crate::transcript::RawTranscript;
use pcs::{Commitment, ExplicitWhir, OpeningProof};

pub use pcs::{WHIR_INITIAL_FOLDING_FACTOR, WHIR_SUBSEQUENT_FOLDING_FACTOR};
pub use program::{ConstraintProgram, ProgramBuilder, Variable};

/// Small description of the production WHIR configuration, without proof tables.
#[derive(Clone, Debug)]
pub struct WhirConfiguration {
    /// Concrete first and subsequent folds, measured in variables.
    pub folding_schedule: Vec<usize>,
    /// Heights of the interleaved Reed--Solomon matrices, including the final round.
    pub fft_domain_sizes: Vec<usize>,
}

/// Check the field-domain limit without constructing a polynomial or proof.
pub fn whir_configuration(num_variables: usize) -> Result<WhirConfiguration, Error> {
    let summary = ExplicitWhir::new(num_variables)
        .map_err(Error::Whir)?
        .parameter_summary();
    let fft_domain_sizes = summary
        .codeword_domain_sizes
        .iter()
        .zip(&summary.folding_schedule)
        .map(|(&domain, &fold)| domain >> fold)
        .collect();
    Ok(WhirConfiguration {
        folding_schedule: summary.folding_schedule,
        fft_domain_sizes,
    })
}

const STATIC_VERSION: u64 = 5;
const LOCAL_DEGREE: usize = 8;
const LOCAL_ROUND_TAG: u64 = 0x5354_4154_4c4f_434c;
const PRODUCT_ROUND_TAG: u64 = 0x5354_4154_5052_4f44;

/// Opaque commitment to the static proof's witness-dependent main trace.
pub(crate) type TraceCommitment = Commitment;

/// Prover-side handle for a directly committed MLE table.
pub(crate) struct MleCommitted {
    whir: ExplicitWhir,
    batch: pcs::CommittedBatch,
}

/// A direct MLE commitment and its batched WHIR opening.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MleOpeningProof {
    pub(crate) commitment: TraceCommitment,
    pub(crate) opening: OpeningProof,
}

impl MleCommitted {
    pub(crate) fn commitment(&self) -> &TraceCommitment {
        &self.batch.commitment
    }

    pub(crate) fn open(
        self,
        low_bit_points: &[&[Bn254]],
        transcript_seed: &[Bn254],
    ) -> MleOpeningProof {
        let points = low_bit_points
            .iter()
            .map(|point| Point::new(point.iter().rev().copied().collect()))
            .collect::<Vec<_>>();
        let commitment = self.batch.commitment.clone();
        let opening = self.whir.open(self.batch, &points, transcript_seed);
        MleOpeningProof {
            commitment,
            opening,
        }
    }

    /// Open a directly committed table while reporting each expensive WHIR
    /// evaluation. This is used by the CAIR benchmark diagnostics only.
    pub(crate) fn open_with_checkpoints(
        self,
        low_bit_points: &[&[Bn254]],
        transcript_seed: &[Bn254],
        checkpoint_label: &str,
    ) -> MleOpeningProof {
        let points = low_bit_points
            .iter()
            .map(|point| Point::new(point.iter().rev().copied().collect()))
            .collect::<Vec<_>>();
        let commitment = self.batch.commitment.clone();
        let opening =
            self.whir
                .open_with_checkpoints(self.batch, &points, transcript_seed, checkpoint_label);
        MleOpeningProof {
            commitment,
            opening,
        }
    }
}

/// Commit a power-of-two MLE evaluation table without a coefficient transform.
pub(crate) fn commit_mle(evaluations: Vec<Bn254>) -> Result<MleCommitted, Error> {
    if evaluations.len() < 2 || !evaluations.len().is_power_of_two() {
        return Err(Error::Whir(
            "direct MLE table length must be a power of two of at least two".to_string(),
        ));
    }
    let whir =
        ExplicitWhir::new(evaluations.len().trailing_zeros() as usize).map_err(Error::Whir)?;
    let batch = whir.commit_evaluations(evaluations).map_err(Error::Whir)?;
    Ok(MleCommitted { whir, batch })
}

/// Verify batched low-bit-first MLE openings.
pub(crate) fn verify_mle_opening(
    table_len: usize,
    low_bit_points: &[&[Bn254]],
    proof: &MleOpeningProof,
    transcript_seed: &[Bn254],
) -> Result<(), Error> {
    if table_len < 2 || !table_len.is_power_of_two() {
        return Err(Error::Whir("invalid direct MLE table length".to_string()));
    }
    let points = low_bit_points
        .iter()
        .map(|point| Point::new(point.iter().rev().copied().collect()))
        .collect::<Vec<_>>();
    let whir = ExplicitWhir::new(table_len.trailing_zeros() as usize).map_err(Error::Whir)?;
    whir.verify(&proof.commitment, &points, &proof.opening, transcript_seed)
        .map_err(|error| Error::Whir(error.to_string()))
}

/// Additional arbitrary-point openings bound into the static transcript.
#[derive(Default)]
pub(crate) struct ExtraMainOpenings {
    pub(crate) points: Vec<Point<Bn254>>,
    pub(crate) transcript_binding: Vec<Bn254>,
}

/// Maximum packed preprocessing width for general gate programs. Arithmetic
/// initializations and ordinary arithmetic baselines both use four columns;
/// use [`ProvingKey::preprocessed_width`] for the actual width.
pub const PREPROCESSING_WIDTH: usize = PRE_WIDTH;

/// Prover key for one fixed low-degree relation.
#[derive(Clone)]
pub struct ProvingKey {
    shape: RelationShape,
    verifying_key: VerifyingKey,
}

/// Verifier key for one fixed low-degree relation.
#[derive(Clone)]
pub struct VerifyingKey {
    domain_size: usize,
    main_width: usize,
    num_public_values: usize,
    public_rows: Vec<(usize, usize)>,
    preprocessing: PreprocessingLayout,
    preprocessed_commitment: Commitment,
}

impl ProvingKey {
    /// Number of rows in the padded multilinear trace for this relation.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.shape.domain_size
    }

    /// Number of columns in the committed preprocessing table, including padding.
    #[must_use]
    pub fn preprocessed_width(&self) -> usize {
        self.shape.preprocessing.width(self.shape.main_width)
    }
}

impl VerifyingKey {
    /// Number of rows in the padded multilinear trace for this relation.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.domain_size
    }

    /// Number of columns in the committed preprocessing table, including padding.
    #[must_use]
    pub fn preprocessed_width(&self) -> usize {
        self.preprocessing.width(self.main_width)
    }
}

/// One multilinear sumcheck transcript.
#[derive(Clone, Serialize, Deserialize)]
struct SumcheckProof {
    rounds: Vec<Vec<Bn254>>,
}

/// A native multilinear static proof with three batched WHIR openings.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    main_width: usize,
    main_commitment: Commitment,
    auxiliary_commitment: Commitment,
    local: SumcheckProof,
    product: SumcheckProof,
    preprocessed_opening: OpeningProof,
    main_opening: OpeningProof,
    auxiliary_opening: OpeningProof,
}

impl Proof {
    /// Borrow the commitment containing the main trace columns.
    pub(crate) const fn main_commitment(&self) -> &TraceCommitment {
        &self.main_commitment
    }

    /// Evaluations appended after the static relation's standard openings.
    pub(crate) fn extra_main_evaluations(&self) -> &[Bn254] {
        &self.main_opening.evaluations[GATE_WIDTH + self.main_width..]
    }
}

/// Static-SNARK setup, proving, or verification failure.
#[derive(Debug, Error)]
pub enum Error {
    /// The supplied witness program differs from the preprocessed relation.
    #[error("constraint program does not match the preprocessed relation")]
    RelationMismatch,
    /// The relation public-input vector has the wrong length.
    #[error("expected {expected} public values, received {actual}")]
    PublicInputCount {
        /// Number encoded in the relation.
        expected: usize,
        /// Number supplied by the caller.
        actual: usize,
    },
    /// A deterministic fixed commitment unexpectedly changed.
    #[error("preprocessed commitment mismatch")]
    PreprocessedCommitment,
    /// The WHIR configuration, commitment, or opening failed.
    #[error("WHIR: {0}")]
    Whir(String),
    /// A multilinear relation, product, or terminal identity is false.
    #[error("multilinear relation identity failed")]
    QuotientIdentity,
    /// A Fiat--Shamir permutation denominator vanished.  This event has
    /// negligible probability and the proof may be retried with fresh
    /// transcript randomness.
    #[error("HyperPlonk ProductCheck denominator is zero")]
    ProductDenominator,
    /// A sumcheck transcript has the wrong shape or consistency relation.
    #[error("sumcheck transcript is malformed")]
    Sumcheck,
    /// A composed protocol could not derive its extra main-trace openings.
    #[error("composed opening: {0}")]
    ComposedOpening(String),
}

/// Preprocess a fixed constraint program into reusable proving/verifying keys.
pub fn setup(program: &ConstraintProgram) -> Result<(ProvingKey, VerifyingKey), Error> {
    let shape = RelationShape::from_program(program);
    let committed = commit_columns(
        &shape.preprocessed_evaluations,
        shape.preprocessing.width(shape.main_width),
    )?;
    let verifying_key = VerifyingKey {
        domain_size: shape.domain_size,
        main_width: shape.main_width,
        num_public_values: shape.num_public_values,
        public_rows: shape.public_rows.clone(),
        preprocessing: shape.preprocessing,
        preprocessed_commitment: committed.commitment().clone(),
    };
    Ok((
        ProvingKey {
            shape,
            verifying_key: verifying_key.clone(),
        },
        verifying_key,
    ))
}

/// Produce a static proof for the concrete assignment in `program`.
pub fn prove(
    key: &ProvingKey,
    program: &ConstraintProgram,
    public_values: &[Bn254],
) -> Result<Proof, Error> {
    prove_with_main_openings(key, program, public_values, |_, _| {
        Ok(ExtraMainOpenings::default())
    })
}

/// Produce a static proof with caller-selected openings of the directly
/// committed main trace.
pub(crate) fn prove_with_main_openings(
    key: &ProvingKey,
    program: &ConstraintProgram,
    public_values: &[Bn254],
    build_extra_openings: impl FnOnce(
        &TraceCommitment,
        &[Vec<Bn254>],
    ) -> Result<ExtraMainOpenings, String>,
) -> Result<Proof, Error> {
    validate_public_values(key.shape.num_public_values, public_values)?;
    if !key.shape.matches(program) {
        return Err(Error::RelationMismatch);
    }
    let n = key.shape.domain_size;

    let phase = Instant::now();
    let preprocessed_committed = commit_columns(
        &key.shape.preprocessed_evaluations,
        key.preprocessed_width(),
    )?;
    profile_checkpoint("static: preprocessed commitment", phase);
    if preprocessed_committed.commitment() != &key.verifying_key.preprocessed_commitment {
        return Err(Error::PreprocessedCommitment);
    }
    let phase = Instant::now();
    let MainTrace {
        columns: main,
        public_column,
    } = key.shape.main_trace(program, public_values);
    profile_checkpoint("static: main trace construction", phase);
    let phase = Instant::now();
    let main_committed = commit_columns(&main, key.shape.main_width)?;
    profile_checkpoint("static: main commitment", phase);
    let phase = Instant::now();
    let extra =
        build_extra_openings(main_committed.commitment(), &main).map_err(Error::ComposedOpening)?;
    profile_checkpoint("static: composed CAIR callback", phase);

    let mut transcript = Transcript::new(n, public_values);
    transcript.observe_preprocessing(key.shape.preprocessing, key.preprocessed_width());
    transcript.observe_commitment(&key.verifying_key.preprocessed_commitment);
    transcript.observe_commitment(main_committed.commitment());
    if !extra.transcript_binding.is_empty() {
        transcript.observe_binding(&extra.transcript_binding);
    }
    let beta = transcript.challenge();
    let gamma = transcript.challenge();

    let phase = Instant::now();
    let product_oracle = product_oracle(
        &key.shape.preprocessed_evaluations[key.shape.preprocessing.sigma_offset()..],
        &main,
        key.shape.main_width,
        beta,
        gamma,
    )?;
    profile_checkpoint("static: HyperPlonk product oracle", phase);
    let phase = Instant::now();
    let product_committed = commit_mle(product_oracle.clone())?;
    profile_checkpoint("static: product commitment", phase);
    transcript.observe_commitment(product_committed.commitment());

    let local_weights = transcript.challenges(LOCAL_CONSTRAINT_COUNT);
    let local_target = transcript.challenges(n.trailing_zeros() as usize);
    let phase = Instant::now();
    let local = prove_local_sumcheck(
        key.shape.preprocessing,
        &key.shape.preprocessed_evaluations,
        &main,
        &public_column,
        &local_weights,
        &local_target,
        &mut transcript,
    );
    profile_checkpoint("static: local sumcheck", phase);

    let product_target = transcript.challenges(n.trailing_zeros() as usize + 1);
    let phase = Instant::now();
    let product = prove_product_sumcheck(
        &key.shape.preprocessed_evaluations[key.shape.preprocessing.sigma_offset()..],
        &main,
        product_oracle,
        key.shape.main_width,
        beta,
        gamma,
        &product_target,
        &mut transcript,
    );
    profile_checkpoint("static: product sumcheck", phase);

    let product_row_point = &product.point[1..];
    let preprocessed_points = preprocessed_opening_points(
        &local.point,
        product_row_point,
        key.shape.main_width,
        key.shape.preprocessing,
    );
    let mut main_points =
        main_opening_points(&local.point, product_row_point, key.shape.main_width);
    main_points.extend(extra.points);
    let product_points = product_opening_points(&product.point);
    let opening_seed = transcript.opening_seed();

    let main_commitment = main_committed.commitment().clone();
    let auxiliary_commitment = product_committed.commitment().clone();
    let (preprocessed_opening, (main_opening, auxiliary_opening)) = join(
        || {
            let phase = Instant::now();
            let opening = open_points(preprocessed_committed, &preprocessed_points, &opening_seed);
            profile_checkpoint("static: preprocessed WHIR opening", phase);
            opening
        },
        || {
            join(
                || {
                    let phase = Instant::now();
                    let opening = open_points(main_committed, &main_points, &opening_seed);
                    profile_checkpoint("static: main WHIR opening", phase);
                    opening
                },
                || {
                    let phase = Instant::now();
                    let opening = open_points(product_committed, &product_points, &opening_seed);
                    profile_checkpoint("static: product WHIR opening", phase);
                    opening
                },
            )
        },
    );
    Ok(Proof {
        main_width: key.shape.main_width,
        main_commitment,
        auxiliary_commitment,
        local: local.proof,
        product: product.proof,
        preprocessed_opening,
        main_opening,
        auxiliary_opening,
    })
}

fn profile_checkpoint(label: &str, started: Instant) {
    if std::env::var_os("DYNAMIC_SNARK_PROFILE").is_some() {
        eprintln!(
            "profile checkpoint: {label} complete in {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
}

/// Verify a static proof against its relation public inputs.
pub fn verify(key: &VerifyingKey, public_values: &[Bn254], proof: &Proof) -> Result<(), Error> {
    verify_with_main_openings(key, public_values, proof, &ExtraMainOpenings::default())
}

/// Verify a static proof and caller-selected main-trace openings.
pub(crate) fn verify_with_main_openings(
    key: &VerifyingKey,
    public_values: &[Bn254],
    proof: &Proof,
    extra: &ExtraMainOpenings,
) -> Result<(), Error> {
    validate_public_values(key.num_public_values, public_values)?;
    if proof.main_width != key.main_width {
        return Err(Error::QuotientIdentity);
    }
    let n = key.domain_size;
    let variables = n.trailing_zeros() as usize;
    let mut transcript = Transcript::new(n, public_values);
    transcript.observe_preprocessing(key.preprocessing, key.preprocessed_width());
    transcript.observe_commitment(&key.preprocessed_commitment);
    transcript.observe_commitment(&proof.main_commitment);
    if !extra.transcript_binding.is_empty() {
        transcript.observe_binding(&extra.transcript_binding);
    }
    let beta = transcript.challenge();
    let gamma = transcript.challenge();
    transcript.observe_commitment(&proof.auxiliary_commitment);

    let local_weights = transcript.challenges(LOCAL_CONSTRAINT_COUNT);
    let local_target = transcript.challenges(variables);
    let (local_claim, local_point) = verify_sumcheck(
        &proof.local,
        LOCAL_DEGREE,
        variables,
        LOCAL_ROUND_TAG,
        &mut transcript,
    )?;
    let product_target = transcript.challenges(variables + 1);
    let (product_claim, product_point) = verify_sumcheck(
        &proof.product,
        product_degree(key.main_width),
        variables + 1,
        PRODUCT_ROUND_TAG,
        &mut transcript,
    )?;

    let product_row_point = &product_point[1..];
    let preprocessed_points = preprocessed_opening_points(
        &local_point,
        product_row_point,
        key.main_width,
        key.preprocessing,
    );
    let mut main_points = main_opening_points(&local_point, product_row_point, key.main_width);
    main_points.extend(extra.points.iter().cloned());
    let product_points = product_opening_points(&product_point);
    let opening_seed = transcript.opening_seed();

    verify_points(
        n * key.preprocessed_width(),
        &key.preprocessed_commitment,
        &preprocessed_points,
        &proof.preprocessed_opening,
        &opening_seed,
    )?;
    verify_points(
        n * key.main_width,
        &proof.main_commitment,
        &main_points,
        &proof.main_opening,
        &opening_seed,
    )?;
    verify_points(
        2 * n,
        &proof.auxiliary_commitment,
        &product_points,
        &proof.auxiliary_opening,
        &opening_seed,
    )?;

    let pre_values = &proof.preprocessed_opening.evaluations;
    let main_values = &proof.main_opening.evaluations;
    let local_opening_count = key.preprocessing.sigma_offset();
    if pre_values.len() != local_opening_count + key.main_width
        || main_values.len() != GATE_WIDTH + key.main_width + extra.points.len()
        || proof.auxiliary_opening.evaluations.len() != 5
    {
        return Err(Error::QuotientIdentity);
    }

    let public_value = public_mle(&local_point, &key.public_rows, public_values);
    let local_pre = key.preprocessing.local_values(&local_point, pre_values);
    let local_terminal = eq_eval(&local_target, &local_point)
        * combined_local_residual(
            key.preprocessing,
            &local_pre,
            &main_values[..GATE_WIDTH],
            public_value,
            &local_weights,
        );
    if local_terminal != local_claim {
        return Err(Error::QuotientIdentity);
    }

    let product_terminal = product_terminal(
        &product_point,
        &pre_values[local_opening_count..],
        &main_values[GATE_WIDTH..GATE_WIDTH + key.main_width],
        &proof.auxiliary_opening.evaluations,
        key.main_width,
        beta,
        gamma,
    )?;
    if eq_eval(&product_target, &product_point) * product_terminal != product_claim {
        return Err(Error::QuotientIdentity);
    }
    Ok(())
}

/// Flatten a commitment into field elements for a composed transcript.
pub(crate) fn commitment_seed(commitment: &TraceCommitment) -> Vec<Bn254> {
    let mut seed = Vec::new();
    seed.push(Bn254::from_usize(commitment.num_roots()));
    for root in commitment.roots() {
        for chunk in root.chunks_exact(16) {
            seed.push(
                Bn254::from_biguint(num_bigint::BigUint::from_bytes_le(chunk))
                    .expect("a 128-bit commitment limb fits BN254"),
            );
        }
    }
    seed
}

/// Interpret a full main-table MLE point in the protocol's low-bit order.
pub(crate) fn main_table_point(low_bit_point: &[Bn254]) -> Point<Bn254> {
    point_from_low(low_bit_point.to_vec())
}

struct ProvedSumcheck {
    proof: SumcheckProof,
    point: Vec<Bn254>,
}

fn prove_local_sumcheck(
    layout: PreprocessingLayout,
    preprocessed: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    public_column: &[Bn254],
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut Transcript,
) -> ProvedSumcheck {
    let local_columns = layout.local_columns();
    let local_width = local_columns.len();
    let mut columns = local_columns
        .iter()
        .map(|&column| layout.local_table(column, main[0].len(), preprocessed))
        .chain(main[..GATE_WIDTH].iter().cloned())
        .chain([public_column.to_vec()])
        .collect::<Vec<_>>();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(target.len());
    let mut rounds = Vec::with_capacity(target.len());
    for round in 0..target.len() {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            LOCAL_DEGREE + 1,
            (LOCAL_DEGREE + 1) * columns.len(),
            || (),
            |scratch, pair, t| {
                let _ = scratch;

                let mut pre = [Bn254::ZERO; LOCAL_PRE_WIDTH];
                for (position, &column) in local_columns.iter().enumerate() {
                    pre[column] = lerp(
                        columns[position][2 * pair],
                        columns[position][2 * pair + 1],
                        t,
                    );
                }
                let main = core::array::from_fn::<_, GATE_WIDTH, _>(|column| {
                    lerp(
                        columns[local_width + column][2 * pair],
                        columns[local_width + column][2 * pair + 1],
                        t,
                    )
                });
                let public = lerp(
                    columns[local_width + GATE_WIDTH][2 * pair],
                    columns[local_width + GATE_WIDTH][2 * pair + 1],
                    t,
                );
                lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_local_residual(layout, &pre, &main, public, weights)
            },
        );
        transcript.observe_message(LOCAL_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge();
        point.push(challenge);
        fold(&mut eq, challenge);
        crate::parallel::fold_columns(&mut columns, challenge);
        rounds.push(evaluations);
    }
    ProvedSumcheck {
        proof: SumcheckProof { rounds },
        point,
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_product_sumcheck(
    permutation: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    product: Vec<Bn254>,
    main_width: usize,
    beta: Bn254,
    gamma: Bn254,
    target: &[Bn254],
    transcript: &mut Transcript,
) -> ProvedSumcheck {
    let n = main[0].len();
    debug_assert_eq!(product.len(), 2 * n);
    debug_assert_eq!(target.len(), n.trailing_zeros() as usize + 1);
    let lift = |values: &[Bn254]| {
        values
            .par_iter()
            .flat_map_iter(|&value| [value, value])
            .collect::<Vec<_>>()
    };
    let mut columns = Vec::with_capacity(2 * main_width + 6);
    columns.extend(permutation.iter().map(|column| lift(column)));
    columns.extend(main.iter().map(|column| lift(column)));
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| product[2 * (index >> 1)])
            .collect(),
    );
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| product[2 * (index >> 1) + 1])
            .collect(),
    );
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| product[index >> 1])
            .collect(),
    );
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| product[(index >> 1) | n])
            .collect(),
    );
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| Bn254::from_bool(index & 1 == 1))
            .collect(),
    );
    // All identity labels are affine in one row-index MLE. No identity
    // columns are committed or retained in the proving key.
    columns.push(
        (0..2 * n)
            .into_par_iter()
            .map(|index| Bn254::from_usize(index >> 1))
            .collect(),
    );

    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(target.len());
    let mut rounds = Vec::with_capacity(target.len());
    for round in 0..target.len() {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            product_degree(main_width) + 1,
            (product_degree(main_width) + 1) * columns.len(),
            || vec![Bn254::ZERO; columns.len()],
            |scratch, pair, t| {
                for (value, column) in scratch.iter_mut().zip(&columns) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                let values = &*scratch;
                lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_product_residual(&values, main_width, beta, gamma)
            },
        );
        transcript.observe_message(PRODUCT_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge();
        point.push(challenge);
        fold(&mut eq, challenge);
        crate::parallel::fold_columns(&mut columns, challenge);
        rounds.push(evaluations);
    }
    ProvedSumcheck {
        proof: SumcheckProof { rounds },
        point,
    }
}

fn verify_sumcheck(
    proof: &SumcheckProof,
    degree: usize,
    variables: usize,
    round_tag: u64,
    transcript: &mut Transcript,
) -> Result<(Bn254, Vec<Bn254>), Error> {
    if proof.rounds.len() != variables {
        return Err(Error::Sumcheck);
    }
    let mut claim = Bn254::ZERO;
    let mut point = Vec::with_capacity(variables);
    for (round, evaluations) in proof.rounds.iter().enumerate() {
        if evaluations.len() != degree + 1 || evaluations[0] + evaluations[1] != claim {
            return Err(Error::Sumcheck);
        }
        transcript.observe_message(round_tag + round as u64, evaluations);
        let challenge = transcript.challenge();
        claim = interpolate(evaluations, challenge);
        point.push(challenge);
    }
    Ok((claim, point))
}

fn combined_local_residual(
    layout: PreprocessingLayout,
    pre: &[Bn254],
    main: &[Bn254],
    public_value: Bn254,
    weights: &[Bn254],
) -> Bn254 {
    evaluate_local_constraints(layout, pre, main, public_value)
        .into_iter()
        .zip(weights)
        .fold(Bn254::ZERO, |sum, (residual, &weight)| {
            sum + residual * weight
        })
}

fn combined_product_residual(
    values: &[Bn254],
    main_width: usize,
    beta: Bn254,
    gamma: Bn254,
) -> Bn254 {
    let labels = &values[..main_width];
    let main = &values[main_width..2 * main_width];
    let work = &values[2 * main_width..];
    debug_assert_eq!(work.len(), 6);
    let row_base = Bn254::from_usize(main_width) * work[5];
    let numerator = (0..main_width).fold(Bn254::ONE, |product, slot| {
        product * (beta * (row_base + Bn254::from_usize(slot + 1)) + main[slot] + gamma)
    });
    let denominator = (0..main_width).fold(Bn254::ONE, |product, slot| {
        product * (beta * labels[slot] + main[slot] + gamma)
    });
    let leaf = work[0];
    let internal = work[1];
    let shifted_zero = work[2];
    let shifted_one = work[3];
    let branch = work[4];
    (Bn254::ONE - branch) * (denominator * leaf - numerator)
        + branch * (internal - shifted_zero * shifted_one)
}

const fn product_degree(main_width: usize) -> usize {
    main_width + 2
}

#[allow(clippy::too_many_arguments)]
fn product_terminal(
    point: &[Bn254],
    labels: &[Bn254],
    main: &[Bn254],
    product: &[Bn254],
    main_width: usize,
    beta: Bn254,
    gamma: Bn254,
) -> Result<Bn254, Error> {
    if point.is_empty()
        || labels.len() != main_width
        || main.len() != main_width
        || product.len() != 5
    {
        return Err(Error::QuotientIdentity);
    }
    let mut values = Vec::with_capacity(2 * main_width + 6);
    values.extend_from_slice(labels);
    values.extend_from_slice(main);
    values.extend_from_slice(&product[..4]);
    values.push(point[0]);
    values.push(
        point[1..]
            .iter()
            .enumerate()
            .map(|(bit, &value)| Bn254::from_usize(1usize << bit) * value)
            .sum(),
    );
    if product[4] != Bn254::ONE {
        return Err(Error::QuotientIdentity);
    }
    Ok(combined_product_residual(&values, main_width, beta, gamma))
}

fn product_oracle(
    permutation: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    main_width: usize,
    beta: Bn254,
    gamma: Bn254,
) -> Result<Vec<Bn254>, Error> {
    let n = main[0].len();
    let mut numerators = vec![Bn254::ONE; n];
    let mut denominators = vec![Bn254::ONE; n];
    numerators
        .par_iter_mut()
        .zip(denominators.par_iter_mut())
        .enumerate()
        .for_each(|(row, (numerator, denominator))| {
            *numerator = (0..main_width).fold(Bn254::ONE, |product, slot| {
                product
                    * (beta * Bn254::from_usize(main_width * row + slot + 1)
                        + main[slot][row]
                        + gamma)
            });
            *denominator = (0..main_width).fold(Bn254::ONE, |product, slot| {
                product * (beta * permutation[slot][row] + main[slot][row] + gamma)
            });
        });
    if denominators.par_iter().any(|value| value.is_zero()) {
        return Err(Error::ProductDenominator);
    }
    let mut inverses = vec![Bn254::ZERO; n];
    let chunk = crate::parallel::grain(n, 2048);
    denominators
        .par_chunks(chunk)
        .zip(inverses.par_chunks_mut(chunk))
        .for_each(|(values, inverses)| {
            batch_multiplicative_inverse_general(values, inverses, |value| value.inverse());
        });
    numerators
        .par_iter_mut()
        .zip(inverses.par_iter())
        .for_each(|(value, inverse)| *value *= *inverse);
    let mut values = vec![Bn254::ZERO; 2 * n];
    values
        .par_chunks_mut(2)
        .zip(numerators.par_iter())
        .for_each(|(row, &value)| row[0] = value);
    // Level d occupies indices 2^(d+2)*k + 2^(d+1)-1. Its children
    // pair the two halves of the preceding level, matching the original recurrence.
    let mut level = numerators;
    let mut stride = 4;
    while level.len() > 1 {
        let half = level.len() / 2;
        let next = level[..half]
            .par_iter()
            .zip(level[half..].par_iter())
            .map(|(&a, &b)| a * b)
            .collect::<Vec<_>>();
        values
            .par_chunks_mut(stride)
            .zip(next.par_iter())
            .for_each(|(block, &value)| block[stride / 2 - 1] = value);
        level = next;
        stride *= 2;
    }
    // The all-ones slot is the sentinel zero, as in the original oracle.
    Ok(values)
}

fn preprocessed_opening_points(
    local: &[Bn254],
    product: &[Bn254],
    main_width: usize,
    layout: PreprocessingLayout,
) -> Vec<Point<Bn254>> {
    let offset = layout.sigma_offset();
    let width = layout.width(main_width);
    let mut points = (0..offset)
        .map(|column| table_point(column, local, width))
        .collect::<Vec<_>>();
    points.extend((offset..offset + main_width).map(|column| table_point(column, product, width)));
    points
}

fn main_opening_points(local: &[Bn254], product: &[Bn254], main_width: usize) -> Vec<Point<Bn254>> {
    (0..GATE_WIDTH)
        .map(|column| table_point(column, local, main_width))
        .chain((0..main_width).map(|column| table_point(column, product, main_width)))
        .collect()
}

fn product_opening_points(point: &[Bn254]) -> Vec<Point<Bn254>> {
    let mut leaf = point.to_vec();
    leaf[0] = Bn254::ZERO;
    let mut internal = point.to_vec();
    internal[0] = Bn254::ONE;
    let mut shifted_zero = point[1..].to_vec();
    shifted_zero.push(Bn254::ZERO);
    let mut shifted_one = point[1..].to_vec();
    shifted_one.push(Bn254::ONE);
    let mut root = vec![Bn254::ONE; point.len()];
    *root.last_mut().expect("a product point is nonempty") = Bn254::ZERO;
    [leaf, internal, shifted_zero, shifted_one, root]
        .into_iter()
        .map(point_from_low)
        .collect()
}

fn point_from_low(low: Vec<Bn254>) -> Point<Bn254> {
    Point::new(low.into_iter().rev().collect())
}

fn table_point(column: usize, row_point: &[Bn254], width: usize) -> Point<Bn254> {
    debug_assert!(width.is_power_of_two() && column < width);
    let mut low = (0..width.trailing_zeros() as usize)
        .map(|bit| Bn254::from_bool(column & (1 << bit) != 0))
        .collect::<Vec<_>>();
    low.extend_from_slice(row_point);
    Point::new(low.into_iter().rev().collect())
}

fn commit_columns(columns: &[Vec<Bn254>], width: usize) -> Result<MleCommitted, Error> {
    if columns.is_empty()
        || columns.len() > width
        || !width.is_power_of_two()
        || columns
            .iter()
            .any(|column| column.len() != columns[0].len())
    {
        return Err(Error::Whir("invalid direct MLE column layout".to_string()));
    }
    let rows = columns[0].len();
    let table = crate::parallel::pack_columns(
        rows,
        width,
        &columns.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    commit_mle(table)
}

fn open_points(committed: MleCommitted, points: &[Point<Bn254>], seed: &[Bn254]) -> OpeningProof {
    committed.whir.open(committed.batch, points, seed)
}

fn verify_points(
    table_len: usize,
    commitment: &Commitment,
    points: &[Point<Bn254>],
    opening: &OpeningProof,
    seed: &[Bn254],
) -> Result<(), Error> {
    let whir = ExplicitWhir::new(table_len.trailing_zeros() as usize).map_err(Error::Whir)?;
    whir.verify(commitment, points, opening, seed)
        .map_err(|error| Error::Whir(error.to_string()))
}

fn public_mle(point: &[Bn254], public_rows: &[(usize, usize)], public_values: &[Bn254]) -> Bn254 {
    public_rows
        .iter()
        .fold(Bn254::ZERO, |sum, &(row, public_index)| {
            sum + public_values[public_index] * eq_at_index_low(point, row)
        })
}

fn eq_evaluations(point: &[Bn254]) -> Vec<Bn254> {
    crate::parallel::eq_evaluations(point)
}

fn eq_eval(left: &[Bn254], right: &[Bn254]) -> Bn254 {
    left.iter()
        .zip(right)
        .fold(Bn254::ONE, |product, (&left, &right)| {
            product * ((Bn254::ONE - left) * (Bn254::ONE - right) + left * right)
        })
}

fn eq_at_index_low(point: &[Bn254], index: usize) -> Bn254 {
    point
        .iter()
        .enumerate()
        .fold(Bn254::ONE, |product, (bit, &coordinate)| {
            product
                * if index & (1 << bit) == 0 {
                    Bn254::ONE - coordinate
                } else {
                    coordinate
                }
        })
}

fn fold(values: &mut Vec<Bn254>, challenge: Bn254) {
    crate::parallel::fold(values, challenge);
}

fn lerp(zero: Bn254, one: Bn254, point: Bn254) -> Bn254 {
    zero + point * (one - zero)
}

fn interpolate(evaluations: &[Bn254], point: Bn254) -> Bn254 {
    debug_assert!(!evaluations.is_empty());
    let mut scratch = (0..evaluations.len())
        .map(|index| {
            let x = Bn254::from_usize(index);
            (0..evaluations.len())
                .filter(|&other| other != index)
                .fold(Bn254::ONE, |product, other| {
                    product * (x - Bn254::from_usize(other))
                })
        })
        .collect::<Vec<_>>();
    let mut inverse_denominators = vec![Bn254::ZERO; scratch.len()];
    batch_multiplicative_inverse_general(&scratch, &mut inverse_denominators, |value| {
        value.inverse()
    });
    scratch.resize(evaluations.len() + 1, Bn254::ZERO);
    scratch[0] = Bn254::ONE;
    for index in 0..evaluations.len() {
        scratch[index + 1] = scratch[index] * (point - Bn254::from_usize(index));
    }
    let mut suffix = Bn254::ONE;
    (0..evaluations.len())
        .rev()
        .fold(Bn254::ZERO, |sum, index| {
            let result =
                sum + evaluations[index] * scratch[index] * suffix * inverse_denominators[index];
            suffix *= point - Bn254::from_usize(index);
            result
        })
}

fn validate_public_values(expected: usize, actual: &[Bn254]) -> Result<(), Error> {
    if actual.len() != expected {
        return Err(Error::PublicInputCount {
            expected,
            actual: actual.len(),
        });
    }
    Ok(())
}

struct Transcript {
    raw: RawTranscript,
    counter: u64,
}

impl Transcript {
    fn observe_preprocessing(&mut self, layout: PreprocessingLayout, width: usize) {
        self.observe(Bn254::from_usize(width));
        for value in layout.statement_elements() {
            self.observe(value);
        }
    }

    fn new(domain_size: usize, public_values: &[Bn254]) -> Self {
        let mut transcript = Self {
            raw: RawTranscript::new(0x5354_4154_4d4c_4553),
            counter: 0,
        };
        transcript.observe(Bn254::from_u64(STATIC_VERSION));
        transcript.observe(Bn254::from_usize(domain_size));
        transcript.observe(Bn254::from_usize(public_values.len()));
        for &value in public_values {
            transcript.observe(value);
        }
        transcript
    }

    fn observe(&mut self, value: Bn254) {
        self.raw.absorb(value);
    }

    fn observe_commitment(&mut self, commitment: &Commitment) {
        for element in commitment_seed(commitment) {
            self.observe(element);
        }
    }

    fn observe_binding(&mut self, binding: &[Bn254]) {
        self.observe(Bn254::from_usize(binding.len()));
        for &element in binding {
            self.observe(element);
        }
    }

    fn observe_message(&mut self, tag: u64, message: &[Bn254]) {
        self.observe(Bn254::from_u64(tag));
        self.observe(Bn254::from_usize(message.len()));
        for &value in message {
            self.observe(value);
        }
    }

    fn challenge(&mut self) -> Bn254 {
        let result = self.raw.challenge(0x5354_4154_4348_0000 + self.counter);
        self.counter += 1;
        result
    }

    fn challenges(&mut self, count: usize) -> Vec<Bn254> {
        (0..count).map(|_| self.challenge()).collect()
    }

    fn opening_seed(&self) -> [Bn254; 2] {
        [
            self.raw.challenge(0x5354_4154_4f50_0000 + self.counter),
            self.raw.challenge(0x5354_4154_4f50_8000 + self.counter),
        ]
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::MerkleCap;

    use super::*;

    fn arithmetic_program(public: Bn254) -> ConstraintProgram {
        let mut builder = ProgramBuilder::new(1);
        let input = builder.public(0, public);
        let two = builder.constant(Bn254::TWO);
        let sum = builder.add(input, two);
        let product = builder.mul(sum, input);
        let fifth = builder.pow5_add(product, Bn254::ONE);
        let affine = builder.lin3(
            [input, sum, product],
            [Bn254::ONE, Bn254::TWO, Bn254::from_u64(3)],
            Bn254::from_u64(4),
        );
        builder.assert_boolean(input);
        builder.assert_equal(fifth, fifth);
        builder.assert_equal(affine, affine);
        builder.finish()
    }

    #[test]
    fn static_snark_round_trip() {
        let public = Bn254::ONE;
        let program = arithmetic_program(public);
        let (pk, vk) = setup(&program).unwrap();
        let proof = prove(&pk, &program, &[public]).unwrap();
        verify(&vk, &[public], &proof).unwrap();
    }

    #[test]
    fn wrong_public_input_is_rejected() {
        let program = arithmetic_program(Bn254::ONE);
        let (pk, vk) = setup(&program).unwrap();
        let proof = prove(&pk, &program, &[Bn254::ONE]).unwrap();
        assert!(verify(&vk, &[Bn254::TWO], &proof).is_err());
    }

    #[test]
    fn invalid_witness_is_rejected() {
        let public = Bn254::ONE;
        let program = arithmetic_program(public);
        let (pk, vk) = setup(&program).unwrap();
        let mut invalid = program.clone();
        invalid.values[0] = Bn254::from_u64(9);
        let proof = prove(&pk, &invalid, &[public]).unwrap();
        assert!(verify(&vk, &[public], &proof).is_err());
    }

    #[test]
    fn product_oracle_satisfies_hyperplonk_recurrence() {
        let program = arithmetic_program(Bn254::ONE);
        let shape = RelationShape::from_program(&program);
        let main = shape.main_trace(&program, &[Bn254::ONE]).columns;
        let beta = Bn254::from_u64(17);
        let gamma = Bn254::from_u64(29);
        let oracle = product_oracle(
            &shape.preprocessed_evaluations[shape.preprocessing.sigma_offset()..],
            &main,
            shape.main_width,
            beta,
            gamma,
        )
        .unwrap();
        let n = shape.domain_size;
        for row in 0..n {
            let numerator = (0..shape.main_width).fold(Bn254::ONE, |product, slot| {
                product
                    * (beta * Bn254::from_usize(shape.main_width * row + slot + 1)
                        + main[slot][row]
                        + gamma)
            });
            let denominator = (0..shape.main_width).fold(Bn254::ONE, |product, slot| {
                product
                    * (beta
                        * shape.preprocessed_evaluations[shape.preprocessing.sigma_offset() + slot]
                            [row]
                        + main[slot][row]
                        + gamma)
            });
            assert_eq!(denominator * oracle[2 * row], numerator);
            assert_eq!(oracle[2 * row + 1], oracle[row] * oracle[row | n]);
        }
        assert_eq!(oracle[n - 1], Bn254::ONE);
    }

    #[test]
    fn verifier_rejects_tampering_at_every_static_proof_layer() {
        let public = Bn254::ONE;
        let program = arithmetic_program(public);
        let (pk, vk) = setup(&program).unwrap();
        let proof = prove(&pk, &program, &[public]).unwrap();
        verify(&vk, &[public], &proof).unwrap();

        let perturb_commitment = |commitment: &Commitment| -> Commitment {
            let mut roots = commitment.roots().to_vec();
            roots[0][0] = roots[0][0].wrapping_add(1);
            MerkleCap::new(roots)
        };

        let mut bad = proof.clone();
        bad.main_commitment = perturb_commitment(&bad.main_commitment);
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.auxiliary_commitment = perturb_commitment(&bad.auxiliary_commitment);
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.preprocessed_opening.evaluations[0] += Bn254::ONE;
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.main_opening.evaluations[0] += Bn254::ONE;
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.auxiliary_opening.evaluations[0] += Bn254::ONE;
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.local.rounds[0][0] += Bn254::ONE;
        assert!(verify(&vk, &[public], &bad).is_err());

        let mut bad = proof.clone();
        bad.product.rounds[0][0] += Bn254::ONE;
        assert!(verify(&vk, &[public], &bad).is_err());

        assert!(matches!(
            verify(&vk, &[], &proof),
            Err(Error::PublicInputCount { .. })
        ));
    }

    #[test]
    fn aligned_tables_are_exactly_the_assignment_and_conjugated_sigma() {
        // The original cycle order differs from sorted order: P must retain it exactly.
        let mut sigma = (0..31).collect::<Vec<_>>();
        sigma[2] = 30;
        sigma[30] = 6;
        sigma[6] = 2;
        let circuit = crate::circuit::Circuit::new(5, 1, sigma.clone()).unwrap();
        let mut z = vec![1, 2, 3, 4, 5, 20].repeat(5);
        z[6] = 3;
        z[8] = 5;
        z.push(3);
        let z = z.into_iter().map(Bn254::from_u64).collect::<Vec<_>>();
        let program = crate::dynamic::regular_hyperplonk_program(&circuit, &z).unwrap();
        let shape = RelationShape::from_program(&program);
        let trace = shape.main_trace(&program, &[z[30]]);
        assert_eq!(shape.main_width, 4);
        assert_eq!(shape.domain_size, 16);
        let address = |i: usize| if i < 30 { 4 * (i / 3) + i % 3 } else { 3 };
        let mut expected_w = vec![Bn254::ZERO; 64];
        let mut expected_p = (1..=64).map(Bn254::from_usize).collect::<Vec<_>>();
        for i in 0..31 {
            expected_w[address(i)] = z[i];
            expected_p[address(i)] = Bn254::from_usize(address(sigma[i]) + 1);
        }
        for t in 0..64 {
            assert_eq!(trace.columns[t % 4][t / 4], expected_w[t]);
            assert_eq!(shape.preprocessed_evaluations[t % 4][t / 4], expected_p[t]);
        }
    }

    #[test]
    fn arithmetic_baseline_commits_only_permutation_and_binds_public_column() {
        let n = 3;
        let n0 = 2;
        let mut permutation = (0..6 * n + n0).collect::<Vec<_>>();
        permutation[0] = 6;
        permutation[6] = 12;
        permutation[12] = 0;
        let circuit = crate::circuit::Circuit::new(n, n0, permutation).unwrap();
        let assignment = [vec![1, 2, 3, 4, 5, 20].repeat(n), vec![9, 11]]
            .concat()
            .into_iter()
            .map(Bn254::from_u64)
            .collect::<Vec<_>>();
        let public = [Bn254::from_u64(9), Bn254::from_u64(11)];
        let program = crate::dynamic::regular_hyperplonk_program(&circuit, &assignment).unwrap();
        let (pk, vk) = setup(&program).unwrap();
        assert_eq!(pk.preprocessed_width(), 4);
        assert_eq!(vk.preprocessed_width(), 4);
        assert_eq!(pk.shape.preprocessed_evaluations.len(), 4);
        let proof = prove(&pk, &program, &public).unwrap();
        assert_eq!(proof.preprocessed_opening.evaluations.len(), 4);
        verify(&vk, &public, &proof).unwrap();
        assert!(verify(&vk, &[public[1], public[0]], &proof).is_err());
        let mut bad = proof.clone();
        bad.preprocessed_opening.evaluations[0] += Bn254::ONE;
        assert!(verify(&vk, &public, &bad).is_err());
        let mut wrong_shape = vk.clone();
        wrong_shape.preprocessing = PreprocessingLayout::Arithmetic {
            gate_pairs: 2,
            public_inputs: 2,
        };
        assert!(verify(&wrong_shape, &public, &proof).is_err());
    }
}
