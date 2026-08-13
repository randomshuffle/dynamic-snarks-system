//! Transparent preprocessed multilinear SNARK backed by Plonky3's WHIR IOPP.
//!
//! Trace columns are committed directly as Boolean-hypercube evaluations. A
//! degree-eight sumcheck checks the local relation, while a second sumcheck
//! checks a compact heap product proving the fixed wiring permutation. WHIR's
//! Reed--Solomon encoding remains an internal commitment detail; no univariate
//! trace interpolation or quotient polynomial is needed.

mod air;
mod pcs;
pub(crate) mod program;

use air::{
    ID0, LOCAL_CONSTRAINT_COUNT, MAIN_WIDTH, MainTrace, PRE_WIDTH, RelationShape, SIGMA0,
    evaluate_local_constraints,
};
use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, batch_multiplicative_inverse_general};
use p3_multilinear_util::point::Point;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::hash_node;
use pcs::{Commitment, ExplicitWhir, OpeningProof};

pub use program::{ConstraintProgram, ProgramBuilder, Variable};

const STATIC_VERSION: u64 = 2;
const LOCAL_DEGREE: usize = 8;
const PRODUCT_DEGREE: usize = 5;
const PRODUCT_WIDTH: usize = 2;
const STANDARD_MAIN_OPENINGS: usize = 2 * MAIN_WIDTH;
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

/// Number of fixed preprocessing columns in every static relation trace.
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
    num_public_values: usize,
    public_rows: Vec<(usize, usize)>,
    preprocessed_commitment: Commitment,
}

impl ProvingKey {
    /// Number of rows in the padded multilinear trace for this relation.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.shape.domain_size
    }
}

impl VerifyingKey {
    /// Number of rows in the padded multilinear trace for this relation.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.domain_size
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
        &self.main_opening.evaluations[STANDARD_MAIN_OPENINGS..]
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
    let committed = commit_columns(&shape.preprocessed_evaluations, PRE_WIDTH)?;
    let verifying_key = VerifyingKey {
        domain_size: shape.domain_size,
        num_public_values: shape.num_public_values,
        public_rows: shape.public_rows.clone(),
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

    let preprocessed_committed = commit_columns(&key.shape.preprocessed_evaluations, PRE_WIDTH)?;
    if preprocessed_committed.commitment() != &key.verifying_key.preprocessed_commitment {
        return Err(Error::PreprocessedCommitment);
    }
    let MainTrace {
        columns: main,
        public_column,
    } = key.shape.main_trace(program, public_values);
    let main_committed = commit_columns(&main, MAIN_WIDTH)?;
    let extra =
        build_extra_openings(main_committed.commitment(), &main).map_err(Error::ComposedOpening)?;

    let mut transcript = Transcript::new(n, public_values);
    transcript.observe_commitment(&key.verifying_key.preprocessed_commitment);
    transcript.observe_commitment(main_committed.commitment());
    if !extra.transcript_binding.is_empty() {
        transcript.observe_binding(&extra.transcript_binding);
    }
    let beta = transcript.challenge();
    let gamma = transcript.challenge();

    let product_columns = product_heap(&key.shape.preprocessed_evaluations, &main, beta, gamma);
    let product_committed = commit_columns(&product_columns, PRODUCT_WIDTH)?;
    transcript.observe_commitment(product_committed.commitment());

    let local_weights = transcript.challenges(LOCAL_CONSTRAINT_COUNT);
    let local_target = transcript.challenges(n.trailing_zeros() as usize);
    let local = prove_local_sumcheck(
        &key.shape.preprocessed_evaluations,
        &main,
        &public_column,
        &local_weights,
        &local_target,
        &mut transcript,
    );

    let product_weights = transcript.challenges(4);
    let product_target = transcript.challenges(n.trailing_zeros() as usize);
    let product = prove_product_sumcheck(
        &key.shape.preprocessed_evaluations,
        &main,
        &product_columns,
        beta,
        gamma,
        &product_weights,
        &product_target,
        &mut transcript,
    );

    let preprocessed_points = preprocessed_opening_points(&local.point, &product.point);
    let mut main_points = main_opening_points(&local.point, &product.point);
    main_points.extend(extra.points);
    let product_points = product_opening_points(&product.point, n);
    let opening_seed = transcript.opening_seed();

    let main_commitment = main_committed.commitment().clone();
    let auxiliary_commitment = product_committed.commitment().clone();
    Ok(Proof {
        main_commitment,
        auxiliary_commitment,
        local: local.proof,
        product: product.proof,
        preprocessed_opening: open_points(
            preprocessed_committed,
            &preprocessed_points,
            &opening_seed,
        ),
        main_opening: open_points(main_committed, &main_points, &opening_seed),
        auxiliary_opening: open_points(product_committed, &product_points, &opening_seed),
    })
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
    let n = key.domain_size;
    let variables = n.trailing_zeros() as usize;
    let mut transcript = Transcript::new(n, public_values);
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
    let product_weights = transcript.challenges(4);
    let product_target = transcript.challenges(variables);
    let (product_claim, product_point) = verify_sumcheck(
        &proof.product,
        PRODUCT_DEGREE,
        variables,
        PRODUCT_ROUND_TAG,
        &mut transcript,
    )?;

    let preprocessed_points = preprocessed_opening_points(&local_point, &product_point);
    let mut main_points = main_opening_points(&local_point, &product_point);
    main_points.extend(extra.points.iter().cloned());
    let product_points = product_opening_points(&product_point, n);
    let opening_seed = transcript.opening_seed();

    verify_points(
        n * PRE_WIDTH,
        &key.preprocessed_commitment,
        &preprocessed_points,
        &proof.preprocessed_opening,
        &opening_seed,
    )?;
    verify_points(
        n * MAIN_WIDTH,
        &proof.main_commitment,
        &main_points,
        &proof.main_opening,
        &opening_seed,
    )?;
    verify_points(
        2 * n * PRODUCT_WIDTH,
        &proof.auxiliary_commitment,
        &product_points,
        &proof.auxiliary_opening,
        &opening_seed,
    )?;

    let pre_values = &proof.preprocessed_opening.evaluations;
    let main_values = &proof.main_opening.evaluations;
    if pre_values.len() != PRE_WIDTH + 8
        || main_values.len() != STANDARD_MAIN_OPENINGS + extra.points.len()
        || proof.auxiliary_opening.evaluations.len() != 10
    {
        return Err(Error::QuotientIdentity);
    }

    let public_value = public_mle(&local_point, &key.public_rows, public_values);
    let local_terminal = eq_eval(&local_target, &local_point)
        * combined_local_residual(
            &pre_values[..PRE_WIDTH],
            &main_values[..MAIN_WIDTH],
            public_value,
            &local_weights,
        );
    if local_terminal != local_claim {
        return Err(Error::QuotientIdentity);
    }

    let product_terminal = product_terminal(
        &product_point,
        &pre_values[PRE_WIDTH..],
        &main_values[MAIN_WIDTH..STANDARD_MAIN_OPENINGS],
        &proof.auxiliary_opening.evaluations,
        beta,
        gamma,
        &product_weights,
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
        seed.extend(root);
    }
    seed
}

/// Select main column zero at a low-bit-first multilinear row point.
pub(crate) fn main_column_point(low_bit_point: &[Bn254], trace_len: usize) -> Point<Bn254> {
    debug_assert!(trace_len.is_power_of_two());
    debug_assert_eq!(low_bit_point.len(), trace_len.trailing_zeros() as usize);
    table_point(0, low_bit_point, MAIN_WIDTH)
}

struct ProvedSumcheck {
    proof: SumcheckProof,
    point: Vec<Bn254>,
}

fn prove_local_sumcheck(
    preprocessed: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    public_column: &[Bn254],
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut Transcript,
) -> ProvedSumcheck {
    let mut columns = preprocessed
        .iter()
        .cloned()
        .chain(main.iter().cloned())
        .chain([public_column.to_vec()])
        .collect::<Vec<_>>();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(target.len());
    let mut rounds = Vec::with_capacity(target.len());
    for round in 0..target.len() {
        let mut evaluations = vec![Bn254::ZERO; LOCAL_DEGREE + 1];
        for (evaluation_index, evaluation) in evaluations.iter_mut().enumerate() {
            let t = Bn254::from_usize(evaluation_index);
            for pair in 0..eq.len() / 2 {
                let pre = core::array::from_fn::<_, PRE_WIDTH, _>(|column| {
                    lerp(columns[column][2 * pair], columns[column][2 * pair + 1], t)
                });
                let main = core::array::from_fn::<_, MAIN_WIDTH, _>(|column| {
                    lerp(
                        columns[PRE_WIDTH + column][2 * pair],
                        columns[PRE_WIDTH + column][2 * pair + 1],
                        t,
                    )
                });
                let public = lerp(
                    columns[PRE_WIDTH + MAIN_WIDTH][2 * pair],
                    columns[PRE_WIDTH + MAIN_WIDTH][2 * pair + 1],
                    t,
                );
                *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_local_residual(&pre, &main, public, weights);
            }
        }
        transcript.observe_message(LOCAL_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge();
        point.push(challenge);
        fold(&mut eq, challenge);
        for column in &mut columns {
            fold(column, challenge);
        }
        rounds.push(evaluations);
    }
    ProvedSumcheck {
        proof: SumcheckProof { rounds },
        point,
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_product_sumcheck(
    preprocessed: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    heap: &[Vec<Bn254>],
    beta: Bn254,
    gamma: Bn254,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut Transcript,
) -> ProvedSumcheck {
    let n = main[0].len();
    let mut columns = Vec::with_capacity(8 + MAIN_WIDTH + 9);
    columns.extend((ID0..ID0 + 4).map(|column| preprocessed[column].clone()));
    columns.extend((SIGMA0..SIGMA0 + 4).map(|column| preprocessed[column].clone()));
    columns.extend(main.iter().cloned());
    for side in 0..2 {
        columns.push(heap[side][..n].to_vec());
        columns.push((0..n).map(|row| heap[side][2 * row]).collect());
        columns.push((0..n).map(|row| heap[side][2 * row + 1]).collect());
        columns.push(heap[side][n..].to_vec());
    }
    let mut internal = vec![Bn254::ONE; n];
    internal[0] = Bn254::ZERO;
    columns.push(internal);

    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(target.len());
    let mut rounds = Vec::with_capacity(target.len());
    for round in 0..target.len() {
        let mut evaluations = vec![Bn254::ZERO; PRODUCT_DEGREE + 1];
        for (evaluation_index, evaluation) in evaluations.iter_mut().enumerate() {
            let t = Bn254::from_usize(evaluation_index);
            for pair in 0..eq.len() / 2 {
                let values = core::array::from_fn::<_, { 8 + MAIN_WIDTH + 9 }, _>(|column| {
                    lerp(columns[column][2 * pair], columns[column][2 * pair + 1], t)
                });
                *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * combined_product_residual(&values, beta, gamma, weights);
            }
        }
        transcript.observe_message(PRODUCT_ROUND_TAG + round as u64, &evaluations);
        let challenge = transcript.challenge();
        point.push(challenge);
        fold(&mut eq, challenge);
        for column in &mut columns {
            fold(column, challenge);
        }
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
    pre: &[Bn254],
    main: &[Bn254],
    public_value: Bn254,
    weights: &[Bn254],
) -> Bn254 {
    evaluate_local_constraints(pre, main, public_value)
        .into_iter()
        .zip(weights)
        .fold(Bn254::ZERO, |sum, (residual, &weight)| {
            sum + residual * weight
        })
}

fn combined_product_residual(
    values: &[Bn254],
    beta: Bn254,
    gamma: Bn254,
    weights: &[Bn254],
) -> Bn254 {
    let labels = &values[..8];
    let main = &values[8..8 + MAIN_WIDTH];
    let work = &values[8 + MAIN_WIDTH..];
    let numerator = (0..4).fold(Bn254::ONE, |product, slot| {
        product * (beta * labels[slot] + main[slot] + gamma)
    });
    let denominator = (0..4).fold(Bn254::ONE, |product, slot| {
        product * (beta * labels[4 + slot] + main[slot] + gamma)
    });
    let internal = work[8];
    weights[0] * internal * (work[0] - work[1] * work[2])
        + weights[1] * internal * (work[4] - work[5] * work[6])
        + weights[2] * (work[3] - numerator)
        + weights[3] * (work[7] - denominator)
}

#[allow(clippy::too_many_arguments)]
fn product_terminal(
    point: &[Bn254],
    labels: &[Bn254],
    main: &[Bn254],
    heap: &[Bn254],
    beta: Bn254,
    gamma: Bn254,
    weights: &[Bn254],
) -> Result<Bn254, Error> {
    if labels.len() != 8 || main.len() != MAIN_WIDTH || heap.len() != 10 {
        return Err(Error::QuotientIdentity);
    }
    let numerator = (0..4).fold(Bn254::ONE, |product, slot| {
        product * (beta * labels[slot] + main[slot] + gamma)
    });
    let denominator = (0..4).fold(Bn254::ONE, |product, slot| {
        product * (beta * labels[4 + slot] + main[slot] + gamma)
    });
    let internal = Bn254::ONE - eq_at_index_low(point, 0);
    let mut residual = Bn254::ZERO;
    for side in 0..2 {
        let offset = 5 * side;
        residual += weights[side] * internal * (heap[offset] - heap[offset + 1] * heap[offset + 2]);
    }
    residual += weights[2] * (heap[3] - numerator);
    residual += weights[3] * (heap[8] - denominator);
    if heap[4] != heap[9] {
        return Err(Error::QuotientIdentity);
    }
    Ok(residual)
}

fn product_heap(
    preprocessed: &[Vec<Bn254>],
    main: &[Vec<Bn254>],
    beta: Bn254,
    gamma: Bn254,
) -> Vec<Vec<Bn254>> {
    let n = main[0].len();
    let mut heap = vec![vec![Bn254::ZERO; 2 * n]; 2];
    for row in 0..n {
        heap[0][n + row] = (0..4).fold(Bn254::ONE, |product, slot| {
            product * (beta * preprocessed[ID0 + slot][row] + main[slot][row] + gamma)
        });
        heap[1][n + row] = (0..4).fold(Bn254::ONE, |product, slot| {
            product * (beta * preprocessed[SIGMA0 + slot][row] + main[slot][row] + gamma)
        });
    }
    for node in (1..n).rev() {
        heap[0][node] = heap[0][2 * node] * heap[0][2 * node + 1];
        heap[1][node] = heap[1][2 * node] * heap[1][2 * node + 1];
    }
    heap
}

fn preprocessed_opening_points(local: &[Bn254], product: &[Bn254]) -> Vec<Point<Bn254>> {
    let mut points = (0..PRE_WIDTH)
        .map(|column| table_point(column, local, PRE_WIDTH))
        .collect::<Vec<_>>();
    points.extend(
        (ID0..ID0 + 4)
            .chain(SIGMA0..SIGMA0 + 4)
            .map(|column| table_point(column, product, PRE_WIDTH)),
    );
    points
}

fn main_opening_points(local: &[Bn254], product: &[Bn254]) -> Vec<Point<Bn254>> {
    (0..MAIN_WIDTH)
        .map(|column| table_point(column, local, MAIN_WIDTH))
        .chain((0..MAIN_WIDTH).map(|column| table_point(column, product, MAIN_WIDTH)))
        .collect()
}

fn product_opening_points(point: &[Bn254], n: usize) -> Vec<Point<Bn254>> {
    let mut points = Vec::with_capacity(10);
    let variables = n.trailing_zeros() as usize;
    for side in 0..2 {
        let mut parent = point.to_vec();
        parent.push(Bn254::ZERO);
        let mut left = Vec::with_capacity(variables + 1);
        left.push(Bn254::ZERO);
        left.extend_from_slice(point);
        let mut right = Vec::with_capacity(variables + 1);
        right.push(Bn254::ONE);
        right.extend_from_slice(point);
        let mut leaf = point.to_vec();
        leaf.push(Bn254::ONE);
        let root = (0..=variables)
            .map(|bit| Bn254::from_bool(bit == 0))
            .collect::<Vec<_>>();
        for row_point in [&parent, &left, &right, &leaf, &root] {
            points.push(table_point(side, row_point, PRODUCT_WIDTH));
        }
    }
    points
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
    let mut table = vec![Bn254::ZERO; rows * width];
    for (column, values) in columns.iter().enumerate() {
        for (row, &value) in values.iter().enumerate() {
            table[row * width + column] = value;
        }
    }
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
    let mut result = vec![Bn254::ONE];
    for &coordinate in point {
        let old = result.len();
        result.resize(old << 1, Bn254::ZERO);
        for index in 0..old {
            let value = result[index];
            result[index] = value * (Bn254::ONE - coordinate);
            result[index | old] = value * coordinate;
        }
    }
    result
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
    for pair in 0..values.len() / 2 {
        values[pair] = lerp(values[2 * pair], values[2 * pair + 1], challenge);
    }
    values.truncate(values.len() / 2);
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
    state: Bn254,
    counter: u64,
}

impl Transcript {
    fn new(domain_size: usize, public_values: &[Bn254]) -> Self {
        let mut transcript = Self {
            state: hash_node(
                100,
                Bn254::from_u64(0x5354_4154_4d4c_4553),
                Bn254::from_usize(domain_size),
            ),
            counter: 0,
        };
        transcript.observe(Bn254::from_u64(STATIC_VERSION));
        transcript.observe(Bn254::from_usize(public_values.len()));
        for &value in public_values {
            transcript.observe(value);
        }
        transcript
    }

    fn observe(&mut self, value: Bn254) {
        self.state = hash_node(101, self.state, value);
    }

    fn observe_commitment(&mut self, commitment: &Commitment) {
        self.observe(Bn254::from_usize(commitment.num_roots()));
        for root in commitment.roots() {
            for &element in root {
                self.observe(element);
            }
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
        let result = hash_node(
            102 + self.counter as usize,
            self.state,
            Bn254::from_u64(self.counter),
        );
        self.counter += 1;
        self.observe(result);
        result
    }

    fn challenges(&mut self, count: usize) -> Vec<Bn254> {
        (0..count).map(|_| self.challenge()).collect()
    }

    fn opening_seed(&self) -> [Bn254; 2] {
        [self.state, Bn254::from_u64(self.counter)]
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
    fn verifier_rejects_tampering_at_every_static_proof_layer() {
        let public = Bn254::ONE;
        let program = arithmetic_program(public);
        let (pk, vk) = setup(&program).unwrap();
        let proof = prove(&pk, &program, &[public]).unwrap();
        verify(&vk, &[public], &proof).unwrap();

        let perturb_commitment = |commitment: &Commitment| -> Commitment {
            let mut roots = commitment.roots().to_vec();
            roots[0][0] += Bn254::ONE;
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
}
