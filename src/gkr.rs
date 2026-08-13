//! Reusable GKR engine for sparse transition computations.
//!
//! Each Poseidon2 row is represented as a three-input gate whose polynomial is
//! a sum of degree-at-most-five univariates.  The same four-gate block is
//! repeated over every hash at a tree level.  This is the data-parallel circuit
//! structure used by Virgo: the prover scans every concrete gate, while the
//! verifier evaluates the repeated wiring predicate from one local block and
//! equality polynomials over the repetition coordinates. The production
//! initial full-tree proof now uses CAIR; the older regular-tree constructor
//! remains here as a reference implementation and regression oracle.

use std::array;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, RawDataSerializable, TwoAdicField};
use serde::de::value::{Error as DeserializerError, SeqDeserializer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{Digest, hash_node, poseidon2_constants};
use crate::static_snark::program::{ConstraintProgram, Operation};

const BLOCK_SIZE: usize = 4;
const INPUT_ARITY: usize = 3;
const MAX_DEGREE: usize = 5;
const SUMCHECK_EVALUATIONS: usize = MAX_DEGREE + 2;
const TRANSCRIPT_DOMAIN: u64 = 0x5649_5247_4f47_4b52;
const CHECKPOINT_BUFFER_FIELDS: usize = 1 << 15;
static CHECKPOINT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One non-interactive GKR proof of a full Merkle-tree evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    layers: Vec<LayerProof>,
}

impl Proof {
    /// Serialize only prover-supplied field messages for composition into a
    /// later Fiat--Shamir transcript. Verifier challenges are deliberately
    /// absent: they are recomputed from these messages, never reabsorbed.
    pub(crate) fn raw_message_seed(&self) -> Vec<Bn254> {
        let mut seed = vec![Bn254::from_usize(self.layers.len())];
        for layer in &self.layers {
            for phase in &layer.phases {
                seed.push(Bn254::from_usize(phase.rounds.len()));
                for evaluations in &phase.rounds {
                    seed.extend(evaluations);
                }
                seed.push(phase.value);
            }
        }
        seed
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct LayerProof {
    phases: [PhaseProof; INPUT_ARITY],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PhaseProof {
    rounds: Vec<[Bn254; SUMCHECK_EVALUATIONS]>,
    value: Bn254,
}

/// The three input-layer claims left after GKR has reduced the public root.
pub(crate) struct InputClaims {
    points: [Vec<Bn254>; INPUT_ARITY],
    coefficients: [Bn254; INPUT_ARITY],
    claim: Bn254,
    transcript_binding: [Bn254; 2],
    trace_len: usize,
}

impl InputClaims {
    /// Low-bit-first points at which the committed main-column MLE is opened.
    pub(crate) fn main_trace_points(&self) -> [&[Bn254]; INPUT_ARITY] {
        array::from_fn(|index| self.points[index].as_slice())
    }

    /// Low-bit-first terminal points for a directly committed MLE table.
    pub(crate) fn mle_points(&self) -> [&[Bn254]; INPUT_ARITY] {
        self.main_trace_points()
    }

    /// Bind the static proof transcript to the complete GKR transcript.
    pub(crate) const fn transcript_binding(&self) -> [Bn254; 2] {
        self.transcript_binding
    }

    /// Check the final GKR input claim using main-trace MLE openings.
    pub(crate) fn verify_main_trace_openings(&self, evaluations: &[Bn254]) -> Result<(), Error> {
        self.verify_mle_openings(evaluations)
    }

    /// Check the final GKR input claim using direct MLE openings.
    pub(crate) fn verify_mle_openings(&self, evaluations: &[Bn254]) -> Result<(), Error> {
        if evaluations.len() != INPUT_ARITY {
            return Err(Error::InputOpeningCount {
                expected: INPUT_ARITY,
                actual: evaluations.len(),
            });
        }
        let combined = self
            .coefficients
            .iter()
            .zip(evaluations)
            .fold(Bn254::ZERO, |sum, (&coefficient, &evaluation)| {
                sum + coefficient * evaluation
            });
        if combined == self.claim {
            Ok(())
        } else {
            Err(Error::InputClaim)
        }
    }

    pub(crate) const fn trace_len(&self) -> usize {
        self.trace_len
    }
}

/// Concatenate terminal points for one batched WHIR opening.
pub(crate) fn shared_mle_points<'a>(claims: &'a [&'a InputClaims]) -> Vec<&'a [Bn254]> {
    claims
        .iter()
        .flat_map(|claims| claims.mle_points())
        .collect()
}

/// Verify the evaluations from one WHIR proof against several GKR terminal
/// claims in the same order as [`shared_mle_points`].
pub(crate) fn verify_shared_mle_openings(
    claims: &[&InputClaims],
    evaluations: &[Bn254],
) -> Result<(), Error> {
    let expected = INPUT_ARITY * claims.len();
    if evaluations.len() != expected {
        return Err(Error::InputOpeningCount {
            expected,
            actual: evaluations.len(),
        });
    }
    for (claims, evaluations) in claims.iter().zip(evaluations.chunks_exact(INPUT_ARITY)) {
        claims.verify_mle_openings(evaluations)?;
    }
    Ok(())
}

/// Seed a shared opening using public data and raw GKR proof messages only.
pub(crate) fn shared_opening_seed(public_seed: &[Bn254], proofs: &[&Proof]) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(0x5348_4152_4544_4f50),
        Bn254::from_usize(public_seed.len()),
    ];
    seed.extend_from_slice(public_seed);
    seed.push(Bn254::from_usize(proofs.len()));
    for proof in proofs {
        let messages = proof.raw_message_seed();
        seed.push(Bn254::from_usize(messages.len()));
        seed.extend(messages);
    }
    seed
}

/// Invalid GKR statement or proof.
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("GKR assignment must be nonempty")]
    EmptyAssignment,
    #[error("GKR public root does not match the evaluated Merkle circuit")]
    RootMismatch,
    #[error("GKR proof has {actual} layers; expected {expected}")]
    LayerCount { expected: usize, actual: usize },
    #[error("GKR layer {layer} phase {phase} has {actual} rounds; expected {expected}")]
    RoundCount {
        layer: usize,
        phase: usize,
        expected: usize,
        actual: usize,
    },
    #[error("GKR sumcheck identity failed at layer {layer}, phase {phase}, round {round}")]
    Sumcheck {
        layer: usize,
        phase: usize,
        round: usize,
    },
    #[error("GKR wiring identity failed at layer {0}")]
    Wiring(usize),
    #[error("GKR prover generated an inconsistent internal claim")]
    ProverClaim,
    #[error("GKR expected {expected} assignment openings; received {actual}")]
    InputOpeningCount { expected: usize, actual: usize },
    #[error("GKR terminal input claim is false")]
    InputClaim,
    #[error("GKR checkpoint I/O failed: {0}")]
    Checkpoint(#[from] io::Error),
}

/// Append-only layer storage. Forward evaluation writes each layer
/// sequentially; the root-to-input GKR reduction seeks backward and reads one
/// layer at a time. The temporary file is deleted on every return path.
struct LayerCheckpoints {
    file: Option<File>,
    path: PathBuf,
    layers: Vec<(u64, usize)>,
}

impl LayerCheckpoints {
    fn create() -> io::Result<Self> {
        let directory = std::env::var_os("DYNAMIC_SNARK_CHECKPOINT_DIR")
            .map_or_else(std::env::temp_dir, PathBuf::from);
        for _ in 0..1024 {
            let id = CHECKPOINT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                "dynamic-snarks-gkr-{}-{id}.layers",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        path,
                        layers: Vec::new(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique GKR checkpoint file",
        ))
    }

    fn append(&mut self, values: &[Bn254]) -> io::Result<()> {
        let file = self.file.as_mut().expect("checkpoint file is open");
        let offset = file.seek(SeekFrom::End(0))?;
        self.layers.push((offset, values.len()));
        let mut bytes = Vec::with_capacity(CHECKPOINT_BUFFER_FIELDS * Bn254::NUM_BYTES);
        for chunk in values.chunks(CHECKPOINT_BUFFER_FIELDS) {
            bytes.clear();
            for &value in chunk {
                bytes.extend_from_slice(&value.into_bytes());
            }
            file.write_all(&bytes)?;
        }
        Ok(())
    }

    fn read(&mut self, layer: usize) -> io::Result<Vec<Bn254>> {
        let &(offset, len) = self.layers.get(layer).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing GKR checkpoint layer")
        })?;
        let file = self.file.as_mut().expect("checkpoint file is open");
        file.seek(SeekFrom::Start(offset))?;
        let mut values = Vec::with_capacity(len);
        let mut bytes = vec![0u8; CHECKPOINT_BUFFER_FIELDS * Bn254::NUM_BYTES];
        let mut remaining = len;
        while remaining > 0 {
            let fields = remaining.min(CHECKPOINT_BUFFER_FIELDS);
            let byte_len = fields * Bn254::NUM_BYTES;
            file.read_exact(&mut bytes[..byte_len])?;
            for encoded in bytes[..byte_len].chunks_exact(Bn254::NUM_BYTES) {
                let deserializer =
                    SeqDeserializer::<_, DeserializerError>::new(encoded.iter().copied());
                let value = Bn254::deserialize(deserializer).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                values.push(value);
            }
            remaining -= fields;
        }
        Ok(values)
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for LayerCheckpoints {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = remove_file(&self.path);
    }
}

#[derive(Clone)]
struct GatePolynomial {
    /// Coefficient `[input][degree - 1]` for degrees one through five.
    coefficients: [[Bn254; MAX_DEGREE]; INPUT_ARITY],
    constant: Bn254,
    mixed_terms: Vec<MixedTerm>,
}

#[derive(Clone)]
struct MixedTerm {
    exponents: [usize; INPUT_ARITY],
    coefficient: Bn254,
}

impl GatePolynomial {
    fn zero() -> Self {
        Self {
            coefficients: [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY],
            constant: Bn254::ZERO,
            mixed_terms: Vec::new(),
        }
    }

    fn linear(coefficients: [Bn254; INPUT_ARITY]) -> Self {
        let mut polynomial = Self::zero();
        for (input, coefficient) in coefficients.into_iter().enumerate() {
            polynomial.coefficients[input][0] = coefficient;
        }
        polynomial
    }

    fn constant(value: Bn254) -> Self {
        Self {
            constant: value,
            ..Self::zero()
        }
    }

    fn evaluate(&self, inputs: [Bn254; INPUT_ARITY]) -> Bn254 {
        let separated = self.coefficients.iter().zip(inputs).fold(
            self.constant,
            |sum, (coefficients, input)| {
                let mut power = input;
                let value = coefficients
                    .iter()
                    .fold(Bn254::ZERO, |value, &coefficient| {
                        let next = value + coefficient * power;
                        power *= input;
                        next
                    });
                sum + value
            },
        );
        self.mixed_terms.iter().fold(separated, |sum, term| {
            let value = term
                .exponents
                .iter()
                .zip(inputs)
                .fold(term.coefficient, |value, (&exponent, input)| {
                    value * input.exp_u64(exponent as u64)
                });
            sum + value
        })
    }

    fn product_difference() -> Self {
        let mut polynomial = Self::linear([Bn254::ZERO, Bn254::ZERO, -Bn254::ONE]);
        polynomial.mixed_terms.push(MixedTerm {
            exponents: [1, 1, 0],
            coefficient: Bn254::ONE,
        });
        polynomial
    }

    fn product() -> Self {
        let mut polynomial = Self::zero();
        polynomial.mixed_terms.push(MixedTerm {
            exponents: [1, 1, 0],
            coefficient: Bn254::ONE,
        });
        polynomial
    }

    fn separated(coefficients: [[Bn254; MAX_DEGREE]; INPUT_ARITY], constant: Bn254) -> Self {
        Self {
            coefficients,
            constant,
            mixed_terms: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct LocalGate {
    inputs: [usize; INPUT_ARITY],
    input_copy_bits: [bool; INPUT_ARITY],
    polynomial: GatePolynomial,
}

#[derive(Clone)]
enum Layer {
    Parallel {
        repeats: usize,
        gates: [LocalGate; BLOCK_SIZE],
    },
    Pair {
        repeats: usize,
        gates: [LocalGate; BLOCK_SIZE],
    },
    /// A fixed power-of-two local gate block repeated independently over all
    /// witness rows. Only the repetition equality predicate grows with the
    /// table; the verifier never enumerates rows.
    Periodic {
        repeats: usize,
        block_size: usize,
        gates: Vec<LocalGate>,
    },
    /// The same local projection repeated between two fixed block widths.
    PeriodicMap {
        repeats: usize,
        input_block_size: usize,
        output_block_size: usize,
        gates: Vec<LocalGate>,
    },
    Butterfly {
        size: usize,
        bit: usize,
        kind: ButterflyKind,
    },
    BitReverse {
        size: usize,
    },
    LeafInput {
        assignment_len: usize,
        trace_len: usize,
        repeats: usize,
    },
    Dense {
        input_size: usize,
        gates: Vec<GlobalGate>,
    },
}

#[derive(Clone)]
enum ButterflyKind {
    MobiusInverse,
    Fourier { generator: Bn254 },
}

#[derive(Clone)]
pub(crate) struct GlobalGate {
    inputs: [usize; INPUT_ARITY],
    polynomial: GatePolynomial,
}

impl GlobalGate {
    pub(crate) fn relay(input: usize) -> Self {
        Self {
            inputs: [input; INPUT_ARITY],
            polynomial: GatePolynomial::linear([Bn254::ONE, Bn254::ZERO, Bn254::ZERO]),
        }
    }

    pub(crate) fn constant(value: Bn254) -> Self {
        Self {
            inputs: [0; INPUT_ARITY],
            polynomial: GatePolynomial::constant(value),
        }
    }

    pub(crate) fn linear(inputs: [usize; INPUT_ARITY], coefficients: [Bn254; INPUT_ARITY]) -> Self {
        Self {
            inputs,
            polynomial: GatePolynomial::linear(coefficients),
        }
    }

    pub(crate) fn affine(
        inputs: [usize; INPUT_ARITY],
        coefficients: [Bn254; INPUT_ARITY],
        constant: Bn254,
    ) -> Self {
        let mut polynomial = GatePolynomial::linear(coefficients);
        polynomial.constant = constant;
        Self { inputs, polynomial }
    }

    pub(crate) fn product_difference(inputs: [usize; INPUT_ARITY]) -> Self {
        Self {
            inputs,
            polynomial: GatePolynomial::product_difference(),
        }
    }

    fn separated(
        inputs: [usize; INPUT_ARITY],
        coefficients: [[Bn254; MAX_DEGREE]; INPUT_ARITY],
        constant: Bn254,
    ) -> Self {
        Self {
            inputs,
            polynomial: GatePolynomial::separated(coefficients, constant),
        }
    }
}

impl Layer {
    const fn output_size(&self) -> usize {
        match self {
            Self::Parallel { repeats, .. }
            | Self::Pair { repeats, .. }
            | Self::LeafInput { repeats, .. } => BLOCK_SIZE * *repeats,
            Self::Periodic {
                repeats,
                block_size,
                ..
            } => *block_size * *repeats,
            Self::PeriodicMap {
                repeats,
                output_block_size,
                ..
            } => *output_block_size * *repeats,
            Self::Butterfly { size, .. } | Self::BitReverse { size } => *size,
            Self::Dense { gates, .. } => gates.len(),
        }
    }

    const fn input_size(&self) -> usize {
        match self {
            Self::Parallel { repeats, .. } => BLOCK_SIZE * *repeats,
            Self::Pair { repeats, .. } => (BLOCK_SIZE * *repeats) << 1,
            Self::Periodic {
                repeats,
                block_size,
                ..
            } => *block_size * *repeats,
            Self::PeriodicMap {
                repeats,
                input_block_size,
                ..
            } => *input_block_size * *repeats,
            Self::Butterfly { size, .. } | Self::BitReverse { size } => *size,
            Self::LeafInput { trace_len, .. } => *trace_len,
            Self::Dense { input_size, .. } => *input_size,
        }
    }

    fn global_gate(&self, output: usize) -> GlobalGate {
        match self {
            Self::Parallel { gates, .. } | Self::Pair { gates, .. } => {
                let copy = output / BLOCK_SIZE;
                let gate = &gates[output % BLOCK_SIZE];
                let inputs = array::from_fn(|input| {
                    let input_copy = match self {
                        Self::Parallel { .. } => copy,
                        Self::Pair { .. } => (copy << 1) | usize::from(gate.input_copy_bits[input]),
                        _ => unreachable!(),
                    };
                    BLOCK_SIZE * input_copy + gate.inputs[input]
                });
                GlobalGate {
                    inputs,
                    polynomial: gate.polynomial.clone(),
                }
            }
            Self::Periodic {
                block_size, gates, ..
            } => {
                let copy = output / block_size;
                let gate = &gates[output % block_size];
                GlobalGate {
                    inputs: gate.inputs.map(|input| block_size * copy + input),
                    polynomial: gate.polynomial.clone(),
                }
            }
            Self::PeriodicMap {
                input_block_size,
                output_block_size,
                gates,
                ..
            } => {
                let copy = output / output_block_size;
                let gate = &gates[output % output_block_size];
                GlobalGate {
                    inputs: gate.inputs.map(|input| input_block_size * copy + input),
                    polynomial: gate.polynomial.clone(),
                }
            }
            Self::Butterfly { size, bit, kind } => {
                let mask = 1usize << bit;
                let base = output & !mask;
                let mut polynomial = GatePolynomial::zero();
                match kind {
                    ButterflyKind::MobiusInverse => {
                        if output & mask == 0 {
                            polynomial.coefficients[0][0] = Bn254::ONE;
                        } else {
                            polynomial.coefficients[0][0] = -Bn254::ONE;
                            polynomial.coefficients[1][0] = Bn254::ONE;
                        }
                    }
                    ButterflyKind::Fourier { generator } => {
                        let log_size = size.trailing_zeros() as usize;
                        let position = output & (mask - 1);
                        let twiddle = generator.exp_u64((position << (log_size - bit - 1)) as u64);
                        polynomial.coefficients[0][0] = Bn254::ONE;
                        polynomial.coefficients[1][0] = if output & mask == 0 {
                            twiddle
                        } else {
                            -twiddle
                        };
                    }
                }
                GlobalGate {
                    inputs: [base, base | mask, base],
                    polynomial,
                }
            }
            Self::BitReverse { size } => {
                let bits = size.trailing_zeros();
                let input = output.reverse_bits() >> (usize::BITS - bits);
                GlobalGate {
                    inputs: [input; INPUT_ARITY],
                    polynomial: GatePolynomial::linear([Bn254::ONE, Bn254::ZERO, Bn254::ZERO]),
                }
            }
            Self::LeafInput {
                assignment_len,
                trace_len,
                ..
            } => {
                let copy = output / BLOCK_SIZE;
                let local = output % BLOCK_SIZE;
                let input = copy.min(trace_len - 1);
                let polynomial = match local {
                    0 if copy < *assignment_len => {
                        GatePolynomial::linear([Bn254::ONE, Bn254::ZERO, Bn254::ZERO])
                    }
                    0 => GatePolynomial::zero(),
                    1 => GatePolynomial::constant(Bn254::from_usize(copy)),
                    2 => GatePolynomial::constant(Bn254::ONE),
                    _ => GatePolynomial::zero(),
                };
                GlobalGate {
                    inputs: [input; INPUT_ARITY],
                    polynomial,
                }
            }
            Self::Dense { gates, .. } => gates[output].clone(),
        }
    }

    fn evaluate(&self, previous: &[Bn254]) -> Vec<Bn254> {
        debug_assert_eq!(previous.len(), self.input_size());
        let mut values = vec![Bn254::ZERO; self.output_size()];
        for (output, value) in values.iter_mut().enumerate() {
            let gate = self.global_gate(output);
            let inputs = gate.inputs.map(|index| previous[index]);
            *value = gate.polynomial.evaluate(inputs);
        }
        values
    }

    fn terminal_evaluation(
        &self,
        output_points: &[Vec<Bn254>],
        output_coefficients: &[Bn254],
        input_points: &[Vec<Bn254>; INPUT_ARITY],
        input_values: [Bn254; INPUT_ARITY],
    ) -> Bn254 {
        match self {
            Self::Butterfly { size, bit, kind } => {
                return butterfly_terminal_evaluation(
                    *size,
                    *bit,
                    kind,
                    output_points,
                    output_coefficients,
                    input_points,
                    input_values,
                );
            }
            Self::BitReverse { .. } => {
                return bit_reverse_terminal_evaluation(
                    output_points,
                    output_coefficients,
                    input_points,
                    input_values[0],
                );
            }
            Self::LeafInput {
                assignment_len,
                trace_len,
                repeats,
            } => {
                return leaf_input_terminal_evaluation(
                    *assignment_len,
                    *trace_len,
                    *repeats,
                    output_points,
                    output_coefficients,
                    input_points,
                    input_values[0],
                );
            }
            Self::Dense { gates, .. } => {
                let mut result = Bn254::ZERO;
                for (output, gate) in gates.iter().enumerate() {
                    let output_weight = output_points.iter().zip(output_coefficients).fold(
                        Bn254::ZERO,
                        |sum, (point, &coefficient)| {
                            sum + coefficient * eq_at_index_low(point, output)
                        },
                    );
                    let input_weight = (0..INPUT_ARITY).fold(Bn254::ONE, |weight, input| {
                        weight * eq_at_index_low(&input_points[input], gate.inputs[input])
                    });
                    result += output_weight * input_weight * gate.polynomial.evaluate(input_values);
                }
                return result;
            }
            Self::Periodic {
                repeats,
                block_size,
                gates,
            } => {
                return periodic_terminal_evaluation(
                    *repeats,
                    *block_size,
                    gates,
                    output_points,
                    output_coefficients,
                    input_points,
                    input_values,
                );
            }
            Self::PeriodicMap {
                repeats,
                input_block_size,
                output_block_size,
                gates,
            } => {
                return periodic_map_terminal_evaluation(
                    *repeats,
                    *input_block_size,
                    *output_block_size,
                    gates,
                    output_points,
                    output_coefficients,
                    input_points,
                    input_values,
                );
            }
            Self::Parallel { .. } | Self::Pair { .. } => {}
        }
        let input_local: [&[Bn254]; INPUT_ARITY] =
            array::from_fn(|input| &input_points[input][..2]);
        let input_copy: [&[Bn254]; INPUT_ARITY] = array::from_fn(|input| &input_points[input][2..]);
        let mut result = Bn254::ZERO;

        let gates = match self {
            Self::Parallel { gates, .. } | Self::Pair { gates, .. } => gates,
            _ => unreachable!(),
        };
        for (local, gate) in gates.iter().enumerate() {
            let local_input_weight = (0..INPUT_ARITY).fold(Bn254::ONE, |weight, input| {
                weight * eq_at_index_low(input_local[input], gate.inputs[input])
            });
            let gate_value = gate.polynomial.evaluate(input_values);
            for (point, &coefficient) in output_points.iter().zip(output_coefficients) {
                let output_local = &point[..2];
                let output_copy = &point[2..];
                let copy_weight = match self {
                    Self::Parallel { .. } => {
                        eq_same_copy(output_copy, input_copy[0], input_copy[1], input_copy[2])
                    }
                    Self::Pair { .. } => {
                        let fixed = (0..INPUT_ARITY).fold(Bn254::ONE, |weight, input| {
                            weight * eq_boolean(input_copy[input][0], gate.input_copy_bits[input])
                        });
                        fixed
                            * eq_same_copy(
                                output_copy,
                                &input_copy[0][1..],
                                &input_copy[1][1..],
                                &input_copy[2][1..],
                            )
                    }
                    _ => unreachable!(),
                };
                result += coefficient
                    * eq_at_index_low(output_local, local)
                    * copy_weight
                    * local_input_weight
                    * gate_value;
            }
        }
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn periodic_terminal_evaluation(
    repeats: usize,
    block_size: usize,
    gates: &[LocalGate],
    output_points: &[Vec<Bn254>],
    output_coefficients: &[Bn254],
    input_points: &[Vec<Bn254>; INPUT_ARITY],
    input_values: [Bn254; INPUT_ARITY],
) -> Bn254 {
    debug_assert_eq!(gates.len(), block_size);
    let local_variables = block_size.trailing_zeros() as usize;
    let copy_variables = repeats.trailing_zeros() as usize;
    let input_local: [&[Bn254]; INPUT_ARITY] =
        array::from_fn(|input| &input_points[input][..local_variables]);
    let input_copy: [&[Bn254]; INPUT_ARITY] =
        array::from_fn(|input| &input_points[input][local_variables..]);
    debug_assert!(input_copy.iter().all(|point| point.len() == copy_variables));

    let mut result = Bn254::ZERO;
    for (local, gate) in gates.iter().enumerate() {
        let local_input_weight = (0..INPUT_ARITY).fold(Bn254::ONE, |weight, input| {
            weight * eq_at_index_low(input_local[input], gate.inputs[input])
        });
        let gate_value = gate.polynomial.evaluate(input_values);
        for (point, &coefficient) in output_points.iter().zip(output_coefficients) {
            let output_local = &point[..local_variables];
            let output_copy = &point[local_variables..];
            result += coefficient
                * eq_at_index_low(output_local, local)
                * eq_same_copy(output_copy, input_copy[0], input_copy[1], input_copy[2])
                * local_input_weight
                * gate_value;
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn periodic_map_terminal_evaluation(
    repeats: usize,
    input_block_size: usize,
    output_block_size: usize,
    gates: &[LocalGate],
    output_points: &[Vec<Bn254>],
    output_coefficients: &[Bn254],
    input_points: &[Vec<Bn254>; INPUT_ARITY],
    input_values: [Bn254; INPUT_ARITY],
) -> Bn254 {
    debug_assert_eq!(gates.len(), output_block_size);
    let input_local_variables = input_block_size.trailing_zeros() as usize;
    let output_local_variables = output_block_size.trailing_zeros() as usize;
    let copy_variables = repeats.trailing_zeros() as usize;
    let input_local: [&[Bn254]; INPUT_ARITY] =
        array::from_fn(|input| &input_points[input][..input_local_variables]);
    let input_copy: [&[Bn254]; INPUT_ARITY] =
        array::from_fn(|input| &input_points[input][input_local_variables..]);
    debug_assert!(input_copy.iter().all(|point| point.len() == copy_variables));

    let mut result = Bn254::ZERO;
    for (local, gate) in gates.iter().enumerate() {
        let local_input_weight = (0..INPUT_ARITY).fold(Bn254::ONE, |weight, input| {
            weight * eq_at_index_low(input_local[input], gate.inputs[input])
        });
        let gate_value = gate.polynomial.evaluate(input_values);
        for (point, &coefficient) in output_points.iter().zip(output_coefficients) {
            let output_local = &point[..output_local_variables];
            let output_copy = &point[output_local_variables..];
            result += coefficient
                * eq_at_index_low(output_local, local)
                * eq_same_copy(output_copy, input_copy[0], input_copy[1], input_copy[2])
                * local_input_weight
                * gate_value;
        }
    }
    result
}

/// A layered arithmetic circuit whose layer widths are powers of two.
///
/// Dense layers are used for the sparse transition DAG. Their wiring is
/// reconstructed from the public update indices and canonical multiproofs.
pub(crate) struct LayeredCircuit {
    input_size: usize,
    layers: Vec<Layer>,
}

impl LayeredCircuit {
    pub(crate) fn new(input_size: usize) -> Self {
        assert!(input_size >= 2 && input_size.is_power_of_two());
        Self {
            input_size,
            layers: Vec::new(),
        }
    }

    pub(crate) fn current_size(&self) -> usize {
        self.layers
            .last()
            .map_or(self.input_size, Layer::output_size)
    }

    pub(crate) fn append_dense(&mut self, mut gates: Vec<GlobalGate>) {
        let input_size = self.current_size();
        assert!(
            gates
                .iter()
                .all(|gate| gate.inputs.iter().all(|&input| input < input_size))
        );
        let output_size = gates.len().max(2).next_power_of_two();
        gates.resize_with(output_size, || GlobalGate::constant(Bn254::ZERO));
        self.layers.push(Layer::Dense { input_size, gates });
    }

    /// Append one fixed local gate pattern repeated over every table row.
    /// This is the Virgo-style replacement for a verifier-linear dense layer.
    pub(crate) fn append_periodic(&mut self, block_size: usize, mut gates: Vec<GlobalGate>) {
        assert!(block_size >= 2 && block_size.is_power_of_two());
        assert_eq!(self.current_size() % block_size, 0);
        assert!(gates.len() <= block_size);
        assert!(
            gates
                .iter()
                .all(|gate| gate.inputs.iter().all(|&input| input < block_size))
        );
        gates.resize_with(block_size, || GlobalGate::constant(Bn254::ZERO));
        let gates = gates
            .into_iter()
            .map(|gate| LocalGate {
                inputs: gate.inputs,
                input_copy_bits: [false; INPUT_ARITY],
                polynomial: gate.polynomial,
            })
            .collect();
        self.layers.push(Layer::Periodic {
            repeats: self.current_size() / block_size,
            block_size,
            gates,
        });
    }

    /// Append a repeated local projection that changes the per-row width.
    pub(crate) fn append_periodic_map(
        &mut self,
        input_block_size: usize,
        output_block_size: usize,
        mut gates: Vec<GlobalGate>,
    ) {
        assert!(input_block_size >= 2 && input_block_size.is_power_of_two());
        assert!(output_block_size >= 2 && output_block_size.is_power_of_two());
        assert_eq!(self.current_size() % input_block_size, 0);
        assert!(gates.len() <= output_block_size);
        assert!(
            gates
                .iter()
                .all(|gate| gate.inputs.iter().all(|&input| input < input_block_size))
        );
        gates.resize_with(output_block_size, || GlobalGate::constant(Bn254::ZERO));
        let gates = gates
            .into_iter()
            .map(|gate| LocalGate {
                inputs: gate.inputs,
                input_copy_bits: [false; INPUT_ARITY],
                polynomial: gate.polynomial,
            })
            .collect();
        self.layers.push(Layer::PeriodicMap {
            repeats: self.current_size() / input_block_size,
            input_block_size,
            output_block_size,
            gates,
        });
    }

    /// Evaluate a batch of Poseidon2 permutations while relaying selected
    /// wires. State words must occupy the first `3 * hash_count` inputs.
    pub(crate) fn append_poseidon_batch(
        &mut self,
        hash_count: usize,
        initial_carries: &[usize],
    ) -> (Vec<usize>, Vec<usize>) {
        assert!(hash_count > 0);
        assert!(3 * hash_count <= self.current_size());
        assert!(
            initial_carries
                .iter()
                .all(|&input| input < self.current_size())
        );

        let mut carries = initial_carries.to_vec();
        let mut append_round = |circuit: &mut Self, polynomials: [GatePolynomial; 3]| {
            let mut gates = Vec::with_capacity(3 * hash_count + carries.len());
            for hash in 0..hash_count {
                let inputs = [3 * hash, 3 * hash + 1, 3 * hash + 2];
                for polynomial in &polynomials {
                    gates.push(GlobalGate {
                        inputs,
                        polynomial: polynomial.clone(),
                    });
                }
            }
            gates.extend(carries.iter().copied().map(GlobalGate::relay));
            circuit.append_dense(gates);
            carries = (3 * hash_count..3 * hash_count + carries.len()).collect();
        };

        append_round(
            self,
            linear_state([
                [Bn254::TWO, Bn254::ONE, Bn254::ONE],
                [Bn254::ONE, Bn254::TWO, Bn254::ONE],
                [Bn254::ONE, Bn254::ONE, Bn254::TWO],
            ]),
        );
        let (external, internal) = poseidon2_constants();
        for &constants in external.get_initial_constants() {
            append_round(self, full_round(constants));
        }
        for constant in internal {
            append_round(self, partial_round(constant));
        }
        for &constants in external.get_terminal_constants() {
            append_round(self, full_round(constants));
        }

        ((0..hash_count).map(|hash| 3 * hash).collect(), carries)
    }

    pub(crate) fn output_size(&self) -> usize {
        self.current_size()
    }

    /// A regular data-parallel circuit checking a batch of width-three
    /// Poseidon2 permutations. Each input block is
    /// `[state_0, state_1, state_2, expected_output_0]`.
    pub(crate) fn poseidon_checks(repeats: usize) -> Self {
        assert!(repeats > 0 && repeats.is_power_of_two());
        let mut circuit = Self::new(BLOCK_SIZE * repeats);
        append_poseidon_layers_with_carry(&mut circuit.layers, repeats);
        circuit
            .layers
            .push(parallel_difference_layer(repeats, 0, 3));
        circuit
    }

    /// A regular pair-reduction circuit checking equality of two products.
    /// Each input block is `[producer_factor, reference_factor, 1, 1]`.
    pub(crate) fn product_equality(row_count: usize) -> Self {
        assert!(row_count >= 2 && row_count.is_power_of_two());
        let mut circuit = Self::new(BLOCK_SIZE * row_count);
        let mut repeats = row_count;
        while repeats > 1 {
            repeats >>= 1;
            circuit.layers.push(product_pair_layer(repeats));
        }
        circuit.layers.push(parallel_difference_layer(1, 0, 1));
        circuit
    }

    /// Project two committed hash blocks from every master row and check all
    /// resulting Poseidon2 permutations with regular wiring.
    pub(crate) fn poseidon_checks_from_table(
        input_block_size: usize,
        row_count: usize,
        hash_offset: usize,
    ) -> Self {
        assert!(hash_offset + 8 <= input_block_size);
        let mut circuit = Self::new(input_block_size * row_count);
        circuit.append_periodic_map(
            input_block_size,
            8,
            (0..8)
                .map(|field| GlobalGate::relay(hash_offset + field))
                .collect(),
        );
        let repeats = 2 * row_count;
        append_poseidon_layers_with_carry(&mut circuit.layers, repeats);
        circuit
            .layers
            .push(parallel_difference_layer(repeats, 0, 3));
        circuit
    }

    /// Derive four producer/reference factor pairs from every committed master
    /// row and check equality of the two products.
    pub(crate) fn routing_product_from_table(
        input_block_size: usize,
        row_count: usize,
        producer_offset: usize,
        reference_offset: usize,
        theta: Bn254,
        gamma: Bn254,
    ) -> Self {
        assert!(producer_offset + 24 <= input_block_size);
        assert!(reference_offset + 24 <= input_block_size);
        let mut circuit = Self::new(input_block_size * row_count);
        let theta2 = theta * theta;
        let theta3 = theta2 * theta;
        let theta4 = theta3 * theta;
        let theta5 = theta4 * theta;
        let mut partials = Vec::with_capacity(16);
        for lane in 0..4 {
            for offset in [producer_offset, reference_offset] {
                let base = offset + 6 * lane;
                partials.push(GlobalGate::linear(
                    [base, base + 1, base + 2],
                    [Bn254::ONE, theta, theta2],
                ));
                partials.push(GlobalGate::linear(
                    [base + 3, base + 4, base + 5],
                    [theta3, theta4, theta5],
                ));
            }
        }
        circuit.append_periodic_map(input_block_size, 16, partials);

        let mut factors = Vec::with_capacity(16);
        for lane in 0..4 {
            let partial = 4 * lane;
            factors.push(GlobalGate::affine(
                [partial, partial + 1, partial],
                [Bn254::ONE, Bn254::ONE, Bn254::ZERO],
                gamma,
            ));
            factors.push(GlobalGate::affine(
                [partial + 2, partial + 3, partial + 2],
                [Bn254::ONE, Bn254::ONE, Bn254::ZERO],
                gamma,
            ));
            factors.push(GlobalGate::constant(Bn254::ONE));
            factors.push(GlobalGate::constant(Bn254::ONE));
        }
        circuit.append_periodic(16, factors);
        let mut repeats = 4 * row_count;
        while repeats > 1 {
            repeats >>= 1;
            circuit.layers.push(product_pair_layer(repeats));
        }
        circuit.layers.push(parallel_difference_layer(1, 0, 1));
        circuit
    }

    #[cfg(test)]
    fn is_regular(&self) -> bool {
        self.layers
            .iter()
            .all(|layer| !matches!(layer, Layer::Dense { .. }))
    }

    #[cfg(test)]
    fn verifier_wiring_profile(&self) -> VerifierWiringProfile {
        let mut profile = VerifierWiringProfile::default();
        for layer in &self.layers {
            profile.layers += 1;
            match layer {
                Layer::Parallel { repeats, gates } | Layer::Pair { repeats, gates } => {
                    profile.local_gate_terms += gates.len();
                    profile.copy_coordinate_terms += repeats.trailing_zeros() as usize;
                }
                Layer::Periodic { repeats, gates, .. } => {
                    profile.local_gate_terms += gates.len();
                    profile.copy_coordinate_terms += repeats.trailing_zeros() as usize;
                }
                Layer::PeriodicMap { repeats, gates, .. } => {
                    profile.local_gate_terms += gates.len();
                    profile.copy_coordinate_terms += repeats.trailing_zeros() as usize;
                }
                Layer::Butterfly { size, .. } | Layer::BitReverse { size } => {
                    profile.copy_coordinate_terms += size.trailing_zeros() as usize;
                }
                Layer::LeafInput { trace_len, .. } => {
                    profile.copy_coordinate_terms += trace_len.trailing_zeros() as usize;
                }
                Layer::Dense { gates, .. } => profile.local_gate_terms += gates.len(),
            }
        }
        profile
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct VerifierWiringProfile {
    layers: usize,
    local_gate_terms: usize,
    copy_coordinate_terms: usize,
}

/// Compile a fixed constraint program into two dense GKR layers.
///
/// The first layer emits `(computed, claimed)` for every operation and the
/// second subtracts each pair. Consequently an all-zero public output claim
/// verifies every program operation at one transcript-derived MLE point.
pub(crate) fn constraint_program_circuit(
    program: &ConstraintProgram,
    public_values: &[Bn254],
) -> LayeredCircuit {
    assert_eq!(public_values.len(), program.num_public_values);
    let input_size = program.values.len().max(2).next_power_of_two();
    let mut circuit = LayeredCircuit::new(input_size);
    let mut pairs = Vec::with_capacity(2 * program.operations.len());
    for operation in &program.operations {
        let (computed, claimed) = operation_pair(operation, public_values);
        pairs.push(computed);
        pairs.push(claimed);
    }
    circuit.append_dense(pairs);

    let residuals = (0..program.operations.len())
        .map(|operation| {
            GlobalGate::linear(
                [2 * operation, 2 * operation + 1, 2 * operation],
                [Bn254::ONE, -Bn254::ONE, Bn254::ZERO],
            )
        })
        .collect();
    circuit.append_dense(residuals);
    circuit
}

/// Return the directly committed, power-of-two-padded program assignment.
pub(crate) fn constraint_program_input(program: &ConstraintProgram) -> Vec<Bn254> {
    let input_size = program.values.len().max(2).next_power_of_two();
    let mut input = program.values.clone();
    input.resize(input_size, Bn254::ZERO);
    input
}

/// Compile one fixed row relation into two Virgo-style periodic layers.
/// Every repeated row must use the same operation sequence; only its committed
/// variable assignment changes.
pub(crate) fn periodic_constraint_circuit(
    template: &ConstraintProgram,
    repeats: usize,
) -> LayeredCircuit {
    assert!(repeats > 0 && repeats.is_power_of_two());
    assert_eq!(template.num_public_values, 0);
    let block_size = periodic_constraint_block_size(template);
    let mut circuit = LayeredCircuit::new(block_size * repeats);
    let pairs = template
        .operations
        .iter()
        .flat_map(|operation| {
            let (computed, claimed) = operation_pair(operation, &[]);
            [computed, claimed]
        })
        .collect();
    circuit.append_periodic(block_size, pairs);
    let residuals = (0..template.operations.len())
        .map(|operation| {
            GlobalGate::linear(
                [2 * operation, 2 * operation + 1, 2 * operation],
                [Bn254::ONE, -Bn254::ONE, Bn254::ZERO],
            )
        })
        .collect();
    circuit.append_periodic(block_size, residuals);
    circuit
}

/// Flatten equally shaped row-program assignments into the periodic input.
pub(crate) fn periodic_constraint_input(programs: &[ConstraintProgram]) -> Vec<Bn254> {
    assert!(!programs.is_empty() && programs.len().is_power_of_two());
    let template = &programs[0];
    assert!(programs.iter().all(|program| {
        program.num_public_values == 0
            && program.values.len() == template.values.len()
            && program.operations == template.operations
    }));
    let block_size = periodic_constraint_block_size(template);
    let mut input = Vec::with_capacity(block_size * programs.len());
    for program in programs {
        input.extend_from_slice(&program.values);
        input.resize(input.len() + block_size - program.values.len(), Bn254::ZERO);
    }
    input
}

pub(crate) fn periodic_constraint_block_size(program: &ConstraintProgram) -> usize {
    program
        .values
        .len()
        .max(2 * program.operations.len())
        .max(2)
        .next_power_of_two()
}

fn operation_pair(operation: &Operation, public_values: &[Bn254]) -> (GlobalGate, GlobalGate) {
    match operation {
        Operation::Add(left, right, output) => (
            GlobalGate::linear(
                [left.0, right.0, left.0],
                [Bn254::ONE, Bn254::ONE, Bn254::ZERO],
            ),
            GlobalGate::relay(output.0),
        ),
        Operation::Mul(left, right, output) => (
            GlobalGate::separated(
                [left.0, right.0, left.0],
                [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY],
                Bn254::ZERO,
            )
            .with_mixed_product(),
            GlobalGate::relay(output.0),
        ),
        Operation::Pow5Add(input, constant, output) => (
            shifted_fifth_gate([input.0; INPUT_ARITY], 0, *constant, Bn254::ONE),
            GlobalGate::relay(output.0),
        ),
        Operation::SboxLin3(inputs, constants, coefficients, output) => {
            let mut powers = [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY];
            let mut constant = Bn254::ZERO;
            for input in 0..INPUT_ARITY {
                let (terms, term_constant) = shifted_fifth(*constants.get(input).unwrap());
                for degree in 0..MAX_DEGREE {
                    powers[input][degree] = coefficients[input] * terms[degree];
                }
                constant += coefficients[input] * term_constant;
            }
            (
                GlobalGate::separated(inputs.map(|input| input.0), powers, constant),
                GlobalGate::relay(output.0),
            )
        }
        Operation::Pow5FirstLin3(inputs, constant, coefficients, output) => {
            let (terms, term_constant) = shifted_fifth(*constant);
            let mut powers = [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY];
            for degree in 0..MAX_DEGREE {
                powers[0][degree] = coefficients[0] * terms[degree];
            }
            powers[1][0] = coefficients[1];
            powers[2][0] = coefficients[2];
            (
                GlobalGate::separated(
                    inputs.map(|input| input.0),
                    powers,
                    coefficients[0] * term_constant,
                ),
                GlobalGate::relay(output.0),
            )
        }
        Operation::Lin3(inputs, coefficients, constant, output) => (
            GlobalGate::separated(
                inputs.map(|input| input.0),
                [
                    [
                        coefficients[0],
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                    ],
                    [
                        coefficients[1],
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                    ],
                    [
                        coefficients[2],
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                        Bn254::ZERO,
                    ],
                ],
                *constant,
            ),
            GlobalGate::relay(output.0),
        ),
        Operation::Equal(left, right) => (GlobalGate::relay(left.0), GlobalGate::relay(right.0)),
        Operation::Boolean(variable) => {
            let mut powers = [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY];
            powers[0][1] = Bn254::ONE;
            (
                GlobalGate::separated([variable.0; INPUT_ARITY], powers, Bn254::ZERO),
                GlobalGate::relay(variable.0),
            )
        }
        Operation::Constant(variable, constant) => (
            GlobalGate::relay(variable.0),
            GlobalGate::constant(*constant),
        ),
        Operation::Public(variable, public_index) => (
            GlobalGate::relay(variable.0),
            GlobalGate::constant(public_values[*public_index]),
        ),
    }
}

impl GlobalGate {
    fn with_mixed_product(mut self) -> Self {
        self.polynomial.mixed_terms.push(MixedTerm {
            exponents: [1, 1, 0],
            coefficient: Bn254::ONE,
        });
        self
    }
}

fn shifted_fifth_gate(
    inputs: [usize; INPUT_ARITY],
    input: usize,
    constant: Bn254,
    coefficient: Bn254,
) -> GlobalGate {
    let (terms, term_constant) = shifted_fifth(constant);
    let mut powers = [[Bn254::ZERO; MAX_DEGREE]; INPUT_ARITY];
    for degree in 0..MAX_DEGREE {
        powers[input][degree] = coefficient * terms[degree];
    }
    GlobalGate::separated(inputs, powers, coefficient * term_constant)
}

/// Coefficients of `(x + constant)^5`, ordered by powers one through five,
/// followed by the degree-zero term.
fn shifted_fifth(constant: Bn254) -> ([Bn254; MAX_DEGREE], Bn254) {
    let c2 = constant * constant;
    let c3 = c2 * constant;
    let c4 = c3 * constant;
    let c5 = c4 * constant;
    (
        [
            Bn254::from_u64(5) * c4,
            Bn254::from_u64(10) * c3,
            Bn254::from_u64(10) * c2,
            Bn254::from_u64(5) * constant,
            Bn254::ONE,
        ],
        c5,
    )
}

#[allow(clippy::too_many_arguments)]
fn butterfly_terminal_evaluation(
    size: usize,
    bit: usize,
    kind: &ButterflyKind,
    output_points: &[Vec<Bn254>],
    output_coefficients: &[Bn254],
    input_points: &[Vec<Bn254>; INPUT_ARITY],
    input_values: [Bn254; INPUT_ARITY],
) -> Bn254 {
    let variables = size.trailing_zeros() as usize;
    let fixed_inputs = eq_boolean(input_points[0][bit], false)
        * eq_boolean(input_points[1][bit], true)
        * eq_boolean(input_points[2][bit], false);
    output_points.iter().zip(output_coefficients).fold(
        Bn254::ZERO,
        |sum, (output, &coefficient)| {
            let mut ordinary_factor = Bn254::ONE;
            let mut weighted_factor = Bn254::ONE;
            for coordinate in 0..variables {
                if coordinate == bit {
                    continue;
                }
                let points = [
                    output[coordinate],
                    input_points[0][coordinate],
                    input_points[1][coordinate],
                    input_points[2][coordinate],
                ];
                let ordinary = equal_boolean_sum(&points, Bn254::ONE);
                ordinary_factor *= ordinary;
                let twiddle_bit = match kind {
                    ButterflyKind::Fourier { generator } if coordinate < bit => {
                        generator.exp_u64((1usize << (coordinate + variables - bit - 1)) as u64)
                    }
                    _ => Bn254::ONE,
                };
                weighted_factor *= equal_boolean_sum(&points, twiddle_bit);
            }
            let output_zero = Bn254::ONE - output[bit];
            let output_one = output[bit];
            let gate_value = match kind {
                ButterflyKind::MobiusInverse => {
                    output_zero * ordinary_factor * input_values[0]
                        + output_one * ordinary_factor * (input_values[1] - input_values[0])
                }
                ButterflyKind::Fourier { .. } => {
                    output_zero
                        * (ordinary_factor * input_values[0] + weighted_factor * input_values[1])
                        + output_one
                            * (ordinary_factor * input_values[0]
                                - weighted_factor * input_values[1])
                }
            };
            sum + coefficient * fixed_inputs * gate_value
        },
    )
}

fn bit_reverse_terminal_evaluation(
    output_points: &[Vec<Bn254>],
    output_coefficients: &[Bn254],
    input_points: &[Vec<Bn254>; INPUT_ARITY],
    input_value: Bn254,
) -> Bn254 {
    output_points.iter().zip(output_coefficients).fold(
        Bn254::ZERO,
        |sum, (output, &coefficient)| {
            let variables = output.len();
            let wiring = (0..variables).fold(Bn254::ONE, |product, coordinate| {
                product
                    * equal_boolean_sum(
                        &[
                            output[coordinate],
                            input_points[0][variables - 1 - coordinate],
                            input_points[1][variables - 1 - coordinate],
                            input_points[2][variables - 1 - coordinate],
                        ],
                        Bn254::ONE,
                    )
            });
            sum + coefficient * wiring * input_value
        },
    )
}

fn leaf_input_terminal_evaluation(
    assignment_len: usize,
    trace_len: usize,
    repeats: usize,
    output_points: &[Vec<Bn254>],
    output_coefficients: &[Bn254],
    input_points: &[Vec<Bn254>; INPUT_ARITY],
    input_value: Bn254,
) -> Bn254 {
    let copy_variables = repeats.trailing_zeros() as usize;
    let trace_variables = trace_len.trailing_zeros() as usize;
    let high_input_selector =
        (copy_variables..trace_variables).fold(Bn254::ONE, |product, coordinate| {
            (0..INPUT_ARITY).fold(product, |product, input| {
                product * (Bn254::ONE - input_points[input][coordinate])
            })
        });

    output_points.iter().zip(output_coefficients).fold(
        Bn254::ZERO,
        |sum, (output, &coefficient)| {
            let local = &output[..2];
            let copy = &output[2..];
            let factors = (0..copy_variables)
                .map(|coordinate| {
                    equal_boolean_sum(
                        &[
                            copy[coordinate],
                            input_points[0][coordinate],
                            input_points[1][coordinate],
                            input_points[2][coordinate],
                        ],
                        Bn254::ONE,
                    )
                })
                .collect::<Vec<_>>();
            let copy_factor = factors.iter().copied().product::<Bn254>();
            let assignment_copy_factor = less_than_boolean_sum(
                copy,
                &[
                    &input_points[0][..copy_variables],
                    &input_points[1][..copy_variables],
                    &input_points[2][..copy_variables],
                ],
                assignment_len,
            );
            let index_evaluation =
                (0..copy_variables).fold(Bn254::ZERO, |index_evaluation, coordinate| {
                    let one_weight = copy[coordinate]
                        * input_points[0][coordinate]
                        * input_points[1][coordinate]
                        * input_points[2][coordinate];
                    let other_weight = factors
                        .iter()
                        .enumerate()
                        .filter(|&(index, _)| index != coordinate)
                        .map(|(_, &factor)| factor)
                        .product::<Bn254>();
                    index_evaluation
                        + Bn254::from_usize(1usize << coordinate) * one_weight * other_weight
                });
            let local_weights = [0, 1, 2].map(|index| eq_at_index_low(local, index));
            let gate_value = local_weights[0] * assignment_copy_factor * input_value
                + local_weights[1] * index_evaluation
                + local_weights[2] * copy_factor;
            sum + coefficient * high_input_selector * gate_value
        },
    )
}

/// Evaluate the multilinear extension of the joint equality predicate over
/// Boolean indices in `0..bound`. `output` and every input point are ordered
/// low bit first.
fn less_than_boolean_sum(output: &[Bn254], inputs: &[&[Bn254]], bound: usize) -> Bn254 {
    debug_assert!(inputs.iter().all(|input| input.len() == output.len()));
    let domain_size = 1usize << output.len();
    debug_assert!(bound <= domain_size);
    if bound == domain_size {
        return (0..output.len()).fold(Bn254::ONE, |product, coordinate| {
            let mut points = Vec::with_capacity(inputs.len() + 1);
            points.push(output[coordinate]);
            points.extend(inputs.iter().map(|input| input[coordinate]));
            product * equal_boolean_sum(&points, Bn254::ONE)
        });
    }

    let mut less = Bn254::ZERO;
    let mut equal = Bn254::ONE;
    for coordinate in (0..output.len()).rev() {
        let mut zero = Bn254::ONE - output[coordinate];
        let mut one = output[coordinate];
        for input in inputs {
            zero *= Bn254::ONE - input[coordinate];
            one *= input[coordinate];
        }
        let either = zero + one;
        if bound & (1 << coordinate) == 0 {
            less *= either;
            equal *= zero;
        } else {
            less = less * either + equal * zero;
            equal *= one;
        }
    }
    less
}

fn equal_boolean_sum(points: &[Bn254], one_multiplier: Bn254) -> Bn254 {
    let zeros = points
        .iter()
        .fold(Bn254::ONE, |product, &point| product * (Bn254::ONE - point));
    let ones = points.iter().copied().product::<Bn254>();
    zeros + one_multiplier * ones
}

fn checkpoint_layer_evaluations(
    layers: &[Layer],
    input: Vec<Bn254>,
) -> Result<(LayerCheckpoints, Vec<Bn254>), Error> {
    let mut checkpoints = LayerCheckpoints::create()?;
    checkpoints.append(&input)?;
    let mut current = input;
    for layer in layers {
        let next = layer.evaluate(&current);
        checkpoints.append(&next)?;
        current = next;
    }
    Ok((checkpoints, current))
}

/// Prove that the canonical padded assignment Merkle tree has `root`.
pub(crate) fn prove(
    assignment: &[Bn254],
    root: Digest,
    commitment_seed: &[Bn254],
    main_trace_mle: Vec<Bn254>,
) -> Result<(Proof, InputClaims), Error> {
    if assignment.is_empty() {
        return Err(Error::EmptyAssignment);
    }
    let padded_len = assignment.len().next_power_of_two();
    if !main_trace_mle.len().is_power_of_two() || main_trace_mle.len() < padded_len {
        return Err(Error::ProverClaim);
    }
    let trace_len = main_trace_mle.len();
    let layers = merkle_layers(assignment.len(), padded_len, trace_len);
    let (mut checkpoints, output) = checkpoint_layer_evaluations(&layers, main_trace_mle)?;
    if output[0] != root {
        return Err(Error::RootMismatch);
    }
    drop(output);

    let mut transcript = Transcript::new(padded_len, root, commitment_seed);
    let mut claim = root;
    let mut claim_points = vec![vec![Bn254::ZERO; 2]];
    let mut claim_coefficients = vec![Bn254::ONE];
    let mut proof_layers = Vec::with_capacity(layers.len());

    for layer_index in (0..layers.len()).rev() {
        let layer = &layers[layer_index];
        let previous = checkpoints.read(layer_index)?;
        let gate_weights =
            combined_eq_table(&claim_points, &claim_coefficients, layer.output_size());
        let mut phase_points: [Vec<Bn254>; INPUT_ARITY] = array::from_fn(|_| Vec::new());
        let mut phase_values = [Bn254::ZERO; INPUT_ARITY];
        let mut phase_proofs = Vec::with_capacity(INPUT_ARITY);

        for phase in 0..INPUT_ARITY {
            let mut coefficients = initialize_phase(
                layer,
                &previous,
                &gate_weights,
                phase,
                &phase_points,
                &phase_values,
            );
            let mut folded_values = previous.clone();
            let honest_sum = sum_polynomial_table(&coefficients, &folded_values);
            if honest_sum != claim {
                return Err(Error::ProverClaim);
            }
            let (phase_proof, point, terminal_claim) = prove_phase(
                &mut transcript,
                &mut coefficients,
                &mut folded_values,
                claim,
            );
            claim = terminal_claim;
            phase_values[phase] = phase_proof.value;
            phase_points[phase] = point;
            phase_proofs.push(phase_proof);
        }

        let expected = layer.terminal_evaluation(
            &claim_points,
            &claim_coefficients,
            &phase_points,
            phase_values,
        );
        if claim != expected {
            return Err(Error::ProverClaim);
        }
        let next_coefficients: [Bn254; INPUT_ARITY] = array::from_fn(|_| transcript.challenge());
        claim = (0..INPUT_ARITY).fold(Bn254::ZERO, |sum, input| {
            sum + next_coefficients[input] * phase_values[input]
        });
        claim_points = phase_points.to_vec();
        claim_coefficients = next_coefficients.to_vec();
        proof_layers.push(LayerProof {
            phases: phase_proofs
                .try_into()
                .expect("there are exactly three input phases"),
        });
    }

    let input_claims = InputClaims {
        points: claim_points
            .try_into()
            .expect("the final reduction has three points"),
        coefficients: claim_coefficients
            .try_into()
            .expect("the final reduction has three coefficients"),
        claim,
        transcript_binding: transcript.binding(),
        trace_len,
    };
    Ok((
        Proof {
            layers: proof_layers,
        },
        input_claims,
    ))
}

/// Verify all GKR reductions except the final shared assignment openings.
pub(crate) fn verify(
    assignment_len: usize,
    trace_len: usize,
    root: Digest,
    commitment_seed: &[Bn254],
    proof: &Proof,
) -> Result<InputClaims, Error> {
    if assignment_len == 0 {
        return Err(Error::EmptyAssignment);
    }
    let padded_len = assignment_len.next_power_of_two();
    if !trace_len.is_power_of_two() || trace_len < padded_len {
        return Err(Error::InputClaim);
    }
    let layers = merkle_layers(assignment_len, padded_len, trace_len);
    if proof.layers.len() != layers.len() {
        return Err(Error::LayerCount {
            expected: layers.len(),
            actual: proof.layers.len(),
        });
    }
    let mut transcript = Transcript::new(padded_len, root, commitment_seed);
    let mut claim = root;
    let mut claim_points = vec![vec![Bn254::ZERO; 2]];
    let mut claim_coefficients = vec![Bn254::ONE];

    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let layer = &layers[layer_index];
        let proof_layer = &proof.layers[proof_index];
        let expected_rounds = layer.input_size().trailing_zeros() as usize;
        let mut phase_points: [Vec<Bn254>; INPUT_ARITY] = array::from_fn(|_| Vec::new());
        let mut phase_values = [Bn254::ZERO; INPUT_ARITY];

        for phase in 0..INPUT_ARITY {
            let phase_proof = &proof_layer.phases[phase];
            if phase_proof.rounds.len() != expected_rounds {
                return Err(Error::RoundCount {
                    layer: layer_index,
                    phase,
                    expected: expected_rounds,
                    actual: phase_proof.rounds.len(),
                });
            }
            let mut point = Vec::with_capacity(expected_rounds);
            for (round, evaluations) in phase_proof.rounds.iter().enumerate() {
                if evaluations[0] + evaluations[1] != claim {
                    return Err(Error::Sumcheck {
                        layer: layer_index,
                        phase,
                        round,
                    });
                }
                transcript.observe_round(evaluations);
                let challenge = transcript.challenge();
                claim = interpolate_evaluations(evaluations, challenge);
                point.push(challenge);
            }
            transcript.observe(phase_proof.value);
            phase_points[phase] = point;
            phase_values[phase] = phase_proof.value;
        }
        let expected = layer.terminal_evaluation(
            &claim_points,
            &claim_coefficients,
            &phase_points,
            phase_values,
        );
        if claim != expected {
            return Err(Error::Wiring(layer_index));
        }
        let next_coefficients: [Bn254; INPUT_ARITY] = array::from_fn(|_| transcript.challenge());
        claim = (0..INPUT_ARITY).fold(Bn254::ZERO, |sum, input| {
            sum + next_coefficients[input] * phase_values[input]
        });
        claim_points = phase_points.to_vec();
        claim_coefficients = next_coefficients.to_vec();
    }

    Ok(InputClaims {
        points: claim_points
            .try_into()
            .expect("the final reduction has three points"),
        coefficients: claim_coefficients
            .try_into()
            .expect("the final reduction has three coefficients"),
        claim,
        transcript_binding: transcript.binding(),
        trace_len,
    })
}

/// Prove a public-output claim for a sparse layered arithmetic circuit.
///
/// `expected_outputs` lists the only nonzero output wires. A random MLE point
/// sampled after the input commitment checks those public roots together with
/// all zero gate/wiring residual wires in one claim.
pub(crate) fn prove_layered(
    circuit: &LayeredCircuit,
    input: Vec<Bn254>,
    expected_outputs: &[(usize, Bn254)],
    transcript_seed: &[Bn254],
) -> Result<(Proof, InputClaims), Error> {
    if input.len() != circuit.input_size {
        return Err(Error::ProverClaim);
    }
    let (mut checkpoints, output) = checkpoint_layer_evaluations(&circuit.layers, input)?;

    let mut transcript = Transcript::new_layered(circuit.output_size(), transcript_seed);
    let output_point = (0..circuit.output_size().trailing_zeros())
        .map(|_| transcript.challenge())
        .collect::<Vec<_>>();
    let expected_claim = expected_outputs
        .iter()
        .fold(Bn254::ZERO, |sum, &(index, value)| {
            sum + value * eq_at_index_low(&output_point, index)
        });
    let actual_claim = mle_evaluation_low(&output, &output_point);
    if actual_claim != expected_claim {
        return Err(Error::ProverClaim);
    }

    prove_layer_reductions(
        &circuit.layers,
        &mut checkpoints,
        &mut transcript,
        vec![output_point],
        vec![Bn254::ONE],
        expected_claim,
        circuit.input_size,
    )
}

/// Verify a sparse layered GKR proof except for its terminal MLE openings.
pub(crate) fn verify_layered(
    circuit: &LayeredCircuit,
    expected_outputs: &[(usize, Bn254)],
    transcript_seed: &[Bn254],
    proof: &Proof,
) -> Result<InputClaims, Error> {
    if proof.layers.len() != circuit.layers.len() {
        return Err(Error::LayerCount {
            expected: circuit.layers.len(),
            actual: proof.layers.len(),
        });
    }
    let mut transcript = Transcript::new_layered(circuit.output_size(), transcript_seed);
    let output_point = (0..circuit.output_size().trailing_zeros())
        .map(|_| transcript.challenge())
        .collect::<Vec<_>>();
    let expected_claim = expected_outputs
        .iter()
        .fold(Bn254::ZERO, |sum, &(index, value)| {
            sum + value * eq_at_index_low(&output_point, index)
        });

    verify_layer_reductions(
        &circuit.layers,
        &mut transcript,
        vec![output_point],
        vec![Bn254::ONE],
        expected_claim,
        circuit.input_size,
        proof,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_layer_reductions(
    layers: &[Layer],
    checkpoints: &mut LayerCheckpoints,
    transcript: &mut Transcript,
    mut claim_points: Vec<Vec<Bn254>>,
    mut claim_coefficients: Vec<Bn254>,
    mut claim: Bn254,
    input_size: usize,
) -> Result<(Proof, InputClaims), Error> {
    let mut proof_layers = Vec::with_capacity(layers.len());
    for layer_index in (0..layers.len()).rev() {
        let layer = &layers[layer_index];
        let previous = checkpoints.read(layer_index)?;
        let gate_weights =
            combined_eq_table(&claim_points, &claim_coefficients, layer.output_size());
        let mut phase_points: [Vec<Bn254>; INPUT_ARITY] = array::from_fn(|_| Vec::new());
        let mut phase_values = [Bn254::ZERO; INPUT_ARITY];
        let mut phase_proofs = Vec::with_capacity(INPUT_ARITY);
        for phase in 0..INPUT_ARITY {
            let mut coefficients = initialize_phase(
                layer,
                &previous,
                &gate_weights,
                phase,
                &phase_points,
                &phase_values,
            );
            let mut folded_values = previous.clone();
            if sum_polynomial_table(&coefficients, &folded_values) != claim {
                return Err(Error::ProverClaim);
            }
            let (phase_proof, point, terminal_claim) =
                prove_phase(transcript, &mut coefficients, &mut folded_values, claim);
            claim = terminal_claim;
            phase_values[phase] = phase_proof.value;
            phase_points[phase] = point;
            phase_proofs.push(phase_proof);
        }
        let expected = layer.terminal_evaluation(
            &claim_points,
            &claim_coefficients,
            &phase_points,
            phase_values,
        );
        if claim != expected {
            return Err(Error::ProverClaim);
        }
        let next_coefficients: [Bn254; INPUT_ARITY] = array::from_fn(|_| transcript.challenge());
        claim = (0..INPUT_ARITY).fold(Bn254::ZERO, |sum, input| {
            sum + next_coefficients[input] * phase_values[input]
        });
        claim_points = phase_points.to_vec();
        claim_coefficients = next_coefficients.to_vec();
        proof_layers.push(LayerProof {
            phases: phase_proofs
                .try_into()
                .expect("there are exactly three input phases"),
        });
    }
    Ok((
        Proof {
            layers: proof_layers,
        },
        InputClaims {
            points: claim_points
                .try_into()
                .expect("the final reduction has three points"),
            coefficients: claim_coefficients
                .try_into()
                .expect("the final reduction has three coefficients"),
            claim,
            transcript_binding: transcript.binding(),
            trace_len: input_size,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_layer_reductions(
    layers: &[Layer],
    transcript: &mut Transcript,
    mut claim_points: Vec<Vec<Bn254>>,
    mut claim_coefficients: Vec<Bn254>,
    mut claim: Bn254,
    input_size: usize,
    proof: &Proof,
) -> Result<InputClaims, Error> {
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let layer = &layers[layer_index];
        let proof_layer = &proof.layers[proof_index];
        let expected_rounds = layer.input_size().trailing_zeros() as usize;
        let mut phase_points: [Vec<Bn254>; INPUT_ARITY] = array::from_fn(|_| Vec::new());
        let mut phase_values = [Bn254::ZERO; INPUT_ARITY];
        for phase in 0..INPUT_ARITY {
            let phase_proof = &proof_layer.phases[phase];
            if phase_proof.rounds.len() != expected_rounds {
                return Err(Error::RoundCount {
                    layer: layer_index,
                    phase,
                    expected: expected_rounds,
                    actual: phase_proof.rounds.len(),
                });
            }
            let mut point = Vec::with_capacity(expected_rounds);
            for (round, evaluations) in phase_proof.rounds.iter().enumerate() {
                if evaluations[0] + evaluations[1] != claim {
                    return Err(Error::Sumcheck {
                        layer: layer_index,
                        phase,
                        round,
                    });
                }
                transcript.observe_round(evaluations);
                let challenge = transcript.challenge();
                claim = interpolate_evaluations(evaluations, challenge);
                point.push(challenge);
            }
            transcript.observe(phase_proof.value);
            phase_points[phase] = point;
            phase_values[phase] = phase_proof.value;
        }
        let expected = layer.terminal_evaluation(
            &claim_points,
            &claim_coefficients,
            &phase_points,
            phase_values,
        );
        if claim != expected {
            return Err(Error::Wiring(layer_index));
        }
        let next_coefficients: [Bn254; INPUT_ARITY] = array::from_fn(|_| transcript.challenge());
        claim = (0..INPUT_ARITY).fold(Bn254::ZERO, |sum, input| {
            sum + next_coefficients[input] * phase_values[input]
        });
        claim_points = phase_points.to_vec();
        claim_coefficients = next_coefficients.to_vec();
    }
    Ok(InputClaims {
        points: claim_points
            .try_into()
            .expect("the final reduction has three points"),
        coefficients: claim_coefficients
            .try_into()
            .expect("the final reduction has three coefficients"),
        claim,
        transcript_binding: transcript.binding(),
        trace_len: input_size,
    })
}

pub(crate) fn mle_evaluation_low(values: &[Bn254], point: &[Bn254]) -> Bn254 {
    debug_assert_eq!(values.len(), 1usize << point.len());
    values
        .iter()
        .enumerate()
        .fold(Bn254::ZERO, |sum, (index, &value)| {
            sum + value * eq_at_index_low(point, index)
        })
}

fn prove_phase(
    transcript: &mut Transcript,
    coefficients: &mut Vec<[Bn254; MAX_DEGREE + 1]>,
    values: &mut Vec<Bn254>,
    initial_claim: Bn254,
) -> (PhaseProof, Vec<Bn254>, Bn254) {
    let rounds = values.len().trailing_zeros() as usize;
    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(rounds);
    let mut messages = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let evaluations = round_evaluations(coefficients, values);
        debug_assert_eq!(evaluations[0] + evaluations[1], claim);
        transcript.observe_round(&evaluations);
        let challenge = transcript.challenge();
        claim = interpolate_evaluations(&evaluations, challenge);
        fold_table(coefficients, challenge);
        fold_table(values, challenge);
        messages.push(evaluations);
        point.push(challenge);
    }
    let value = values[0];
    transcript.observe(value);
    (
        PhaseProof {
            rounds: messages,
            value,
        },
        point,
        claim,
    )
}

fn initialize_phase(
    layer: &Layer,
    previous: &[Bn254],
    gate_weights: &[Bn254],
    phase: usize,
    phase_points: &[Vec<Bn254>; INPUT_ARITY],
    phase_values: &[Bn254; INPUT_ARITY],
) -> Vec<[Bn254; MAX_DEGREE + 1]> {
    let mut result = vec![[Bn254::ZERO; MAX_DEGREE + 1]; layer.input_size()];
    for (output, &gate_weight) in gate_weights.iter().enumerate() {
        let gate = layer.global_gate(output);
        let fixed_weight = (0..phase).fold(gate_weight, |weight, input| {
            weight * eq_at_index_low(&phase_points[input], gate.inputs[input])
        });
        let mut constant = gate.polynomial.constant;
        for input in 0..INPUT_ARITY {
            if input == phase {
                continue;
            }
            let value = if input < phase {
                phase_values[input]
            } else {
                previous[gate.inputs[input]]
            };
            constant += evaluate_univariate(&gate.polynomial.coefficients[input], value);
        }
        let target = &mut result[gate.inputs[phase]];
        target[0] += fixed_weight * constant;
        for (target, &coefficient) in target[1..]
            .iter_mut()
            .zip(&gate.polynomial.coefficients[phase])
        {
            *target += fixed_weight * coefficient;
        }
        for term in &gate.polynomial.mixed_terms {
            let mut coefficient = fixed_weight * term.coefficient;
            for (input, &exponent) in term.exponents.iter().enumerate() {
                if input == phase {
                    continue;
                }
                let value = if input < phase {
                    phase_values[input]
                } else {
                    previous[gate.inputs[input]]
                };
                coefficient *= value.exp_u64(exponent as u64);
            }
            target[term.exponents[phase]] += coefficient;
        }
    }
    result
}

fn round_evaluations(
    coefficients: &[[Bn254; MAX_DEGREE + 1]],
    values: &[Bn254],
) -> [Bn254; SUMCHECK_EVALUATIONS] {
    debug_assert_eq!(coefficients.len(), values.len());
    debug_assert!(values.len() >= 2 && values.len().is_power_of_two());
    let mut result = [Bn254::ZERO; SUMCHECK_EVALUATIONS];
    for pair in 0..values.len() / 2 {
        let left = pair << 1;
        let right = left | 1;
        for (point, output) in result.iter_mut().enumerate() {
            let point = Bn254::from_usize(point);
            let value = values[left] + point * (values[right] - values[left]);
            let mut power = Bn254::ONE;
            for (&left_coefficient, &right_coefficient) in
                coefficients[left].iter().zip(&coefficients[right])
            {
                let coefficient = left_coefficient + point * (right_coefficient - left_coefficient);
                *output += coefficient * power;
                power *= value;
            }
        }
    }
    result
}

fn sum_polynomial_table(coefficients: &[[Bn254; MAX_DEGREE + 1]], values: &[Bn254]) -> Bn254 {
    coefficients
        .iter()
        .zip(values)
        .fold(Bn254::ZERO, |sum, (coefficients, &value)| {
            let mut power = Bn254::ONE;
            let evaluation = coefficients.iter().fold(Bn254::ZERO, |sum, &coefficient| {
                let next = sum + coefficient * power;
                power *= value;
                next
            });
            sum + evaluation
        })
}

fn fold_table<T>(table: &mut Vec<T>, challenge: Bn254)
where
    T: FoldValue,
{
    let half = table.len() / 2;
    for pair in 0..half {
        let left = pair << 1;
        let right = left | 1;
        table[pair] = T::fold(&table[left], &table[right], challenge);
    }
    table.truncate(half);
}

trait FoldValue: Sized {
    fn fold(left: &Self, right: &Self, challenge: Bn254) -> Self;
}

impl FoldValue for Bn254 {
    fn fold(left: &Self, right: &Self, challenge: Bn254) -> Self {
        *left + challenge * (*right - *left)
    }
}

impl FoldValue for [Bn254; MAX_DEGREE + 1] {
    fn fold(left: &Self, right: &Self, challenge: Bn254) -> Self {
        array::from_fn(|degree| left[degree] + challenge * (right[degree] - left[degree]))
    }
}

fn interpolate_evaluations(evaluations: &[Bn254; SUMCHECK_EVALUATIONS], point: Bn254) -> Bn254 {
    // Newton's forward-difference formula at the integer points 0 through 6.
    let mut differences = *evaluations;
    let mut result = differences[0];
    let mut binomial = Bn254::ONE;
    let inverses = batch_small_inverses();
    for (order, &inverse) in inverses.iter().enumerate().skip(1) {
        for index in 0..SUMCHECK_EVALUATIONS - order {
            differences[index] = differences[index + 1] - differences[index];
        }
        binomial *= (point - Bn254::from_usize(order - 1)) * inverse;
        result += differences[0] * binomial;
    }
    result
}

fn batch_small_inverses() -> [Bn254; SUMCHECK_EVALUATIONS] {
    let mut values = array::from_fn(|index| Bn254::from_usize(index.max(1)));
    let mut prefix = [Bn254::ONE; SUMCHECK_EVALUATIONS];
    for index in 1..SUMCHECK_EVALUATIONS {
        prefix[index] = prefix[index - 1] * values[index];
    }
    let mut inverse = prefix[SUMCHECK_EVALUATIONS - 1].inverse();
    for index in (1..SUMCHECK_EVALUATIONS).rev() {
        let value = values[index];
        values[index] = inverse * prefix[index - 1];
        inverse *= value;
    }
    values[0] = Bn254::ONE;
    values
}

fn evaluate_univariate(coefficients: &[Bn254; MAX_DEGREE], value: Bn254) -> Bn254 {
    let mut power = value;
    coefficients.iter().fold(Bn254::ZERO, |sum, &coefficient| {
        let result = sum + coefficient * power;
        power *= value;
        result
    })
}

fn combined_eq_table(points: &[Vec<Bn254>], coefficients: &[Bn254], size: usize) -> Vec<Bn254> {
    let mut result = vec![Bn254::ZERO; size];
    for (point, &coefficient) in points.iter().zip(coefficients) {
        let evaluations = eq_evaluations_low(point);
        debug_assert_eq!(evaluations.len(), size);
        for (result, evaluation) in result.iter_mut().zip(evaluations) {
            *result += coefficient * evaluation;
        }
    }
    result
}

fn eq_evaluations_low(point: &[Bn254]) -> Vec<Bn254> {
    let mut result = vec![Bn254::ONE];
    for (bit, &coordinate) in point.iter().enumerate() {
        let old_len = result.len();
        result.resize(old_len << 1, Bn254::ZERO);
        for mask in 0..old_len {
            let value = result[mask];
            result[mask] = value * (Bn254::ONE - coordinate);
            result[mask | (1 << bit)] = value * coordinate;
        }
    }
    result
}

fn eq_at_index_low(point: &[Bn254], index: usize) -> Bn254 {
    point
        .iter()
        .enumerate()
        .fold(Bn254::ONE, |value, (bit, &coordinate)| {
            value
                * if index & (1 << bit) == 0 {
                    Bn254::ONE - coordinate
                } else {
                    coordinate
                }
        })
}

fn eq_boolean(point: Bn254, bit: bool) -> Bn254 {
    if bit { point } else { Bn254::ONE - point }
}

fn eq_same_copy(gate: &[Bn254], input0: &[Bn254], input1: &[Bn254], input2: &[Bn254]) -> Bn254 {
    debug_assert_eq!(gate.len(), input0.len());
    debug_assert_eq!(gate.len(), input1.len());
    debug_assert_eq!(gate.len(), input2.len());
    gate.iter().zip(input0).zip(input1).zip(input2).fold(
        Bn254::ONE,
        |product, (((&g, &u), &v), &w)| {
            product
                * ((Bn254::ONE - g) * (Bn254::ONE - u) * (Bn254::ONE - v) * (Bn254::ONE - w)
                    + g * u * v * w)
        },
    )
}

fn merkle_layers(assignment_len: usize, padded_len: usize, trace_len: usize) -> Vec<Layer> {
    debug_assert!(assignment_len > 0 && assignment_len <= padded_len);
    debug_assert!(padded_len.is_power_of_two());
    debug_assert!(trace_len.is_power_of_two() && trace_len >= padded_len);
    let mut layers = Vec::new();
    let trace_variables = trace_len.trailing_zeros() as usize;

    // The static WHIR adapter commits to the Boolean-hypercube evaluation
    // table of the coefficient polynomial. Undo that Möbius transform, then
    // run the radix-2 DFT to recover the Plonk trace's subgroup evaluations.
    for bit in 0..trace_variables {
        layers.push(Layer::Butterfly {
            size: trace_len,
            bit,
            kind: ButterflyKind::MobiusInverse,
        });
    }
    layers.push(Layer::BitReverse { size: trace_len });
    let generator = Bn254::two_adic_generator(trace_variables);
    for bit in 0..trace_variables {
        layers.push(Layer::Butterfly {
            size: trace_len,
            bit,
            kind: ButterflyKind::Fourier { generator },
        });
    }
    layers.push(Layer::LeafInput {
        assignment_len,
        trace_len,
        repeats: padded_len,
    });
    append_poseidon_layers(&mut layers, padded_len);
    let height = padded_len.trailing_zeros() as usize;
    let mut repeats = padded_len;
    for level in 0..height {
        repeats >>= 1;
        layers.push(pair_layer(repeats, Bn254::from_usize(2 + level)));
        append_poseidon_layers(&mut layers, repeats);
    }
    layers
}

fn pair_layer(repeats: usize, domain: Bn254) -> Layer {
    let relay = |right: bool| LocalGate {
        inputs: [0; INPUT_ARITY],
        input_copy_bits: [right; INPUT_ARITY],
        polynomial: GatePolynomial::linear([Bn254::ONE, Bn254::ZERO, Bn254::ZERO]),
    };
    let constant = |value| LocalGate {
        inputs: [0; INPUT_ARITY],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::constant(value),
    };
    Layer::Pair {
        repeats,
        gates: [
            relay(false),
            relay(true),
            constant(domain),
            constant(Bn254::ZERO),
        ],
    }
}

fn product_pair_layer(repeats: usize) -> Layer {
    let product = |local| LocalGate {
        inputs: [local, local, local],
        input_copy_bits: [false, true, false],
        polynomial: GatePolynomial::product(),
    };
    let one = || LocalGate {
        inputs: [0; INPUT_ARITY],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::constant(Bn254::ONE),
    };
    Layer::Pair {
        repeats,
        gates: [product(0), product(1), one(), one()],
    }
}

fn parallel_difference_layer(repeats: usize, left: usize, right: usize) -> Layer {
    let mut gates: [LocalGate; BLOCK_SIZE] = array::from_fn(|_| LocalGate {
        inputs: [0; INPUT_ARITY],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::zero(),
    });
    gates[0] = LocalGate {
        inputs: [left, right, left],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::linear([Bn254::ONE, -Bn254::ONE, Bn254::ZERO]),
    };
    Layer::Parallel { repeats, gates }
}

fn append_poseidon_layers(layers: &mut Vec<Layer>, repeats: usize) {
    // TODO(poseidon-gkr): replace this generic repeated degree-five circuit
    // with a Poseidon-specific GKR reduction to lower prover work/proof size.
    // The shared terminal WHIR openings do not change under that optimization.
    layers.push(parallel_layer(
        repeats,
        linear_state([
            [Bn254::TWO, Bn254::ONE, Bn254::ONE],
            [Bn254::ONE, Bn254::TWO, Bn254::ONE],
            [Bn254::ONE, Bn254::ONE, Bn254::TWO],
        ]),
    ));
    let (external, internal) = poseidon2_constants();
    for &constants in external.get_initial_constants() {
        layers.push(parallel_layer(repeats, full_round(constants)));
    }
    for constant in internal {
        layers.push(parallel_layer(repeats, partial_round(constant)));
    }
    for &constants in external.get_terminal_constants() {
        layers.push(parallel_layer(repeats, full_round(constants)));
    }
}

fn append_poseidon_layers_with_carry(layers: &mut Vec<Layer>, repeats: usize) {
    layers.push(parallel_layer_with_carry(
        repeats,
        linear_state([
            [Bn254::TWO, Bn254::ONE, Bn254::ONE],
            [Bn254::ONE, Bn254::TWO, Bn254::ONE],
            [Bn254::ONE, Bn254::ONE, Bn254::TWO],
        ]),
    ));
    let (external, internal) = poseidon2_constants();
    for &constants in external.get_initial_constants() {
        layers.push(parallel_layer_with_carry(repeats, full_round(constants)));
    }
    for constant in internal {
        layers.push(parallel_layer_with_carry(repeats, partial_round(constant)));
    }
    for &constants in external.get_terminal_constants() {
        layers.push(parallel_layer_with_carry(repeats, full_round(constants)));
    }
}

fn parallel_layer(repeats: usize, polynomials: [GatePolynomial; 3]) -> Layer {
    let mut gates: [LocalGate; BLOCK_SIZE] = array::from_fn(|_| LocalGate {
        inputs: [0, 1, 2],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::zero(),
    });
    for (gate, polynomial) in gates.iter_mut().zip(polynomials) {
        gate.polynomial = polynomial;
    }
    Layer::Parallel { repeats, gates }
}

fn parallel_layer_with_carry(repeats: usize, polynomials: [GatePolynomial; 3]) -> Layer {
    let mut layer = parallel_layer(repeats, polynomials);
    let Layer::Parallel { gates, .. } = &mut layer else {
        unreachable!();
    };
    gates[3] = LocalGate {
        inputs: [3; INPUT_ARITY],
        input_copy_bits: [false; INPUT_ARITY],
        polynomial: GatePolynomial::linear([Bn254::ONE, Bn254::ZERO, Bn254::ZERO]),
    };
    layer
}

fn linear_state(matrix: [[Bn254; 3]; 3]) -> [GatePolynomial; 3] {
    matrix.map(GatePolynomial::linear)
}

fn full_round(constants: [Bn254; 3]) -> [GatePolynomial; 3] {
    let matrix = [
        [Bn254::TWO, Bn254::ONE, Bn254::ONE],
        [Bn254::ONE, Bn254::TWO, Bn254::ONE],
        [Bn254::ONE, Bn254::ONE, Bn254::TWO],
    ];
    array::from_fn(|output| sbox_linear_polynomial(constants, matrix[output]))
}

fn partial_round(constant: Bn254) -> [GatePolynomial; 3] {
    let matrix = [
        [Bn254::TWO, Bn254::ONE, Bn254::ONE],
        [Bn254::ONE, Bn254::TWO, Bn254::ONE],
        [Bn254::ONE, Bn254::ONE, Bn254::from_u64(3)],
    ];
    array::from_fn(|output| {
        let mut polynomial =
            GatePolynomial::linear([Bn254::ZERO, matrix[output][1], matrix[output][2]]);
        add_shifted_fifth(&mut polynomial, 0, constant, matrix[output][0]);
        polynomial
    })
}

fn sbox_linear_polynomial(constants: [Bn254; 3], coefficients: [Bn254; 3]) -> GatePolynomial {
    let mut polynomial = GatePolynomial::zero();
    for input in 0..INPUT_ARITY {
        add_shifted_fifth(
            &mut polynomial,
            input,
            constants[input],
            coefficients[input],
        );
    }
    polynomial
}

fn add_shifted_fifth(polynomial: &mut GatePolynomial, input: usize, shift: Bn254, scale: Bn254) {
    let shift2 = shift.square();
    let shift3 = shift2 * shift;
    let shift4 = shift3 * shift;
    let shift5 = shift4 * shift;
    polynomial.constant += scale * shift5;
    polynomial.coefficients[input][0] += scale * Bn254::from_u64(5) * shift4;
    polynomial.coefficients[input][1] += scale * Bn254::from_u64(10) * shift3;
    polynomial.coefficients[input][2] += scale * Bn254::from_u64(10) * shift2;
    polynomial.coefficients[input][3] += scale * Bn254::from_u64(5) * shift;
    polynomial.coefficients[input][4] += scale;
}

struct Transcript {
    state: Bn254,
    counter: u64,
}

impl Transcript {
    fn new(padded_len: usize, root: Digest, commitment_seed: &[Bn254]) -> Self {
        let mut transcript = Self {
            state: hash_node(
                200,
                Bn254::from_u64(TRANSCRIPT_DOMAIN),
                Bn254::from_usize(padded_len),
            ),
            counter: 0,
        };
        transcript.observe(root);
        transcript.observe(Bn254::from_usize(commitment_seed.len()));
        for &value in commitment_seed {
            transcript.observe(value);
        }
        transcript
    }

    fn new_layered(output_size: usize, seed: &[Bn254]) -> Self {
        let mut transcript = Self {
            state: hash_node(
                210,
                Bn254::from_u64(TRANSCRIPT_DOMAIN ^ 0x5452_414e_5349_5449),
                Bn254::from_usize(output_size),
            ),
            counter: 0,
        };
        transcript.observe(Bn254::from_usize(seed.len()));
        for &value in seed {
            transcript.observe(value);
        }
        transcript
    }

    fn observe(&mut self, value: Bn254) {
        self.state = hash_node(201, self.state, value);
    }

    fn observe_round(&mut self, evaluations: &[Bn254; SUMCHECK_EVALUATIONS]) {
        for &evaluation in evaluations {
            self.observe(evaluation);
        }
    }

    fn challenge(&mut self) -> Bn254 {
        let challenge = hash_node(
            202 + self.counter as usize,
            self.state,
            Bn254::from_u64(self.counter),
        );
        self.counter += 1;
        self.observe(challenge);
        challenge
    }

    fn binding(&self) -> [Bn254; 2] {
        [self.state, Bn254::from_u64(self.counter)]
    }
}

#[cfg(test)]
mod tests {
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};

    use super::*;
    use crate::merkle::MerkleTree;
    use crate::static_snark::{commit_mle, commitment_seed, verify_mle_opening};

    #[test]
    fn disk_checkpoints_round_trip_and_cleanup() {
        let values = (0..CHECKPOINT_BUFFER_FIELDS + 3)
            .map(Bn254::from_usize)
            .collect::<Vec<_>>();
        let path;
        {
            let mut checkpoints = LayerCheckpoints::create().unwrap();
            path = checkpoints.path().to_path_buf();
            checkpoints.append(&values).unwrap();
            checkpoints.append(&[Bn254::from_u64(91)]).unwrap();
            assert_eq!(checkpoints.read(0).unwrap(), values);
            assert_eq!(checkpoints.read(1).unwrap(), [Bn254::from_u64(91)]);
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    #[test]
    fn bounded_leaf_selector_matches_boolean_enumeration() {
        let output = [Bn254::from_u64(2), Bn254::from_u64(3), Bn254::from_u64(4)];
        let inputs = [
            [Bn254::from_u64(5), Bn254::from_u64(6), Bn254::from_u64(7)],
            [Bn254::from_u64(8), Bn254::from_u64(9), Bn254::from_u64(10)],
            [
                Bn254::from_u64(11),
                Bn254::from_u64(12),
                Bn254::from_u64(13),
            ],
        ];
        for bound in 0..=8 {
            let actual =
                less_than_boolean_sum(&output, &[&inputs[0], &inputs[1], &inputs[2]], bound);
            let expected = (0..bound).fold(Bn254::ZERO, |sum, index| {
                sum + eq_at_index_low(&output, index)
                    * inputs
                        .iter()
                        .map(|point| eq_at_index_low(point, index))
                        .product::<Bn254>()
            });
            assert_eq!(actual, expected, "bound={bound}");
        }
    }

    #[test]
    fn virgo_gkr_round_trip_and_terminal_openings() {
        let assignment = (0..5).map(Bn254::from_usize).collect::<Vec<_>>();
        let root = MerkleTree::new(assignment.clone())
            .unwrap()
            .commitment()
            .root;
        let seed = [Bn254::from_u64(91), Bn254::from_u64(92)];
        let committed = committed_trace(&assignment);
        let trace_len = committed.len();
        let (proof, claims) = prove(&assignment, root, &seed, committed.clone()).unwrap();
        let verified = verify(assignment.len(), trace_len, root, &seed, &proof).unwrap();
        assert_eq!(claims.transcript_binding(), verified.transcript_binding());

        let evaluations = verified
            .main_trace_points()
            .map(|point| evaluate_table(&committed, point));
        verified.verify_main_trace_openings(&evaluations).unwrap();

        let mut bad = evaluations;
        bad[0] += Bn254::ONE;
        assert!(verified.verify_main_trace_openings(&bad).is_err());
    }

    #[test]
    fn gkr_rejects_wrong_root_and_tampering() {
        let assignment = [Bn254::from_u64(7), Bn254::from_u64(8)];
        let root = MerkleTree::new(assignment.to_vec())
            .unwrap()
            .commitment()
            .root;
        let committed = committed_trace(&assignment);
        assert!(prove(&assignment, root + Bn254::ONE, &[], committed.clone(),).is_err());

        let (mut proof, _) = prove(&assignment, root, &[], committed.clone()).unwrap();
        proof.layers[0].phases[0].rounds[0][0] += Bn254::ONE;
        assert!(verify(assignment.len(), committed.len(), root, &[], &proof).is_err());
    }

    #[test]
    fn regular_product_tree_checks_both_products() {
        let producers = (1..=8).map(Bn254::from_usize).collect::<Vec<_>>();
        let references = [3usize, 1, 8, 4, 2, 7, 5, 6].map(Bn254::from_usize);
        let mut input = Vec::with_capacity(32);
        for (&producer, reference) in producers.iter().zip(references) {
            input.extend([producer, reference, Bn254::ONE, Bn254::ONE]);
        }

        let circuit = LayeredCircuit::product_equality(8);
        assert!(circuit.is_regular());
        let seed = [Bn254::from_u64(37)];
        let (proof, prover_claims) = prove_layered(&circuit, input.clone(), &[], &seed).unwrap();
        let verifier_claims = verify_layered(&circuit, &[], &seed, &proof).unwrap();
        assert_eq!(
            prover_claims.transcript_binding(),
            verifier_claims.transcript_binding()
        );
        let evaluations = verifier_claims
            .mle_points()
            .map(|point| evaluate_table(&input, point));
        verifier_claims.verify_mle_openings(&evaluations).unwrap();

        let mut bad = input;
        bad[1] += Bn254::ONE;
        assert!(prove_layered(&circuit, bad, &[], &seed).is_err());
    }

    #[test]
    fn regular_poseidon_batch_checks_expected_outputs() {
        let mut input = Vec::new();
        for row in 0..4 {
            let left = Bn254::from_usize(2 * row + 1);
            let right = Bn254::from_usize(2 * row + 2);
            input.extend([
                left,
                right,
                Bn254::from_usize(2 + row),
                hash_node(row, left, right),
            ]);
        }

        let circuit = LayeredCircuit::poseidon_checks(4);
        assert!(circuit.is_regular());
        let seed = [Bn254::from_u64(41)];
        let (proof, _) = prove_layered(&circuit, input.clone(), &[], &seed).unwrap();
        let claims = verify_layered(&circuit, &[], &seed, &proof).unwrap();
        let evaluations = claims
            .mle_points()
            .map(|point| evaluate_table(&input, point));
        claims.verify_mle_openings(&evaluations).unwrap();

        input[3] += Bn254::ONE;
        assert!(prove_layered(&circuit, input, &[], &seed).is_err());
    }

    #[test]
    fn one_whir_opening_links_two_gkr_terminal_claims() {
        let mut input = Vec::new();
        for row in 0..8 {
            let value = Bn254::from_usize(row + 1);
            input.extend([
                value,
                value,
                Bn254::from_usize(2 + row),
                hash_node(row, value, value),
            ]);
        }
        let committed = commit_mle(input.clone()).unwrap();
        let mut gkr_seed = vec![Bn254::from_u64(73)];
        gkr_seed.extend(commitment_seed(committed.commitment()));

        let poseidon_circuit = LayeredCircuit::poseidon_checks(8);
        let product_circuit = LayeredCircuit::product_equality(8);
        let (poseidon_proof, poseidon_prover_claims) =
            prove_layered(&poseidon_circuit, input.clone(), &[], &gkr_seed).unwrap();
        let (product_proof, product_prover_claims) =
            prove_layered(&product_circuit, input.clone(), &[], &gkr_seed).unwrap();
        let poseidon_claims =
            verify_layered(&poseidon_circuit, &[], &gkr_seed, &poseidon_proof).unwrap();
        let product_claims =
            verify_layered(&product_circuit, &[], &gkr_seed, &product_proof).unwrap();
        assert_eq!(
            poseidon_prover_claims.transcript_binding(),
            poseidon_claims.transcript_binding()
        );
        assert_eq!(
            product_prover_claims.transcript_binding(),
            product_claims.transcript_binding()
        );

        let claims = [&poseidon_claims, &product_claims];
        let points = shared_mle_points(&claims);
        let opening_seed = shared_opening_seed(&gkr_seed, &[&poseidon_proof, &product_proof]);
        let mut opening = committed.open(&points, &opening_seed);
        verify_mle_opening(input.len(), &points, &opening, &opening_seed).unwrap();
        verify_shared_mle_openings(&claims, &opening.opening.evaluations).unwrap();

        opening.opening.evaluations[0] += Bn254::ONE;
        assert!(verify_mle_opening(input.len(), &points, &opening, &opening_seed).is_err());
        assert!(verify_shared_mle_openings(&claims, &opening.opening.evaluations).is_err());
    }

    fn row_constraint_circuit(repeats: usize) -> LayeredCircuit {
        let mut circuit = LayeredCircuit::new(16 * repeats);
        circuit.append_periodic(
            16,
            vec![
                GlobalGate::linear([0, 1, 2], [Bn254::ONE, Bn254::ONE, -Bn254::ONE]),
                GlobalGate::product_difference([0, 1, 3]),
            ],
        );
        circuit
    }

    #[test]
    fn periodic_wiring_checks_rows_without_dense_gates() {
        let repeats = 8;
        let mut input = vec![Bn254::ZERO; 16 * repeats];
        for row in 0..repeats {
            let left = Bn254::from_usize(row + 2);
            let right = Bn254::from_usize(row + 5);
            input[16 * row] = left;
            input[16 * row + 1] = right;
            input[16 * row + 2] = left + right;
            input[16 * row + 3] = left * right;
        }
        let circuit = row_constraint_circuit(repeats);
        assert!(circuit.is_regular());
        let seed = [Bn254::from_u64(101)];
        let (proof, _) = prove_layered(&circuit, input.clone(), &[], &seed).unwrap();
        let claims = verify_layered(&circuit, &[], &seed, &proof).unwrap();
        let evaluations = claims
            .mle_points()
            .map(|point| evaluate_table(&input, point));
        claims.verify_mle_openings(&evaluations).unwrap();

        input[16 * 5 + 2] += Bn254::ONE;
        assert!(prove_layered(&circuit, input, &[], &seed).is_err());
    }

    #[test]
    fn periodic_verifier_wiring_cost_is_logarithmic_in_rows() {
        let small = row_constraint_circuit(16).verifier_wiring_profile();
        let large = row_constraint_circuit(1 << 16).verifier_wiring_profile();
        assert_eq!(small.layers, large.layers);
        assert_eq!(small.local_gate_terms, 16);
        assert_eq!(small.local_gate_terms, large.local_gate_terms);
        assert_eq!(small.copy_coordinate_terms, 4);
        assert_eq!(large.copy_coordinate_terms, 16);
    }

    fn committed_trace(assignment: &[Bn254]) -> Vec<Bn254> {
        let mut values = assignment.to_vec();
        values.resize(values.len().next_power_of_two(), Bn254::ZERO);
        let mut coefficients = Radix2DFTSmallBatch::<Bn254>::default().idft(values);
        let variables = coefficients.len().trailing_zeros() as usize;
        for bit in 0..variables {
            for mask in 0..coefficients.len() {
                if mask & (1 << bit) != 0 {
                    let lower = coefficients[mask ^ (1 << bit)];
                    coefficients[mask] += lower;
                }
            }
        }
        coefficients
    }

    fn evaluate_table(table: &[Bn254], point: &[Bn254]) -> Bn254 {
        table
            .iter()
            .zip(eq_evaluations_low(point))
            .fold(Bn254::ZERO, |sum, (&value, weight)| sum + value * weight)
    }
}
