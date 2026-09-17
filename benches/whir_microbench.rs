//! Standalone WHIR commitment/opening folding-factor and code-rate benchmark.

#[path = "../src/hash.rs"]
mod hash;
#[path = "../src/static_snark/pcs.rs"]
mod pcs;

#[path = "../src/parallel.rs"]
mod parallel;

use std::error::Error;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use pcs::{ExplicitWhir, OpeningTimings, ParameterSummary, RateSchedule};

const DEFAULT_LOG_SIZE: usize = 18;
const DEFAULT_FACTORS: &[usize] = &[1, 2, 3, 4];
const DEFAULT_SAMPLES: usize = 5;
const DEFAULT_CLAIMS: usize = 1;
const CSV_HEADER: &str = "log_size,claims,factor,rate_schedule,sample,position,folding_schedule,round_log_inv_rates,codeword_domains,effective_queries,final_variables,commit_ms,eval_ms,proof_ms,open_total_ms,prover_ms,verify_ms,proof_payload_bytes,initial_commitment_bytes";

fn main() -> Result<(), Box<dyn Error>> {
    let log_size = env_usize("WHIR_MICROBENCH_LOG_SIZE", DEFAULT_LOG_SIZE)?;
    let factors = env_usize_list("WHIR_MICROBENCH_FACTORS", DEFAULT_FACTORS)?;
    let rates = env_rate_schedules()?;
    let samples = env_usize("WHIR_MICROBENCH_SAMPLES", DEFAULT_SAMPLES)?;
    let warmups = env_usize("WHIR_MICROBENCH_WARMUPS", 1)?;
    let claims = env_usize("WHIR_MICROBENCH_CLAIMS", DEFAULT_CLAIMS)?;
    let fresh_instance = env_bool("WHIR_MICROBENCH_FRESH_INSTANCE", false)?;
    if log_size == 0 || log_size >= usize::BITS as usize {
        return Err("WHIR_MICROBENCH_LOG_SIZE must be in 1..usize::BITS".into());
    }
    if samples == 0 || claims == 0 || factors.is_empty() || factors.contains(&0) {
        return Err("samples, claims, and folding factors must be positive".into());
    }
    let mut csv = match std::env::var("WHIR_MICROBENCH_CSV") {
        Ok(path) => Some(BufWriter::new(File::create(path)?)),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(csv) = &mut csv {
        writeln!(csv, "{CSV_HEADER}")?;
    }

    let entries = 1usize << log_size;
    let points = opening_points(log_size, claims);
    let table = polynomial(entries);
    let mut expected_evaluations = None;

    println!("WHIR multilinear PCS microbenchmark");
    println!("  polynomial entries: 2^{log_size} = {entries}");
    println!("  arbitrary-point claims batched into one proof: {claims}");
    println!("  security: 127-bit capacity-bound, zero PoW; starting code rate: 1/2");
    println!("  schedules: fixed = 1/2 throughout; default = native WHIR rate reduction");
    println!("  warmups per arm: {warmups}; measured samples per arm: {samples}");
    println!("  arm order reverses each sample; all proofs verified");
    println!(
        "  parallel feature: {}; RAYON_NUM_THREADS: {}",
        cfg!(feature = "parallel"),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "automatic".into())
    );
    println!("  fresh WHIR instance per sample: {fresh_instance}");
    println!("  polynomial construction/cloning and WHIR configuration: excluded");
    println!("  proof payload: all field elements and hashes; excludes encoding metadata");
    println!("  initial commitment is reported separately; prover = commit + open");
    println!();
    println!("{CSV_HEADER}");

    for factor in factors {
        if factor > log_size {
            eprintln!("skipping folding factor {factor}: exceeds arity {log_size}");
            continue;
        }
        let whirs = rates
            .iter()
            .map(|&rate| ExplicitWhir::new_with_rate_schedule(log_size, factor, rate))
            .collect::<Result<Vec<_>, _>>()?;
        let mut measurements = vec![Vec::with_capacity(samples); rates.len()];
        for iteration in 0..warmups + samples {
            let warming_up = iteration < warmups;
            let sample_index = if warming_up {
                iteration
            } else {
                iteration - warmups
            };
            let seed = [
                Bn254::from_u64(0x5748_4952),
                Bn254::from_usize(log_size),
                Bn254::from_usize(iteration),
            ];
            // Alternate AB/BA in the measured section independently of warmup count.
            for position in 0..rates.len() {
                let arm = if sample_index % 2 == 0 {
                    position
                } else {
                    rates.len() - 1 - position
                };
                let rate = rates[arm];
                eprintln!(
                    "factor {factor}, {}: {} {}",
                    rate.label(),
                    if warming_up { "warmup" } else { "sample" },
                    sample_index + 1
                );
                let sample_whir;
                let whir = if fresh_instance {
                    sample_whir = ExplicitWhir::new_with_rate_schedule(log_size, factor, rate)?;
                    &sample_whir
                } else {
                    &whirs[arm]
                };
                let (sample, evaluations) = measure(whir, table.clone(), &points, &seed)?;
                if let Some(expected) = &expected_evaluations {
                    assert_eq!(
                        &evaluations, expected,
                        "all arms must open the same polynomial"
                    );
                } else {
                    expected_evaluations = Some(evaluations);
                }
                if !warming_up {
                    if let Some(csv) = &mut csv {
                        writeln!(
                            csv,
                            "{}",
                            sample.csv_row(
                                log_size,
                                claims,
                                factor,
                                rate,
                                &(sample_index + 1).to_string(),
                                &(position + 1).to_string(),
                                &whir.parameter_summary(),
                            )
                        )?;
                        csv.flush()?;
                    }
                    measurements[arm].push(sample);
                }
            }
        }
        for (arm, &rate) in rates.iter().enumerate() {
            let median = Sample::median(&measurements[arm]);
            println!(
                "{}",
                median.csv_row(
                    log_size,
                    claims,
                    factor,
                    rate,
                    "median",
                    "",
                    &whirs[arm].parameter_summary()
                )
            );
        }
    }
    Ok(())
}

fn measure(
    whir: &ExplicitWhir,
    evaluations: Vec<Bn254>,
    points: &[Point<Bn254>],
    seed: &[Bn254],
) -> Result<(Sample, Vec<Bn254>), Box<dyn Error>> {
    let started = Instant::now();
    let batch = whir.commit_evaluations(evaluations)?;
    let commit = started.elapsed();
    let commitment = batch.commitment.clone();
    let initial_commitment_bytes = 32 * commitment.num_roots();
    let started = Instant::now();
    let (proof, opening) = whir.open_profiled(batch, points, seed);
    let open_total = started.elapsed();
    let started = Instant::now();
    whir.verify(&commitment, points, &proof, seed)?;
    let verify = started.elapsed();
    let proof_payload_bytes = proof.payload_size_bytes();
    black_box(&proof);
    Ok((
        Sample {
            commit,
            opening,
            open_total,
            prover: commit + open_total,
            verify,
            proof_payload_bytes,
            initial_commitment_bytes,
        },
        proof.evaluations,
    ))
}

#[derive(Clone, Copy)]
struct Sample {
    commit: Duration,
    opening: OpeningTimings,
    open_total: Duration,
    prover: Duration,
    verify: Duration,
    proof_payload_bytes: usize,
    initial_commitment_bytes: usize,
}

impl Sample {
    fn median(samples: &[Self]) -> Self {
        Self {
            commit: median(samples.iter().map(|s| s.commit).collect()),
            opening: OpeningTimings {
                evaluations: median(samples.iter().map(|s| s.opening.evaluations).collect()),
                proof: median(samples.iter().map(|s| s.opening.proof).collect()),
            },
            open_total: median(samples.iter().map(|s| s.open_total).collect()),
            prover: median(samples.iter().map(|s| s.prover).collect()),
            verify: median(samples.iter().map(|s| s.verify).collect()),
            proof_payload_bytes: median(samples.iter().map(|s| s.proof_payload_bytes).collect()),
            initial_commitment_bytes: median(
                samples.iter().map(|s| s.initial_commitment_bytes).collect(),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn csv_row(
        &self,
        log_size: usize,
        claims: usize,
        factor: usize,
        rate: RateSchedule,
        sample: &str,
        position: &str,
        summary: &ParameterSummary,
    ) -> String {
        let mut effective_queries = summary.round_queries.clone();
        effective_queries.push(summary.final_queries);
        format!(
            "{log_size},{claims},{factor},{},{sample},{position},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{}",
            rate.label(),
            usize_list(&summary.folding_schedule),
            usize_list(&summary.round_log_inv_rates),
            usize_list(&summary.codeword_domain_sizes),
            usize_list(&effective_queries),
            summary.final_sumcheck_rounds,
            milliseconds(self.commit),
            milliseconds(self.opening.evaluations),
            milliseconds(self.opening.proof),
            milliseconds(self.open_total),
            milliseconds(self.prover),
            milliseconds(self.verify),
            self.proof_payload_bytes,
            self.initial_commitment_bytes,
        )
    }
}

fn median<T: Ord + Copy>(mut values: Vec<T>) -> T {
    values.sort_unstable();
    values[values.len() / 2]
}

fn polynomial(entries: usize) -> Vec<Bn254> {
    SmallRng::seed_from_u64(0x5748_4952)
        .sample_iter(StandardUniform)
        .take(entries)
        .collect()
}

fn opening_points(log_size: usize, claims: usize) -> Vec<Point<Bn254>> {
    (0..claims)
        .map(|claim| {
            Point::new(
                (0..log_size)
                    .map(|variable| Bn254::from_usize(3 * variable + 5 * claim + 2))
                    .collect(),
            )
        })
        .collect()
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn env_usize_list(name: &str, default: &[usize]) -> Result<Vec<usize>, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => value
            .split(',')
            .map(|part| Ok(part.trim().parse()?))
            .collect(),
        Err(std::env::VarError::NotPresent) => Ok(default.to_vec()),
        Err(error) => Err(error.into()),
    }
}

fn env_rate_schedules() -> Result<Vec<RateSchedule>, Box<dyn Error>> {
    let value = match std::env::var("WHIR_MICROBENCH_RATE_SCHEDULES") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "fixed,default".into(),
        Err(error) => return Err(error.into()),
    };
    let mut result = Vec::new();
    for part in value.split(',') {
        let rate = match part.trim() {
            "fixed" => RateSchedule::FixedHalf,
            "default" => RateSchedule::WhirDefault,
            _ => return Err("WHIR_MICROBENCH_RATE_SCHEDULES accepts fixed,default".into()),
        };
        if result.contains(&rate) {
            return Err("WHIR_MICROBENCH_RATE_SCHEDULES must not repeat an arm".into());
        }
        result.push(rate);
    }
    Ok(result)
}

fn env_bool(name: &str, default: bool) -> Result<bool, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => match value.as_str() {
            "0" | "false" => Ok(false),
            "1" | "true" => Ok(true),
            _ => Err(format!("{name} must be one of 0, 1, false, or true").into()),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn usize_list(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(":")
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
