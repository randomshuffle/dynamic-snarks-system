//! Native hash microbenchmark over identical 72-byte logical inputs.

use std::hint::black_box;
use std::time::{Duration, Instant};

use blake3::hash as blake3_hash;
use dynamic_snarks_system::Field;
use dynamic_snarks_system::hash::poseidon2;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use sha3::{Digest, Sha3_256};

const HASHES_PER_SAMPLE: usize = 100;
const SAMPLES: usize = 10;
const MESSAGE_BYTES: usize = 72;

fn main() {
    let (poseidon_inputs, byte_inputs) = inputs();

    // Construct Poseidon parameters and touch every implementation before the
    // timer so initialization, input encoding, and cold dispatch are excluded.
    let poseidon = poseidon2();
    run_poseidon(&poseidon, &poseidon_inputs);
    run_sha3(&byte_inputs);
    run_blake3(&byte_inputs);

    let mut poseidon_samples = Vec::with_capacity(SAMPLES);
    let mut sha3_samples = Vec::with_capacity(SAMPLES);
    let mut blake3_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        poseidon_samples.push(time(|| run_poseidon(&poseidon, &poseidon_inputs)));
        sha3_samples.push(time(|| run_sha3(&byte_inputs)));
        blake3_samples.push(time(|| run_blake3(&byte_inputs)));
    }

    println!("native hash microbenchmark");
    println!("  input bytes per hash: {MESSAGE_BYTES}");
    println!("  hashes per timed sample: {HASHES_PER_SAMPLE}");
    println!("  timed samples: {SAMPLES}");
    println!("  setup and input encoding: excluded");
    println!();
    println!("algorithm,median_batch_us,median_ns_per_hash,min_ns_per_hash,max_ns_per_hash");
    report("poseidon2-bn254", &mut poseidon_samples);
    report("sha3-256", &mut sha3_samples);
    report("blake3", &mut blake3_samples);
}

fn inputs() -> (Vec<[Field; 3]>, Vec<[u8; MESSAGE_BYTES]>) {
    let mut poseidon_inputs = Vec::with_capacity(HASHES_PER_SAMPLE);
    let mut byte_inputs = Vec::with_capacity(HASHES_PER_SAMPLE);
    for index in 0..HASHES_PER_SAMPLE {
        let left = (2 * index + 1) as u64;
        let right = (2 * index + 2) as u64;
        let domain = (index + 2) as u64;
        poseidon_inputs.push([
            Field::from_u64(left),
            Field::from_u64(right),
            Field::from_u64(domain),
        ]);

        let mut message = [0u8; MESSAGE_BYTES];
        message[..8].copy_from_slice(&domain.to_le_bytes());
        message[8..16].copy_from_slice(&left.to_le_bytes());
        message[40..48].copy_from_slice(&right.to_le_bytes());
        byte_inputs.push(message);
    }
    (poseidon_inputs, byte_inputs)
}

fn run_poseidon<P>(poseidon: &P, inputs: &[[Field; 3]])
where
    P: Permutation<[Field; 3]>,
{
    for &input in inputs {
        let _ = black_box(poseidon.permute(input));
    }
}

fn run_sha3(inputs: &[[u8; MESSAGE_BYTES]]) {
    for input in inputs {
        black_box(Sha3_256::digest(input));
    }
}

fn run_blake3(inputs: &[[u8; MESSAGE_BYTES]]) {
    for input in inputs {
        black_box(blake3_hash(input));
    }
}

fn time(work: impl FnOnce()) -> Duration {
    let started = Instant::now();
    work();
    started.elapsed()
}

fn report(name: &str, samples: &mut [Duration]) {
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let per_hash =
        |duration: Duration| duration.as_secs_f64() * 1_000_000_000.0 / HASHES_PER_SAMPLE as f64;
    println!(
        "{name},{:.3},{:.3},{:.3},{:.3}",
        median.as_secs_f64() * 1_000_000.0,
        per_hash(median),
        per_hash(samples[0]),
        per_hash(*samples.last().expect("there is at least one sample")),
    );
}
