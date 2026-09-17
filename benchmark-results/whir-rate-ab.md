# WHIR fixed-half-rate versus default rate reduction

Run date: 2026-09-08. This experiment changes only the intermediate RS code-rate schedule in the standalone WHIR PCS; production continues to use fixed rate `1/2`.

## Preprocessing change completed first

The initial arithmetic relation now commits eight permutation columns (`8N`, previously `32N`); the baseline commits four (`4N`, previously `32N`). `N` is each relation’s own padded row count. Gate selectors and identity labels are evaluated from public formulas. Preprocessing opening claims fall from 48 to 8 and from 40 to 4, respectively. General gate programs retain their committed local selectors/constants. The witness table, original HyperPlonk product oracle, and Poseidon trace are unchanged.

## Measurements

Medians of five measured samples per arm after one warmup. Prover time is commitment plus opening, measured per sample before taking its median. Payload is the complete opening-proof field/hash payload, not a serialized file size.

| Polynomial entries | Batched claims | Prover, fixed (ms) | Prover, default (ms) | Default prover increase | Payload, fixed (KiB) | Payload, default (KiB) | Payload reduction |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^18 | 1 | 85.84 | 105.80 | 23.3% | 343.72 | 184.28 | 46.4% |
| 2^18 | 8 | 132.47 | 161.02 | 21.6% | 343.94 | 184.50 | 46.4% |
| 2^20 | 1 | 458.58 | 558.15 | 21.7% | 395.59 | 207.00 | 47.7% |
| 2^20 | 8 | 532.13 | 579.84 | 9.0% | 395.81 | 207.22 | 47.6% |

The default schedule reduced payload by 46–48% and increased median total prover time by 9–23% in these runs. Median verification time fell from 2.49–2.76 ms to 1.25–1.45 ms. These are PCS measurements; they do not measure the speedup from preprocessing or the total initial/transition SNARK. Laptop timings have substantial variance (one default `2^20`, one-claim sample took 914 ms versus its 558 ms median), so the timing percentages are indicative. Proof-payload sizes were identical across all five samples of each case/arm.

| Entries | Claims | Schedule | Commit (ms) | Evaluate claims/OOD (ms) | Proximity proof (ms) | Opening total (ms) | Verify (ms) | Prover range (ms) |
|---:|---:|:---|---:|---:|---:|---:|---:|:---|
| 2^18 | 1 | fixed | 30.254 | 3.498 | 52.592 | 56.076 | 2.491 | 84.558–115.616 |
| 2^18 | 1 | default | 32.454 | 3.976 | 70.578 | 74.077 | 1.250 | 102.198–157.156 |
| 2^18 | 8 | fixed | 35.818 | 18.766 | 77.670 | 96.102 | 2.500 | 130.561–184.003 |
| 2^18 | 8 | default | 35.104 | 20.762 | 105.276 | 126.073 | 1.291 | 153.703–176.874 |
| 2^20 | 1 | fixed | 162.456 | 16.503 | 260.774 | 277.322 | 2.756 | 412.254–605.901 |
| 2^20 | 1 | default | 166.521 | 18.444 | 381.043 | 396.404 | 1.445 | 526.429–913.772 |
| 2^20 | 8 | fixed | 148.024 | 62.820 | 324.983 | 387.640 | 2.629 | 466.969–555.728 |
| 2^20 | 8 | default | 142.986 | 61.732 | 362.178 | 429.462 | 1.421 | 547.967–653.532 |

The median of a sum need not equal the sum of its component medians.

## Parameters and method

- Apple M2 MacBook Air, 16 GiB memory, 8 CPU cores (4 performance + 4 efficiency); Rust 1.92.0; optimized Cargo bench profile; `--features parallel`, `RAYON_NUM_THREADS=8`.
- Plonky3 0.6.2, BN254 scalar field, BLAKE3 Merkle hashing and Fiat–Shamir, configured 127-bit capacity-bound security target, zero PoW.
- Folding factor four (16 field elements per queried leaf) and starting rate `1/2` in both arms. `fixed` sets every intermediate log-inverse rate to 1. `default` leaves the override empty, so Plonky3 derives its native schedule.
- The polynomial table is sampled with `SmallRng::seed_from_u64(0x57484952)` and `StandardUniform`. Identical polynomial and externally specified opening points in both arms. Construction, cloning, and WHIR configuration occur outside timers. FFT twiddles are cached process-wide and warmed for both arms.
- Measured order alternates fixed/default, default/fixed. Each pair uses the same seed, varying between pairs. Every generated proof is verified and all arms’ claimed polynomial evaluations are compared.
- Payload counts 32 bytes per stored BN254 field element or BLAKE3 digest, including claimed evaluations, OOD answers, all Merkle paths, intermediate roots, folding sumchecks, stored zero PoW witnesses, and final-polynomial entries. It excludes container lengths/tags and the initial 32-byte commitment; no Merkle-path deduplication or encoding compression is applied. This is neither an in-memory allocation count nor a claim about a particular wire encoding.

| Entries | Schedule | Code rates | RS domain sizes | Queries per domain | WHIR folding schedule | Final sumcheck variables |
|---:|:---|:---|:---|:---|:---|---:|
| 2^18 | fixed | 1/2, 1/2, 1/2 | 2^19, 2^15, 2^11 | 137, 137, 128 | 4, 4, 4 | 6 |
| 2^18 | default | 1/2, 1/16, 1/128 | 2^19, 2^18, 2^17 | 137, 33, 19 | 4, 4, 4 | 6 |
| 2^20 | fixed | 1/2, 1/2, 1/2, 1/2 | 2^21, 2^17, 2^13, 2^9 | 137, 137, 137, 32 | 4, 4, 4, 4 | 4 |
| 2^20 | default | 1/2, 1/16, 1/128, 1/1024 | 2^21, 2^20, 2^19, 2^18 | 137, 33, 19, 13 | 4, 4, 4, 4 | 4 |

Query counts are capped at the number of available leaves. The larger default domains and lower code rates reduce query counts, trading additional prover work for fewer transmitted openings. At fixed rate, factor-four folding shrinks the domain by 16; the default shrinks it by two.

## Reproduce

Run from the repository root; choose `18` or `20` for log size and `1` or `8` for claims. To preserve the checked-in observations, the example writes the new samples to `/tmp`.

```sh
WHIR_MICROBENCH_LOG_SIZE=18 \
WHIR_MICROBENCH_FACTORS=4 \
WHIR_MICROBENCH_RATE_SCHEDULES=fixed,default \
WHIR_MICROBENCH_CLAIMS=1 \
WHIR_MICROBENCH_WARMUPS=1 \
WHIR_MICROBENCH_SAMPLES=5 \
WHIR_MICROBENCH_FRESH_INSTANCE=0 \
WHIR_MICROBENCH_CSV=/tmp/whir-rate-ab.csv \
RAYON_NUM_THREADS=8 \
cargo bench --offline --bench whir_microbench --features parallel
```

Raw samples and run output:

- `2^18`, 1 claim(s): [CSV](whir-rate-ab-n18-c1.csv), [run output](whir-rate-ab-n18-c1.log).
- `2^18`, 8 claim(s): [CSV](whir-rate-ab-n18-c8.csv), [run output](whir-rate-ab-n18-c8.log).
- `2^20`, 1 claim(s): [CSV](whir-rate-ab-n20-c1.csv), [run output](whir-rate-ab-n20-c1.log).
- `2^20`, 8 claim(s): [CSV](whir-rate-ab-n20-c8.csv), [run output](whir-rate-ab-n20-c8.log).

## Validation

- `cargo test --offline`: 66 unit tests and two end-to-end tests passed. Coverage includes analytic selectors with padding/public rows, nontrivial wiring, altered preprocessing evaluations and selector descriptions, generic gate programs, and rejection of a proof under the wrong WHIR rate schedule.
- `cargo check --offline --features parallel --all-targets`: passed.
- Full initialization plus two updates and baseline proofs passed with `DYNAMIC_SNARK_TRACE_LOG=9`, `DYNAMIC_SNARK_UPDATE_LOGS=1`, `DYNAMIC_SNARK_SEQUENCE_LEN=2`, `DYNAMIC_SNARK_TIME_FULL_INITIAL=1`, `RAYON_NUM_THREADS=8`, and `cargo bench --offline --bench dynamic_snark --features parallel`. The harness asserted eight preprocessing columns for initialization and four for the baseline.
