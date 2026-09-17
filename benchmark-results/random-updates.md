# Fresh random updates with identity wiring

Run date: 2026-09-09 (America/New_York). Only dynamic updates were timed. Baseline proofs and the full initial static/CAIR proof were not rerun. Setup and the native trusted base commitment were prepared outside the timers. The transition prover and hierarchy maintenance are the same as in the complete dynamic system.

The 256-gate experiment was stopped at the user’s request and is excluded from this report. Both 16-gate cases completed all ten revisions.

## Proving times

All times are seconds. The first update is measured separately from a ten-revision sequence starting from the same base state. Each sequence revision draws a fresh uniformly sampled set of distinct gates. The sequence mean includes the cost of proving composed update sets when the hierarchy merges tables.

| Arithmetic gates | Gates selected per revision | First random update | Random sequence mean | Sequence median | Slowest revision |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 1.638 | 3.519 | 2.246 | 12.292 |
| 65,536 | 16 | 1.613 | 3.887 | 2.400 | 14.663 |

These ten timings are a history-dependent sequence, not independent samples of a stationary workload. The mean is the measured cost per incoming revision over this sequence; the median and maximum expose the merge spikes. A single fixed seed was measured, so these results do not provide confidence intervals over random workloads.

## Reference to the previous localized workload

The contiguous and baseline columns below are copied from [the previous aligned-layout measurements](aligned-comparison.md); they were not remeasured. The random first-update comparison primarily exposes path scattering. The random sequence comparison also includes accumulation of distinct positions and hierarchy merges. The previous contiguous run retained the same gate set on every revision.

| Arithmetic gates | Gates selected | Previous contiguous first | Random first | Previous contiguous mean | Random mean | Previous baseline mean |
|---:|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 0.422 | 1.638 | 0.401 | 3.519 | 0.668 |
| 65,536 | 16 | 0.924 | 1.613 | 0.784 | 3.887 | 2.576 |

The previous first-update timings followed generation of a full initial proof; these timings use the trusted-base harness and therefore have different cache/allocation histories. All setup, verification, workload sampling, and statistics collection are outside the proving timers.

## Sparse table growth

A selected gate supplies all three logical wire positions, including the unchanged right input. The actually rebuilt transition can contain more gates than the incoming revision because it composes earlier update tables.

| Arithmetic gates | Gates selected per revision | First sparse rows | Largest sparse rows | Largest composed gate set | Distinct gates after ten revisions |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 2,048 | 16,384 | 128 | 160 |
| 65,536 | 16 | 2,048 | 16,384 | 128 | 160 |

The main oracle has `256R` Boolean evaluations for sparse row count `R`. The product oracle has `R × nextpow2(14 + 2 log2 R)` evaluations. Every measured transition has main width 128 and product width 64. Per-revision positions, hierarchy levels, oracle dimensions, and timings are retained in [the revision CSV](random-update-revisions.csv).

## Workload and validation

- Apple M2 MacBook Air, 16 GB RAM, release benchmark profile, parallel features, eight Rayon threads. Benchmark cases run sequentially.
- Fixed identity wiring and 256 unchanged public-input occurrences. Gate rows alternate addition and multiplication.
- Each case starts `StdRng` with seed `20260909`, using `rand` 0.10.2 from `Cargo.lock`. Each revision samples gates uniformly without replacement; gates may recur across revisions. The sampled indices are sorted for the public update API. Position fingerprints are recorded in the CSV and logs.
- Value generation is unchanged from the previous workload: for gate pair `g`, revision `j`, and multiplication flag `t`, the left input is `g+j+1+t`, the right input is two, and the output is recomputed by addition or multiplication. Thus randomness changes positions, while every selected gate has a changed left input and output.
- The first updated state and every state in the ten-revision sequence were verified outside their timers. The seeded-workload integration test also checks reproducibility, full gate tuples, valid assignments, changing support, and successful hierarchy compositions through the real prover.
- The random-workload integration test, parallel all-targets Cargo check, formatting check, and whitespace check passed.
- No cryptographic parameters or constraints changed. WHIR retains fixed RS rate one-half, folding factor four, configured 127-bit capacity-bound security target, zero PoW, BN254, and BLAKE3 commitments/Fiat–Shamir. Assignment and wiring vector trees use Poseidon2.
- Measurements include update validation, table composition, native Merkle maintenance, the actual composed transition proof, and refreshing the public-input opening. They exclude preprocessing, trusted base construction, verification, workload generation, and statistics output.
- Peak process RSS was 1.938 GiB in the 65,536-gate run. The 16,384-gate sequence completed successfully, but its optional external resource-reporting wrapper could not read an OS counter; peak RSS is therefore left unavailable in the summary CSV. The in-process proving timers and verification results were unaffected.

## Reproduce

Use trace log `14` or `16` with update log `4` (16 gates). The baseline and full initial proof are disabled explicitly.

```sh
DYNAMIC_SNARK_TRACE_LOG=14 \
DYNAMIC_SNARK_UPDATE_LOGS=4 \
DYNAMIC_SNARK_SEQUENCE_LEN=10 \
DYNAMIC_SNARK_UPDATE_ONLY=1 \
DYNAMIC_SNARK_UPDATE_PATTERN=random \
DYNAMIC_SNARK_SEED=20260909 \
RAYON_NUM_THREADS=8 \
cargo bench --offline --bench dynamic_snark --features parallel
```

[Case summary CSV](random-updates.csv), [per-revision CSV](random-update-revisions.csv).

- [16,384 gates, 16 gates per revision](random-updates-n14-u4.log).
- [65,536 gates, 16 gates per revision](random-updates-n16-u4.log).
