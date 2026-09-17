# Baseline, full initialization, and updates after preprocessing reduction

Run date: 2026-09-09 (America/New_York). WHIR retains the original production parameters: fixed RS rate `1/2`, folding factor four (16 fields per queried leaf), configured 127-bit capacity-bound security target, zero PoW, BN254, BLAKE3 Merkle commitments and Fiat–Shamir. No protocol or benchmark code was changed for these measurements.

## Proving times

All times below are seconds. Baseline and update columns are arithmetic means over ten successive revisions; initialization is one full proof per benchmark case. Baseline means a complete ordinary HyperPlonk proof from scratch, with the public-input suffix bound directly and no Merkle/CAIR proof. Initialization includes the full static arithmetic and assignment-Merkle CAIR proof. Updates refresh an already initialized dynamic proof.

| Arithmetic gates | Updated gates | Baseline mean | Full initialization | Update mean | Baseline / update |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 1.225 | 20.399 | 0.386 | 3.174× |
| 16,384 | 256 | 1.178 | 14.687 | 6.352 | 0.185× |
| 65,536 | 16 | 4.979 | 70.881 | 0.399 | 12.466× |
| 65,536 | 256 | 4.938 | 78.918 | 6.392 | 0.772× |

A ratio above one means updating was faster. Initialization is repeated on the same base circuit for the two update sizes; differences between these timings are run-to-run variation, not a dependence of initialization on the subsequent update size. FFT twiddles are cached process-wide. These are laptop wall-clock observations, without a confidence interval.

## First-update latency

Each first update starts from the fully generated and verified initial proof; this measurement is separate from the subsequent ten-revision sequence.

| Arithmetic gates | Updated gates | First baseline (s) | First update (s) | Baseline / update |
|---:|---:|---:|---:|---:|
| 16,384 | 16 | 1.210 | 0.396 | 3.060× |
| 16,384 | 256 | 1.219 | 6.215 | 0.196× |
| 65,536 | 16 | 4.774 | 0.399 | 11.959× |
| 65,536 | 256 | 4.820 | 6.186 | 0.779× |

## Workload and timing boundaries

- Apple M2 MacBook Air, 16 GB memory; optimized Cargo bench profile with `--features parallel` and `RAYON_NUM_THREADS=8`.
- 256 public inputs. Half of the arithmetic gates are additions and half multiplications, alternating by row. The synthetic wiring permutation is the identity.
- The same contiguous gate set at the beginning of the assignment is updated in every revision. A 16-gate update supplies 48 wire positions; a 256-gate update supplies 768. Each full three-wire gate tuple is supplied, including its unchanged right input. This is a localized repeated-update workload; scattered positions or nontrivial wiring can change sparse-DAG costs.
- Setup/indexing and all verification checks are outside the reported proving timers. Baseline timers include arithmetization and proving; initialization includes native assignment validation, the Merkle tree, arithmetization, static/CAIR proving, and prover-state construction. Update timers include validation, hierarchy maintenance, sparse transition proving, and refreshing the public-input opening.
- Each initial proof, first updated proof, first baseline proof, and final dynamic sequence is verified by the benchmark harness. All runs completed successfully.
- Arithmetic preprocessing commits eight columns for initialization and four for the baseline. Baseline public-input rows cause its trace to round to twice the initial arithmetic trace in these cases. The benchmark asserts the expected widths.
- These runs measure the complete proving operations, unlike the earlier standalone PCS rate-schedule experiment. They do not measure proof sizes or isolate the speedup attributable to preprocessing alone.

| Arithmetic gates | Assignment positions | Initial trace rows | Baseline trace rows | Updated gates | Sparse transition rows | Transition Poseidon hashes |
|---:|---:|---:|---:|---:|---:|---:|
| 16,384 | 49,408 | 16,384 | 32,768 | 16 | 512 | 636 |
| 16,384 | 49,408 | 16,384 | 32,768 | 256 | 8,192 | 9,252 |
| 65,536 | 196,864 | 65,536 | 131,072 | 16 | 512 | 648 |
| 65,536 | 196,864 | 65,536 | 131,072 | 256 | 8,192 | 9,264 |

## Reproduce

Run from the repository root. Change the trace log from `14` to `16` for the larger circuit.

```sh
DYNAMIC_SNARK_TRACE_LOG=14 \
DYNAMIC_SNARK_UPDATE_LOGS=4,8 \
DYNAMIC_SNARK_SEQUENCE_LEN=10 \
DYNAMIC_SNARK_UPDATE_PATTERN=contiguous \
DYNAMIC_SNARK_TIME_FULL_INITIAL=1 \
RAYON_NUM_THREADS=8 \
cargo bench --offline --bench dynamic_snark --features parallel
```

[Machine-readable summary](preprocessed-comparison.csv), [16,384-gate run log](preprocessed-comparison-n14.log), [65,536-gate run log](preprocessed-comparison-n16.log).
