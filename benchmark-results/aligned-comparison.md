# Baseline, initialization, and updates with the aligned assignment layout

Run date: 2026-09-09 (America/New_York). Production WHIR parameters are unchanged: fixed RS rate `1/2`, folding factor four (16 fields per queried leaf), configured 127-bit capacity-bound security target, zero PoW, BN254, and BLAKE3 Merkle commitments and Fiat–Shamir. The assignment and indexed-wiring vector trees use Poseidon2.

## Proving times

Times are seconds. Baseline and update are arithmetic means over ten successive revisions. Full initialization is one complete static arithmetic plus assignment-Merkle CAIR proof per benchmark case. Setup/indexing and verification are excluded.

| Arithmetic gates | Updated gates | Baseline mean | Full initialization | Update mean | Baseline / update |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 0.668 | 15.805 | 0.401 | 1.668× |
| 16,384 | 256 | 0.682 | 13.434 | 6.333 | 0.108× |
| 65,536 | 16 | 2.576 | 70.885 | 0.784 | 3.286× |
| 65,536 | 256 | 2.691 | 69.887 | 6.450 | 0.417× |

A ratio above one means updating was faster. Initialization is repeated on the same base circuit for the two update sizes; its timing differences are variation between runs, not a dependence on the subsequent update size. FFT twiddles are cached process-wide. These are laptop wall-clock measurements, without confidence intervals.

## Comparison with the previous preprocessing-only layout

Each cell below is **previous → aligned**, in seconds. The previous measurements use the same workload and WHIR settings; they are preserved in [the earlier report](preprocessed-comparison.md). These are separate benchmark runs, not interleaved statistical samples.

| Arithmetic gates | Updated gates | Baseline mean | Full initialization | Update mean |
|---:|---:|---:|---:|---:|
| 16,384 | 16 | 1.225 → 0.668 | 20.399 → 15.805 | 0.386 → 0.401 |
| 16,384 | 256 | 1.178 → 0.682 | 14.687 → 13.434 | 6.352 → 6.333 |
| 65,536 | 16 | 4.979 → 2.576 | 70.881 → 70.885 | 0.399 → 0.784 |
| 65,536 | 256 | 4.938 → 2.691 | 78.918 → 69.887 | 6.392 → 6.450 |

- Baseline means fall by about 42–48%. Public inputs now occupy column three alongside the gate triples, removing the suffix rows that previously doubled the padded trace.
- Initialization halves its arithmetic witness and preprocessing tables from `8N` to `4N` entries each. Its large Poseidon CAIR table is unchanged for these power-of-two circuit sizes, so the total timing improvement is smaller and variable.
- Alignment spreads three-wire gate tuples across four physical slots. This adds authenticated sparse nodes. For the 65,536-gate circuit with a 16-gate update, the sparse table crosses the 512-row boundary and pads to 1,024 rows. The main update oracle doubles from 131,072 to 262,144 entries; the product oracle crosses a column-padding boundary too, growing from 16,384 to 65,536 entries. The update mean rises from 0.399 to 0.784 seconds.
- The other three cases retain their padded sparse dimensions. Their update means remain within about 4% of the previous measurements. There is no update-column reduction from this change.

## Polynomial and Merkle dimensions

Let `N` denote the arithmetic gate count in these power-of-two cases. Initialization and baseline both have `N` rows and four columns in each of `W` and `P`; each polynomial has `4N` Boolean evaluations. Initial `V` remains `2N` entries. The baseline also uses `2N` entries in `V` now that its row count is `N`. The assignment tree contains `4N` physical leaves; initialization CAIR still contains `64 × 8N = 512N` evaluations. See [the exact table and oracle definitions](../docs/aligned-oracles.md).

| Arithmetic gates | Updated gates | Sparse rows, previous → aligned | Poseidon hashes, previous → aligned | Update main entries | Update product entries |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 16 | 512 → 512 | 636 → 726 | 131,072 | 16,384 |
| 16,384 | 256 | 8,192 → 8,192 | 9,252 → 10,782 | 2,097,152 | 524,288 |
| 65,536 | 16 | 512 → 1,024 | 648 → 738 | 262,144 | 65,536 |
| 65,536 | 256 | 8,192 → 8,192 | 9,264 → 10,794 | 2,097,152 | 524,288 |

Both update oracles use the physical leaf indices induced by the new assignment encoding. Their layout formulas are unchanged; their dimensions follow the actual sparse paths and power-of-two padding. The main width is 128 columns in every case.

## First-update latency

Each first update starts from a fully generated and verified initial proof. It is measured separately from the ten-revision sequence.

| Arithmetic gates | Updated gates | First baseline (s) | First update (s) | Baseline / update |
|---:|---:|---:|---:|---:|
| 16,384 | 16 | 0.658 | 0.422 | 1.561× |
| 16,384 | 256 | 0.646 | 5.962 | 0.108× |
| 65,536 | 16 | 2.915 | 0.924 | 3.154× |
| 65,536 | 256 | 3.080 | 7.065 | 0.436× |

## Workload and validation

- Apple M2 MacBook Air, 16 GB memory; optimized Cargo bench profile, `--features parallel`, `RAYON_NUM_THREADS=8`.
- 256 public-input occurrences. Half the arithmetic gates are additions and half multiplications, alternating by row. The synthetic wiring permutation is the identity.
- The same contiguous set of gates at the beginning of the assignment is updated on every revision. A 16-gate update supplies 48 logical wire positions; a 256-gate update supplies 768. Every three-wire gate tuple is supplied, including its unchanged right input. Scattered updates or nontrivial wiring can change the sparse-path dimensions and cost.
- Baseline timers include arithmetization and proving. Initial timers include assignment validation, the native Merkle tree, arithmetization, static/CAIR proving, and prover-state construction. Update timers include validation, hierarchy maintenance, sparse proving, and refreshing the public-input opening.
- Each full initial proof, first updated proof, first baseline proof, and final dynamic sequence is verified by the benchmark harness. Both benchmark processes completed successfully.
- The implementation passed 69 unit tests and three end-to-end tests, including nontrivial permutation cycles, non-power-of-two shapes, mixed logical updates that require physical reordering, and rejection of padding/gate/public aliases.
- The final parallel all-targets Cargo check, formatting check, and whitespace check passed. A corrected physical-length test fixture was also rerun successfully after the full suite.
- These runs measure prover time and polynomial dimensions. They do not measure serialized proof size.

## Reproduce

Run from the repository root. Change trace log `14` to `16` for the larger circuit.

```sh
DYNAMIC_SNARK_TRACE_LOG=14 \
DYNAMIC_SNARK_UPDATE_LOGS=4,8 \
DYNAMIC_SNARK_SEQUENCE_LEN=10 \
DYNAMIC_SNARK_UPDATE_PATTERN=contiguous \
DYNAMIC_SNARK_TIME_FULL_INITIAL=1 \
RAYON_NUM_THREADS=8 \
cargo bench --offline --bench dynamic_snark --features parallel
```

[Machine-readable summary](aligned-comparison.csv), [16,384-gate run log](aligned-comparison-n14.log), [65,536-gate run log](aligned-comparison-n16.log).
