# Separate sumcheck and WHIR opening profiles

For the first **single-leaf / single-Merkle-path update at 65,536 arithmetic gates**, relation sumchecks take approximately **47 ms**, and the main plus product WHIR openings take approximately **18 ms**. Total update latency averages **77.74 ms** with detailed timers disabled. This uses the column-aware evaluation and shared-row initial-weight optimizations already implemented.

The main sumcheck bottleneck is evaluating and weighting the local constraints. The largest remaining component inside WHIR is constructing the weights for later STIR query constraints.

## Measurement scope

Apple M2 MacBook Air, 16 GB RAM, release build, Rust 1.92.0, `--features parallel`, eight Rayon threads. No `whir-initial-64` feature. The workload changes public input 128 from 9 to 10, with identity wiring and 256 public inputs. It has one updated position, a depth-18 Merkle path, 128 sparse rows, a 256 × 128 main polynomial table and a 128 × 32 product table.

Each sample starts from a clone of the same trusted base with empty update tables. Initialization, the initial full proof, cloning, verification and destruction are excluded. These are repeated first updates, not successive updates into a growing hierarchy.

An isolated source snapshot contains optional wall-clock timers in the relation prover, PCS wrapper, `p3-whir 0.6.2` and `p3-sumcheck 0.6.2`. The shared production implementation and Cargo registry were not modified for profiling. Thirty samples ran with detailed timers disabled, followed by thirty with them enabled. **All 60 updates verified.**

| Timing mode | Mean update | Median update |
|---|---:|---:|
| Coarse checkpoints only | 77.742 ms | 77.513 ms |
| Detailed timers enabled | 82.163 ms | 81.973 ms |

Detailed timing/logging adds **4.42 ms, or 5.7%**, in this comparison. The disabled mode still contains the diagnostic code and existing coarse logging. Fine measurements below describe the instrumented run; they are approximate attribution, not an overhead-free CPU profile. Parent timers include nested timing/logging; do not add parents and children. Coarse phase totals have millisecond resolution.

## Relation sumchecks

| Phase | Mean with detailed timers disabled |
|---|---:|
| Local relation sumcheck | 24.0 ms |
| Poseidon partial-round sumcheck | 14.1 ms |
| Poseidon full-round reductions | 4.0 ms |
| Routing product sumcheck | 5.0 ms |

These exclude WHIR's internal folding sumchecks, which are counted under opening costs below.

### Local constraints: repeated residual evaluation

| Measured component | Mean per update |
|---|---:|
| Construct compact constraint residuals | **14.54 ms** |
| Weight residuals and accumulate with the equality factor | **4.98 ms** |
| Interpolate the row's 58 column values | 3.63 ms |
| Construct messages and derive challenges | 0.22 ms |
| Fold tables | 0.19 ms |

The prover uses degree bound **18**, hence **19 evaluation points per round**. Across seven rounds, the number of row pairs is 64 + 32 + … + 1 = 127. This produces **2,413 point/pair evaluations**, each constructing **96 residuals**: **231,648 residual terms** per update. The evaluation loops are sequential even with the `parallel` feature.

Residual construction and weighting consume roughly **19.5 of the 24 ms**. The first two rounds alone account for 11.42 and 5.91 ms in the detailed buckets. `compact_residuals` also allocates a fresh vector on each call, but allocation was not isolated from field arithmetic, so these results do not establish allocator or memory bandwidth dominance.

The most useful next experiments are proving a tighter degree bound for this circuit shape, fusing residual generation with its fixed weighted sum, and parallelizing the pair reduction. `compact_constraint_degree` currently uses the maximum selector bit width plus three, subject to a minimum of six; some range selectors simplify for power-of-two sizes. Any lower bound needs correctness validation before use. Buffer reuse is another candidate, with unmeasured benefit.

Source: `src/transition_cair.rs::prove_local_sumcheck` and `src/transition_relation.rs::{compact_constraint_degree, compact_residuals}`.

### Poseidon: the sequential tail dominates

Partial-round pair kernels consume **13.21 ms**; table folding takes 0.54 ms and message/challenge handling 0.04 ms.

| Row pairs | Execution | Pair-kernel mean |
|---:|---|---:|
| 128 | Parallel | 2.87 ms |
| 64 | Parallel | 1.72 ms |
| 32 | Sequential | **4.36 ms** |
| 16 | Sequential | 2.18 ms |
| 8 | Sequential | 1.09 ms |
| 4 | Sequential | 0.56 ms |
| 2 | Sequential | 0.28 ms |
| 1 | Sequential | 0.14 ms |

`src/poseidon_sumcheck.rs::sum_pairs` switches to sequential execution below **64 pairs**. Halving from 64 to 32 pairs therefore makes the round **2.5× slower**. The sequential tail totals **8.61 ms**, or **65%** of pair-kernel time. Testing a lower threshold is a concrete next step; its gain has not been measured here.

Full-round reductions spend 2.59 ms in pair kernels, versus 0.17 ms in message/challenge handling and 0.27 ms folding. The routing product sumcheck similarly spends 4.91 ms in pair kernels, versus 0.05 ms and 0.34 ms respectively. Their remaining outer time includes preparation and other work. These phases are dominated by pair arithmetic as well.

## WHIR openings

The normal coarse totals are **14.1 ms main + 4.0 ms product**. The detailed run measures approximately 15.23 ms and 4.80 ms. Opening costs include terminal claim evaluation and WHIR's own folding sumchecks. The original polynomial commitments made before opening are outside this scope; folded commitments made during WHIR are included.

| Selected internal component | Main | Product | Combined |
|---|---:|---:|---:|
| Later STIR query-weight construction | **4.84 ms** | 0.83 ms | **5.67 ms** |
| Terminal claim evaluation/absorption | 2.75 ms | 1.19 ms | 3.94 ms |
| Initial claim-weight construction | 1.67 ms | 0.49 ms | 2.16 ms |
| Folding-sumcheck coefficient arithmetic | 1.88 ms | 0.25 ms | 2.12 ms |
| Folding-sumcheck table folding | 0.98 ms | 0.29 ms | 1.27 ms |
| Folded-commitment FFTs | 0.31 ms | 0.09 ms | 0.41 ms |
| Folded-commitment Merkle construction | 0.37 ms | 0.12 ms | 0.48 ms |
| Merkle queries and queried-leaf folds | 0.38 ms | 0.20 ms | 0.58 ms |

The table lists separate selected components, not a complete accounting of every opening instruction. Initial OOD evaluation/setup adds 0.82 ms combined; later OOD weight construction adds 0.19 ms. Small transcript operations, query sampling, allocation and instrumentation account for additional work.

The largest component comes from `p3-sumcheck/src/constraints/statement/select.rs::SelectStatement::combine`. For query points `z_j`, it constructs weights of the form `W[b] = Σ_j gamma^(s+j) z_j^b`. It first materializes the powers for every index/query combination, then reduces each row using the batching challenge.

Across both openings, **power-table expansion takes 3.02 ms** and **weighted reduction 2.27 ms**. The largest individual stage is the main opening's 11-variable STIR constraint: **2,048 × 137 = 280,576 field elements, or 8.56 MiB**. That stage alone takes **4.30 ms**, including 2.28 ms expanding powers and 1.84 ms reducing them.

This is a later query-constraint construction, distinct from the initial column claims optimized previously. Avoiding the full powers table through streamed or blocked accumulation is a promising experiment. An FFT formulation exploiting the query domain may also be worth evaluating. The measurements establish expensive table construction and reduction, but do not establish memory bandwidth as the limiting hardware resource. FFT and Merkle operations are relatively small at this workload.

## Reproduce and inspect

Use a fresh destination; the preparation script requires locally cached versions of both dependency crates and refuses to overwrite an existing snapshot.

```sh
python3 scripts/prepare_update_profile.py /tmp/update-profile-repro
cargo build --offline --manifest-path /tmp/update-profile-repro/Cargo.toml \
  --release --features parallel --example first_update

env -u DYNAMIC_SNARK_PROFILE_DETAIL \
  DYNAMIC_SNARK_TRACE_LOG=16 DYNAMIC_SNARK_FIRST_KIND=leaf \
  DYNAMIC_SNARK_FIRST_SAMPLES=30 DYNAMIC_SNARK_PROFILE=1 RAYON_NUM_THREADS=8 \
  /tmp/update-profile-repro/target/release/examples/first_update \
  > /tmp/internals-control.csv 2> /tmp/internals-control.log

DYNAMIC_SNARK_PROFILE_DETAIL=1 \
  DYNAMIC_SNARK_TRACE_LOG=16 DYNAMIC_SNARK_FIRST_KIND=leaf \
  DYNAMIC_SNARK_FIRST_SAMPLES=30 DYNAMIC_SNARK_PROFILE=1 RAYON_NUM_THREADS=8 \
  /tmp/update-profile-repro/target/release/examples/first_update \
  > /tmp/internals-detail.csv 2> /tmp/internals-detail.log
```

The actual run reused a Cargo target directory for compilation, then retained its executable separately. [Run metadata](internals-run.json) records binary and instrumented source hashes. [Preparation script](../scripts/prepare_update_profile.py), [summary parser](summarize-internals.py), [latencies](internals-latency.csv), [component totals](internals-summary.csv), [individual rounds](internals-rounds.csv), and [raw detailed events](internals-events.csv) are retained. The parser reads the four `internals-{control,detail}.{csv,log}` files beside it, aggregates within each sample before averaging, and regenerates the summary CSVs.

The profiling build and both complete runs succeeded. Python syntax checks for the preparation/parser scripts and `git diff --check` passed. No further optimization is implemented by this profiling experiment.
