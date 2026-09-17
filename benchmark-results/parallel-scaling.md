# Parallelism audit: baseline and first single-path update

Both provers use multiple threads when built with `--features parallel`, but substantial arithmetic remains serial. At 65,536 gates, increasing the Rayon pool from one to eight workers improved the ordinary baseline by **1.27×** and the first single-path update by **1.65×**. The two custom baseline relation sumchecks account for **88%** of baseline proving time at eight workers and have no threaded execution path.

## Measured scaling

| Rayon workers | Baseline mean | First single-leaf update mean |
|---:|---:|---:|
| 1 | 3,388.7 ms | 134.39 ms |
| 2 | 2,999.6 ms | 102.27 ms |
| 4 | 2,786.7 ms | 85.71 ms |
| 8 | 2,669.3 ms | 81.30 ms |

Eight workers were fastest among the tested counts, but reduced latency by only **4.2% baseline / 5.1% update** relative to four. This supports keeping eight for these laptop measurements, without establishing an optimal count for larger workloads or servers.

Hardware: Apple M2 MacBook Air, four performance and four efficiency cores, 16 GB RAM. Release build, `parallel` enabled, initial WHIR folding factor four, no `whir-initial-64` feature. Both paths use the same executable and worker count. The benchmark records Rayon's actual pool size, not just the environment setting.

Each process performs one verified warmup of each path, then six measured proofs of each. The ordinary baseline proves the complete updated arithmetic witness. Every dynamic sample clones the same trusted base with an empty update hierarchy and changes public input 128 from 9 to 10. There are 65,536 gates, 256 public inputs, identity wiring, and exactly one updated Merkle leaf. Setup, the initial full proof, witness/program preparation, cloning, verification and destruction are outside proving timers. Baseline/update order alternates within each process; worker counts ran sequentially in order **1, 8, 2, 4**.

All **48 timed proofs and eight warmup proofs verified**. These are short wall-clock runs with coarse checkpoint logging, not CPU utilization samples or randomized cross-machine estimates. The heavier baseline proofs interleaved with updates make this a different timing context from the earlier update-only 77.74 ms mean; the slight absolute difference does not represent a code change.

## What uses the workers

The Cargo default feature list is empty. `RAYON_NUM_THREADS=8` by itself does not enable parallel execution: the binary must also be compiled with `--features parallel`. That feature enables the shared `p3-maybe-rayon` backend throughout Plonky3, including dependencies that do not have a separate feature explicitly listed in our manifest. Both provers share that backend; the baseline is not accidentally missing the WHIR parallel feature.

| Computation | Current implementation |
|---|---|
| Baseline local and product relation sumchecks | Serial evaluation loops, reductions and table folding |
| Baseline product oracle | Serial factor construction, batch inversion and product recurrence |
| Update local and routing-product relation sumchecks | Serial evaluation loops and folding |
| Update Poseidon partial/full-round reductions | Pair reduction uses Rayon at **64 or more pairs**, serial below that |
| Poseidon trace construction and surrounding sparse/table preparation | Serial Rust loops |
| WHIR FFTs and PCS Merkle construction | Parallel Plonky3 kernels |
| WHIR STIR power-table expansion and weighted reduction | Already parallel across table rows |
| WHIR folding-sumcheck coefficient computation | Parallel only when **pair count > 16,384** |
| WHIR polynomial folding | Parallel at **4,096 or more table elements** in the prefix-fold kernel |
| Optimized column claim evaluation and column-weight accumulation | Serial loops; row-weight generation and dense-claim fallback use library kernels |
| Separate final WHIR openings | Called sequentially; three in the baseline, two in the update |

The original assignment Merkle tree uses our serial Poseidon implementation, distinct from WHIR's parallel PCS Merkle implementation. For one updated path, successive levels depend on the previous hash, so that path has little inherent parallelism. Larger sets of independent paths or nodes offer more opportunities. This path hashing is not the measured dominant cost of a single-path update.

## Where threading helps, and where it stops helping

Mean coarse phase measurements from this sweep:

| Baseline component | 1 worker | 8 workers |
|---|---:|---:|
| Local relation sumcheck | 952 ms | 960 ms |
| Product relation sumcheck | 1,435 ms | 1,378 ms |
| Product oracle | 53 ms | 54 ms |
| Three polynomial commitments combined | 314 ms | 73 ms |
| Three WHIR openings combined | 630 ms | 200 ms |

The baseline's two relation sumchecks still consume **2,338 of 2,669 ms** at eight workers. Their small timing variations across pool sizes are not evidence of parallel execution: the source loops are serial. The commitment/opening stages show useful scaling, but they are too small a fraction of total proving time to deliver a large overall speedup.

| Update component | 1 worker | 8 workers |
|---|---:|---:|
| Local relation sumcheck | 24.3 ms | 24.3 ms |
| Routing product sumcheck | 6.0 ms | 6.0 ms |
| Poseidon partial-round sumcheck | 33.2 ms | 14.0 ms |
| Poseidon full-round reductions | 6.5 ms | 4.0 ms |
| Main + product WHIR openings | 39.3 ms | 19.7 ms |

For the update, local and routing-product sumchecks alone remain **37%** of total proving time at eight workers. The [detailed profile](internals-profile.md) also identified an expensive serial Poseidon tail: the 64-pair round took 1.72 ms in parallel, whereas the 32-pair round took 4.36 ms after switching to serial execution. The tail consumed 65% of partial-round pair-kernel time.

There is an additional cutoff relevant specifically to this small update. The main WHIR polynomial has 32,768 entries, so its largest coefficient round has exactly 16,384 pairs. Since the library condition is strict `>`, **all coefficient rounds in both update openings run serially**. Larger baseline tables cross the threshold in their early rounds. That threshold is a tuning candidate for BN254; a scalar/parallel crossover should be measured rather than assumed from generic library defaults. BN254's field packing width is one in this version, so packed-kernel terminology does not imply multiple field elements per SIMD vector.

## Highest-value next work

1. Parallelize the independent pair contributions inside both baseline relation sumchecks and the update's local/product sumchecks, using per-worker scratch buffers and a field-sum reduction. Optimize repeated residual work at the same time where appropriate. This improves both sides of the performance comparison.
2. Tune the Poseidon pair threshold and WHIR coefficient threshold on BN254 and the intended machine. A useful threshold depends on work per pair as well as the number of pairs.
3. Consider concurrent final openings after their points/seeds are fixed. They have separate prover/transcript instances, but already use the same Rayon pool internally; any benefit and memory cost need measurement.
4. Improve STIR's power-table construction algorithm. Its expensive expansion/reduction already uses threads, so simply adding Rayon there would not address the remaining cost.

Sumcheck rounds themselves have sequential Fiat–Shamir dependencies. The opportunity is to parallelize independent arithmetic **within** a round, and independent openings after their inputs are fixed. More workers alone cannot remove the large serial sections. Server worker counts, physical cores versus SMT, affinity and NUMA policies remain unmeasured by this laptop sweep.

Source locations: `src/static_snark.rs::{prove_local_sumcheck, prove_product_sumcheck, product_oracle}`, `src/transition_cair.rs::{prove_local_sumcheck, prove_product_sumcheck}`, `src/poseidon_sumcheck.rs::sum_pairs`, and `src/static_snark/pcs/structured_openings.rs`. Dependency cutoffs are in `p3-sumcheck-0.6.2/src/strategy.rs` and `p3-multilinear-util-0.6.2/src/poly.rs`; STIR threading is in `p3-sumcheck-0.6.2/src/constraints/statement/select.rs`.

## Reproduce

```sh
cargo build --offline --release --features parallel --example parallel_scaling
for workers in 1 8 2 4; do
  RAYON_NUM_THREADS="$workers" DYNAMIC_SNARK_TRACE_LOG=16 \
    DYNAMIC_SNARK_FIRST_SAMPLES=6 DYNAMIC_SNARK_PROFILE=1 \
    target/release/examples/parallel_scaling \
    > "/tmp/threads-$workers.csv" 2> "/tmp/threads-$workers.log"
done
```

The measured executable was built from an isolated source copy to protect the shared checkout from profiling changes. [Harness](../examples/parallel_scaling.rs), [latency summary](parallel-scaling/summary.csv), [phase summary](parallel-scaling/phases.csv), [run metadata](parallel-scaling/run.json), [source hashes](parallel-scaling/source.json), and [enabled feature tree](parallel-scaling/rayon-features.txt) are retained. The [parser](parallel-scaling/summarize.py) reads raw files beside it, excludes warmups, aggregates repeated component labels within each proof, then averages over proofs. Its syntax check, harness formatting and `git diff --check` passed. No production parallelization changes were made in this audit.
