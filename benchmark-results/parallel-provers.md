# Shared parallel prover implementation

Measured on September 9, 2026, on the local M2 MacBook Air (4 performance and
4 efficiency cores, 16 GiB), using Rust 1.92 release builds and `parallel`.
These are laptop measurements, not predictions for 96 EC2 workers.

All three proof paths now share parallel sumcheck arithmetic, table preparation,
folding, and the same patched WHIR backend. The baseline benefits most from
removing its previously serial local and product sumchecks.

| Operation, 65,536 gates, 8 workers | Before | After | Speedup |
| --- | ---: | ---: | ---: |
| Full dynamic initialization | 75.379 s | 37.652 s | 2.00× |
| Baseline proof | 2,858.569 ms | 708.549 ms | 4.03× |
| First single-leaf update | 80.283 ms | 45.513 ms | 1.76× |

Baseline and update entries are means of five measured samples after one
verified warmup per path. Initialization is one complete run per configuration,
so its result has no repeat-based uncertainty estimate. The final eight-worker
baseline samples range from 659.356 to 800.954 ms (median 683.069 ms); updates
range from 41.019 to 51.836 ms (median 45.927 ms). The mean baseline/update
ratio changes from 35.61× to 15.57×, reflecting a substantially stronger baseline.

The one-worker controls also improve. Scaling below compares the final code
with itself at one and eight workers, using the same parallel-enabled binary.

| Operation | Before, 1 worker | After, 1 worker | After, 8 workers | New 1→8 speedup |
| --- | ---: | ---: | ---: | ---: |
| Full initialization | 187.478 s | 173.413 s | 37.652 s | 4.61× |
| Baseline | 3,492.505 ms | 3,089.060 ms | 708.549 ms | 4.36× |
| First update | 134.832 ms | 121.934 ms | 45.513 ms | 2.68× |

## Implementation

- Custom local, routing, and product sumchecks partition both evaluation points
  and row pairs, reuse task-local scratch, and combine exact field sums.
  Poseidon sumchecks use adaptive row-pair tasks instead of the fixed cutoff.
- Initial native Merkle trees and their Poseidon traces process independent rows
  within each level in parallel. Sparse DAG validation/construction, independent
  trace rows, compact witness tables, assignment embedding, and product factors
  also use Rayon.
- Shared equality-table construction, column copies, bounded table transposition,
  and column folding distribute memory work. Folding compacts bounded blocks in
  place without allocating an additional half-witness for every column.
- The baseline product oracle uses parallel factors, chunked batch inversion,
  and parallel work within each product-tree level.
- The baseline's three final WHIR openings and the update's two final openings
  execute concurrently after their challenges and role-specific seeds are fixed.
  Nested work uses the same pool, rather than separate pools per opening.
- The vendored `p3-sumcheck` coefficient kernels use a field-size-aware work
  threshold. Scalar STIR accumulation streams weighted query powers in parallel
  output blocks, removing the dense polynomial-size × query-count temporary
  matrix. Scratch is proportional to query count per active task; the output
  weight polynomial is still retained. Both changes apply to all three provers.
  See [the dependency patch notes](../vendor/p3-sumcheck/LOCAL_CHANGES.md).

Task sizes depend on available workers and work per item. There is no CPU-model
branch, eight-worker cap, core affinity setting, or per-proof private pool.
Fiat–Shamir rounds, dependent tree levels, and hierarchy carries retain their
required ordering. Small tails cannot fill a large pool, and memory bandwidth
can limit scaling even when independent arithmetic is available.

Coarse phase timers explain much of the observed change:

| Phase, 8 workers | Before | After |
| --- | ---: | ---: |
| Baseline local sumcheck | 953.2 ms | 222.8 ms |
| Baseline product sumcheck | 1,581.6 ms | 284.4 ms |
| Initial assignment Merkle tree | 6.864 s | 1.480 s |
| Initial Poseidon/Merkle trace | 7.080 s | 1.583 s |
| Initial routing sumcheck | 1.590 s | 0.375 s |
| Update local sumcheck | 24.0 ms | 6.8 ms |
| Update Poseidon sumcheck | 14.2 ms | 9.2 ms |
| Update product sumcheck | 6.0 ms | 2.2 ms |

These timers are rounded and sometimes nested. Concurrent opening durations
overlap and must not be added to obtain total wall time. Initial Poseidon
sumchecks and full-round reductions still account for about 19.1 s of the
37.7 s initialization. Baseline local/product sumchecks still account for
about 507 ms of 709 ms. Parallelism removes serial execution from these large
loops; it does not remove their underlying arithmetic cost.

## Matched workload and timing

The common [comparison example](../examples/prover_comparison.rs) constructs
65,536 gates with identity wiring and 256 public inputs. It changes one public
input leaf from 9 to 10. Each update starts from a clone of the same fully
proved initial state with an empty update hierarchy. It calls the real
`dynamic::update`; initialization calls the real `dynamic::initialize`.

The baseline proves the same updated arithmetic witness from scratch. It proves
the ordinary arithmetic statement, while dynamic initialization additionally
establishes the authenticated state needed for later updates. Thus the timings
compare the intended operations, whose proof obligations differ.

Indexing/setup, baseline program preparation, and state cloning occur outside
prover timers. Verification, proof serialization/fingerprinting, and destruction
of each returned proof or cloned state also occur outside the prover timers.
Initialization includes its native assignment validation, tree construction,
and complete composed static/CAIR proof. Samples alternate baseline/update
order, with no concurrent benchmark processes, compilation, or test execution.

Both builds use the same field, security settings, four-variable WHIR folding
schedule, existing column-aware evaluation/shared-row weights, and coarse
profiling setting (`DYNAMIC_SNARK_PROFILE=1`, detail profiling disabled).
No transcript, proof format, degree bound, or security parameter was changed
by this parallelization. The previous implementation is a snapshot of the
working source immediately before these changes, not the repository HEAD.

All 44 timed proofs and eight warmup proofs verified. Each phase's full
serialized-proof BLAKE3 fingerprint matches across both builds and worker
counts; see [proof fingerprints](parallel-provers/proof-hashes.json).

## Validation and reproduction

The complete test suite passes in all three configurations:

```sh
cargo test --offline
cargo test --offline --features parallel
cargo test --offline --features parallel,whir-initial-64
cargo check --offline --all-targets --features parallel,whir-initial-64
```

Each test configuration passes 80 unit tests; serial mode also passes four
integration tests, and each parallel configuration passes five. New tests
compare coefficient reductions and streamed STIR weights with direct scalar
references, including boundary sizes and zero challenges. The complete-proof
test compares initialization, public-leaf and gate updates, hierarchy merges,
and baseline proofs byte-for-byte across pools of 1, 8, and 96 workers.
That 96-worker test uses a small correctness fixture, not a performance workload.

Reproduce the final measurement from this source:

```sh
cargo build --offline --release --example prover_comparison --features parallel
RAYON_NUM_THREADS=8 DYNAMIC_SNARK_TRACE_LOG=16 \
  DYNAMIC_SNARK_FIRST_SAMPLES=5 DYNAMIC_SNARK_PROFILE=1 \
  target/release/examples/prover_comparison > after-8.csv 2> after-8.log
```

Repeat with `RAYON_NUM_THREADS=1` for the control. Ensure
`DYNAMIC_SNARK_PROFILE_DETAIL` is unset. Set `RAYON_NUM_THREADS=96` on EC2;
the binary must be built with `parallel`. The separate EC2 experiment uses
`parallel,whir-initial-64`, applying that folding schedule uniformly to the
baseline, initial proof, and updates. Its correctness is tested here, but the
tables above use `parallel` alone. See [the EC2 guide](../docs/ec2-2p24-experiment.md).

Raw samples, coarse profiles, source/binary hashes, run metadata, test logs,
and the validation/summarization script are under
[`parallel-provers/`](parallel-provers/). The buildable
[`before-source.tar.gz`](parallel-provers/before-source.tar.gz) and
[`after-source.tar.gz`](parallel-provers/after-source.tar.gz) preserve the
manifests, source, vendored crates, examples, benchmarks, and tests. Each contains
the common comparison example; build it with the command above after extraction.
Archive/file hashes are recorded in `source-archives.json`.
`before-streaming/` contains an
intermediate implementation's measurements and is excluded from these results.
The first control's optional macOS `time -l` wrapper could not read
`kern.clockrate` under the sandbox after all proof records completed; the
reported times come from successful in-process prover timers. No OS resource
statistics or measured peak-memory claim is made here.
