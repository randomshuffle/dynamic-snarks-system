# Column-aware openings: first-update comparison

Implemented column-aware polynomial evaluation and shared-row equality-weight construction. At **65,536 arithmetic gates**, first-update median latency fell by **36.6% (1.58× speedup)** for both a literal single-leaf update and a complete one-gate update.

## Matched measurements

Each case has 30 independent first updates from clones of the same trusted base state, with empty update tables. These are fixed-workload repetitions, not a sequence with hierarchy merges.

| Update | Control median | Optimized median | Reduction | Control mean | Optimized mean |
|---|---:|---:|---:|---:|---:|
| One public-input leaf | 122.470 ms | **77.665 ms** | **36.58%** | 123.485 ms | 77.825 ms |
| One gate / three wire positions | 123.724 ms | **78.371 ms** | **36.66%** | 126.771 ms | 78.690 ms |

The first measured update in each process also improved: **124.542 → 79.616 ms** for the leaf and **124.754 → 81.249 ms** for the gate. Subsequent repetitions benefit from process caches but still start from an empty update hierarchy.

The control gate run had one 198.475 ms sample; it is retained in the raw data and mean. Median comparisons avoid overstating the gain from that outlier. Optimized leaf times ranged from 77.002 to 79.616 ms, and optimized gate times from 77.852 to 82.220 ms. These are laptop wall-clock measurements, without a confidence interval over machines or randomized workloads.

The control was rebuilt from the same isolated source snapshot as the optimized executable, replacing only the two optimized arithmetic calls with their previous implementations. The exact replacement is retained in [the control patch](opening-opts-control.patch). An unrelated WHIR folding experiment was being edited in the shared checkout; neither executable enables its `whir-initial-64` feature. This comparison uses the newly measured control, rather than the slightly slower [earlier profiling baseline](first-update-n16.md).

Hardware and workload match the earlier experiment: Apple M2 MacBook Air, 16 GB RAM, release build, Rust 1.92.0, `--features parallel`, eight Rayon threads, identity wiring, and 256 public inputs. WHIR uses folding factor four, rate one-half, the configured 127-bit target, and zero PoW. The leaf is public input 128; the gate is addition gate 32,768. Both have 128 sparse rows, a 32,768-field main table, and a 4,096-field product table. Initialization, cloning, verification, and state destruction are outside the proving timer. The initial full static/CAIR proof is omitted through the existing trusted-base harness.

## Where the saving came from

Mean instrumented times for the single-leaf case:

| Phase | Control | Optimized |
|---|---:|---:|
| Main claim evaluations | 27.433 ms | **3.000 ms** |
| Product claim evaluations | 5.933 ms | **1.000 ms** |
| Main claim-weight construction | 17.533 ms | **1.670 ms** |
| Product claim-weight construction | 1.237 ms | **0.486 ms** |
| Main WHIR opening, total | 54.400 ms | **14.133 ms** |
| Product WHIR opening, total | 9.100 ms | **4.000 ms** |
| Local relation sumcheck | 24.000 ms | 24.000 ms |
| Poseidon partial-round sumcheck | 14.033 ms | 14.000 ms |
| Poseidon full-round reductions | 4.067 ms | 4.000 ms |

The opening totals include evaluation and weight-construction subphases; do not add them together. Existing evaluation/phase checkpoints round to milliseconds, while weight timers report microsecond precision. Checkpoint logging is included in these instrumented timings.

Combined WHIR opening time fell **63.5 → 18.13 ms**, about **71%**. This explains nearly all of the 45.66 ms reduction in mean first-leaf-update time. The local relation sumcheck is now the largest individual phase at **24 ms**, around 31% of the optimized update. Its degree bound and implementation were left unchanged by this optimization.

## Implementation

The arithmetic lives in `src/static_snark/pcs/structured_openings.rs`, called by `ExplicitLayout::add_claim` and `ExplicitLayout::into_sumcheck` in `src/static_snark/pcs.rs`.

- A trailing run of Boolean coordinates in a Plonky3 big-endian point identifies a fixed column and its stride. Evaluation reads that column directly and uses the equality weights of the remaining row point. Fully Boolean points reduce to a single table entry. The row prefix may itself contain Boolean coordinates.
- A cache retains only the most recent row point and its equality vector. Consecutive column claims reuse it, and memory does not grow with the number of claims.
- Combined claim weights are accumulated directly into the selected columns. Dense/OOD points remain in the general batched kernel. Their powers of the batching challenge retain their original claim indices, even when column claims appear between them. Entirely dense batches use the original overwrite kernel.
- Claim values and order, transcript absorption, sumcheck constraints, verifier logic, and proof representation are preserved. There are still 119 main terminal claims and 58 product terminal claims, plus one OOD claim per opening.

## Validation

All **120 matched benchmark updates** verified successfully outside the timers. Verification means stayed similar: leaf 17.015 → 16.868 ms; gate 17.264 → 16.900 ms.

Four new tests cover:

1. Every coordinate pattern over `{0, 1, 7, -11}` for dimensions zero through six, comparing optimized evaluation against the generic evaluator.
2. The actual 256-row / 128-column main-table shape, including repeated row points and boundary columns.
3. Exact equality of combined weight tables and claimed sums with the original implementation for mixed dense/column claims, duplicate and interleaved claims, fully Boolean points, empty batches, and batching challenges `0`, `1`, `13`, and `-1`.
4. Identical sumcheck messages, PoW witnesses, challenge points, and subsequent transcript challenge when using the optimized layout versus the original evaluation and weight construction.

The final shared-checkout run of `cargo test --offline --features parallel` passed **76 unit tests and four integration tests**. `cargo check --offline --all-targets --features parallel`, formatting of the changed Rust module, and `git diff --check` passed. The PCS module has an explicit relative path so the standalone WHIR benchmark can also include it directly. Cargo continues to emit warnings, including unused test-helper warnings under that benchmark's direct module inclusion.

## Reproduce

```sh
cargo build --offline --release --example first_update --features parallel

DYNAMIC_SNARK_TRACE_LOG=16 \
DYNAMIC_SNARK_FIRST_KIND=leaf \
DYNAMIC_SNARK_FIRST_SAMPLES=30 \
DYNAMIC_SNARK_PROFILE=1 \
RAYON_NUM_THREADS=8 \
target/release/examples/first_update \
  > benchmark-results/opening-opts-after-leaf.csv \
  2> benchmark-results/opening-opts-after-leaf.log
```

Repeat with kind `gate` and matching output names. To rebuild the control, apply `opening-opts-control.patch` to an isolated copy of the optimized source and build the same example with the same features; retain its executable separately. Run it with output names `opening-opts-control-leaf` / `opening-opts-control-gate`. The measured process order was control leaf, optimized leaf, control gate, optimized gate, with no benchmark processes running concurrently in this task.

```sh
python3 benchmark-results/summarize-opening-opts.py
```

[Latency summary](opening-opts-summary.csv), [phase summary](opening-opts-phases.csv), [run configuration and executable hashes](opening-opts-run.json), [leaf samples](opening-opts-after-leaf.csv), [gate samples](opening-opts-after-gate.csv).
