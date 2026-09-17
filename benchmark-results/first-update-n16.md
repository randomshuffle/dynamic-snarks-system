# First update at 65,536 arithmetic gates

Measured 2026-09-09. A literal one-leaf update takes **126.1 ms median**; the smallest complete gate update takes **128.1 ms median**. **WHIR openings account for about 51% of the one-leaf update time.** Native Merkle-path maintenance is below the existing checkpoint's 1 ms reporting resolution.

## Workload and timing

The new `examples/first_update.rs` driver clones the same trusted base state before every sample. Every timed update therefore starts with empty hierarchy tables and creates exactly one transition proof. These are repeated first updates, without sequence composition or merge spikes.

| Workload | Supplied logical positions | First sample (ms) | Median (ms) | Mean (ms) | Min–max (ms) |
|---|---:|---:|---:|---:|---:|
| One public-input leaf | 1 | 126.545 | 126.128 | 126.964 | 124.300–143.083 |
| One addition gate | 3 | 128.583 | 128.148 | 128.850 | 125.699–138.947 |

Each row contains 30 samples in one process. The sample standard deviations are 3.478 ms and 2.814 ms, respectively. Identical positions and values are used for every repetition; these distributions describe runtime variation for the fixed workloads, not variation across random updates. The first sample follows native setup; later samples reuse process caches and allocations.

- The circuit has 32,768 addition gates and 32,768 multiplication gates, identity wiring, and 256 public-input occurrences.
- The aligned assignment commitment has `4 × 65,536 = 262,144` leaves, so a leaf path has **18 edges** (19 hashes including the leaf hash).
- The literal leaf case changes public input 128 from 9 to 10, at logical position 196,736 / physical leaf 515. Identity wiring permits this standalone public-input change.
- The gate case changes addition gate 32,768, with physical leaves 131,072–131,074. The left input and output change; the unchanged right input is also supplied to satisfy gate closure. An arbitrary single gate wire cannot be supplied alone through the update API.
- Timed work includes update validation, hierarchy insertion, sparse Merkle maintenance, transition proving, and public-input opening refresh. Setup, trusted base construction, state cloning, verification, and state destruction are outside the timer.
- The full initial static/CAIR proof is omitted, following the existing transition-only benchmark harness. Both production and benchmark updates call the same transition prover and hierarchy rebuild. This measures the first transition after trusted native initialization; it does not reproduce the cache history of generating a full initial proof.
- Apple M2 MacBook Air, four performance and four efficiency cores, 16 GB RAM (verified with `system_profiler`). Release profile, `--features parallel`, eight Rayon threads, Rust 1.92.0, `aarch64-apple-darwin`. Fixed WHIR rate one-half, folding factor four, configured 127-bit target, zero PoW, BN254, and BLAKE3 PCS hashing. The assignment and wiring vector commitments use Poseidon2.
- Source base commit: `anonymous`, plus the pre-existing working-tree implementation. No proving algorithm or cryptographic parameter was changed for this experiment.

## Where the time goes

Mean phase times for the literal one-leaf case, from the same 30 samples:

| Phase | Time (ms) | Share of update |
|---|---:|---:|
| Main WHIR opening | 54.53 | 43.0% |
| Product WHIR opening | 10.03 | 7.9% |
| Local relation sumcheck | 25.00 | 19.7% |
| Poseidon partial-round sumcheck | 14.57 | 11.5% |
| Poseidon full-round reductions | 4.00 | 3.2% |
| Routing/product sumcheck | 6.00 | 4.7% |
| Main + product commitments | 5.03 | 4.0% |
| Sparse DAG/table construction | 4.07 | 3.2% |
| Poseidon witness trace construction | 3.03 | 2.4% |

Other preparation and maintenance account for the remainder. Existing checkpoints round to milliseconds, so components do not sum exactly. Native sparse-path updates, update validation, hierarchy insertion, and cached public-input refresh each reported `0.000s` in every sample; this means below reporting resolution, not zero work. Parent phase totals in the raw phase CSV must not be added to their child phases.

The one-leaf and one-gate shapes both pad to 128 sparse rows. Their main table is `256 × 128 = 32,768` field elements (1 MiB), and the product table is `128 × 32 = 4,096` elements (128 KiB). They require 114 and 132 non-boundary old/new Poseidon checks, respectively, but both commit 256 scalar-trace slots. Removing the two extra gate leaves does not cross a table-padding boundary.

## Bottleneck and optimization targets

**1. Exploit the structure of WHIR opening claims.** The main opening contains 119 terminal claims and one OOD claim; the product opening contains 58 terminal claims and one OOD claim. In `src/transition_cair.rs::main_opening_points`, 50 compact columns are opened separately at the local sumcheck point and again at the product sumcheck point. Most of these points fix the column bits to Boolean values and share the row coordinates.

`src/static_snark/pcs.rs::ExplicitLayout::add_claim` currently calls `self.poly.eval_ext` independently for each claim. The installed Plonky3 implementation uses a generic split-equality dot product over the full table. It does not specialize these accesses to the selected column or reuse the shared row evaluation. Main-claim evaluations cost **27.43 ms**, and product-claim evaluations cost **6.23 ms**. These timers include the OOD evaluation and per-claim transcript/checkpoint work.

After evaluations, `ExplicitLayout::into_sumcheck` forms a generic `EqStatement` and calls `Constraint::combine_new` to construct the initial sumcheck weights. Additional timers over a separate 100-update leaf run measured:

| WHIR subphase | Main (ms) | Product (ms) |
|---|---:|---:|
| Claim-weight construction | 17.593 | 1.275 |
| Initial folding sumcheck, including table copy/prover construction | 2.842 | 0.518 |

The weight timers cover challenge derivation and statement construction as well as the equality-weight kernel. They are nested within the WHIR proof timers, not additional work. This identifies **about 52.5 ms** across claim evaluation and weight construction as a concrete optimization budget; it is not a promised saving.

The first implementation target should be column-aware evaluation and shared-row equality weights while preserving all existing evaluation values, claim ordering, and transcript messages. The combined weight table can exploit the fixed Boolean column selectors and shared row factors. A later alternative is to reduce the number of terminal claims through additional authenticated column batching; that would require protocol/transcript review.

**2. Tighten the local sumcheck degree bound for this shape.** `compact_constraint_degree` returns 18 from the 15-bit gate-pair index, causing 19 message evaluations per round. `prove_local_sumcheck` executes the point/pair loops sequentially, even with the parallel feature. It consumes another 25 ms. For this circuit, the gate-pair and public-input bounds exactly fill their bit domains, and `prefix_selector` returns the constant one. Consequently those particular range constraints do not require the general high-degree bound. A shape-specific bound merits algebraic validation and prover/verifier tests before changing it. Reusing residual buffers and parallelizing the independent pair reductions are additional candidates.

**3. Revisit Poseidon sumchecks after opening and local-relation work.** Partial and full rounds together cost 18.57 ms. Their existing parallel kernels already contribute less wall time than WHIR opening preparation or the local sumcheck. Optimizing native Merkle updates would affect a much smaller portion of this workload.

## Validation and profiling limits

All 30 leaf updates, all 30 gate updates, and all 100 additional instrumented leaf updates passed transition-chain and public-input verification outside their timers. Both base states were verified too. The original benchmark also completed and verified a one-gate first update at 129.324 ms and its separate one-update sequence at 125.059 ms.

The release build, `cargo check --offline --all-targets --features parallel`, example formatting check, and `git diff --check` passed. Cargo emitted pre-existing warnings. Changes consist of the standalone repetition driver, two optional WHIR phase checkpoints, and result artifacts.

macOS `sample` could not attach to the benchmark process. No call-stack sampling profile was obtained; the findings above use direct wall-clock instrumentation and inspection of the checked-out/installed Rust code. The attempted sampler log is retained. Checkpoint output was redirected to files and remains inside the measured proving calls; these are instrumented laptop measurements.

## Reproduce

```sh
cargo build --offline --release --example first_update --features parallel

DYNAMIC_SNARK_TRACE_LOG=16 \
DYNAMIC_SNARK_FIRST_KIND=leaf \
DYNAMIC_SNARK_FIRST_SAMPLES=30 \
DYNAMIC_SNARK_PROFILE=1 \
RAYON_NUM_THREADS=8 \
target/release/examples/first_update \
  > benchmark-results/first-update-n16-leaf.csv \
  2> benchmark-results/first-update-n16-leaf-profile.log
```

Repeat with kind `gate` and matching output names. For the detailed WHIR run, use kind `leaf`, 100 samples, and output names `first-update-n16-leaf-detail.csv` / `first-update-n16-leaf-detail.log`. Then run:

```sh
python3 benchmark-results/summarize-first-update.py
```

Data: [latency summary](first-update-n16-summary.csv), [all phase means](first-update-n16-phases.csv), [WHIR subphase means](first-update-n16-whir.csv), [leaf samples](first-update-n16-leaf.csv), [gate samples](first-update-n16-gate.csv), [detailed-run samples](first-update-n16-leaf-detail.csv).
