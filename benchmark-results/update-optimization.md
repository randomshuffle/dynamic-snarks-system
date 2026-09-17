# First-update arithmetic and opening optimization

For a single-leaf first update at **65,536 gates**, the eight-worker median
falls from **41.303 ms to 29.723 ms**, a **28.0% reduction (1.39× speedup)**.
Both builds already include the preceding shared parallelization and streamed
STIR weights. Measurements use the local M2, Rust 1.92 release builds,
`--features parallel`, and the unchanged four-variable WHIR folding schedule.

| Workers | Samples per build | Before median | After median | Before mean | After mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8 | 90 | 41.303 ms | 29.723 ms | 43.608 ms | 29.876 ms |
| 1 | 30 | 121.529 ms | 82.529 ms | 121.959 ms | 82.688 ms |

Eight-worker samples come from three alternating process pairs, with one warmup
and 30 measured updates per process. Before-batch medians are 41.641, 41.396,
and 40.416 ms; after-batch medians are 29.722, 29.702, and 29.748 ms. The before
run includes a 219.213 ms outlier, retained in the mean. Only designated warmups
are excluded. Median improvement is the headline because of this variability.

Each update changes public input 128 from 9 to 10, with identity wiring and
256 public inputs. The assignment tree has depth 18; the transition has 128
sparse rows, a 256 × 128 main table, and a 128 × 32 product table. Every sample
starts with empty update tables. Indexing, trusted base construction, state
cloning, verification, and destruction are outside update timers. All 240
measured updates in the matched comparison verified. Builds, tests, and other
benchmark processes did not run concurrently with these measurements.

A separate run through the full `dynamic::initialize`, `dynamic::update`, and
`dynamic::verify` APIs confirms a **29.944 ms median / 30.493 ms mean** over five
first updates from a fully proved base. That run also verifies a baseline median
of 647.665 ms and one complete initialization taking 24.229 s. These latter two
values are validation-run measurements, not a new matched before/after study.

## Changes

**Transpose the scalar Poseidon recurrence once.** The 58 fixed constraint
weights define a linear combination of 57 state coordinates, 56 fifth powers,
and four boundary coordinates. Previously each pair constructed seven versions
of those arrays and evaluated/weighted the recurrence seven times. The new code
precomputes the linear combination's coefficients once per sumcheck, accumulates
the weighted degree-five polynomial for each pair, and evaluates that polynomial
at the existing seven dyadic points. No witness assumption is used in this
identity. It applies to initial proofs and updates and preserves the messages
exactly. The original residual evaluator remains an independent verifier/test
reference. See [`PartialWeights`](../src/poseidon_scalar.rs).

**Use the actual local-constraint degree bound.** A prefix selector covering
the entire bit domain is the constant polynomial one, including at non-Boolean
points. Here the 15-bit gate-pair and 8-bit public-input ranges are both full.
The previous bound counted their full bit widths anyway. The new bound is

```text
max(6, level_bits + 3, gate_range_degree + 3, public_range_degree + 3)
range_degree = 0 for empty/full ranges, otherwise at most the bit width
```

Range/equality terms have at most two row/role selector factors and one
sumcheck equality factor. The remaining residuals have degree at most four
before that equality factor; the existing conservative floor of six is kept.
Level equality selectors still have degree five for this workload, making the
bound **8 instead of 18**. Seven local rounds therefore carry **9 instead of 19
field elements each**, saving 70 field elements (2,240 bytes of field payload)
and more than half the point/pair evaluations. General partial ranges retain
their conservative degree bound. Prover and verifier derive the same bound
from the statement. See [`compact_constraint_degree`](../src/transition_relation.rs).

**Batch terminal column claims.** Consecutive claims sharing a row point now
reuse one row-weight table and evaluate their columns in parallel. Larger row
domains can also split each column reduction. Values are absorbed into the
challenger in their original order, preserving batching powers and transcripts.
Small reductions avoid entering Rayon when only one row chunk exists. The
opening checkpoint now reports the completed batch once, reducing diagnostic
output as well as arithmetic scheduling overhead. This PCS change applies
equally to baseline, initial, and update proofs. See
[`structured_openings.rs`](../src/static_snark/pcs/structured_openings.rs).

The first two changes alone produced a 31.857 ms median in a preliminary
30-sample run. This is indicative attribution; the matched table above measures
the final combined implementation.

## Current profile

Coarse stage medians from the matched eight-worker runs:

| Stage | Before | After |
| --- | ---: | ---: |
| Local relation sumcheck | 6 ms | 3 ms |
| Poseidon partial-round sumcheck | 8 ms | 3 ms |
| Poseidon full-round reductions | 4 ms | 4 ms |
| Routing product sumcheck | 2 ms | 2 ms |
| Main WHIR opening | 11 ms | 8 ms |
| Product WHIR opening | 5 ms | 3 ms |

The two openings overlap; their durations must not be added as sequential
update costs. These timers round to milliseconds. Setup, initial commitments,
opening preparation, and other work account for the rest of the update.

The refreshed isolated profiler times parallel kernels from their calling
thread. A scoped opening identifier distinguishes nested WHIR events from
the concurrent main and product openings. No per-pair timers or shared atomic
counters are inserted into the arithmetic loops.

Selected detailed elapsed times, averaged over 30 measured updates:

| Component | Before | After |
| --- | ---: | ---: |
| Local pair kernel | 5.205 ms | 2.872 ms |
| Poseidon partial pair kernel | 7.075 ms | 2.171 ms |
| Full-round pair kernels | 2.261 ms | 2.184 ms |
| Full-round table folding | 1.253 ms | 1.138 ms |
| Main opening terminal claims | 4.672 ms | 0.732 ms |
| Product opening terminal claims | 1.871 ms | 0.363 ms |
| Main opening STIR weight accumulation | 2.254 ms | 2.357 ms |
| Main opening sumcheck coefficients | 0.712 ms | 0.965 ms |
| Main opening sumcheck table folding | 0.799 ms | 1.031 ms |

Detailed timing/logging adds about **6.2 ms per update**: before, the instrumented
binary averages 39.540 ms disabled versus 45.802 ms enabled; after, 29.710 versus
35.943 ms. Treat detailed numbers as attribution, not overhead-free CPU time.
Nested timers include child diagnostics, concurrent workers compete for the
same pool, and terminal-claim timing includes the checkpoint change. Do not
infer additive savings from this table or treat small differences in unchanged
kernels as regressions.

The remaining priority is the **main WHIR opening**, especially its STIR query
weights (about 2.36 ms in the detailed run), initial claim weights (about 1.48 ms
in coarse runs), and internal coefficient/folding arithmetic. In the relation
prover, **full-round reductions and local constraints** now deserve more
attention; partial-round recurrence evaluation is no longer dominant. Folded
WHIR FFT/Merkle work is comparatively small in this workload. The initial main
commitment is outside the opening totals and remains a separate several-ms
cost worth profiling more closely.

## Correctness and compatibility

All 83 unit tests pass in serial, parallel, and `parallel,whir-initial-64`
configurations, together with four serial/five parallel integration tests.
The all-target EC2-feature check passes. Additional checks cover:

- Every optimized Poseidon message evaluation against the original residual
  polynomial on arbitrary off-trace inputs, varied weights, and equality data.
- Finite differences of every local residual times a linear equality factor
  across full, partial, empty, small, and large ranges, supplementing the degree
  argument above.
- Batched claim values, order, duplicate/mixed points, and the next transcript
  challenge against sequential claim absorption.
- Complete initial, baseline, and multi-update proofs with hierarchy merges
  at 1, 8, and 96 workers under both folding feature configurations.

The full initialization and baseline proof fingerprints match those from the
previous implementation exactly. **Update proofs change because local messages
are shorter**: old update proofs for affected shapes must be regenerated for
the new verifier. WHIR settings, field, constraint identities, and security
targets are unchanged. No 96-worker performance claim is made on the laptop.

## Reproduction and artifacts

```sh
cargo build --offline --release --features parallel --example first_update
env -u DYNAMIC_SNARK_PROFILE_DETAIL \
  RAYON_NUM_THREADS=8 DYNAMIC_SNARK_TRACE_LOG=16 \
  DYNAMIC_SNARK_FIRST_KIND=leaf DYNAMIC_SNARK_FIRST_SAMPLES=31 \
  DYNAMIC_SNARK_PROFILE=1 target/release/examples/first_update
```

Drop sample zero as the warmup. Use `RAYON_NUM_THREADS=1` for the control.
For current-source detailed profiling, choose a fresh destination:

```sh
python3 scripts/prepare_update_profile.py /tmp/update-profile-repro
cargo build --offline --manifest-path /tmp/update-profile-repro/Cargo.toml \
  --release --features parallel --example first_update
```

Run that example with the same environment and
`DYNAMIC_SNARK_PROFILE_DETAIL=1`. Profiling changes remain in the isolated
source tree; the Cargo registry and production dependency sources are not
instrumented. The original pre-parallel profiling script is retained as a
historical artifact and must not be used with the current implementation.

[`update-optimization/`](update-optimization/) retains raw samples, profiling
logs, phase/round summaries, parsers, test logs, binary/source hashes, the final
production source archive, and both instrumented source archives. The production
control is the [previous parallel source snapshot](parallel-provers/after-source.tar.gz).
`run_updates.py` records the actual sequence of frozen binaries in `run.json`.
`full-summary.json` records the full-API validation timings and proof fingerprints.
