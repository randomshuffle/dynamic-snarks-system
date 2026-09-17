# Endpoint-GKR memory plan, September 10, 2026

For the current implementation, the exact **2^20-gate sweep through 1,024
updated gates, with twelve sequential updates per size, projects 68.1875 GiB**.
This is a conservative planning estimate, not measured peak RSS. With the
runner's 70% memory allowance it requires at least 97.411 GiB installed RAM;
128 GiB is a suitable capacity target. This 16 GiB Mac has an 11.2 GiB allowance.
The full 2^20 experiment was not launched.

The requested [2^17-gate run through 64-gate updates](../benchmark-results/endpoint-n17-u64-i16-20260910/README.md)
has now completed: 97 verified measurements in 143.578 seconds, with a macOS
peak RSS of 2.904 GiB. That is a residency measurement, distinct from the
7.3125 GiB planning estimate; the report explains the memory metric's scope.

The subsequent [2^18 monitored run through 64-gate updates](../benchmark-results/endpoint-n18-u64-i16-20260910/README.md)
also completed, with 97 verified measurements in 212.879 seconds. Its macOS
footprint peaked at **13.303 GiB**, even though kernel peak RSS was only
3.272 GiB. It therefore exceeds the earlier 8 GB footprint budget. The new
`--rss-limit-gb` option is an explicit sampled-RSS trial mode; it does not cap
footprint or allocation. Normal runs retain the conservative preflight guard.

## Current request: stay below 8 GB without changing the prover

No checkpointing, recomputation or other prover algorithm changes were made.
For the full twelve-update sweep through 1,024 gates per update, the conservative
preflight gives these results with first interleaving 16:

| Gate count | Estimated peak bytes | GiB | Decimal GB |
| --- | ---: | ---: | ---: |
| 2^11 = 2,048 | 4,055,891,968 | 3.777 | 4.056 |
| 2^12 = 4,096 | 8,111,783,936 | 7.555 | 8.112 |
| 2^13 = 8,192 | 16,223,567,872 | 15.109 | 16.224 |

Thus **2^12 gates** is the largest power-of-two circuit below an **8 GiB**
budget according to this estimator. For a strict **8,000,000,000-byte** budget,
the estimator instead admits **2^11 gates**. These are the largest sizes
admitted by the conservative estimates, not measured limits of this machine;
the actual maximum below either RSS ceiling has not been established. Sparse
row padding causes the large step between these cases.

If the update sweep is capped at 64 gates per revision instead, **2^17 gates**
projects 7.3125 GiB (7.852 decimal GB), below either ceiling. For the requested
full sweep, the large composed updates are the limiting phase.

The estimates use BN254, identity wiring, 256 public inputs, seed 20260909,
one full initialization and independent twelve-update sequences for each power
of two from 1 to 1,024. They cover both the baseline and retained dynamic state.
Using shared versus paired baselines changes sample counts, not this estimate.

## Why the smaller polynomials do not yet yield a small-memory prover

For N = 2^20 gates, the physical assignment has K = 4N = 2^22 positions and the
initial digest oracle has 2K = 2^23 field elements. Its raw field storage is
**256 MiB**, down from the legacy scalar oracle's 16 GiB at this circuit size.

However, `src/poseidon_scalar/round_reduction.rs` currently constructs all 65
width-three state layers before consuming them in reverse. Their field storage
alone is `65 × 3 × 2^23 × 32` bytes = **48.75 GiB**. This is a property of the
current prover implementation; the proof protocol does not require retaining
every layer simultaneously.

| Current preflight component, 2^20 gates | GiB |
| --- | ---: |
| Initial Poseidon state layers alone | 48.7500 |
| Initial phase, including working-memory allowance | 58.5000 |
| Largest composed update, transition workspace allowance | 60.1875 |
| Retained circuit/key/base and baseline allowance | 8.0000 |
| **Full experiment planning peak** | **68.1875** |

Phases are sequential, so the peak is the maximum of initialization and update
plus retained state. The largest composed update contains 24,477 positions and
has R = 2^20 sparse rows. Both main and product oracles have 64 columns and
2^26 field elements (2 GiB each). The transition estimator budgets twelve
copies of the combined oracle storage for WHIR and sumcheck work, plus the
transient Poseidon states. This multiplier is conservative, not a claim that
twelve complete copies are simultaneously resident.

## Checkpointing tradeoff

Checkpointing is possible without changing proof messages, their order, or the
verifier. One concrete design saves states at rounds 0, 8, ..., 56 during a
forward pass, then reconstructs and consumes each block while proving backward.
Checkpoints are released when their block is consumed.

Such a block scheme needs roughly 16 state layers rather than 65. Every
intermediate state is generated at most twice: state construction uses at most
two forward passes, while sumcheck and opening work is unchanged. This does not
introduce a factor logarithmic in the gate count. Recursive checkpoint schemes
can instead trade a logarithmic number of stored layers for logarithmic replay
overhead in the **number of Poseidon rounds**, which is fixed at 64 here.

For the initial proof at 2^20 gates, approximately sixteen layers would use
12 GiB of field storage instead of 48.75 GiB. For the largest update, which has
2R = 2^21 hash slots, they would use roughly 3 GiB instead of 12.1875 GiB.
These are proposed state-buffer budgets, not measured whole-process RAM or
timing results. Checkpointing has not been implemented in this task.

The other buffers still matter. At the largest update's hash-reduction phase,
the two current WHIR commitments retain their 2 GiB polynomials and rate-1/2
4 GiB codewords: **12 GiB combined**, before Merkle digests. Product witness
columns, compact routing witnesses, circuit state and the hash-reduction buffers
are additional. An eight-round checkpoint scheme alone therefore would not
make this complete sweep fit comfortably in 16 GiB. Reducing retained witness
copies, changing buffer lifetimes, or streaming/recomputing commitment data
would require a separate implementation and memory measurement.

## First interleaving can be 16

The runner now accepts `--initial-interleaving 16` or `64`, always using 16 in
later rounds. Its default remains 64 for compatibility with earlier commands.
It builds the corresponding feature set and records the actual configuration.

With half-rate encoding and initial interleaving 16, the first FFT height is
`2 × polynomial_elements / 16`. At 2^20 gates this is:

- Initial digest oracle: 2^23 elements, first FFT height **2^20**.
- Largest composed update main/product oracle: 2^26 elements each, first FFT
  height **2^23**.

Both fit BN254's 2^28 two-adic limit. The 2^24 initial digest oracle has 2^27
elements and first FFT height 2^24, so 16 also fits that configuration. Its
current whole-experiment memory preflight is 936 GiB. Interleaving changes FFT
matrix height/width and opening behavior; it does not shrink the state layers
or the total rate-1/2 codeword element count.

## Local alternatives and commands

The exact seeded preflights give these current planning peaks:

| Gate count | Largest update size included | Peak GiB | Passes this Mac's allowance? |
| --- | ---: | ---: | --- |
| 2^12 | 1,024 | 7.555 | Yes |
| 2^13 | 1,024 | 15.109 | No |
| 2^15 | 1,024 | 30.344 | No |
| 2^17 | 256 | 8.523 | Yes |
| 2^17 | 1,024 | 31.094 | No |
| 2^18 | 1,024 | 32.094 | No |
| 2^20 | 1,024 | 68.188 | No |

Thus **2^17 gates through 256-gate updates** is a larger local rehearsal that
passes the current guard. It has not been run here. Always keep the guard;
estimates are not guaranteed upper bounds.

Inspect the requested configuration without generating proofs:

```bash
python3 scripts/run_experiment.py --trace-log 20 --threads 8 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7,8,9,10 \
  --sequence-len 12 --seed 20260909 --baseline-mode shared \
  --preflight-only --offline \
  --output "benchmark-results/endpoint-n20-check-$(date -u +%Y%m%dT%H%M%SZ)"
```

On a host with sufficient memory, omit `--preflight-only` and use its intended
Rayon worker count. For the smaller local run:

```bash
python3 scripts/run_experiment.py --trace-log 17 --threads 8 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7,8 \
  --sequence-len 12 --seed 20260909 --baseline-mode shared --offline \
  --output "benchmark-results/endpoint-n17-$(date -u +%Y%m%dT%H%M%SZ)"
```

Both retain prover-time and proof-size recording, binary proof checkpoints and
result archives. Repackage the current working source for another machine using
`scripts/package_experiment.py`; the September 9 saved source packages predate
the default endpoint PIOPs and selectable interleaving.

## Validation records

The 16-way configuration completed a small end-to-end smoke run: 37 verified
proofs, 37 size measurements and four decoded-and-verified checkpoints, including
the twelfth revision of both update sequences. A separate 64-way compatibility
smoke run verified three proofs and their three checkpoints. Large runs below
are preflights only.

- [2^20 preflight, 16-way](../benchmark-results/endpoint-preflight-n20-i16-20260910/preflight.csv)
- [2^20 WHIR configuration](../benchmark-results/endpoint-preflight-n20-i16-20260910/experiment.json)
- [2^17 preflight](../benchmark-results/endpoint-preflight-n17-i16-20260910/preflight.csv)
- [2^24 preflight](../benchmark-results/endpoint-preflight-n24-i16-20260910/preflight.csv)
- [16-way smoke completion](../benchmark-results/endpoint-i16-smoke-n9-20260910/validation.json)
- [64-way smoke completion](../benchmark-results/endpoint-i64-smoke-n9-20260910/validation.json)
