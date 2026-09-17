# Endpoint PIOP scaling: 16 and 128 gate updates

The endpoint approach improves relative to the big-polynomial approach over
this measured range: approximately parity at 16 gates, then **19.2% less prover
time at 128 gates**. Verification remains slower and the field/hash proof payload
is about 10% larger. This makes the approach more promising for larger update
batches than the original one-gate observation suggested.

## Setup

- Same circuit: 65,536 gates, identity wiring, 256 public inputs.
- One update per case, starting from a trusted base and empty update hierarchy.
- Uniform random gate subsets without replacement, seed `20260909`; exactly the
  same gates and replacement values for the two variants at each size. Each
  submitted gate tuple has three positions; left input and output change, while
  the right input remains two.
- Release builds with `parallel`, all eight logical CPU threads. The endpoint
  binary additionally enables `experimental-poseidon-gkr`.
- Original WHIR parameters: fixed half rate, folding parameter 4, security
  parameter 127, zero proof of work.
- Protocol source hashes match the one-gate run. Only the driver changed to
  accept update size and provide a memory preflight; no proposed midpoint
  checkpoint or new arithmetic optimization is included.
- Cases run sequentially: big polynomial 16, endpoints 16, big polynomial 128,
  endpoints 128. Profiling is enabled with stderr redirected to files.

## Prover and verifier time

| Gates in update | Big polynomial prover | Endpoint prover | Endpoint / big | Big polynomial verifier | Endpoint verifier |
|---|---:|---:|---:|---:|---:|
| 1 (prior run) | 32.979 ms | 56.532 ms | 1.714× | 17.374 ms | 21.039 ms |
| 16 | 330.160 ms | 345.583 ms | 1.047× | 19.433 ms | 26.121 ms |
| 128 | 3165.548 ms | 2556.506 ms | 0.808× | 22.669 ms | 29.398 ms |

A ratio below one means the endpoint prover is faster. At 16 gates its measured
prover time is 4.7% higher; that small difference is inconclusive with one sample.
At 128 gates it takes 2.557 s versus 3.166 s (19.2% less time, or 1.24× speedup).
These runs show a size-dependent tradeoff; they do not establish an asymptotic
bound or a precise crossover size.

Update time includes tree maintenance, transition proving and the final public
input opening. Indexing, trusted-base construction, serialization and destruction
are excluded. Verification is timed separately. No baseline SNARK or initial
computation proof is benchmarked. The one-gate row is retained from the previous
experiment, not rerun. There is one timed update per new case and no warmup
update proof, so these numbers are observations rather than medians.

## Proof size

Payload counts field elements and BLAKE3 digests at 32 bytes each. CBOR includes
serialization overhead. Both cover hierarchy roots, the transition proof and the
public-input opening, excluding the initial proof and keys.

| Gates in update | Big polynomial payload | Endpoint payload | Payload change | Big polynomial CBOR | Endpoint CBOR |
|---|---:|---:|---:|---:|---:|
| 1 (prior run) | 402.22 KiB | 430.03 KiB | +6.91% | 572.46 KiB | 570.37 KiB |
| 16 | 703.06 KiB | 773.94 KiB | +10.08% | 1028.68 KiB | 1063.74 KiB |
| 128 | 940.19 KiB | 1036.81 KiB | +10.28% | 1397.75 KiB | 1455.51 KiB |

## Tables and memory estimates

Each field element occupies 32 bytes. For both new sizes, the unchanged product
table has 64 columns. The big main table is `2R × 128`; the endpoint main table
is `R × 64`. Thus the main oracle is 4× smaller, and all committed tables together
are 2.5× smaller. The larger product-table width explains why the combined
reduction is 2.5× here versus 3× in the one-gate case.

| Update gates | Sparse rows R | Active hashes / slots | Main fields: big / endpoint | Product fields | Committed table memory: big / endpoint | Outer sumcheck rounds: big / endpoint |
|---|---:|---:|---:|---:|---:|---:|
| 16 | 2,048 | 1,758 / 4,096 | 524,288 / 131,072 | 131,072 | 20 / 8 MiB | 82 / 790 |
| 128 | 16,384 | 11,748 / 32,768 | 4,194,304 / 1,048,576 | 1,048,576 | 160 / 64 MiB | 103 / 988 |

Conservative transition working-memory estimates are **240 / 120.4 MiB** for
16 gates and **1.875 / 0.940 GiB** for 128 gates (big polynomial / endpoints).
They include WHIR working allocations and, for endpoints, transient full state
layers. They are estimates, not measured peak RSS, and exclude the persistent
circuit/index/base state. Supplementary `/usr/bin/time -l` memory collection was
unavailable because of a sandbox restriction on `sysctl kern.clockrate`; it failed
after the first benchmark had completed and printed its internally timed results.

## Why the larger case improves

At 128 gates, profiling gives these approximate costs:

| Phase | Big polynomial | Endpoints |
|---|---:|---:|
| Main commitment | 623 ms | 177 ms |
| Hash trace and hash reductions combined | 599 ms | 1,172 ms |
| Concurrent main/product opening phase | 950 ms | 300 ms |

The endpoint hash proof still costs about 573 ms more. But the main commitment
saves about 446 ms and the opening phase about 650 ms. Their combined savings
outweigh the extra hash reductions. This is the practical reason for the crossover
in this sample; it does not require the endpoint hash arithmetic itself to win.

## Validation and reproduction

All four update proofs verified. Recorded inputs, workload fingerprints, table
dimensions and thread counts match between variants at each size. All measured
shapes match the preflight. Both release builds and formatting/whitespace checks
pass. Protocol source hashes are unchanged from the prior tested implementation.

Build as in [the protocol documentation](../../docs/poseidon-endpoint-experiment.md),
then run each case sequentially. For example:

```sh
DYNAMIC_SNARK_CHANGED_GATES=16 DYNAMIC_SNARK_PROFILE=1 /tmp/poseidon-piop-scalar-trace
DYNAMIC_SNARK_CHANGED_GATES=16 DYNAMIC_SNARK_PROFILE=1 /tmp/poseidon-piop-endpoint-gkr
DYNAMIC_SNARK_CHANGED_GATES=128 DYNAMIC_SNARK_PROFILE=1 /tmp/poseidon-piop-scalar-trace
DYNAMIC_SNARK_CHANGED_GATES=128 DYNAMIC_SNARK_PROFILE=1 /tmp/poseidon-piop-endpoint-gkr
```

Add `DYNAMIC_SNARK_PREFLIGHT=1` to print the workload and estimates without proving.

- [Machine-readable results, source hashes and selected gates](results.json)
- 16 gates: [big-polynomial output](scalar-trace-16.stdout), [profile](scalar-trace-16.stderr);
  [endpoint output](endpoint-gkr-16.stdout), [profile](endpoint-gkr-16.stderr).
- 128 gates: [big-polynomial output](scalar-trace-128.stdout), [profile](scalar-trace-128.stderr);
  [endpoint output](endpoint-gkr-128.stdout), [profile](endpoint-gkr-128.stderr).
