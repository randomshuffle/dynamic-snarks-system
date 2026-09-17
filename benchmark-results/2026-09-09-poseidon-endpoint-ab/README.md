# One-gate endpoint PIOP A/B — 2026-09-09

Exactly **one update per variant**, on the same identity-wired circuit with
65,536 gates and 256 public inputs. Seed `20260909` selects zero-based gate
36,706; the three-wire tuple is submitted, with left input and output changing.
Both release binaries use `parallel` and all **8 logical CPU threads**.
WHIR is unchanged: fixed rate 1/2, folding parameter 4, security parameter 127,
zero proof of work. These are transition-update measurements; no baseline SNARK
or initial-computation proof was benchmarked.

| Metric | Existing scalar trace | Experimental endpoints |
|---|---:|---:|
| Update prover | 32.979 ms | 56.532 ms |
| Verifier | 17.374 ms | 21.039 ms |
| Main committed fields | 32,768 | 8,192 |
| Product committed fields | 4,096 | 4,096 |
| Total committed fields | 36,864 | 12,288 |
| Outer sumcheck rounds | 54 | 526 |
| Proof field elements | 8,669 | 10,610 |
| Proof BLAKE3 digests | 4,202 | 3,151 |
| Field/hash payload | 411,872 B (402.22 KiB) | 440,352 B (430.03 KiB) |
| Complete CBOR serialization | 586,194 B (572.46 KiB) | 584,059 B (570.37 KiB) |

The main oracle is **4× smaller**, and the total committed witness is **3×
smaller**. In this observation, proving is **1.71× slower** and verification
**1.21× slower**. The field/hash proof payload grows
**6.91%**. CBOR is **0.36% smaller**, mostly because its
encoding overhead penalizes BLAKE3 digest arrays more than field byte strings;
this is not a reduction in the field/hash payload. Payload counts include the
hierarchy commitments, transition proof and public-input opening, but no initial
proof or indexing key.

The shape is `R = 128`, `c = 50`, with 132 active hashes padded to 256 hash slots.
The old main table is `256 × 128`; the new table is `128 × 64`. The reduction
comes from replacing intermediate scalar trace columns with eight hash endpoint
columns and removing the compact witness's unused half of the row domain.
Private sparse routing metadata remains, so this is not the dense initial
construction's digest-only oracle.

The profile explains the timing: the existing hash trace, partial-round check,
and full-round reductions take approximately **1 + 3 + 5 ms**. Building and
reducing all rounds in the experiment takes approximately **40 ms**. Main
commitment time falls from roughly **4 to 2 ms**, and the main opening falls
from **9 to 4 ms**, which does not offset the hash-reduction cost.

Timing includes update tree maintenance, transition proving, and refreshing the
public-input opening. Indexing and trusted-base construction occur first,
outside the timers. Serialization and destruction are excluded; verification is
timed separately. Profiling was enabled for both runs and stderr redirected to
files. There are no warmup update proofs or repeated samples. Small differences
are not statistically meaningful with this sample count.

The option remains behind `experimental-poseidon-gkr`; the existing approach is
the default. This prototype reduces committed size but retains transient full
state layers, so its RAM use does not have the same asymptotic improvement.

Validation: the original build passes 83 unit tests and three end-to-end tests;
the experimental build passes 85 unit tests and the same three end-to-end tests.
New tests check native Poseidon equivalence, terminal authentication, tampering,
JSON serialization round trips, and byte-identical transition proofs with one
and eight workers. Both measured proofs verified successfully.

- [Protocol and reproduction](../../docs/poseidon-endpoint-experiment.md)
- [Machine-readable results and source hashes](results.json)
- [Original stdout](scalar-trace.stdout), [profile](scalar-trace.stderr)
- [Experimental stdout](endpoint-gkr.stdout), [profile](endpoint-gkr.stderr)
