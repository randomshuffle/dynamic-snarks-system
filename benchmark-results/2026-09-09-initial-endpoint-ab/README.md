# Initial-computation digest-only PIOP A/B

The new initial prover takes **20.695 s versus 31.633 s** in this matched
observation: **34.58% less time**, or **1.53× speedup**. The complete proof's
field/hash payload grows only **1.36%**. Verification is slower, while CBOR
serialization is slightly smaller. The initial Merkle oracle itself is 64× smaller.

## Matched configuration and scope

Both release binaries use all **eight logical CPU threads**, an identity-wired
circuit of **65,536 gates**, and 256 public inputs. Each pair has an addition
and multiplication gate; assignment values follow the same deterministic pattern
as the update A/B. There are 196,864 logical assignment positions, encoded into
262,144 physical gate-order slots. Both runs produce the same Merkle root.

WHIR keeps the existing fixed half-rate schedule, folding parameter four,
security parameter 127 and zero proof of work. The original binary uses
`parallel`; the new one uses `parallel,experimental-poseidon-gkr`. The 64-round
GKR arithmetic engine is reused unchanged from the update experiment.

Each binary runs **one complete dynamic initialization**, then verifies the
proof. The timed initialization includes native assignment checks, the assignment
Merkle tree, arithmetic relation construction, the arithmetic and Merkle PIOPs,
WHIR proofs, the public-input opening, and prover-state construction. Input
construction, indexing, serialization, additional decoded-proof verification and
destruction are excluded. Verification time is measured separately. No standalone
baseline SNARK or update proof is benchmarked.

These are single observations, not medians. The original binary ran first and
the digest-only binary second, in separate processes. Profiling was enabled for
both, with stderr redirected to files.

## Measurements

| Metric | Previous scalar trace | Digest-only GKR |
|---|---:|---:|
| Complete initial prover | 31.633 s | 20.695 s |
| Complete verifier | 26.318 ms | 34.830 ms |
| Merkle oracle field elements | 33,554,432 | 524,288 |
| Merkle oracle field storage | 1 GiB | 16 MiB |
| Outer Merkle sumcheck rounds | 114 | 1,216 |
| Merkle oracle opening queries | 15 | 5 |
| Complete proof fields | 30,108 | 34,972 |
| Complete proof BLAKE3 digests | 21,753 | 17,596 |
| Complete field/hash payload | 1,659,552 B (1620.66 KiB) | 1,682,176 B (1642.75 KiB) |
| Complete CBOR proof | 2,461,929 B (2404.23 KiB) | 2,361,040 B (2305.70 KiB) |

Payload counts every BN254 element and BLAKE3 digest at 32 bytes. It includes
both initial proof components, hierarchy roots and the final public-input
opening, excluding keys and prover state. CBOR includes framing and its larger
encoding of digest arrays; its change differs from the field/hash payload change.

| Merkle-proof component only | Previous scalar trace | Digest-only GKR |
|---|---:|---:|
| Field/hash payload | 636,448 B (621.53 KiB) | 659,072 B (643.62 KiB) |
| CBOR serialization | 961,009 B (938.49 KiB) | 860,702 B (840.53 KiB) |

## What changed

The new initial Merkle oracle is just the `2K`-entry digest heap, including one
fixed dummy digest. Its hash inputs are derived from child-digest restrictions,
the existing assignment polynomial, and public index/domain formulas. Therefore
no input columns or separate routing sumcheck are needed. The verifier checks
all 64 Poseidon rounds through the existing endpoint GKR engine and authenticates
five digest evaluations plus one assignment evaluation. The arithmetic PIOP is
unchanged. See [the exact polynomial identities and protocol](../../docs/initial-endpoint-experiment.md).

Profiling attributes the Merkle PIOP's costs approximately as follows:

| Phase | Previous scalar trace | Digest-only GKR |
|---|---:|---:|
| Merkle proof callback, total | 29.777 s | 18.820 s |
| Oracle commitment | 10.253 s | 0.071 s |
| Oracle opening | 5.266 s | 0.091 s |
| Hash trace / digest-input preparation | 1.512 s | 0.788 s |
| Hash sumchecks (new includes transient layer construction) | 11.341 s | 17.869 s |
| Routing sumcheck | 0.513 s | None |

The new hash-reduction phase costs more, but the savings in commitment and
opening time dominate. The 64× oracle reduction is substantially larger than
the 4× reduction available in sparse updates.

These are **oracle-storage numbers, not peak process RAM measurements**. The
new prover still holds 65 transient width-three layers: about 3.047 GiB of field
storage at this size, in addition to digests, WHIR state and arithmetic proof
state. The old scalar trace buffers hold about 1.484 GiB before the large packed
commitment and its WHIR working allocations. Peak process RAM was not measured.

## Validation

Both complete proofs verified, and both CBOR round trips verified. Assignment
and commitment fingerprints match between variants, as do circuit dimensions,
thread count and WHIR configuration. Each actual table shape matches preflight.

The original build passes 83 unit tests, three end-to-end tests, and two
serialization tests. The experimental build passes 87 unit tests, the same three
end-to-end tests, and the same two serialization tests. New tests exercise the
input identities at non-Boolean points, native hash/root consistency, changed
roots and assignment evaluations, modified openings and round messages, malformed
shapes, and identical proof bytes with one/eight workers. Integration tests cover
nonidentity wiring and padded non-power-of-two circuit sizes. Formatting and
whitespace checks pass.

The feature remains opt-in. It now selects both the initial digest-only PIOP and
the previously implemented sparse endpoint PIOP. Earlier experimental initial
proofs must be regenerated; update protocol arithmetic is unchanged.

## Reproduction and raw results

Use [the initial benchmark commands](../../docs/initial-endpoint-experiment.md#reproduction).
The `initial_poseidon_ab` driver supports `DYNAMIC_SNARK_PREFLIGHT=1` for shape
inspection without proving. The default is exactly one `2^16`-gate initialization.

- [Machine-readable measurements, source hashes and fingerprints](results.json)
- [Previous prover output](scalar-trace.stdout), [profile](scalar-trace.stderr)
- [Digest-only output](digest-gkr.stdout), [profile](digest-gkr.stderr)
