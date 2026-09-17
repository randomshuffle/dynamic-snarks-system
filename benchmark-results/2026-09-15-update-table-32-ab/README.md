# Update table E: 32-column one-gate comparison

The update table now uses exactly **32 columns**, down from 45 used columns
padded to 64. This matched single-update measurement gives a 3.0% smaller
field/hash proof payload and 14.0% lower prover wall time. There is one sample
per variant; the timing difference is not an estimate of a repeatable speedup.

| Metric | Before: 45 used / 64 padded | After: 32 used / 32 padded |
|---|---:|---:|
| Update prover | 57.090250 ms | 49.094291 ms |
| Verifier | 21.876292 ms | 21.838000 ms |
| Full field/hash proof payload | 420,384 B (410.531 KiB) | 407,968 B (398.406 KiB) |
| Complete CBOR serialization | 550,125 B | 534,125 B |
| Proof field elements | 10,419 | 10,127 |
| Proof BLAKE3 digests | 2,718 | 2,622 |
| Update table E | 4 × 64 = 256 fields | 4 × 32 = 128 fields |
| Node table | 128 × 16 = 2,048 fields | 128 × 16 = 2,048 fields |
| Routing product table | 128 × 32 = 4,096 fields | 128 × 32 = 4,096 fields |
| Total committed fields | 6,400 | 6,272 |
| E evaluation requests | 90 | 64 |
| All three oracles' evaluation requests | 180 | 154 |
| Outer sumcheck rounds | 528 | 528 |
| Node / E / routing sumcheck degrees | 8 / 6 / 9 | 8 / 6 / 9 |
| Conservative transition allocation estimate | 4,841,472 B | 4,399,104 B |

The E commitment is half the size; all committed tables together shrink by
2.0%. Both variants retain 256 hash slots (132 non-boundary hashes), the same
64-round Poseidon2 PIOP, and three WHIR commitments/openings. This change does
not reduce the Poseidon workload. Phase instrumentation does not separately
time that PIOP in these two binaries, so it cannot attribute the full observed
8 ms reduction to the E optimization. Memory figures are allocation estimates,
including temporary buffers, rather than measured process RSS.

## What changed

The fixed part of E drops from 22 to 17 fields by removing the unused node
flag, a reserved zero column, the duplicate neighbor value, and the two stored
update-row index copies. The neighbor Merkle opening now authenticates beta
directly. Gate-pair and public-input indices are reconstructed from one shared
bit block; row type selects the bound, and unused high bits are constrained to
zero. Thus the used width is

`17 + max(b(n), b(n0))`, where `b(x) = max(1, ceil(log2(max(1,x))))`.

Here `n=32768`, `n0=256`, so the bit block has 15 columns and the used width is
32. Larger circuit parameters can require more columns. All substitutions into
the previous routing expressions are linear, preserving routing degree nine.
The node oracle, Merkle hash definitions/constants, gate-order indexing, hash
PIOP, and WHIR configuration are unchanged.

The default `compact-merkle` implementation uses the new layout. Its transcript
version is incremented to 2; existing roots and indexed keys retain their
meaning, but update proofs must be regenerated. The exact column meanings are
listed in [the oracle documentation](../../docs/aligned-oracles.md#current-compact-layout).

## Matched workload

- 65,536 gates, 32,768 gate pairs, 256 public inputs, identity wiring, BN254.
- One randomly selected gate, index **36706**, seed **20260909**. Its three
  wire positions are submitted, so `k=|U|=3` and `g=1`; the right input remains
  2 while the left input and output change.
- Identical workload fingerprint:
  `42870fd8c258cad74cb75c40d187dccbed499b7748a0cf3d21de443ec4260692`.
- Both release binaries use all **8** available threads with `parallel`.
- Original WHIR parameters: rate 1/2, folding parameter 4, security target 127
  bits, no proof of work, no `whir-initial-64` feature.
- Both binaries were built before timing and run sequentially, before then
  after, with no concurrent builds or tests. No warmup update proofs or repeats.
- Timed work includes tree maintenance, the hierarchy transition proof, and the
  public-input opening. Indexing, trusted-base initialization, serialization,
  decoded-proof verification, and destruction are outside the timers.
- Payload includes hierarchy commitments, transition proofs, and the final
  public-input opening. No baseline or initial-computation proof was benchmarked.
- Both measured proofs verified, and both serialized CBOR payloads were decoded
  using the existing proof-size helper and verified again.

## Reproduction and validation

`source-before.tar.gz` and `source-after.tar.gz` preserve the complete build
inputs for both versions. Extract each into a separate directory and run:

```sh
cargo build --offline --release --features parallel --example poseidon_piop_ab
DYNAMIC_SNARK_PROFILE=1 DYNAMIC_SNARK_TRACE_LOG=16 DYNAMIC_SNARK_CHANGED_GATES=1 \
  target/release/examples/poseidon_piop_ab
```

Build both versions first, then run their binaries sequentially. The locally
retained `before.bin` and `after.bin` are ignored by Git. Both use the same
unmodified benchmark harness and print the same protocol-family name; table
dimensions distinguish them.

Validation: **101 tests pass** (94 unit and 7 integration), including shared-bit
range failures, non-Boolean bits, unused high bits, equivalence with previous
routing on valid gate/public/padding rows, false-copy rejection after removing
the neighbor column, resource estimates against materialized tables, nonidentity
wiring, mixed updates, proof tampering, CBOR roundtrips, and thread determinism.
Sumcheck degree tests pass. Both retained noncompact configurations compile,
and formatting and whitespace checks pass.

- [Exact results, parameters, and archive/binary hashes](results.json)
- [Before stdout](before.stdout), [before phase log](before.stderr)
- [After stdout](after.stdout), [after phase log](after.stderr)
- [Unit tests](tests-unit.log), [integration tests](tests-integration.log)
- [After-source hash manifest](source-after.sha256)
- [Analysis script](analyze.py)
