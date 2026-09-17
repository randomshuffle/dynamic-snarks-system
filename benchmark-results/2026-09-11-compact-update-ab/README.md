# Compact partial-Merkle update: one-gate A/B

The compact construction reduces committed polynomial entries by 47.9% and the
full transmitted field/hash payload by 4.5%. In this single sample it takes 5.7%
longer to prove and 5.1% longer to verify. This is one measurement per variant,
not a statistical estimate of their relative speed.

| Metric | Previous endpoint PIOP (A) | Compact partial trees (B) |
|---|---:|---:|
| Update prover time | 56.810292 ms | 60.070875 ms |
| Verifier time | 20.895208 ms | 21.962875 ms |
| Full field/hash payload | 440,352 B (430.031 KiB) | 420,384 B (410.531 KiB) |
| Serialized CBOR | 584,059 B | 550,125 B |
| Field elements in proof | 10,610 | 10,419 |
| BLAKE3 hashes in proof | 3,151 | 2,718 |
| Main/node oracle | 128 × 64 = 8,192 fields | 128 × 16 = 2,048 fields |
| Separate update/gate oracle | — | 4 × 64 = 256 fields |
| Routing product oracle | 128 × 32 = 4,096 fields | 128 × 32 = 4,096 fields |
| Total committed oracle entries | 12,288 fields (384 KiB) | 6,400 fields (200 KiB) |
| Main/node WHIR evaluation requests | 112 | 32 |
| Update/gate WHIR evaluation requests | — | 90 |
| Routing-product evaluation requests | 58 | 58 |
| Outer sumcheck rounds | 526 | 528 |
| Node/local sumcheck degree | 8 | 8 |
| Update/gate local sumcheck degree | — | 6 |
| Routing-product sumcheck degree | 4 | 9 |
| Poseidon2 sumcheck degree | 6 | 6 |
| Conservative transition allocation estimate | 6,316,032 B | 4,841,472 B |

Both variants use the same 256 hash slots, of which 132 are non-boundary hashes,
and the same 64-round Poseidon2 reduction. Its transient state arrays have
49,920 field entries in both variants. Thus reducing the node commitment does
not remove the dominant hash computation. The compact protocol also has one
extra WHIR opening and a higher-degree routing sumcheck; the latter measured
approximately 5 ms versus 3 ms in the retained phase checkpoints. These facts
explain why a smaller commitment need not immediately yield a faster one-gate
proof; this experiment does not determine scaling at larger update sizes.

## Workload and timing

- Circuit: 65,536 gates (32,768 addition/multiplication pairs), 256 public
  inputs, identity wiring, BN254, height-18 gate-order Merkle trees.
- One update of one uniformly sampled gate without replacement; deterministic
  seed `20260909`, gate `36706`. All three wire positions are included (the right input remains 2), so
  `k = |U| = 3` and the number of touched gates is `g = 1`.
- Workload fingerprint:
  `42870fd8c258cad74cb75c40d187dccbed499b7748a0cf3d21de443ec4260692`.
- All 8 available CPU threads, release builds, parallel feature enabled, local
  Darwin 23.0.0 arm64 host. A and B were built before either timed run, then run
  sequentially with no compilation or tests running concurrently.
- Original WHIR parameters: fixed rate 1/2, folding factor 4 (16-fold), security
  target 127 bits, proof of work disabled. No `whir-initial-64` feature.
- Prover timing includes tree maintenance, hierarchy update proof, and final
  public-input opening. It excludes indexing, the natively checked trusted base,
  cloning, proof serialization, decoded-proof verification, and destruction.
- The transmitted payload includes hierarchy commitments, the update proof, and
  the public-input opening. The trusted initial computation is excluded. There
  was no baseline or initial-computation benchmark.
- Both original proofs and proofs decoded from the measured CBOR payload passed
  verification. CBOR decoding uses the existing byte-sequence normalization in
  `benches/support/proof_size.rs` required by WHIR's tagged Serde enum.
- Measured peak RSS is unavailable: `/usr/bin/time -l` could not query
  `kern.clockrate` inside the sandbox. This wrapper reports exit status 1 after
  the benchmark completes; both benchmark programs printed all measurements and
  successful verification results. Allocation numbers above are conservative
  transition estimates, not measured process RSS.

## Construction

B commits fourteen node columns padded to sixteen:
`(a_old,b_old,c_old,o_old,a_new,b_new,c_new,o_new,tau,tree,ell,J,q_old,q_new)`.
The first three rows are the assignment, permutation, and neighbor roots.
Root, internal, leaf, boundary, and padding are distinct scalar row tags.
The auxiliary fields carry boundary digests or an internal-level inverse.
Parent/child routing carries `(tree,ell,J,d_old,d_new)`; there are no per-node
level bits or separate position-within-layer labels. Paired assignment boundary
digests are equal, and the single permutation/neighbor hash lanes are equal.

The separate update/gate table has `S = next_power_of_two(max(2,k+g))` rows and
`next_power_of_two(22 + pair_bits + public_bits)` columns. It retains gate
constraints, update values, and range/mapping witnesses on the small domain.
Its update index is stored in physical gate order; the logical index is derived
from the gate-pair/role/offset or public-input index witnesses.

One shared product oracle covers both tables. For each lane it multiplies the
shifted node tuple and shifted update/gate tuple. Auxiliary columns are extended
by zeros from S to R; the verifier authenticates their low-coordinate opening
and multiplies it by the public zero-prefix selector. Node routing degree five
plus auxiliary routing degree three gives product degree eight, then the
sumcheck equality factor gives degree nine.

## Reproduce

The current default selects B. The previous endpoint implementation remains
available explicitly; it is distinct from the older scalar-Poseidon variant.

```sh
cargo build --release --no-default-features --features poseidon-gkr,parallel --example poseidon_piop_ab
cp target/release/examples/poseidon_piop_ab /tmp/compact-merkle-a
cargo build --release --features parallel --example poseidon_piop_ab
cp target/release/examples/poseidon_piop_ab /tmp/compact-merkle-b
DYNAMIC_SNARK_PROFILE=1 /tmp/compact-merkle-a
DYNAMIC_SNARK_PROFILE=1 /tmp/compact-merkle-b
```

An immutable A binary was saved before implementation edits. The measured A was
rebuilt using the same old prover with the common updated harness, which now
verifies decoded CBOR proofs and prints all oracle dimensions. The previous
`transition_cair/round_reduction.rs` is byte-for-byte unchanged; its parent
modules differ from their saved originals only by declarations of the new,
feature-gated compact modules. B and A share the Poseidon2 reduction engine.

Raw measurements: [A stdout](a.stdout), [A stderr](a.stderr),
[B stdout](b.stdout), [B stderr](b.stderr). Exact figures, percentage changes,
binary hashes, and settings are in [results.json](results.json). Source inputs
are hashed in [source-at-build.sha256](source-at-build.sha256). The current
[source.sha256](source.sha256) differs only by formatting the order of two module
declarations after measurement; the pre-edit source files are in
[source-a](source-a). Locally retained executable snapshots are ignored by Git.

Validation: 98 tests passed with the compact default, and 94 with the retained
endpoint variant. They cover end-to-end nonidentity wiring, mixed gate/public
updates, random workloads and hierarchy composition, CBOR roundtrips, identical
proof bytes with 1/8/96 workers, native root/level/index/boundary and leaf-linkage
attacks, proof/oracle/transcript tampering, and off-cube sumcheck degree bounds.
