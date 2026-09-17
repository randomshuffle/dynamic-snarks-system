# Previous combined sparse-update endpoint PIOP

This document describes the combined endpoint table used before `compact-merkle`.
Select it with `--no-default-features --features poseidon-gkr`.
The current default separates node and update/gate records; see the
[compact-layout comparison](../benchmark-results/2026-09-11-compact-update-ab/README.md).
The legacy scalar trace is available with `--no-default-features`; the former
`experimental-poseidon-gkr` feature is a compatibility alias. Both use the same Poseidon2 constants,
local sparse relation, routing product argument, Fiat–Shamir construction,
and WHIR parameters. The endpoint PIOP has a separate transcript domain/version
and transition proof representation. Generate and verify with the same features.
The feature also selects the [digest-only initial PIOP](initial-endpoint-experiment.md),
which derives hash inputs from the fixed heap layout and needs no routing sumcheck.

## Committed tables

Let `R` be the power-of-two padded sparse-row count, and `c` the number of
compact routing-witness columns. Every sparse row has an old and a new hash,
including dummy hashes on rows that do not need an active computation.

The legacy main table has `2R` rows and `next_pow2(c + 65)` columns.
Its first `c` columns hold routing data in the first `R` rows and zero thereafter;
64 columns hold the scalar Poseidon trace, and one holds the third input.

The combined endpoint table `A` has `R` rows and `next_pow2(c + 8)` columns:

| Columns | Meaning at sparse row `i` |
|---|---|
| 0–3 | Old hash input `x`, input `y`, domain `d`, digest `h` |
| 4–7 | New hash input `x`, input `y`, domain `d`, digest `h` |
| 8–`c+7` | The existing compact routing witness |
| Remaining | Zero padding |

The prover commits the multilinear extension of this entire table. After
routing challenges, it also commits the unchanged product table, with `R` rows
and `next_pow2(14 + 2 log2 R)` columns. Local and product sumchecks are unchanged.
There is no committed intermediate Poseidon state in `A`.

## Hash reduction

Number hash slots `2i + b`, with `b = 0` for old and `b = 1` for new.
Let `v = log2(2R)`. Let `S_j` be the three-coordinate multilinear extension of
the states before round `j`, where `S_0` denotes hash inputs. There are 64 round
maps `F_j` for `j=0,...,63`; the first includes Poseidon2's initial external linear layer.
Every `F_j` has degree five.

The verifier samples `t` and obtains a claimed digest evaluation `h(t)`.
Starting with coordinate weights `(1,0,0)`, a degree-six sumcheck establishes

```
claimed output = sum_{x in {0,1}^v} eq(t,x) * <weights, F_j(S_j(x))>.
```

Here `eq(t,x) = product_k [t_k x_k + (1-t_k)(1-x_k)]` and `<.,.>` is the
three-coordinate dot product. Each sumcheck has `v` rounds and seven field
evaluations per round. At its terminal point `q`, the prover sends the three
input-state evaluations. The verifier checks the resulting terminal identity.
After absorbing those values, it samples fresh coordinate weights and reduces
the resulting claim through the preceding Poseidon round. Repeat through all
64 rounds, finishing with three evaluations of the original hash inputs.

The initial digest evaluation and three final input evaluations are authenticated
against `A`. For a hash point `(b,u)`, the field-`f` query uses low column bits
`(bit_0(f), bit_1(f), b)`, all higher column bits zero, and row point `u`.
Thus each endpoint needs one oracle query, even when `b` is non-Boolean.
The local checks connect these same endpoints to the sparse Merkle routing data
and public roots. The unchanged routing argument enforces consistent edges.

Both commitments have one batched WHIR opening. The main opening has `2c+12`
queries: `c+8` for local checks, `c` for routing, and four for hash endpoints.
The opening transcript binds both commitments and every sumcheck and boundary
message. Hash inputs and outputs are committed before any reduction challenge.

The committed hash witness loses its factor proportional to the round count.
The cost moves into `64v` sumcheck rounds and their messages. The implementation
still materializes 65 width-three state layers transiently; it does **not**
claim a corresponding reduction in prover witness RAM. Sparse routing metadata
is retained, so the dense-initial-proof digest-only table reduction does not
apply directly to the total sparse-update oracle size.

## Reproduction

Build both binaries before timing, then run them sequentially:

```sh
cargo build --offline --release --example poseidon_piop_ab --no-default-features --features parallel
cp target/release/examples/poseidon_piop_ab /tmp/poseidon-piop-scalar-trace
cargo build --offline --release --example poseidon_piop_ab --no-default-features --features poseidon-gkr,parallel
cp target/release/examples/poseidon_piop_ab /tmp/poseidon-piop-endpoint-gkr
/tmp/poseidon-piop-scalar-trace
/tmp/poseidon-piop-endpoint-gkr
```

Set `DYNAMIC_SNARK_CHANGED_GATES=16` or `128` on each invocation to compare
one update containing that many random gates. The default remains one gate.
Set `DYNAMIC_SNARK_PREFLIGHT=1` to print the exact workload, table dimensions,
and conservative transition-memory estimate without indexing or proving.

The driver uses every logical CPU reported by Rust, identical identity-wired
circuits of `2^16` gates, 256 public inputs, and a random gate set selected with
seed `20260909`. It submits each complete three-wire gate tuple; the right input
remains two and the other two values change. Exactly one update is timed per
variant, starting from a trusted base with no previous updates. No baseline
SNARK or initial-computation proof is benchmarked. Indexing, base construction,
serialization, and destruction are excluded. Update timing includes tree
maintenance and the public-input opening; verifier timing is separate.

The driver reports both complete CBOR bytes and the field/hash payload at
32 bytes per field element or BLAKE3 digest. These include hierarchy roots,
the transition proof, and the final public-input opening, excluding an initial
proof. CBOR overhead includes its array encoding of BLAKE3 digests.
One observation per variant is a smoke comparison, not a timing distribution.

The [recorded eight-thread A/B](../benchmark-results/2026-09-09-poseidon-endpoint-ab/README.md)
has a 4× smaller main oracle, but 1.71× slower proving and a 6.91% larger
field/hash proof payload. Complete CBOR sizes are nearly equal.

The [16- and 128-gate comparison](../benchmark-results/2026-09-09-poseidon-endpoint-scaling/README.md)
shows a better prover tradeoff at larger update sizes: near parity at 16 gates
and 19.2% less prover time at 128 gates in the recorded single observations.
Verification remains slower and the field/hash payload is about 10% larger.

Validation covers native Poseidon equivalence, all round-message kernels,
tampered round and boundary messages, statement/root binding, opening tampering,
JSON proof round trips, and byte-identical transition proofs on one/eight threads.
The existing unit and end-to-end suites exercise both selected transition PIOPs.
