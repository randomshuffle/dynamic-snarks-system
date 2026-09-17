# Digest-only initial Merkle PIOP

Full initialization uses the endpoint GKR engine already used for sparse updates,
selected by the default `poseidon-gkr` feature. Its initial oracle contains only
the Merkle digest heap. The legacy scalar trace is available with
`--no-default-features`; `experimental-poseidon-gkr` is a compatibility alias.
The two initial PIOPs have separate proof representations and transcript domains.
Generate and verify with the same variant. Legacy proofs must be regenerated
for the new default.

The [matched initial-computation benchmark](../benchmark-results/2026-09-09-initial-endpoint-ab/README.md)
takes 20.695 s with this construction versus 31.633 s with the previous scalar
trace at `2^16` gates and eight workers. The complete field/hash proof payload
grows 1.36%; verification takes 34.83 ms versus 26.32 ms. Each is one observation.

## Oracles and identities

Let `K = 2^h` be the size of the physical, padded gate-order assignment table
`W`, already committed by the arithmetic proof. The protocol consumes that
complete power-of-two table, including padding; it does not consume an unpadded
logical assignment. The public root is `cm`.

Define `O[1..2K)` as the standard binary Merkle heap: root at one, children of
`i` at `2i` and `2i+1`, and leaves at `K..2K`. Set `O[0] = zeta`, where
`zeta = Poseidon2(0,0,0)[0]`. Commit the multilinear extension of `O`.
This oracle has `2K` field elements, versus `64 × 2K` in the scalar trace.

Coordinates are ordered least significant bit first. A hash point is `(u,b)`,
where `u` has `h` coordinates and `b` is the final, most significant coordinate.
Write `delta_0(u,b) = (1-b) product_j (1-u_j)` and
`index(u) = sum_j 2^j u_j`. The three input MLEs are exactly

```
X(u,b) = (1-b) O(0,u) + b W(u) - delta_0(u,b) zeta
Y(u,b) = (1-b) O(1,u) + b index(u) - delta_0(u,b) cm
D(u,b) = b + (1-b) sum_{j=0}^{h-1} (h+1-j) u_j product_{k=j+1}^{h-1}(1-u_k).
```

On internal heap rows these are the two child digests and the node's domain.
On leaf rows they are the assignment value, leaf index and domain one.
At row zero they are all zero. Every expression is multilinear, so the
identities hold at non-Boolean points as well as on the hypercube. The root
and dummy corrections are valid because both `O(1,0,...,0)=cm` and `O(0)=zeta`
are explicitly authenticated.

There are no input or intermediate-state columns in `O`, and no routing
sumcheck. The fixed heap layout supplies routing through these identities.

## Protocol

1. Commit `O` after the arithmetic commitment to `W`. Bind both commitments,
   `K`, and `cm` into the initial endpoint transcript.
2. Run the existing 64-round endpoint GKR reduction on `2K` hash instances,
   from a random evaluation of the digest output to three input evaluations.
   Each of the 64 degree-six sumchecks has `h+1` variable rounds.
3. Authenticate five evaluations of `O` in one batched WHIR opening: the
   output claim, two child restrictions at the final input point, root, and
   dummy. Obtain one evaluation of `W` at the final input point's `u` coordinates
   through the arithmetic proof's existing extra-opening interface.
4. Check the three input identities above, output equality, root, and dummy.
   Bind every GKR message into both opening transcripts.

The unchanged arithmetic proof enforces gates, wiring and assignment padding;
the initial Merkle proof authenticates the root of that same assignment.

## Implementation and validation

`src/cair/round_reduction.rs` implements the initial proof and verifier;
`src/poseidon_scalar/round_reduction.rs` is the unchanged 64-round hash engine.
Native digest construction processes each heap level in parallel. Its public
round constants, leaf domains, node domains and roots match the existing tree.

Tests compare the derived input MLEs against actual input tables at Boolean and
non-Boolean points, check native roots, reject altered statements and proofs,
and compare proof bytes on one/eight workers. Existing end-to-end tests include
nonidentity wiring and padded non-power-of-two circuit sizes. The benchmark
also verifies a CBOR round trip of each complete initial proof.

The hash engine still materializes all 65 width-three state layers transiently.
For `2^16` gates, that is 3.047 GiB of field storage, even though the new digest
oracle itself is only 16 MiB. This is an oracle-size reduction, not a claim
that transient witness memory is independent of the hash round count.

## Reproduction

```sh
cargo build --offline --release --example initial_poseidon_ab --no-default-features --features parallel
cp target/release/examples/initial_poseidon_ab /tmp/initial-poseidon-scalar-trace
cargo build --offline --release --example initial_poseidon_ab --features parallel
cp target/release/examples/initial_poseidon_ab /tmp/initial-poseidon-digest-gkr
DYNAMIC_SNARK_PROFILE=1 /tmp/initial-poseidon-scalar-trace
DYNAMIC_SNARK_PROFILE=1 /tmp/initial-poseidon-digest-gkr
```

The driver defaults to `2^16` gates and uses all logical CPU threads. Set
`DYNAMIC_SNARK_PREFLIGHT=1` to report shape without indexing or proving, or
`DYNAMIC_SNARK_TRACE_LOG` to change circuit size. WHIR retains the original
fixed half-rate schedule, folding parameter four and security parameter 127.
Each binary proves one complete initialization and separately times verification.
Indexing, input generation, serialization and destruction are outside the prover
timer. No standalone baseline proof or update is benchmarked.
