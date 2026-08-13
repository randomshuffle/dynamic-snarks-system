# Dynamic SNARK system

Rust implementation of the dynamic SNARK compiler from Section 4 of the
neighboring `dhbs` paper.

## Instantiation

- BN254 scalar field (`p3-bn254`), with a two-adic subgroup suitable for FFTs.
- Width-three Poseidon2 with a one-field-element, 32-byte digest and the
  Plonky3 BN254 128-bit parameter schedule (8 full and 56 partial rounds).
- A preprocessed multilinear static argument with gate selectors, a fixed
  wiring permutation product, and Fiat--Shamir sumchecks.
- Plonky3 WHIR at a configured 127-bit security target for every polynomial
  commitment and arbitrary-point opening.
- Position-bound Poseidon2 Merkle vector commitments for the Section 4 dynamic
  compiler.
- A Poseidon-specific commit-all-intermediate-rounds (CAIR) proof for the
  initial full-tree Merkle computation. Its terminal claims share one batched
  WHIR opening and are linked to the static proof's main commitment.
- A sparse-DAG CAIR proof for each transition. Transitions have no dense
  Plonkish trace or per-level key.

CAIR places every Merkle hash in a 1-indexed binary-heap row. It commits the
65 width-three Poseidon states (195 columns), combining the initial external
linear layer with the first full round. One degree-six sumcheck checks all 64
Poseidon transitions with Fiat--Shamir random linear-combination weights. A
second, degree-three sumcheck checks both child routes, leaf values, the
non-power-of-two leaf range, indices, and level domains. The verifier opens the
two child evaluations and the public root rather than scanning any row.

The static prover commits trace values directly as evaluations of multilinear
polynomials over the Boolean hypercube. CAIR therefore links its leaf-value
claim straight to one opening of the static main column; no inverse-Möbius,
bit-reversal, or FFT bridge is committed. All CAIR terminal claims use one WHIR
opening. Fiat--Shamir queries hash only commitments, public statement data, and
length-delimited raw sumcheck messages; earlier challenge outputs are
recomputed rather than reabsorbed.

The current CAIR implementation retains the committed tables and folded
sumcheck tables in memory. Disk-backed column streaming is a follow-up
engineering optimization; it does not change the proof object or verifier.

The dynamic prover maintains the paper's `ceil(log2(m + 1))` update tables.
Each transition privately commits one compact sparse-row table containing a
paired old/new assignment DAG, an indexed-permutation DAG, a new-assignment
neighbor DAG, update links, and affected gate triples. The old/new hashes are
packed into one 195-column Poseidon trace over a domain twice as large as the
sparse-row domain. Row-batched sumchecks check the local relation and all
Poseidon rounds. Routing tuples are algebraically derived from the committed
sparse row, so they require no duplicate columns. After the main commitment is
fixed, Fiat--Shamir derives the routing compression challenges and the prover
makes a small second commitment to all product-tree rounds. A third sumcheck
checks tuple compression and the entire product tree. Each commitment has one
batched WHIR opening. This two-phase ordering avoids committing to product
values before their Fiat--Shamir challenges exist. The verifier key retains
only `(n, n0, m)` and the fixed
permutation commitment. Public inputs are checked with a final Merkle
multiproof.

Execution is sequential by default. Polynomial loops are expressed as
independent column/row maps, and `--features parallel` enables the custom
Poseidon sumcheck pair reduction and the Plonky3/WHIR parallel backends.
The degree-six Poseidon messages use the dyadic points
`{0, 1, -1, 2, -2, 1/2, -1/2}`. Their seven affine values are fused per row
pair, and all seven fifth powers are derived together. Partial-round linear
layers are transposed into the constraint weights once, then the weighted
residual is assembled in coefficient form before evaluating all seven points.
Each folded table is halved in place for the next linear-time sumcheck round.

`dynamic::index` preprocesses only the initial relation. The compatibility
functions `preprocess_update_sizes` and `preprocess_all_levels` perform no
transition setup because sparse CAIR tables are derived from each update.

## Minimal use

```rust
use dynamic_snarks_system::{Field, circuit::Circuit, dynamic};
use p3_field::PrimeCharacteristicRing;

let circuit = Circuit::new(1, 1, (0..7).collect())?;
let assignment = [1, 2, 3, 3, 4, 12, 9]
    .map(Field::from_u64)
    .to_vec();
let (pk, vk) = dynamic::index(circuit)?;
let state = dynamic::initialize(&pk, assignment)?;
dynamic::verify(&vk, &[Field::from_u64(9)], state.proof())?;
# Ok::<(), dynamic::Error>(())
```

Updates are sorted `(position, value)` pairs. Updates touching a gate must
contain its complete three-wire tuple, as required by Section 4.

## Tests

```text
cargo test --offline
cargo check --features parallel --offline
```

The test profile enables optimized field arithmetic while retaining debug
assertions. The end-to-end test performs real Poseidon2-in-circuit and WHIR
proofs, so it takes substantially longer than ordinary unit tests.

## Benchmark

The end-to-end benchmark compares a dynamic update with an ordinary
from-scratch HyperPlonk-style proof of the updated arithmetic circuit. The
baseline binds the public-input suffix directly and contains no Merkle
commitment or CAIR proof. Both the dynamic and baseline proving keys are
preprocessed before the timers. By default the original HyperPlonk circuit has
exactly `2^16` arithmetic-gate rows. Internally the synthetic benchmark pairs
half addition rows with half multiplication rows. It uses `2^8` public inputs,
changes `2^4` and `2^8` arithmetic gates, and reports both the first-update
latency and the average over ten revisions:

```text
cargo bench --bench dynamic_snark --features parallel
```

Initial indexing happens before the timers; transitions require no
update-dependent preprocessing. Before allocating a proving key, the benchmark
prints the exact sparse row shape and conservative RAM peaks for the CAIR
initialization and sparse transition. Unsafe cases are skipped
unless `DYNAMIC_SNARK_FORCE=1` is set. The output also prints the original
trace, the reduced initial relation trace, and the number of Poseidon
permutations in each sparse transition DAG. Each
changed arithmetic gate contributes its complete three-position wire tuple,
and the ten revisions repeatedly change the same gate set. Environment
variables `DYNAMIC_SNARK_TRACE_LOG`, `DYNAMIC_SNARK_UPDATE_LOGS`, and
`DYNAMIC_SNARK_SEQUENCE_LEN` select smaller smoke-test configurations;
`DYNAMIC_SNARK_PREFLIGHT_ONLY=1` prints resource estimates without proving. The
benchmark skips a case when a projected RAM peak exceeds 70% of physical
memory;
`DYNAMIC_SNARK_FORCE=1` overrides this safety check.

The native hash microbenchmark compares one parameter-reused BN254 Poseidon2
permutation with SHA3-256 and BLAKE3 over the same prebuilt 72-byte logical
inputs. Each timed sample averages 100 hashes:

```text
cargo bench --bench hash_microbench
```

## Dependency compatibility

Plonky3 0.6.2 uses one unstable `MaybeUninit` helper in `p3-util` on stable
Rust 1.92. This repository vendors that crate and replaces only that call with
the equivalent stable `from_raw_parts` operation; all protocol crates remain
pinned to 0.6.2.
