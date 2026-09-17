# Dynamic SNARK system

Rust implementation of the dynamic SNARK compiler from Section 4 of the
neighboring `dhbs` paper.

For the current 2^23-gate BN254 experiment on r5.24xlarge, with 16-way WHIR
interleaving, update sizes through 128 gates and 40 updates per size, including
prover/verifier time and proof-size means and maxima, see the
[current EC2 preparation guide](docs/ec2-r5-n23-20260916.md).

## Instantiation

- BN254 scalar field (`p3-bn254`), with a two-adic subgroup suitable for FFTs.
- Width-three Poseidon2 with a one-field-element, 32-byte digest and the
  Plonky3 BN254 128-bit parameter schedule (8 full and 56 partial rounds).
- The original HyperPlonk PIOP decomposition: a gate ZeroCheck and a wiring
  PermCheck reduced through ProductCheck and ZeroCheck to Fiat--Shamir
  sumchecks.
- Plonky3 WHIR at a configured 127-bit security target, folding factor four
  (16 field elements per queried leaf), rate-one-half Reed--Solomon codewords,
  and native BLAKE3 Merkle hashing and Fiat--Shamir for every polynomial
  commitment and arbitrary-point opening.
- Position-bound Poseidon2 Merkle vector commitments for the Section 4 dynamic
  compiler.
- A digest-only Merkle PIOP for initialization: one digest heap oracle,
  linked directly to the static proof's assignment commitment.
- A sparse endpoint PIOP for each transition, with a separate routing product
  argument. Transitions have no dense Plonkish trace or per-level key.

Both Merkle PIOPs use the same batched hash PIOP. It reduces all 64 Poseidon2
rounds with degree-six sumchecks, returning one output evaluation and three
input evaluations for the caller to authenticate. No intermediate hash states
are committed. Initialization derives the hash inputs from the fixed heap and
assignment layouts, so it needs no routing sumcheck. Its Merkle oracle has
`8N` field elements, and the verifier requests five digest evaluations plus one
evaluation of the existing assignment oracle.

The default `compact-merkle` feature enables `poseidon-gkr` and splits
transition nodes from update/gate records. Build with
`--no-default-features --features poseidon-gkr` for the previous combined
endpoint table, or `--no-default-features` for the legacy scalar trace;
`experimental-poseidon-gkr` remains a compatibility alias for `poseidon-gkr`.
The variants have different proof representations and transcripts. Generate and
verify proofs with the same variant; regenerate legacy proofs for the new default.

The static prover uses one row per actual gate rather than compiling copy
constraints or output comparisons into extra rows. Gate correctness is a
ZeroCheck. Wiring correctness is HyperPlonk's multiset PermCheck: one
`2N`-evaluation product oracle is constrained by a ZeroCheck and opened at its
root. Initialization and the ordinary baseline both use four columns: two
gate inputs, one gate output, and a public-input occurrence or zero. The
assignment Merkle tree commits directly to this row-major table. The Merkle
leaf-value claim is therefore one opening of the same main polynomial,
without a duplicate assignment view. All initial Merkle terminal claims use one WHIR
opening, alongside the linked assignment opening. Fiat--Shamir queries hash only commitments, public statement data,
and length-delimited raw sumcheck messages; earlier challenge outputs are
recomputed rather than reabsorbed.

Both arithmetic relations now have the same padded gate-row count `N` and
commit `4N` witness fields (`W`) and `4N` preprocessing fields (`P`). Public
inputs occupy column three, so the baseline adds no public-input rows. `P`
contains the original wiring conjugated by the logical-to-physical leaf map;
unused positions are fixed points. Gate selectors, zero-padding masks, and
identity labels are public formulas, and each preprocessing opening has four
claims. General gate programs retain committed local selectors/constants.
The original `2N` HyperPlonk product oracle is retained.

The update API still uses logical assignment indices. Assignment and wiring
trees, sparse transition constraints, and public-input openings all translate
them to physical leaf addresses. The compact update node table has 14 used
columns padded to 16; its row count depends on the authentication paths.
Update/gate records occupy a separate, smaller oracle. The previous combined
endpoint table used 64 columns for the benchmarked shapes. See the
[compact-layout comparison](benchmark-results/2026-09-11-compact-update-ab/README.md)
and the [assignment and preprocessing oracles](docs/aligned-oracles.md).
This changes the static/transition transcripts and vector-commitment encoding;
keys, roots, and proofs must be regenerated.

The hash prover materializes all 65 width-three state layers transiently.
The reduction in committed oracle size does not remove the round-count factor
from this working memory. Streaming or checkpointing these layers remains an
engineering optimization.

The dynamic prover maintains the paper's `ceil(log2(m + 1))` update tables.
Each transition privately commits a node table containing a paired old/new
assignment DAG, an indexed-permutation DAG, and a new-assignment neighbor DAG.
Its 14 columns are eight hash input/output fields, a row type, a tree identifier,
a level, a heap address, and two fields reused for boundary digests or a level
inverse. Three designated roots and authenticated child references imply valid
node levels and addresses; internal nodes satisfy `level * inverse = 1`.
The node table has `16R` committed fields. A separate table holds `k = |U|`
update links, `g` affected gate triples, and their index range witnesses, with
`S = next_pow2(max(2, k + g))` rows and `O(log N)` columns.
It uses `17 + max(b(n), b(n0))` fields per row before power-of-two padding,
where `b` is the range-bit count. Gate-pair and public-input indices share
one bit block; redundant index copies and the neighbor-value copy are derived.
For the 65,536-gate benchmark this is 32 columns, down from 45 padded to 64.
See the [matched one-gate comparison](benchmark-results/2026-09-15-update-table-32-ab/README.md).
This layout changes the compact transition transcript; update proofs must be
regenerated, while the indexed keys and Merkle roots are unchanged.
Two local sumchecks check these tables, and the shared hash PIOP checks both
hash lanes. After both commitments are fixed, Fiat--Shamir derives routing
compression challenges, and the prover commits the shared routing product
table. A further sumcheck binds its factors to both witness oracles and checks
the product tree. Each of the three commitments has one batched WHIR opening.
The verifier key retains only
`(n, n0, m)` and the fixed permutation commitment. Public inputs are checked
with a final Merkle multiproof.

Execution is sequential by default. `--features parallel` enables the same
Rayon backend for the baseline, full initialization, and updates. Custom
sumchecks split independent message evaluations and row pairs across the pool,
with reusable task scratch. Merkle levels, Poseidon trace rows, witness/table
preparation, product-oracle construction, folding, and independent final WHIR
openings also use the pool. Task sizes adapt to the worker count; no CPU model
or fixed eight-thread limit is assumed. Fiat–Shamir rounds and Merkle levels
retain their required dependency order. Set `RAYON_NUM_THREADS` when launching
the process; it does not enable parallelism in a binary built without the
`parallel` feature. The shared Plonky3 scheduling and STIR memory changes are documented in
[`vendor/p3-sumcheck/LOCAL_CHANGES.md`](vendor/p3-sumcheck/LOCAL_CHANGES.md).
The degree-six Poseidon messages use the dyadic points
`{0, 1, -1, 2, -2, 1/2, -1/2}`. Their seven affine values are fused per row
pair, and all seven fifth powers are derived together. Each folded table is halved in place for the next linear-time sumcheck round.

`dynamic::index` preprocesses only the initial relation. The compatibility
functions `preprocess_update_sizes` and `preprocess_all_levels` perform no
transition setup because sparse tables are derived from each update.

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
baseline binds the public inputs in column three and contains no Merkle
commitment or CAIR proof. Both the dynamic and baseline proving keys are
preprocessed before the timers. By default the original HyperPlonk circuit has
exactly `2^14` arithmetic-gate rows. Internally the synthetic benchmark pairs
half addition rows with half multiplication rows. It uses `2^8` public inputs,
changes `2^4` arithmetic gates, and reports both the first-update
latency and the average over ten revisions. Each revision samples a fresh
uniform gate subset without replacement, using seed `20260909` and identity
wiring:

```text
cargo bench --bench dynamic_snark --features parallel
```

Initial indexing happens before the timers; transitions require no
update-dependent preprocessing. By default the benchmark starts from a
trusted base commitment without materializing the initial proof;
`DYNAMIC_SNARK_TIME_FULL_INITIAL=1` generates, verifies, and separately times
the complete initial proof. Before allocating a proving key, the benchmark
prints the exact first-update sparse shape and a conservative bound obtained
from the final composed hierarchy supports. This also covers earlier
transitions merged into those supports. Unsafe cases are skipped
unless `DYNAMIC_SNARK_FORCE=1` is set. The output also prints the original
trace, the reduced initial relation trace, and the number of Poseidon
permutations in each sparse transition DAG. Each
changed arithmetic gate contributes its complete three-position wire tuple,
including its unchanged right input. Left inputs vary deterministically by
gate and revision, with outputs recomputed to satisfy the gate. Randomness
affects the selected positions. `DYNAMIC_SNARK_UPDATE_PATTERN=contiguous`
restores the old repeated-prefix workload; `random` is the default.
`DYNAMIC_SNARK_SEED` selects the RNG seed. Workloads are generated outside the
timers and their position fingerprints are logged; retain `Cargo.lock` when
reproducing the seeded `StdRng` stream. Environment
variables `DYNAMIC_SNARK_TRACE_LOG`, `DYNAMIC_SNARK_UPDATE_LOGS`, and
`DYNAMIC_SNARK_SEQUENCE_LEN` select smaller smoke-test configurations;
`DYNAMIC_SNARK_PREFLIGHT_ONLY=1` prints resource estimates without proving. The
benchmark skips a case when a projected RAM peak exceeds 70% of physical
memory;
`DYNAMIC_SNARK_FORCE=1` overrides this safety check.
`DYNAMIC_SNARK_UPDATE_ONLY=1` skips baseline setup/proving and suppresses the
full initial proof, using the trusted-base transition harness. Each updated
state is verified outside its timer. Logs include each revision's time,
cumulative distinct positions, and the actual composed transition's size,
hierarchy level, and oracle dimensions. Empty baseline CSV fields mean that
baseline proving was skipped.

```sh
DYNAMIC_SNARK_UPDATE_ONLY=1 DYNAMIC_SNARK_UPDATE_PATTERN=random \
DYNAMIC_SNARK_SEED=20260909 RAYON_NUM_THREADS=8 \
cargo bench --offline --bench dynamic_snark --features parallel
```

See [the random-update measurements](benchmark-results/random-updates.md) for
fresh random gate sets and [the aligned-layout benchmark results](benchmark-results/aligned-comparison.md)
for the previous repeated-contiguous workload and layout comparison.

For repeated first updates from an empty hierarchy, use the `first_update`
example with `DYNAMIC_SNARK_TRACE_LOG=16`, `DYNAMIC_SNARK_FIRST_KIND=leaf`
(or `gate`), and `DYNAMIC_SNARK_FIRST_SAMPLES=30`. Column-aware PCS evaluation
and shared-row equality weights reduce the measured single-leaf median from
122.5 ms to 77.7 ms with eight Rayon threads. See the
[matched comparison and reproduction commands](benchmark-results/opening-opts.md).

The subsequent shared parallelization improves the baseline, full initialization,
and first update together. At 65,536 gates and eight workers, their measured
times are 709 ms, 37.7 s, and 45.5 ms, respectively. See the
[parallel prover comparison](benchmark-results/parallel-provers.md) for matched
before/after measurements, one-worker controls, and 96-worker correctness checks.
The `prover_comparison` example measures all three operations with verified proofs.

Further recurrence-weight hoisting, a tighter local degree bound, and batched
terminal column evaluations bring the single-leaf first-update median to
29.7 ms at eight workers. See the [update optimization and current profile](benchmark-results/update-optimization.md).
The tighter bound shortens update sumcheck messages; update proofs from older
builds must be regenerated for the new verifier when that bound changes.

The `poseidon-gkr` implementation commits only hash endpoints
alongside sparse routing data and reduces all 64 Poseidon rounds with sumcheck.
See the [protocol and reproduction](docs/poseidon-endpoint-experiment.md) and
[one-gate, eight-thread A/B](benchmark-results/2026-09-09-poseidon-endpoint-ab/README.md).
Those measurements use the previous combined endpoint layout. Its main oracle
shrinks 4× in that experiment, while proving takes 1.71× longer;
the original scalar trace remains available with `--no-default-features`.
The same unmodified provers reach near parity for a 16-gate update, and the
endpoint prover takes 19.2% less time at 128 gates; see the
[larger-update comparison](benchmark-results/2026-09-09-poseidon-endpoint-scaling/README.md)
for verification time, proof sizes, memory estimates and the single-sample limits.
The default also selects a [digest-only initial PIOP](docs/initial-endpoint-experiment.md).
Its Merkle oracle is 64× smaller and the matched full initialization takes
20.695 s versus 31.633 s, with a 1.36% increase in the complete field/hash proof
payload; see the [initial-computation A/B](benchmark-results/2026-09-09-initial-endpoint-ab/README.md).

The native hash microbenchmark compares one parameter-reused BN254 Poseidon2
permutation with SHA3-256 and BLAKE3 over the same prebuilt 72-byte logical
inputs. Each timed sample averages 100 hashes:

```text
cargo bench --bench hash_microbench
```

The standalone WHIR microbenchmark commits a deterministic random
`2^18`-entry multilinear polynomial and opens it at one arbitrary point. It
sweeps folding factors 1, 2, 3, and 4 (Merkle leaf widths 2, 4, 8, and 16),
comparing fixed rate `1/2` with Plonky3's default WHIR rate reduction at each
factor. Both start at `1/2` and use the same 127-bit capacity-bound security
target and zero PoW. The default schedule halves the RS domain each round;
at factor four its code rates become `1/2, 1/16, 1/128, ...`. Production
continues to use fixed rate `1/2`.

Each arm has one warmup followed by five measured samples with alternating
arm order. All proofs are verified and their claimed evaluations compared.
The benchmark reports medians for commitment, point evaluation, proximity
proof generation, total opening, total prover (commitment plus opening), and
verification. It also counts the complete cryptographic proof payload:
32 bytes per BN254 field element or BLAKE3 digest, including every Merkle
path, intermediate commitment, OOD answer, sumcheck message, stored PoW
witness, and final-polynomial element. Container lengths and encoding tags
are excluded; the initial commitment's 32 bytes are reported separately.

```text
WHIR_MICROBENCH_FACTORS=4 RAYON_NUM_THREADS=8 \
  cargo bench --offline --bench whir_microbench --features parallel
```

`WHIR_MICROBENCH_LOG_SIZE`, `WHIR_MICROBENCH_FACTORS`,
`WHIR_MICROBENCH_SAMPLES`, `WHIR_MICROBENCH_WARMUPS`,
`WHIR_MICROBENCH_CLAIMS`, `WHIR_MICROBENCH_RATE_SCHEDULES` (`fixed,default`),
and `WHIR_MICROBENCH_FRESH_INSTANCE` override the defaults. Configuration
and polynomial construction/cloning are excluded from timers. FFT twiddles
are cached process-wide even when fresh instances are requested.
`WHIR_MICROBENCH_CSV` writes raw per-sample measurements to the specified
file. See [the rate-schedule A/B results](benchmark-results/whir-rate-ab.md)
for measurements and reproduction commands.

## Dependency compatibility

Plonky3 0.6.2 uses one unstable `MaybeUninit` helper in `p3-util` on stable
Rust 1.92. This repository vendors that crate and replaces only that call with
the equivalent stable `from_raw_parts` operation; all protocol crates remain
pinned to 0.6.2.
