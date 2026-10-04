# Dynamic SNARK with Ligerito and Poseidon2b

This is the implementation used by the current paper. It implements ordinary
arithmetic HyperPlonk, dynamic initialization, sparse updates, and a hierarchy
of retained transition proofs over GF(2^128). [Reproduction instructions](../../docs/reproduce.md)
cover the three final experiments: the update-size sweep, 10,000 one-gate updates,
and 1,000 128-gate updates. Recorded evidence is under [results/paper](../../results/paper/).

The crate depends on the sibling [Poseidon2b compression crate](../poseidon2b-compress-ligerito/)
and the shared [vendored Flock core](../../vendor/flock-core/UPSTREAM.md). Its standalone
Cargo lockfile pins the dependency resolution. Selected later exploratory reports are in [archive](../../archive/); obsolete
pre-Ligerito source is excluded from the publication tree.

The field is Flock's GHASH polynomial basis, with modulus
`X^128 + X^7 + X^2 + X + 1`. `field::F` forwards multiplication to Flock's `F128`;
integer constructors encode polynomial coefficients. `RUSTFLAGS='-C target-cpu=native'`
selects the native CPU kernels on supported ARM and x86 machines.

Merkle compression maps four GF(2^128) words to two words using
`first_two_words(P(x) + x)`. Poseidon2b uses width four, the x^7 S-box,
eight full rounds, and 58 partial rounds. Leaves encode `[value, index, 0, 0]`;
parents encode the two child digests. The surrounding relation authenticates
tree shape, coordinates, roots, and public inputs. The final experiments use
one committed checkpoint after round 33; the GKR batches two 33-round segments.
The API also supports three or seven checkpoints for historical comparisons.

The Ligerito configuration uses the Fast profile, JohnsonOod assumption,
rate 1/2, 64 initial lanes, SHA-256 Merkle commitments, and derived grinding.
The parameter target is 100 bits per PCS round. This target does not establish
100-bit aggregate security for the complete dynamic proof after combining all
components. Full-field challenges are uniform in GF(2^128), and the outer
transcript is BLAKE3. Small tables are padded to at least 8,192 field elements
for the selected PCS profile. No ring switching is used.

The current dynamic prover buffers sparse updates in a **non-hiding direct tail**.
The direct witness reveals update positions and old/new values; it authenticates
them with canonical Merkle boundaries and checks arithmetic and copy constraints.
When the serialized tail exceeds its cap, the accumulated transition is promoted
into the polynomial hierarchy and proved with Ligerito. Every retained transition
and the initial proof are included in the complete dynamic proof. The verifier
also limits plaintext to at most the other complete-proof bytes.

The library API defaults to a **64 KiB cap**. The paper experiments explicitly
select **2 MiB** with `--plaintext-kib 2048` and use a base-two hierarchy.
Use `dynamic::index_with_plaintext_cap` to configure matching prover/verifier keys;
a zero cap disables the direct path. The cap measures the entire serialized direct
witness, including headers and the new root. Promotions depend on actual path
sharing and wiring rather than a fixed revision count.

From the repository root, build and check the implementation with:

```sh
cargo +1.92.0 fetch --locked --manifest-path final/dynamic-ligerito/Cargo.toml
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --locked --release --offline \
  --manifest-path final/dynamic-ligerito/Cargo.toml --bin whole_system
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 test --locked --offline \
  --manifest-path final/dynamic-ligerito/Cargo.toml
python3 -m unittest discover -s final/dynamic-ligerito/scripts -p 'test_*.py'
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The `scripts/ec2_suite.py` driver runs the three experiments sequentially and
validates every measured proof. Its full defaults are 2^23 arithmetic gates,
256 public inputs, 32 workers, a 2 MiB direct-tail cap, and base-two hierarchy.
The sweep changes 1, 2, 4, 8, 16, 32, 64, and 128 gates, with 40 consecutive
revisions and a paired ordinary baseline for every revision. The one-gate
trajectory samples the baseline at revision 1, every 100 revisions, and the
final revision. The 128-gate trajectory samples every 10 revisions with both
endpoints retained. Sampled baseline totals are estimates; dynamic costs include
all measured updates and hierarchy promotions.

For a local check, use a fresh output directory and a memory cutoff suited to
the host (at most 90% of detected RAM/cgroup capacity):

```sh
python3 final/dynamic-ligerito/scripts/ec2_suite.py /tmp/dynamic-snark-smoke \
  --smoke --threads 2 --memory-limit-gib 4 --no-plot
```

The smoke suite uses 2^10 gates and shorter trajectories. It validates the workflow;
it does not reproduce the final paper's timing measurements. Full experiments
require the hardware and memory preparation in the reproduction guide.

`whole_system` verifies every measured proof and serializes, decodes, and reverifies
initialization, baseline snapshots, polynomial promotions, and first/final dynamic
proofs. Timers include witness generation and hierarchy work; setup/indexing,
verification, serialization, diagnostics, workload generation, and I/O are outside
prover timers. The amortization analysis also reports a setup-inclusive curve.

Completed trajectories can be reanalyzed without rerunning proofs:

```sh
python3 final/dynamic-ligerito/scripts/one_gate_amortization.py analyze \
  results/paper/one-gate/run-a --output /tmp/one-gate-analysis --no-plot
```

The analyzers stream either `samples.jsonl` or the publication copy
`samples.jsonl.gz`, reject incomplete/unverified runs, and retain every promotion
spike in the cumulative cost. Plotting requires matplotlib; measurement and
`--no-plot` analysis use Python's standard library.
