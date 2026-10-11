# Dynamic SNARK system

Rust implementation accompanying **A Black-Box Compiler from Static to Dynamic
SNARKs**. This repository contains the evaluated amortized construction. The
system proves an initial computation, then maintains a
proof as gate assignments change. We compare dynamic updates with recomputing
an ordinary HyperPlonk proof from scratch in three experiments: an update-size
sweep, 10,000 one-gate updates, and 1,000 128-gate updates.

## Implementation

The evaluated implementation is in
[`final/dynamic-ligerito`](final/dynamic-ligerito/). It uses
**GF(2^128)** arithmetic from the vendored `flock-core`, with hardware-accelerated
carry-less multiplication, and **Ligerito** for multilinear polynomial commitments.
The dynamic system and HyperPlonk baseline share the same field and PCS backend.
The baseline proves circuit constraints and public inputs; dynamic initialization
also proves consistency with the assignment Merkle tree.
The paper uses TensorSwitch for its asymptotic instantiation and Ligerito for
the evaluated implementation in this repository.

- **Ligerito parameters:** Fast profile, rate-1/2 encodings, and a 100-bit
  per-round target in the Johnson-bound regime with out-of-domain sampling.
- **PCS commitments and Fiat–Shamir:** SHA-256 for Ligerito's Merkle commitments
  and internal transcript; BLAKE3 for the surrounding PIOP transcripts.
- **Relation Merkle trees:** 64-byte-to-32-byte **Poseidon2b** compression over
  four binary-field words, with 8 full rounds, 58 partial rounds, and an `x^7`
  S-box. Compression returns the first two words of `P(x) + x`. Leaves encode
  `[value, index, 0, 0]`; internal nodes encode their two two-word child digests.
- **Hash proofs:** one committed four-word checkpoint after round 33, batching
  two 33-round GKR segments with the factored kernel.
- **Update hierarchy:** base 2, with a **2 MiB direct-tail cap** in the paper
  experiments. Rayon parallelism is used throughout.

The 100-bit target applies to each PCS round; it is not an aggregate security
claim for the complete dynamic proof.

Small updates accumulate in a single direct tail containing updated indices,
old/new values, wiring information, and shared Merkle openings. The verifier
checks this tail directly. When its serialized size exceeds the cap, the prover
creates a polynomial update proof with Ligerito, inserts it into the hierarchy,
and performs the required merges. This is a **SNARK promotion**. The tail then
resets, and superseded hierarchy proofs are removed after composition.

The library entry points are `dynamic::index`, `dynamic::initialize`,
`dynamic::update`, and `dynamic::verify`; `index_with_plaintext_cap` configures
the direct-tail budget. The library defaults to 64 KiB; the paper suite explicitly
selects 2 MiB. Updates use sorted logical assignment indices and the
complete three-wire tuple for each selected gate. The evaluated implementation
does not implement the paper's zero-knowledge compiler modifications; the direct
tail exposes its indices and values.

The current source is under [`final/`](final/), its recorded measurements are
under [`results/paper/`](results/paper/), and vendored Flock arithmetic is under
[`vendor/flock-core`](vendor/flock-core/). Earlier Ligerito investigations are summarized under [`archive/`](archive/).
Each retained historical experiment has a short `EXPERIMENT.md` describing its
purpose and selected summaries. Pre-Ligerito implementations and results, bulk
proof checkpoints, duplicate logs, and transferred bundles have been removed.
Hash parameters and reference tests are in
[`final/poseidon2b-compress-ligerito`](final/poseidon2b-compress-ligerito/).

## Three paper experiments

The reported experiments used an AWS **r7a.8xlarge** with an **AMD EPYC 9R14**
processor, 32 physical cores / 32 vCPUs, and **256 GiB RAM**, running Ubuntu 24.04
x86-64. The code was compiled with Rust 1.92.0 in release mode and
`-C target-cpu=native`, using **32 Rayon workers**.

The circuit contains **2^23 = 8,388,608 gates**, split equally between addition
and multiplication, with identity wiring and **256 fixed public inputs**. All
three experiments use seed `20260909` and run sequentially, each with a separate
full dynamic initialization.

| Experiment | Gates per update | Consecutive updates | HyperPlonk baseline schedule | Verified proofs |
|---|---|---:|---|---:|
| Update-size sweep | 1, 2, 4, 8, 16, 32, 64, 128 | 40 per size | Fresh paired proof at every revision and size | 641 |
| One-gate amortization | 1 | 10,000 | Revision 1 and every 100 revisions through 10,000 | 10,102 |
| 128-gate amortization | 128 | 1,000 | Revision 1 and every 10 revisions through 1,000 | 1,102 |

The sweep starts each update-size trajectory from a copy of the same fully
proved initial state. Every revision samples distinct gates uniformly without
replacement; a gate may recur in later revisions. Each selected gate contributes
all three wire positions, so an update of `g` gates has `|U| = 3g`. Public inputs
remain fixed. The execution order of sampled baseline/update pairs alternates.
There are no discarded warmups.

All **11,845 measured proofs were verified**, including three initial proofs,
11,320 dynamic updates, and 522 baseline proofs. Every dynamic update is measured,
including all promotions and hierarchy merges. Initialization, baseline snapshots,
promotions, and the first/final dynamic proofs also undergo serialization round
trips and re-verification. Maximum benchmark resident memory was **135.696 GiB**,
covering the benchmark process but excluding compilation and other processes.
The identity-wiring workload does not measure propagation through nontrivial wiring.

## Results

Prover timers include witness construction, state maintenance, and hierarchy
composition. Indexing, verification, serialization, statistics collection,
workload generation, and I/O are outside these timers. Verification checks the
complete retained dynamic proof.

Proof size is the **complete `bincode` serialization**, including field elements,
hashes, indices, dimensions, and container overhead. Field elements occupy
16 bytes and hashes occupy 32 bytes. Dynamic update sizes include the initial
proof, all retained polynomial transition proofs, the direct tail, and the
current public-input opening. MiB denotes 2^20 bytes.

### Update-size sweep

Each update row summarizes 40 proofs. The HyperPlonk row aggregates all 320
paired baseline proofs; each update speedup uses its own 40 paired baseline
samples. Speedups exclude initialization. Values are rounded as in the paper.

| Phase / gates updated | Prover mean (ms) | Prover max (ms) | Verifier mean (ms) | Verifier max (ms) | Proof mean (MiB) | Proof max (MiB) | Prover speedup |
|---|---:|---:|---:|---:|---:|---:|---:|
| HyperPlonk | 7,970 | 8,560 | 4.70 | 4.88 | 1.22 | 1.22 | 1.00× |
| Initial dynamic | 310,000 | — | 13.5 | — | 2.28 | — | — |
| Update 1 | 0.39 | 0.56 | 15.4 | 17.4 | 2.31 | 2.33 | 20,500× |
| Update 2 | 1.27 | 1.74 | 17.3 | 21.2 | 2.33 | 2.38 | 6,300× |
| Update 4 | 2.15 | 2.58 | 21.1 | 28.3 | 2.38 | 2.46 | 3,690× |
| Update 8 | 3.10 | 3.71 | 28.3 | 41.7 | 2.46 | 2.61 | 2,570× |
| Update 16 | 3.84 | 4.90 | 42.1 | 67.9 | 2.62 | 2.91 | 2,070× |
| Update 32 | 4.03 | 6.24 | 68.6 | 118 | 2.91 | 3.46 | 1,980× |
| Update 64 | 66.5 | 2,430 | 101 | 193 | 3.41 | 4.27 | 120× |
| Update 128 | 190 | 4,850 | 107 | 202 | 4.09 | 5.73 | 41.8× |

The 1–32-gate trajectories remain within the direct-tail budget for all 40
revisions. The 64-gate trajectory promotes at revision 37, and the 128-gate
trajectory promotes at revisions 19 and 38. These promotions explain the larger
maximum prover times. Dynamic proofs are larger and require more verification
time than an ordinary baseline proof.

### One-gate and 128-gate amortization

The long sequences include the full initialization cost and every update,
promotion, and merge. Each sequence measures **101 fresh baseline proofs** from
its own trajectory. At prefix `n`, cumulative prover speedup is:

```text
speedup(n) = n * mean(sampled baseline prover time)
             / (initial dynamic prover time + sum(update prover times 1..n))
```

Baseline totals are estimated from the sampled mean; every dynamic timing is
measured. The baseline is charged for proving each updated state, with no extra
initial-state proof. A second plotted curve adds measured indexing once to each
side. Both curves exclude verification and I/O.

| Metric | One-gate updates | 128-gate updates |
|---|---:|---:|
| Consecutive updates | 10,000 | 1,000 |
| Initialization (s) | 311 | 310 |
| Total update proving time (s) | 232 | 358 |
| Mean update prover time (ms) | 23.2 | 358 |
| Amortized prover time including initialization (ms/update) | 54.3 | 668 |
| Mean sampled baseline prover time (s) | 8.01 | 7.80 |
| Final speedup including initialization | 147× | 11.7× |
| Final speedup including initialization and indexing | 144× | 11.5× |
| First and sustained break-even revision | 39 | 41 |
| SNARK promotions | 4 | 52 |
| Final dynamic proof size (MiB) | 4.63 | 9.35 |
| Final baseline proof size (MiB) | 1.22 | 1.21 |
| Final dynamic verifier time (ms) | 84.9 | 211 |
| Final baseline verifier time (ms) | 4.84 | 5.19 |

Proof sizes and verifier times in this table are measurements at the final
revision, rather than means over the sequence.

The final speedup is also the maximum observed in each measured sequence.
These are single-run observations over the stated windows. The one-gate run
first promotes at revision 2,317; the larger-update run includes 52 promotions,
so its average reflects repeated polynomial proving and hierarchy composition.

The [complete result report](results/paper/README.md)
links the raw evidence and audit. The paper's underlying measurements and plots are:

- **Sweep:** [comparison CSV](results/paper/sweep/comparison.csv),
  [validation](results/paper/sweep/validation.json),
  and [plot](results/paper/sweep/sweep.png).
- **One gate:** [result report](results/paper/one-gate/README.md),
  [all prefixes](results/paper/one-gate/curve.csv),
  and [speedup plot](results/paper/one-gate/speedup.png).
- **128 gates:** [result report](results/paper/128-gate/README.md),
  [all prefixes](results/paper/128-gate/curve.csv),
  and [speedup plot](results/paper/128-gate/speedup.png).

## Reproduce the experiments

Run from the repository root on an Ubuntu x86-64 host with at least 240 GiB of
usable RAM and swap disabled. The reported host has 256 GiB. The suite checks
memory estimates and available RAM before running, and uses a 216 GiB RSS cutoff.

Install system dependencies, Rust 1.92.0, and locked Cargo dependencies, then
build the Ligerito benchmark without running it:

```sh
bash scripts/bootstrap_ligerito_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'

BENCH_RESULTS="$HOME/bench-results/paper-ligerito-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BENCH_RESULTS"
```

An optional short rehearsal uses 2^10 gates and a 64 KiB tail to exercise
promotions. It produces **777 verified samples**:

```sh
python3 final/dynamic-ligerito/scripts/ec2_suite.py \
  "$BENCH_RESULTS/rehearsal" --smoke --threads 32 --memory-limit-gib 16
```

Run the full three-experiment suite once:

```sh
python3 final/dynamic-ligerito/scripts/ec2_suite.py \
  "$BENCH_RESULTS/measurements" \
  --trace-log 23 --threads 32 --memory-limit-gib 216 --hierarchy-base 2
```

The suite selects the 2 MiB tail, one checkpoint, factored kernel, seed,
revision counts, and baseline schedules described above. Each output directory
must be new. For source packaging, native memory calibration, and result
archiving, see the [EC2 suite guide](docs/reproduce.md).

### Results and validation

Check completion before treating a run as complete:

```sh
jq -e '.status == "complete" and .verified_samples == 11845' \
  "$BENCH_RESULTS/measurements/status.json"
jq -e '.complete and .verified_samples == 641' \
  "$BENCH_RESULTS/measurements/sweep/validation.json"
jq -e '.verified_samples == 10102' \
  "$BENCH_RESULTS/measurements/one-gate/summary.json"
jq -e '.verified_samples == 1102' \
  "$BENCH_RESULTS/measurements/128-gate/summary.json"
```

| File / directory | Contents |
|---|---|
| `suite-config.json`, `memory-plan.json`, `whole-system` | Suite parameters, memory plan, and frozen benchmark binary |
| `status.json` | Suite completion and total verified sample count |
| `sweep/comparison.csv`, `sweep/validation.json` | Sweep aggregates, paired speedups, and completeness checks |
| `one-gate/curve.csv`, `128-gate/curve.csv` | Cumulative timings and speedups at every integer prefix |
| `one-gate/summary.json`, `128-gate/summary.json` | Long-sequence maxima, break-even points, promotions, and metadata |
| Each stage's `run-a/` | Raw `samples.jsonl`, configuration, setup costs, logs, checkpoints, and memory samples |
| `sweep/sweep.*`, each long stage's `speedup.*` | PNG, SVG, and PDF plots |

Completed stages can be validated and reused by repeating the suite command
with `--resume`. A partially completed update trajectory must restart from its
initial state.

## Implementation checks and publication

After the bootstrap, check the evaluated Rust implementation and benchmark
utilities with:

```sh
RAYON_NUM_THREADS=8 cargo +1.92.0 test --locked --release --offline \
  --manifest-path final/dynamic-ligerito/Cargo.toml
python3 -m unittest discover -s final/dynamic-ligerito/scripts -p 'test_*.py'
```

The Rust command uses the native CPU flags exported above. The saved paper
measurements can be checked independently without rebuilding the prover:

```sh
python3 results/paper/verify.py
```

See [publication notes](PUBLICATION.md) for generating a clean public snapshot,
licenses, and the distinction between recorded execution provenance and the
reorganized source tree.
The existing development history retains historical metadata and result archives;
publish the generated snapshot with fresh Git history as described there.
