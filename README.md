# Dynamic SNARK system

Rust implementation of the amortized dynamic SNARK compiler evaluated in the
accompanying paper. The system proves an initial computation, then maintains a
proof as gate assignments change. The experiment compares these updates with
recomputing a HyperPlonk proof from scratch.

## Implementation

The implementation uses the BN254 scalar field and Plonky3 0.6.2. Both the
dynamic SNARK and the HyperPlonk baseline use the same WHIR polynomial
commitment backend and field arithmetic.

- **Relation Merkle trees:** width-three Poseidon2, with 8 full rounds and
  56 partial rounds, and a one-field-element digest.
- **WHIR commitments and Fiat–Shamir:** BLAKE3 with 256-bit digests.
- **WHIR parameters:** folding four variables per round, corresponding to
  interleaving 16 in every round; Reed–Solomon rate 1/2 throughout; a 127-bit
  capacity-bound security target and no proof of work.
- **Parallelism:** Rayon, enabled with `--features parallel`, for the baseline,
  initialization, and updates.

The initial proof links the circuit assignment to its Poseidon2 Merkle tree.
Update proofs authenticate the affected paths and gate changes using compact
node and update tables. The Poseidon2 PIOP batches all 64 rounds and commits
only hash endpoints. The prover maintains the amortized hierarchy of transition
proofs and removes superseded levels after merges.

The library entry points are `dynamic::index`, `dynamic::initialize`,
`dynamic::update`, and `dynamic::verify`. Updates use sorted logical assignment
indices and include the complete three-wire tuple for every selected gate.
The default `compact-merkle` feature selects the implementation used in the
paper. Vendored dependency patches are selected by `Cargo.toml`.

## Paper experiment

The reported run used an AWS **i4i.24xlarge** with Intel Xeon Platinum 8375C
processors, 96 vCPUs (48 physical cores), and 768 GiB RAM. It ran Ubuntu 26.04
x86-64 and Rust 1.92.0, compiled in release mode with `-C target-cpu=native`.
The benchmark used **48 Rayon workers**, restricted to one logical CPU per
physical core across two sockets, with allocations interleaved across both
NUMA nodes.

The circuit contains **2^23 = 8,388,608 gates**, split equally between addition
and multiplication, with the identity wiring permutation and 256 fixed public
inputs. The experiment uses seed `20260909` and consists of:

1. One full initial dynamic computation.
2. Forty HyperPlonk baseline proofs, paired with the assignments from the
   one-gate update sequence and shared as the reference for all update sizes.
3. A separate sequence of **40 consecutive updates** for each gate count
   **1, 2, 4, 8, 16, 32, 64, and 128**. Every sequence starts from the same
   fully proved initial state.

Each revision samples distinct gates uniformly without replacement; a gate may
be selected again in a later revision. Each selected gate contributes all three
wire positions, so an update of `g` gates has `|U| = 3g`. The left input changes,
the right input stays at 2, and the output is recomputed. Public inputs remain
fixed. The experiment runs once, with no warmup runs or discarded samples.

All **361 proofs** were verified. The benchmark process completed in
**42.68 minutes**, with **424.55 GiB peak resident memory**. These resource
figures exclude dependency installation and compilation. The workload uses
identity wiring; it does not measure propagation through nontrivial wiring.

## Results

Each mean and maximum covers 40 proofs, except for the single initial
computation. Update prover time includes state maintenance and hierarchy
composition. Verification covers the entire retained dynamic proof.
Workload generation, circuit indexing, copying each starting state,
serialization, and file writes are outside the prover and verifier timers.

Proof size is the **field-and-hash payload**: 32 bytes for each field element
and each BLAKE3 digest, including commitments, sumcheck messages, evaluations,
and Merkle authentication data. It excludes indices, dimensions, and
serialization overhead. Update proof sizes include the initial proof and every
active transition proof. MiB denotes 2^20 bytes.

Prover speedup is the baseline mean prover time divided by the update mean
prover time, excluding initialization.

| Phase / gates updated | Prover mean (s) | Prover max (s) | Verifier mean (ms) | Verifier max (ms) | Proof mean (MiB) | Proof max (MiB) | Prover speedup |
|---|---:|---:|---:|---:|---:|---:|---:|
| HyperPlonk | 28.413 | 28.716 | 16.926 | 17.366 | 1.715 | 1.715 | 1.00× |
| Initial dynamic | 716.408 | — | 54.709 | — | 2.740 | — | — |
| Update 1 | 0.207 | 0.540 | 91.537 | 126.160 | 4.511 | 6.164 | 137.02× |
| Update 2 | 0.277 | 0.753 | 95.665 | 134.645 | 4.776 | 6.658 | 102.40× |
| Update 4 | 0.378 | 1.230 | 99.814 | 142.062 | 5.050 | 7.234 | 75.07× |
| Update 8 | 0.524 | 2.299 | 103.150 | 148.691 | 5.277 | 7.624 | 54.20× |
| Update 16 | 0.743 | 4.320 | 107.122 | 154.538 | 5.520 | 8.096 | 38.22× |
| Update 32 | 1.125 | 8.469 | 111.157 | 162.102 | 5.783 | 8.593 | 25.26× |
| Update 64 | 1.916 | 16.506 | 116.042 | 172.906 | 6.087 | 9.200 | 14.83× |
| Update 128 | 3.602 | 32.701 | 120.294 | 181.313 | 6.394 | 9.812 | 7.89× |

Including initialization, proving an entire 40-update sequence takes
12.08–14.34 minutes, depending on update size, compared with 18.94 minutes
for 40 baseline proofs: a 1.57×–1.32× speedup. The maximum update times occur
at revision 32, which triggers the largest merge in these sequences. The
largest retained proofs occur at revision 31, before superseded levels are
removed. Dynamic proofs are larger and require more verification time than
one baseline proof.

The [raw samples](benchmark-results/ec2-i4i-n23-20260917/full-n23-u128/samples.csv),
[timing comparison](benchmark-results/ec2-i4i-n23-20260917/full-n23-u128/comparison.csv), and
[proof-size measurements](benchmark-results/ec2-i4i-n23-20260917/full-n23-u128/proof-sizes.csv)
contain the underlying measurements. The
[complete result archive](benchmark-results/ec2-i4i-n23-20260917/full-n23-u128.tar.gz)
includes the configuration, sanitized source snapshot, logs, and proof checkpoints.

## Reproduce the experiment

Run the following from the repository root on an Ubuntu x86-64 host with
sufficient RAM. The reported configuration uses 768 GiB; the runner checks a
conservative memory estimate before proving.

Install the system dependencies and pinned Rust toolchain, fetch the locked
Cargo dependencies, and build the benchmark without running it:

```sh
bash scripts/bootstrap_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
unset DYNAMIC_SNARK_PROFILE DYNAMIC_SNARK_PROFILE_DETAIL

BENCH_RESULTS="$HOME/bench-results/paper-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BENCH_RESULTS"
python3 scripts/run_experiment.py --threads 48 --initial-interleaving 16 \
  --build-only --offline --output "$BENCH_RESULTS/build"
```

Run the full experiment once:

```sh
taskset -c 0-47 python3 scripts/run_experiment.py \
  --trace-log 23 --threads 48 --initial-interleaving 16 \
  --update-logs 0,1,2,3,4,5,6,7 --sequence-len 40 --seed 20260909 \
  --baseline-mode shared --offline --numa-interleave \
  --output "$BENCH_RESULTS/full-n23-u128"
```

CPUs `0-47` selected one logical CPU per physical core on the reported host.
Check `lscpu -e=CPU,CORE,SOCKET,NODE` and adjust the CPU list on a different
host. The runner sets the Rayon worker count from `--threads` and reuses the
release build. Every output directory must be new.

### Results and validation

The runner saves results incrementally in `$BENCH_RESULTS/full-n23-u128/`
and creates `$BENCH_RESULTS/full-n23-u128.tar.gz` on exit, including if the
run fails. Check the completion records before treating a run as complete:

```sh
jq -e '.state == "complete" and .exit_code == 0' \
  "$BENCH_RESULTS/full-n23-u128/status.json"
jq -e '.complete and .verified_samples == 361 and .proof_checkpoints == 10' \
  "$BENCH_RESULTS/full-n23-u128/validation.json"
(cd "$BENCH_RESULTS/full-n23-u128" && sha256sum -c SHA256SUMS)
```

| File | Contents |
|---|---|
| `samples.csv` | Per-proof prover time, verifier time, and proof-size measurements |
| `summary.csv`, `comparison.csv` | Timing aggregates and baseline speedups |
| `proof-sizes.csv`, `proof-size-comparison.csv` | Proof-size aggregates, including field-and-hash payload bytes |
| `proof-components.csv`, `proofs/` | Component sizes and ten saved proof checkpoints |
| `experiment.json`, `metadata.json`, `source.tar.gz` | Parameters, build/hardware metadata, and source snapshot |
| `run.log`, `resources.json` | Progress log, process duration, and peak resident memory |
| `status.json`, `validation.json`, `SHA256SUMS` | Completion, sample validation, and file checksums |

Copy the result archive to your machine using your SSH host and key. For
example, from a separate local shell, substitute your connection details and
the run directory printed by the runner:

```sh
scp -i /path/to/key.pem \
  ubuntu@YOUR_HOST:/home/ubuntu/bench-results/YOUR_RUN/full-n23-u128.tar.gz .
```

## Validation and anonymous publication

After fetching dependencies, the implementation and benchmark utilities can
be checked with:

```sh
cargo test --locked --offline --features parallel
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The source and result archives accompanying the paper have sanitized identity
metadata. New runs can record local paths, Git metadata, and archive ownership;
follow [the anonymous-publication notes](ANONYMITY.md) before sharing them.
