# BN254 experiment on EC2

> Current launch recipe: [forty-revision experiment guide](ec2-readiness-20260914.md).
> It uses the compact partial-Merkle default, explicitly selects 16-way first
> interleaving, and supersedes the older source archives, 64-way commands and
> 1,788 GiB planning figure and twelve-revision statistics retained below.

This guide runs the exact source tree transferred from your Mac. The experiment
changes may not yet be on GitHub, so cloning `main` alone is insufficient.

The latest [2^17 local run through 64-gate updates](../benchmark-results/endpoint-n17-u64-i16-20260910/README.md)
completed with the current endpoint PIOPs and 16-way folding throughout. It
includes timings, complete proof sizes and measured macOS peak RSS.

A [subsequent 2^18 monitored local run](../benchmark-results/endpoint-n18-u64-i16-20260910/README.md)
completed the same sweep. Its measured footprint was 13.303 GiB versus 3.272 GiB
RSS; use the footprint result when assessing the previous 8 GB memory target.

The [completed local 2^15 proof-size sweep](ec2-proof-size-results.md) includes
both prover times and complete proof-size comparisons through 128 updated gates.
The [prepared source archive with proof-size recording](../benchmark-results/ec2-experiment-source-with-proof-sizes-20260909.tar.gz)
includes these changes; earlier source archives do not.

The saved source archives and historical memory/FFT figures below describe the
legacy scalar-trace PIOP. Current source builds select endpoint GKR for initial
and update proofs and record `merkle_piop` in `experiment.json`. Its initial
oracle has one digest column instead of 64; the runner accounts for its 195
transient state fields per hash in preflight. Rerun preflight from the exact
source snapshot before using the historical resource plan. The workload and
WHIR settings described below are unchanged.

For current endpoint-GKR estimates and 16-way first interleaving, see the
[September 10 memory plan](endpoint-memory-plan.md). The runner accepts
`--initial-interleaving 16`; the commands below retain their earlier 64-way
default. The current 2^20 full-sweep estimate is 68.19 GiB, and the current
2^24 estimate is 936 GiB. These are planning estimates, not measured peaks.

## Experiment specification

| Setting | Value |
| --- | --- |
| Circuit | 2^24 = 16,777,216 gate rows; alternating addition/multiplication |
| Public inputs | 256, each equal to 9 |
| Wiring | Identity permutation |
| Field | BN254 scalar field, 32 bytes per field element |
| WHIR | 64-way first interleaving, 16-way subsequent folding; rate 1/2 each round |
| Protocol parameters | Existing 127-bit security target, capacity-bound assumption, zero proof-of-work bits |
| Initial computation | One complete `dynamic::initialize`, verified once |
| Update sizes | 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1,024 gates |
| Sequence | 12 consecutive updates per size; each size resets to the shared initial state |
| Randomness | Seed 20260909; fresh uniform gate subset without replacement per revision |
| Baseline | 12 full regular HyperPlonk proofs paired with the one-gate sequence, shared as the reference for all sizes |
| Measurements | 1 initial + 132 dynamic updates + 12 baseline proofs = 145 verified timing records |
| Proof sizes | Full proof at every measurement; baseline mean, full initial proof, and final proof after revision 12 for each update size |

Gate positions are random; values are deterministic, revision-dependent valid
gate assignments. Gates may recur across revisions. Each selected gate supplies
its full three-wire tuple; the right input remains 2 while the left input and
output change. This satisfies the updater's gate-closure requirement. The full
workload, including values, is saved. Updating the public inputs is excluded.

Indexing for baseline and dynamic keys is measured separately in `setup.csv`,
once each. Initial proving includes the complete initial proof, without a trusted
initialization shortcut. Baseline proving includes constructing its constraint
program. Dynamic proving includes the actual production update, including any
hierarchy composition. Verification is timed separately for every proof.
Case-reset clones and external witness bookkeeping are outside proving timers.
Where baseline proofs are measured, the runner alternates baseline/update order across revisions. There are no
discarded warmups: the average contains exactly revisions 1 through 12. The first
update timing is also reported separately because composition costs vary by
revision. These are sequence averages, not confidence intervals from independent
whole-experiment repetitions.

To shorten the run, `--baseline-mode shared` generates baseline proofs only for
the first listed update size (normally one gate), and reuses their mean as the
reference for every size. This gives **145 samples**: one initial, 12 baseline
and 132 updates, with **13 summary groups**. Those baseline proofs use the first
case's twelve witnesses, not the other cases' witnesses. `baseline.json` records
this distinction. `--baseline-mode paired` retains all 265 samples. The default and commands below
use `shared` to reduce rental time. Select `paired` when a witness-by-witness
baseline comparison is desired.

The benchmark target requires `parallel`. The runner enables `whir-initial-64`
for `--initial-interleaving 64` (the default) and omits it for
`--initial-interleaving 16`. Generate and verify experiment proofs with the same
feature set. The feature changes the first round for all production PCS calls,
including baseline, initial proof and updates, making the comparison consistent.

## Proof-size convention

Proof-size recording is automatic for both `--trace-log 15` and `--trace-log 24`.
The same run commands below now produce two distinct size measurements:

- **Cryptographic payload bytes:** 32 times the number of BN254 elements plus
  32 times the number of BLAKE3 digests. This includes sumcheck messages, claimed
  evaluations, opened leaves, OOD answers, final polynomials, stored PoW values,
  commitments and all Merkle authentication hashes. Poseidon roots and sibling
  digests are BN254 elements and are included once in the field count.
- **Serialized proof bytes:** the exact length of the complete uncompressed
  CBOR file, using pinned `ciborium` 0.2.2 and the existing Serde proof types.
  This also includes indices, dimensions, tags, lengths and field names. The
  current field serialization uses 32 Montgomery bytes per BN254 value. CBOR
  adds framing, and Serde's BLAKE3 byte arrays also have CBOR array/integer
  overhead. This is a concrete storage format, not a minimized protocol encoding.

[Ciborium encoding documentation](https://docs.rs/ciborium/0.2.2/ciborium/)

The dynamic size at revision 12 measures the **entire retained verifier proof**:
initial HyperPlonk proof, initial Merkle CAIR, all active transition proofs,
hierarchy commitments, and the public-input Merkle multiproof. The separately
supplied public-input vector, verification key, witness and retained prover trees
are outside the proof-size scope. `proof-components.csv` breaks down the complete
proof by its top-level components; their byte counts sum to the full file size.

Serialization and size accounting happen after each prover/verification timer
stops. Initial and final-revision proofs are also decoded and verified again
before being saved to `proofs/*.cbor`. These extra checks are outside the reported
prover and verifier times. Total process wall time and peak RSS include accounting,
serialization and these additional verification checks. The benchmark helper
`benches/support/proof_size.rs` supplies the compatible decoder for WHIR's Serde
representation.

`proof-size-comparison.csv` compares the baseline mean, the initial dynamic proof,
and the final dynamic proof separately for each update size. The final size is
the size at revision 12; it is not an average across revisions. In shared-baseline
mode, all rows use the same twelve baseline measurements. The full 2^24 sizes
will be measured on EC2, not extrapolated from the smaller rehearsal.

## 1. Choose the host

Use Ubuntu 24.04 LTS **x86-64**, `x8i.48xlarge`, in US East (N. Virginia), with
default CPU options. AWS lists **192 vCPUs and 3,072 GiB RAM**. It has 96 physical
cores with two hardware threads per core.

- [AWS X8i specifications](https://aws.amazon.com/ec2/instance-types/x8i/)
- [AWS memory-optimized CPU specifications](https://docs.aws.amazon.com/ec2/latest/instancetypes/mo.html)

The exact 2^24 workload preflight projects **1,788 GiB peak**, dominated by the
full initial proof. This is a conservative planning estimate, not a measured RSS
or a guaranteed upper bound. The runner permits at most 70% of detected physical
or cgroup memory, whichever is smaller: about 2,150 GiB on this host. A 2 TiB host
does not pass this margin. The result records actual process peak RSS separately.

The original CAIR evaluation table has 2^33 elements (256 GiB). Interleaving does
not remove that table. With initial factor 64 and inverse rate 2, the first FFT
height is 2^(33 + 1 - 6) = **2^28**, exactly BN254's supported two-adic limit.
The later domain heights are 2^24, 2^20, 2^16, 2^12, 2^8 and 2^4.

Spot is a reasonable cost choice if a restart is acceptable. Use a **one-time
Spot request**, and configure the EBS volume containing results with **Delete on
termination disabled**. For the simplest setup, a 100 GiB gp3 root volume can
hold both sources and `~/bench-results`; proof working memory is RAM, not EBS.
If using a separate persistent results volume, substitute its mounted directory
for `~/bench-results` throughout. Use your SSH key and allow inbound SSH from
your own IP. Before launch, check availability and the regional **All X Spot
Instance Requests** quota; the launch needs 192 vCPUs.

- [EC2 instance quotas](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-instance-quotas.html)
- [Spot interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)
- [EBS persistence on termination](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/preserving-volumes-on-termination.html)

Spot can interrupt a long proof. Completed timing rows are flushed and synced to
EBS immediately, but the proof state lives in RAM and cannot be resumed after
termination. The final archive is created at normal completion or a handled
failure; abrupt termination may leave only the result directory. Retained EBS
preserves that directory for recovery. Check the live Spot quote and capacity
when launching; no fixed completion time or Spot availability is assumed here.

## 2. Package and transfer from your Mac

Run locally in this repository. The archive includes uncommitted source changes,
the locked dependencies manifest and the vendored patch; it excludes build
outputs, benchmark results and `.git`.

```bash
cd /path/to/dynamic-snarks-system
SOURCE_ARCHIVE="$HOME/Desktop/dynamic-snarks-experiment-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
python3 scripts/package_experiment.py "$SOURCE_ARCHIVE"

# Replace these two values with your instance's public address and local key.
EC2_HOST=ec2-your-instance.compute-1.amazonaws.com
EC2_KEY="$HOME/.ssh/your-ec2-key.pem"
scp -i "$EC2_KEY" "$SOURCE_ARCHIVE" "ubuntu@$EC2_HOST:~/experiment-source.tar.gz"
ssh -i "$EC2_KEY" "ubuntu@$EC2_HOST"
```

## 3. Prepare the instance

Run on EC2. Cloning records the requested GitHub repository; extracting the
archive overlays the exact working sources being tested.

```bash
sudo apt-get update
sudo apt-get install -y git
mkdir -p ~/research
cd ~/research
git clone https://example.invalid/anonymous/dynamic-snarks-system.git
cd dynamic-snarks-system
tar -xzf ~/experiment-source.tar.gz --strip-components=1 -C .
bash scripts/bootstrap_ec2.sh
source "$HOME/.cargo/env"

# Compile for this EC2 CPU, not for the Mac. Keep this setting for every run.
export RUSTFLAGS='-C target-cpu=native'
mkdir -p ~/bench-results
lscpu
free -h
numactl --hardware
python3 scripts/run_experiment.py --threads 96 --build-only \
  --output ~/bench-results/build-$(date -u +%Y%m%dT%H%M%SZ)
```

The bootstrap installs Rust **1.92.0**, build tools, Python, tmux, numactl and jq,
and fetches `Cargo.lock` dependencies. Subsequent commands can run offline and
reuse the release binary. For a private repository, use your normal GitHub
authentication if the clone prompts for it.

If minimizing preparation time on the 3 TiB instance is critical, run this step
on a smaller x8i host, such as the 128 GiB `x8i.2xlarge`, and create an AMI after
compilation. Launch the large Spot host from that AMI. Keep the CPU family and
source files unchanged for reuse of a `target-cpu=native` binary. Direct setup on
the large instance is simpler and avoids the image-creation step.

## 4. Check threading and rehearse

Rayon is available through the `parallel` Cargo feature. The runner sets
`RAYON_NUM_THREADS` and records **Rayon's actual worker count** in
`experiment.json`. Use **96 workers** as the starting choice; **192** is also
supported. Worker count does not pin one worker to each physical core.

The baseline, full initialization, and updates share the same pool. Custom
sumchecks distribute independent message evaluations and row pairs; Merkle
levels, Poseidon trace construction, table preparation, product construction,
and final openings also use Rayon. Scheduling uses the worker count and work
per item, without a laptop-specific cap. Small arithmetic tails and sequential
Fiat–Shamir/tree-level dependencies remain, so 192 workers is not a promise of
twice the throughput of 96. Complete proofs are checked for exact equality at
1, 8 and 96 workers on a small fixture; 96-worker EC2 performance still needs
to be measured. `--numa-interleave` applies
`numactl --interleave=all` to distribute allocations across NUMA nodes. It is a
fixed starting policy, not a performance result established on this host.

[Rayon thread-count configuration](https://docs.rs/rayon/latest/rayon/struct.ThreadPoolBuilder.html#method.num_threads)

First check the final configuration without allocating its proof tables:

```bash
python3 scripts/run_experiment.py --trace-log 24 --threads 96 \
  --preflight-only --offline --numa-interleave \
  --output ~/bench-results/preflight-n24-$(date -u +%Y%m%dT%H%M%SZ)
```

`preflight_complete` means configuration and workload estimation succeeded;
inspect the printed memory estimate against the printed 70% allowance. A real
run refuses an insufficient host before indexing or proving and never silently
skips update sizes.

Run the complete **2^15 rehearsal** on EC2 before the paid full experiment:

```bash
python3 scripts/run_experiment.py --trace-log 15 --threads 96 \
  --offline --numa-interleave --output ~/bench-results/rehearsal-n15
python3 scripts/summarize_experiment.py ~/bench-results/rehearsal-n15 --require-complete
cat ~/bench-results/rehearsal-n15/resources.json
```

The 2^15 full sweep projects 60.25 GiB peak, so it fits a 128 GiB preparation host
with the safety margin. On that smaller host use its actual CPU count, e.g.
`--threads 8`, and omit or retain NUMA interleaving as appropriate.

Optional short EC2 thread comparison, run sequentially, with the same source,
CPU and NUMA policy:

```bash
for THREADS in 96 192; do
  python3 scripts/run_experiment.py --trace-log 15 --update-logs 4 \
    --sequence-len 3 --threads "$THREADS" --offline --numa-interleave \
    --output "$HOME/bench-results/thread-check-$THREADS"
done
```

Compare initial and baseline/update timings in the two `summary.csv` files.
This is a small calibration, not proof that the same thread count wins at 2^24.
Keep the selected worker count fixed for the full experiment. Every run requires
a new output directory, so use a timestamp if repeating a command.

## 5. Run 2^24 inside tmux

```bash
tmux new -s snark-bench
```

Inside tmux:

```bash
cd ~/research/dynamic-snarks-system
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
RUN_DIR="$HOME/bench-results/n24-$(date -u +%Y%m%dT%H%M%SZ)"
printf '%s\n' "$RUN_DIR" > ~/bench-results/latest-run.txt
python3 scripts/run_experiment.py --trace-log 24 --threads 96 \
  --update-logs 0,1,2,3,4,5,6,7,8,9,10 --sequence-len 12 \
  --seed 20260909 --baseline-mode shared --offline --numa-interleave --output "$RUN_DIR"
python3 scripts/summarize_experiment.py "$RUN_DIR" --require-complete
cat "$RUN_DIR/status.json"
cat "$RUN_DIR/resources.json"
```

Detach with **Ctrl-b, then d**. Reconnect using `tmux attach -t snark-bench`.
Closing SSH does not stop the run. All phases run sequentially; no competing
benchmark is launched in the background. Compilation, downloads and packaging
are excluded from proof timers. Expensive key indexing and full initialization
are shared across the update sizes.

The terminal prints sample boundaries; detailed progress during a long proof is
available from a second SSH session:

```bash
RUN_DIR=$(cat ~/bench-results/latest-run.txt)
tail -f "$RUN_DIR/run.log"
```

Proof timers include the prover's existing progress logging. Downloading the
archive and any CSV analysis happen after the benchmark has finished.

Success requires `status.json` to say `complete` and `validation.json` to report
`complete: true`, `verified_samples: 145` and `expected_samples: 145`
(or 265 for paired mode).
For proof-size-enabled runs, `proof_size_samples` must match `verified_samples`;
the default 2^24 shared-baseline run also records **13 proof checkpoints** (one
initial, one baseline, eleven final dynamic proofs). Paired mode records 23.
An exit or a partial CSV alone is not a successful experiment.

## 6. Results and copying back

Each run produces a directory plus its sibling **`<run-directory>.tar.gz`**.

| File | Contents |
| --- | --- |
| `comparison.csv` | Eleven update sizes, baseline/update means and their ratio |
| `summary.csv` | 13 groups: one initial, one baseline and eleven update; count, mean, median, min/max, sample SD and verification mean |
| `samples.csv` | All 145 individual proof timings, revisions, distinct-gate counts, field/hash counts, payload/serialized bytes and checkpoint paths |
| `proof-sizes.csv` | Per-phase and per-size mean/min/max payload and serialized sizes |
| `proof-size-comparison.csv` | Baseline mean, initial proof, and full final-revision dynamic proof size for each update size |
| `proof-components.csv` | Initial/final checkpoint component sizes, including framing; sums to each full proof |
| `proof-size-format.json`, `proofs/*.cbor` | Size definitions and saved, decoded-and-verified binary proof checkpoints |
| `setup.csv` | Baseline and dynamic indexing times |
| `resources.json` | Benchmark wall time, CPU time, peak RSS and exit code; excludes compiler RSS |
| `experiment.json` | Workload, protocol and actual Rayon settings |
| `baseline.json` | Paired/shared baseline mode and reference update size |
| `preflight.csv` | Per-case composed-support dimensions and memory estimates |
| `workload.csv`, `workload-fingerprints.csv` | Reproducible update positions and field values; position fingerprints |
| `metadata.json`, `source.tar.gz` | Host/toolchain details, source-file hashes, binary hash and exact source snapshot |
| `run.log`, `build.log`, `build-artifacts.jsonl` | Full proof progress and Cargo diagnostics |
| `status.json`, `validation.json`, `SHA256SUMS` | Completion checks and artifact checksums |

Every reported sample passed its corresponding verifier before being written.
The archive includes the saved proof checkpoints, source snapshot and workload.
Keep these together with the encoding specification and feature metadata when
comparing or reproducing proof sizes. Older archives from before this addition
contain timing measurements only.

From a **new local Mac terminal**, with the same host/key variables set:

```bash
mkdir -p ~/Downloads/snark-bench-results
REMOTE_RUN=$(ssh -i "$EC2_KEY" "ubuntu@$EC2_HOST" 'cat ~/bench-results/latest-run.txt')
scp -i "$EC2_KEY" "ubuntu@$EC2_HOST:$REMOTE_RUN.tar.gz" ~/Downloads/snark-bench-results/
LOCAL_RUN=$(basename "$REMOTE_RUN")
cd ~/Downloads/snark-bench-results
tar -xzf "$LOCAL_RUN.tar.gz"
cd "$LOCAL_RUN"
shasum -a 256 -c SHA256SUMS
cat status.json
cat validation.json
open comparison.csv
open proof-size-comparison.csv
```

Confirm the archive/checksums and completeness **before terminating the
instance**. Then terminate it in EC2, check that the one-time Spot request has no
replacement pending, and remove unneeded retained EBS volumes after results are
safe locally. Retained storage continues to incur its own charge.

For an interrupted run, recover the retained volume and copy the entire run
directory. `summarize_experiment.py DIRECTORY` reports complete cases and missing
samples; `--require-complete` exits nonzero if anything is missing. To finish
missing sizes, launch a fresh run in a new directory with `--update-logs` listing
only those sizes. That run must regenerate its initial state. Keep its metadata
and initialization separate; do not combine independent runs into a purported
single-initialization experiment. Rerun the full sweep for that exact claim.

## Local rehearsal limits

The Mac has 16 GiB RAM. A full 2^15 sweep does not pass the memory guard because
the 512- and 1,024-gate sequences grow large composed transition proofs. The
local split rehearsal uses:

```bash
python3 scripts/run_experiment.py --trace-log 15 --threads 8 --offline \
  --baseline-mode paired --update-logs 0,1,2,3,4,5,6,7 \
  --output "benchmark-results/ec2-rehearsal-n15-$(date -u +%Y%m%dT%H%M%SZ)"
python3 scripts/run_experiment.py --trace-log 11 --threads 8 --offline \
  --baseline-mode shared --output "benchmark-results/ec2-rehearsal-n11-$(date -u +%Y%m%dT%H%M%SZ)"
```

The first covers 32,768 gates and eight update sizes (193 verified samples); the
second covers all eleven sizes with 2,048 gates (145 samples, shared baseline). Both use the same
12-revision logic and WHIR settings. Both passed; see [measured rehearsal results](ec2-rehearsal-results.md). These local runs cannot establish
Linux, NUMA or x8i performance; the EC2 rehearsal above checks that environment.
The latest 2^15 rerun also passed proof-size accounting and checkpoint recovery;
see [proof sizes and prover times](ec2-proof-size-results.md).
