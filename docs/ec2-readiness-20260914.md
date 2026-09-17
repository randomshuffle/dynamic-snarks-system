# EC2 experiment: forty revisions, September 14, 2026

> The [September 15 preparation guide](ec2-prep-20260915.md) includes the newer
> update-table layout, fresh source package, and x8i.24xlarge launch plan.
> The measured results below describe the preceding layout.

Use this recipe for the current compact partial-Merkle implementation. The
September 9 source archives and historical 64-way launch commands predate it.
This revision changes the experiment to forty updates and adds average/maximum
prover time, verifier time and current full-proof size comparisons. The prover
algorithm is unchanged; obsolete hierarchy proofs already get dropped on composition.

## Validation completed

- A full local sweep at 2^10 gates, all eleven update sizes, forty revisions,
  one initialization and forty shared baseline proofs passed: **481/481 verified
  timing/size samples and 13 decoded-and-verified proof checkpoints**. It used
  eight Rayon workers and 16-way folding throughout, with the compact variant.
- Every mean/max comparison was independently checked against samples.csv.
  All 34 archived checksums passed, and 113 code/build-input files match the
  measured source snapshot. The run took 746.08 seconds on the Mac; this is a
  workflow check, not an EC2 performance prediction.
- All 13 Python result/memory tests and both Rust proof-size tests passed.
  The Rust test checks occupied serialized hierarchy levels and verifies all
  forty decoded update proofs, including repeated multilevel compositions.
- The exact forty-revision 2^15 and 2^24 configurations completed preflight.
  No proofs at those sizes were generated for this validation.

For example, the one-gate sequence's payload peaks at **3,724,128 bytes at
revision 31**, then drops to **2,414,080 bytes at revision 40**. This confirms
that final size and maximum size are distinct measurements.

Records:
[local validation](../benchmark-results/ec2-forty-compact-n10-i16-20260914/validation.json),
[timing comparisons](../benchmark-results/ec2-forty-compact-n10-i16-20260914/comparison.csv),
[proof-size comparisons](../benchmark-results/ec2-forty-compact-n10-i16-20260914/proof-size-comparison.csv),
[2^15 preflight](../benchmark-results/ec2-forty-compact-n15-i16-20260914/preflight.csv),
[2^24 preflight](../benchmark-results/ec2-forty-compact-n24-i16-20260914/preflight.csv).
The earlier twelve-revision records remain historical. The Linux rehearsal and
large-instance measurements remain to be done.

## Experiment

| Setting | Value |
| --- | --- |
| Circuit | 2^24 = 16,777,216 actual gates, alternating addition and multiplication |
| Field / permutation | BN254 / identity wiring |
| Public inputs | 256, all equal to nine, unchanged by updates |
| PIOP | Digest-only initial Merkle oracle; compact partial-Merkle transitions |
| WHIR | 16-way first and later folding; rate 1/2; configured security target 127 bits under the capacity-bound assumption; no proof of work |
| Updated gates per revision | 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1,024 |
| Sequences | One full initialization; each size starts from that state and applies 40 consecutive updates |
| Randomness | Seed 20260909; uniform gate subset without replacement within each revision |
| Baseline | 40 complete regular HyperPlonk proofs on the one-gate sequence; their statistics are shared across sizes |
| Outputs | 481 verified timing/size samples and 13 decoded-and-verified proof checkpoints |

Gate locations are random; field values follow a deterministic revision-dependent
formula. Every selected gate supplies all three wire positions, including its
unchanged right input of two; the left input and output change. Thus an update
of g gates supplies 3g positions. Gates may recur across revisions. Different
sizes use the same seed and separate state, rather than continuing the preceding
size's history.

Initialization includes the complete arithmetic and initial Merkle proofs.
Update timing includes tree maintenance, actual hierarchy composition and the
final public-input opening. Baseline timing includes constructing the ordinary
gate program and proving it. Indexing is recorded separately in setup.csv;
compilation, workload generation, case reset/cloning, serialization and extra
checkpoint verification are outside the proof timers. These costs still contribute
to wall time and the EC2 bill. Every proof is verified, with verification timed
separately. Update verification checks the entire current dynamic proof, including
the retained initial proof and all active transitions. It is not an incremental
verifier with an already-trusted previous proof. Verification excludes decoding,
serialization, disk I/O and the extra checkpoint round-trip check. There are no
discarded warmups or discarded composition-heavy updates.

The forty updates describe one sequential history for each size. Its arithmetic
mean and observed maximum include all revisions 1 through 40, including the first
update and composition-heavy revisions. They are not forty independent trials or
a bound on future updates. The single initialization has no variance
estimate. Identity wiring permits independent gate changes; this experiment does
not measure propagation through a nontrivial application circuit.

## Proof sizes

Record both cryptographic payload and complete uncompressed CBOR bytes. Payload
is 32 bytes per BN254 element or BLAKE3 digest, including sumcheck messages,
opened field values, commitments, Merkle paths and Poseidon digests. Complete
CBOR also includes indices, dimensions, tags, names and framing; it is not a
minimal wire encoding. Every revision measures the entire current retained
dynamic proof: initial arithmetic/Merkle proofs, active transitions, hierarchy
commitments and public-input multiproof. Separately supplied public inputs,
verification keys, witnesses and prover state are excluded.

Composition overwrites the target transition proof and clears every absorbed
level with `None`. Obsolete proof objects and their field/hash vectors are dropped;
the fixed hierarchy vector still encodes empty slots, which count only as CBOR
framing. Hierarchy commitments and still-active transitions remain part of the
proof. Size means and maxima are over forty separate current-proof measurements,
not a concatenation of the update history. The maximum need not occur at revision
40. The proof-size regression test checks the occupied serialized levels and
verifies the decoded full proof after every one of forty updates.

The initial measurement is one proof. Baseline statistics use the same forty
shared proofs for every size. Report both payload and CBOR means/maxima for each
forty-update sequence; keep the revision-40 size as an additional diagnostic.
Only the initial proof and final revision of each measured case are saved as CBOR
files (13 files total). Intermediate and maximum sizes/timings remain in samples.csv;
the largest proof's serialized bytes are not separately saved unless it is final.

| File | Comparison data |
| --- | --- |
| `samples.csv` | Every proof's prover seconds, verifier seconds, field/hash counts, payload bytes and serialized bytes, identified by size and revision |
| `summary.csv` | Per phase/size: proving mean/median/min/max/SD, verification mean/max and completeness/counts; initialization is one sample |
| `comparison.csv` | Per update size: baseline and update prover mean/max, baseline and update verifier mean/max, initial prover/verifier seconds, proving mean ratio and first-update seconds |
| `proof-sizes.csv` | Per phase/size: mean field/hash counts and payload/serialized mean/min/max, with completeness/counts |
| `proof-size-comparison.csv` | Initial sizes, shared baseline mean/max sizes and dynamic mean/max sizes for both encodings; also final sizes, final/baseline ratios and checkpoint paths |

`dynamic_mean_payload_bytes`, `dynamic_max_payload_bytes`,
`dynamic_mean_serialized_bytes` and `dynamic_max_serialized_bytes` are the primary
update size metrics. `dynamic_final_*` columns refer only to revision 40.
`update_mean_seconds` / `update_max_seconds` are prover times;
`update_mean_verify_seconds` / `update_max_verify_seconds` are verifier times.
Each maximum is computed separately: the slowest proof, slowest verification and
largest proof can occur at different revisions. No values are discarded.

## Capacity and threading

The current exact seeded 2^24 preflight projects **936 GiB**, dominated by
initialization. This is a conservative allocation plan, not a measured peak or
a guaranteed bound. Initial hash state layers alone occupy
65 * 3 * 2^27 * 32 bytes = **780 GiB**. Compact transitions reduce their committed
tables but retain the same hash-round state engine.

The initial digest polynomial has 2^27 fields (4 GiB); with 16-way interleaving
its first FFT has height 2^24, below BN254's 2^28 limit. The largest composed
update has 98,214 positions, 2^22 node rows and a 16-column node oracle. Its
transition allocation estimate is about 195.75 GiB, before the separate 128 GiB
retained-state/baseline allowance. The full experiment remains initialization-bound.

The exact 2^15 rehearsal with forty updates and all eleven sizes projects
**51.44 GiB**, so it needs at least about 73.5 GiB of available host/cgroup RAM to
pass the 70% guard. A 128 GiB Linux preparation host fits this plan. This complete
rehearsal does not fit the local 16 GiB Mac; the local workflow validation uses
2^10 gates with all eleven sizes and forty revisions instead.

AWS lists x8i.48xlarge with **3,072 GiB, 192 vCPUs and 96 physical cores**.
The runner's 70% memory allowance is about 2,150 GiB on that host. A
1,536 GiB x8i.24xlarge also passes the planning margin, with 96 vCPUs and 48
physical cores; a 1,024 GiB host fails it. Actual Linux memory and cost per
completed run have not been measured. Check live prices and available capacity.

- [AWS X8i sizes](https://aws.amazon.com/ec2/instance-types/x8i/)
- [AWS CPU specifications](https://docs.aws.amazon.com/ec2/latest/instancetypes/mo.html)

Rayon is enabled throughout the three provers and WHIR. On x8i.48xlarge start
with 96 workers, then compare 192 using the same calibration workload. Worker
count does not imply physical-core pinning. NUMA interleaving is a starting
allocation policy, not a measured optimum. Initial proving and small sparse
updates may prefer different worker counts; keep one chosen count fixed for
the primary comparison. No concurrent benchmark processes should run.

## Before renting the large host

Use the fresh package `benchmark-results/ec2-experiment-compact-i16-r40-20260914.tar.gz`
and its manifest. A plain GitHub clone does not contain the many uncommitted
benchmark/implementation files. To create another source snapshot:

```sh
python3 scripts/package_experiment.py /tmp/ec2-source.tar.gz
```

Choose Ubuntu 24.04 x86-64 in us-east-1. The x8i.48xlarge Spot request needs
192 available vCPUs in the regional **All X Spot Instance Requests** quota;
AWS documents a default quota of zero. Account quota, current Spot quote,
availability zone, SSH key and subnet have not been checked in this review.

Use persistent EBS for results with DeleteOnTermination disabled, and confirm
the result path is on that volume. A 100 GiB gp3 volume is a reasonable artifact
capacity starting point. Spot interruption preserves completed records on retained
EBS, but the current runner cannot restore the in-memory prover state. A failed
run must regenerate indexing/initialization and rerun unfinished size sequences.
Saved verifier-proof checkpoints are not resumable prover checkpoints.

- [Spot quotas](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-spot-limits.html)
- [Spot interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)
- [EBS persistence](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/preserving-volumes-on-termination.html)

For minimum large-instance rental time, prepare dependencies and compile on a
smaller x8i Linux host, then create an AMI. Keep the same CPU family if using
`target-cpu=native`. The Mac binary cannot be transferred as the Linux executable.

## Commands on EC2

Transfer the source archive with scp, unpack it, and enter dynamic-snarks-system.
Set BENCH_RESULTS to the writable mount on the retained EBS volume.

```sh
bash scripts/bootstrap_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
unset DYNAMIC_SNARK_PROFILE DYNAMIC_SNARK_PROFILE_DETAIL
export BENCH_RESULTS=/mnt/bench-results
test -w "$BENCH_RESULTS"

python3 scripts/run_experiment.py --threads 96 --initial-interleaving 16 \
  --build-only --offline --output "$BENCH_RESULTS/build"

python3 scripts/run_experiment.py --trace-log 24 --threads 96 \
  --initial-interleaving 16 --sequence-len 40 --preflight-only --offline \
  --output "$BENCH_RESULTS/preflight-n24"

python3 scripts/run_experiment.py --trace-log 15 --threads 96 \
  --initial-interleaving 16 --sequence-len 40 --baseline-mode shared \
  --offline --numa-interleave --output "$BENCH_RESULTS/rehearsal-n15"
```

The rehearsal uses the same forty-revision design as the full run: all eleven
update sizes, forty shared baseline proofs and one initialization, totaling 481
samples. Run the same two `jq` checks below on `rehearsal-n15` and copy/check its
archive before renting the large host. On the smaller preparation instance, set
`--threads` to its available vCPUs (for example 8 on x8i.2xlarge). The 96-worker
commands are for x8i.48xlarge.

For another local run use `--trace-log 15 --threads 8 --initial-interleaving 16 --sequence-len 40`;
use a new output directory and omit `--numa-interleave` on macOS.
The same summaries work for the 2^15, 2^17, 2^18 and 2^24 gate settings, subject
to the memory guard. Restrict sizes only when explicitly desired with `--update-logs`
(for example `0,1,2,3,4,5,6` for updates through 64). Do not bypass the memory guard
to run the full 2^15/all-sizes rehearsal on a machine that fails its preflight.

Optionally calibrate the CPU
choice on 2^20 gates, which exercises more memory and parallel work than 2^15:

```sh
for THREADS in 96 192; do
  python3 scripts/run_experiment.py --trace-log 20 --threads "$THREADS" \
    --initial-interleaving 16 --update-logs 6 --sequence-len 3 \
    --baseline-mode shared --offline --numa-interleave \
    --output "$BENCH_RESULTS/calibration-n20-t$THREADS"
done
```

Choose the primary worker count from calibration. The following uses 96. Run it
inside tmux so SSH disconnection does not terminate the shell; ensure the exports
above are present in that shell. Each output directory must be new.

```sh
python3 scripts/run_experiment.py --trace-log 24 --threads 96 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7,8,9,10 \
  --sequence-len 40 --seed 20260909 --baseline-mode shared \
  --offline --numa-interleave --output "$BENCH_RESULTS/full-n24"

jq -e '.state == "complete" and .exit_code == 0' "$BENCH_RESULTS/full-n24/status.json"
jq -e '.complete and .verified_samples == 481 and .proof_size_samples == 481 and .proof_checkpoints == 13' \
  "$BENCH_RESULTS/full-n24/validation.json"
```

The runner writes timing/size comparison CSVs, individual measurements, component
breakdowns, workload, source/build metadata, setup timings, wall time/peak RSS,
checksums and 13 proof files. It creates full-n24.tar.gz alongside the directory.
Normal execution records the child's peak RSS; a sampled memory timeline is
currently tied to the optional RSS-cutoff mode. Keep the normal allocation guard
for the EC2 experiment.

From the Mac, using the actual SSH key and host:

```sh
scp -i /path/to/key.pem ubuntu@HOST:/mnt/bench-results/full-n24.tar.gz .
tar -xzf full-n24.tar.gz
(cd full-n24 && shasum -a 256 -c SHA256SUMS)
```

Check the local archive and validation record before terminating the instance.
If interrupted, recover the retained directory even if no final archive exists.
The older guide's recovery instructions describe summarizing partial records.

## Optimization choices still open

1. Tune worker count and NUMA/physical-core placement on Linux; all provers must
   use the recorded configuration. Do not infer 192-worker throughput from 96.
2. Profile the compact routing sumcheck and extra WHIR opening before assuming
   smaller commitments improve time. The September 11 one-gate A/B reduced
   committed fields by 47.9% and payload by 4.5%, but was 5.7% slower in its one
   timing sample. It is not evidence of the crossover at large updates.
3. Audit redundant buffers and their lifetimes if lower-memory hosts are desired.
   Poseidon state checkpoint/recomputation could reduce the 780 GiB layer budget,
   but would add work. It remains unimplemented, in line with the request to
   avoid sacrificing prover time for memory.
4. Shared baseline mode saves 400 full proofs relative to paired mode. Use
   paired mode for a baseline on every updated witness (881 total measurements).
   Multiple seeds/repeated initializations would improve statistical evidence
   but are additional runs beyond the agreed one-initialization, forty-update design.

There is no measured 2^24 Linux runtime, peak memory or guaranteed rental duration.
Use the Linux rehearsal/calibration to choose the machine and estimate wall time.
