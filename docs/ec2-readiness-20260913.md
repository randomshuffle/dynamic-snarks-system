# EC2 experiment readiness, September 13, 2026

> Historical twelve-revision recipe. Use the [forty-revision experiment guide](ec2-readiness-20260914.md)
> for current commands and prover/verifier time and proof-size averages/maxima.

Use this recipe for the current compact partial-Merkle implementation. The
September 9 source archives and historical 64-way launch commands predate it.
The production source matches the September 11 compact validation record;
the readiness review only corrects experiment variant metadata and updates
launch documentation. No prover algorithm or memory-recomputation changes were made.

## Readiness checks completed

- The current compact runner completed 2^11 gates with all eleven update sizes
  through 1,024 gates and twelve revisions per size: **145/145 verified timing
  and size records, 13 decoded-and-verified proof checkpoints**. All 34 archived
  file checksums passed; 90 code/build-input files match the measured snapshot.
- The exact 2^24 configuration passed preflight with 96 configured workers,
  16-way interleaving and the compact variant recorded explicitly. No 2^24
  proofs were generated locally.
- The earlier 2^17 and 2^18 complete sweeps used the preceding endpoint update
  variant. The September 11 compact validation recorded 98 passing tests and a
  one-gate comparison; those production source files still match this package.

Current records:
[small-sweep validation](../benchmark-results/ec2-readiness-compact-n11-i16-20260913/validation.json),
[2^24 preflight](../benchmark-results/ec2-readiness-compact-n24-i16-20260913/preflight.csv),
[compact A/B](../benchmark-results/2026-09-11-compact-update-ab/README.md).
These validate local correctness and artifact handling; the Linux rehearsal and
large-instance resource/performance measurements remain to be done.

## Experiment

| Setting | Value |
| --- | --- |
| Circuit | 2^24 = 16,777,216 actual gates, alternating addition and multiplication |
| Field / permutation | BN254 / identity wiring |
| Public inputs | 256, all equal to nine, unchanged by updates |
| PIOP | Digest-only initial Merkle oracle; compact partial-Merkle transitions |
| WHIR | 16-way first and later folding; rate 1/2; configured security target 127 bits under the capacity-bound assumption; no proof of work |
| Updated gates per revision | 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1,024 |
| Sequences | One full initialization; each size starts from that state and applies 12 consecutive updates |
| Randomness | Seed 20260909; uniform gate subset without replacement within each revision |
| Baseline | 12 complete regular HyperPlonk proofs on the one-gate sequence; their mean is shared across sizes |
| Outputs | 145 verified timing/size samples and 13 decoded-and-verified proof checkpoints |

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
separately. There are no discarded warmups or discarded composition-heavy updates.

The twelve updates describe one sequence average, not twelve independent trials
or a long-run amortization measurement. The single initialization has no variance
estimate. Identity wiring permits independent gate changes; this experiment does
not measure propagation through a nontrivial application circuit.

## Proof sizes

Record both cryptographic payload and complete uncompressed CBOR bytes. Payload
is 32 bytes per BN254 element or BLAKE3 digest, including sumcheck messages,
opened field values, commitments, Merkle paths and Poseidon digests. Complete
CBOR also includes indices, dimensions, tags, names and framing; it is not a
minimal wire encoding. The revision-12 measurement includes the entire retained
dynamic proof: initial arithmetic/Merkle proofs, active transitions, hierarchy
commitments and public-input multiproof. Separately supplied public inputs,
verification keys, witnesses and prover state are excluded.

## Capacity and threading

The current exact seeded 2^24 preflight projects **936 GiB**, dominated by
initialization. This is a conservative allocation plan, not a measured peak or
a guaranteed bound. Initial hash state layers alone occupy
65 * 3 * 2^27 * 32 bytes = **780 GiB**. Compact transitions reduce their committed
tables but retain the same hash-round state engine.

The initial digest polynomial has 2^27 fields (4 GiB); with 16-way interleaving
its first FFT has height 2^24, below BN254's 2^28 limit. The largest composed
update has 24,573 positions, 2^20 node rows and a 16-column node oracle. Its
transition allocation estimate is about 48.94 GiB, before the separate 128 GiB
retained-state/baseline allowance. The full experiment remains initialization-bound.

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

Use the fresh package `benchmark-results/ec2-experiment-compact-i16-20260913.tar.gz`
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
  --initial-interleaving 16 --preflight-only --offline \
  --output "$BENCH_RESULTS/preflight-n24"

python3 scripts/run_experiment.py --trace-log 15 --threads 96 \
  --initial-interleaving 16 --sequence-len 12 --baseline-mode shared \
  --offline --numa-interleave --output "$BENCH_RESULTS/rehearsal-n15"
```

The rehearsal defaults to all eleven update sizes. Optionally calibrate the CPU
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
  --sequence-len 12 --seed 20260909 --baseline-mode shared \
  --offline --numa-interleave --output "$BENCH_RESULTS/full-n24"

jq -e '.state == "complete" and .exit_code == 0' "$BENCH_RESULTS/full-n24/status.json"
jq -e '.complete and .verified_samples == 145 and .proof_size_samples == 145 and .proof_checkpoints == 13' \
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
4. Shared baseline mode saves 120 full proofs relative to paired mode. Use
   paired mode for a baseline on every updated witness (265 total measurements).
   Multiple seeds/repeated initializations would improve statistical evidence
   but are additional runs beyond the agreed one-initialization, twelve-update design.

There is no measured 2^24 Linux runtime, peak memory or guaranteed rental duration.
Use the Linux rehearsal/calibration to choose the machine and estimate wall time.
