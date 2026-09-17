# EC2 2^23-gate experiment, September 17, 2026

Completed successfully on **i4i.24xlarge**, Ubuntu 26.04 x86-64, Intel Xeon Platinum 8375C, 96 vCPUs and 768 GiB nominal RAM. Used **48 Rayon workers**, pinned to CPUs 0–47 (one worker per physical core across two sockets), with NUMA interleaving. Compiled with Rust 1.92.0 and `-C target-cpu=native`.

The benchmark process took **42.68 minutes** and peaked at **424.550 GiB RSS**. This excludes dependency fetching, compilation, and final archive creation. All **361 samples** were verified; **10 CBOR checkpoints** were decoded and verified by the benchmark. The downloaded archive and all extracted file checksums passed; timing and size aggregates were independently recomputed.

Configuration: 8,388,608 gates, BN254, identity permutation, 256 fixed public inputs, WHIR interleaving 16 throughout, rate 1/2, 127-bit capacity-bound target, zero proof-of-work, and workload seed 20260909. One initial proof, 40 shared baseline proofs paired with the one-gate revisions, and 40 consecutive random updates for each size 1, 2, 4, 8, 16, 32, 64, 128. Each size starts separately from the same proved initial state. No warmups or repeated sweeps.

The correct sample count is 1 + 40 + 8 × 40 = 361. An earlier planning count of 341 was a bookkeeping error; the configured workload was unchanged, and the driver completion check was corrected during the run.

Pairs below are **mean / observed maximum** over 40 revisions. Initial computation is one sample. Update proving includes state maintenance and hierarchy composition. Verification and sizes include the entire retained dynamic proof. Circuit indexing, copying each starting state, serialization, and disk writes are outside prover/verifier timers.

| Phase / gates updated | Prover time (s), mean / max | Verifier time (ms), mean / max | Mean prover speedup vs baseline |
|---|---:|---:|---:|
| HyperPlonk baseline | 28.413 / 28.716 | 16.926 / 17.366 | — |
| Initial dynamic computation | 716.408 | 54.709 | — |
| Update 1 | 0.207 / 0.540 | 91.537 / 126.160 | 137.02× |
| Update 2 | 0.277 / 0.753 | 95.665 / 134.645 | 102.40× |
| Update 4 | 0.378 / 1.230 | 99.814 / 142.062 | 75.07× |
| Update 8 | 0.524 / 2.299 | 103.150 / 148.691 | 54.20× |
| Update 16 | 0.743 / 4.320 | 107.122 / 154.538 | 38.22× |
| Update 32 | 1.125 / 8.469 | 111.157 / 162.102 | 25.26× |
| Update 64 | 1.916 / 16.506 | 116.042 / 172.906 | 14.83× |
| Update 128 | 3.602 / 32.701 | 120.294 / 181.313 | 7.89× |

Payload counts all field elements and BLAKE3 hashes at 32 bytes each, including Merkle authentication data. Poseidon digests are already counted as field elements. CBOR is the complete uncompressed serialization, including encoding overhead. Both exclude separately supplied public inputs, the verification key, and private prover state. MiB = 2^20 bytes.

| Phase / gates updated | Payload MiB, mean / max | CBOR MiB, mean / max |
|---|---:|---:|
| HyperPlonk baseline | 1.715 / 1.715 | 2.614 / 2.616 |
| Initial dynamic computation | 2.740 | 4.019 |
| Update 1 | 4.511 / 6.164 | 6.401 / 8.619 |
| Update 2 | 4.776 / 6.658 | 6.782 / 9.329 |
| Update 4 | 5.050 / 7.234 | 7.181 / 10.165 |
| Update 8 | 5.277 / 7.624 | 7.515 / 10.738 |
| Update 16 | 5.520 / 8.096 | 7.874 / 11.435 |
| Update 32 | 5.783 / 8.593 | 8.267 / 12.180 |
| Update 64 | 6.087 / 9.200 | 8.723 / 13.089 |
| Update 128 | 6.394 / 9.812 | 9.189 / 14.011 |

## Including initialization

The following compares one complete dynamic initialization plus each 40-update sequence against 40 fresh baseline proofs, using prover time only. It excludes verification, indexing, serialization, and I/O.

| Gates updated | Initial + 40 updates (min) | 40 baselines (min) | Speedup |
|---|---:|---:|---:|
| 1 | 12.078 | 18.942 | 1.568× |
| 2 | 12.125 | 18.942 | 1.562× |
| 4 | 12.192 | 18.942 | 1.554× |
| 8 | 12.290 | 18.942 | 1.541× |
| 16 | 12.436 | 18.942 | 1.523× |
| 32 | 12.690 | 18.942 | 1.493× |
| 64 | 13.217 | 18.942 | 1.433× |
| 128 | 14.341 | 18.942 | 1.321× |

For one-gate updates, the payload maximum occurred at revision 31: 6.164 MiB. The final retained proof has payload 4.477 MiB, reflecting removal of superseded levels.

## Reproducibility

- [Full result archive](full-n23-u128.tar.gz)
- [Raw samples](full-n23-u128/samples.csv)
- [Timing comparison](full-n23-u128/comparison.csv)
- [Proof-size comparison](full-n23-u128/proof-size-comparison.csv)
- [Local validation](copy-validation.json)
- [Source and build metadata](full-n23-u128/metadata.json)
- [Preparation evidence](remote-preparation/)

Source aggregate SHA256: `5c0ef44f371f42a8473708a6b17ff31610c3043489ddffede65d8a82f7fe7374`.
Binary SHA256: `658089cc77634969a2b24c3f0697f622145a3fa88f6006142530586322a5e1ad`.
Archive SHA256: `c0a87f3f4088ca7a6a1066e197312372e9f4f93804705ffe92518086525acbbc`.

Run started at `2026-09-17T04:19:59.381575+00:00` and finished at `2026-09-17T05:02:40.316979+00:00`.

Exact invocation (with inherited CPU affinity `0-47`):

```sh
python3 scripts/run_experiment.py --trace-log 23 --threads 48 --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7 --sequence-len 40 --seed 20260909 --baseline-mode shared --offline --numa-interleave --output /home/ubuntu/dynamic-snark-benchmark/full-n23-u128
```

All original remote experiment data was preserved. This task did not stop, terminate, reboot, or reconfigure the instance. Build files are isolated under a new /tmp directory; results remain in /home/ubuntu/dynamic-snark-benchmark as well as on this Mac.
