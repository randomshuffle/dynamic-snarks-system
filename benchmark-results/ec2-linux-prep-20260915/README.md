# EC2 Linux rehearsal, September 15–16, 2026 (New York time)

Completed successfully on **x8i.2xlarge**, Ubuntu 26.04 x86-64, with eight Rayon workers on four physical cores. All thirteen Python runner tests passed on Linux. All **481 proofs** were verified and all **13 saved CBOR proofs** were decoded and verified by the benchmark. The copied archive passed all 34 checksums; the timing and size aggregates were independently recomputed from the raw samples.

The benchmark process took **42.53 minutes** and reached **28.674 GiB peak RSS** on Linux. This excludes dependency installation, compilation and final archive creation. The conservative allocation estimate for this rehearsal was 46.94 GiB; the measured peak is specific to this 2^15 run. The 2^24 preflight remains an unmeasured estimate of 936 GiB.

Configuration: 32,768 gates, BN254, identity permutation, 256 public inputs, 16-way first and later WHIR folding, seed 20260909, one initial computation, forty shared baseline proofs, and an independent forty-revision sequence for each update size 1, 2, 4, ..., 1,024 gates. All updates within a sequence are consecutive. No samples are discarded as warmups.

Each pair below is **mean / maximum** over forty proofs. Initial computation has one sample. Proving and verification timers exclude serialization and disk writes. Verification and proof sizes cover the complete retained dynamic proof, including the initial proof and active hierarchy levels.

| Phase / gates updated | Proving time (s), mean / max | Verification (ms), mean / max |
|---|---:|---:|
| Baseline HyperPlonk | 0.332 / 0.340 | 5.280 / 5.464 |
| Initial dynamic computation | 11.790 / 11.790 | 28.954 / 28.954 |
| Update 1 | 0.091 / 0.640 | 51.881 / 73.061 |
| Update 2 | 0.157 / 1.261 | 54.994 / 79.153 |
| Update 4 | 0.284 / 2.510 | 58.061 / 84.541 |
| Update 8 | 0.484 / 2.795 | 61.063 / 91.163 |
| Update 16 | 0.870 / 5.272 | 63.203 / 95.215 |
| Update 32 | 1.543 / 10.795 | 65.936 / 99.920 |
| Update 64 | 2.763 / 21.903 | 68.741 / 105.495 |
| Update 128 | 5.000 / 45.740 | 71.667 / 111.170 |
| Update 256 | 7.829 / 49.130 | 73.883 / 115.898 |
| Update 512 | 14.738 / 96.437 | 76.732 / 121.013 |
| Update 1024 | 26.836 / 194.613 | 80.064 / 127.889 |

Payload counts field elements and BLAKE3 digests, including Merkle authentication data, at 32 bytes each. Poseidon digests are field elements and are included once in the field-element count. CBOR is the actual full serialized proof size, including encoding overhead. Sizes are in MiB (1,048,576 bytes).

| Phase / gates updated | Payload MiB, mean / max | CBOR MiB, mean / max |
|---|---:|---:|
| Baseline HyperPlonk | 0.815 / 0.815 | 1.186 / 1.187 |
| Initial dynamic computation | 1.419 / 1.419 | 1.977 / 1.977 |
| Update 1 | 2.933 / 4.307 | 3.993 / 5.812 |
| Update 2 | 3.206 / 4.842 | 4.383 / 6.576 |
| Update 4 | 3.505 / 5.409 | 4.813 / 7.392 |
| Update 8 | 3.787 / 6.006 | 5.224 / 8.263 |
| Update 16 | 4.027 / 6.469 | 5.576 / 8.939 |
| Update 32 | 4.281 / 6.942 | 5.952 / 9.638 |
| Update 64 | 4.540 / 7.438 | 6.339 / 10.381 |
| Update 128 | 4.812 / 7.973 | 6.749 / 11.181 |
| Update 256 | 5.053 / 8.490 | 7.116 / 11.968 |
| Update 512 | 5.327 / 9.008 | 7.534 / 12.757 |
| Update 1024 | 5.623 / 9.551 | 7.986 / 13.589 |

Obsolete levels are removed: for one-gate updates, the largest payload occurred at revision **31** (4,515,840 bytes), while revision 40 retained only **3,189,088 bytes**. Proof size need not increase monotonically.

Files:

- [Complete results archive](rehearsal-n15.tar.gz)
- [Prover and verifier comparisons](rehearsal-n15/comparison.csv)
- [Proof size comparisons](rehearsal-n15/proof-size-comparison.csv)
- [Every individual sample](rehearsal-n15/samples.csv)
- [Validation](rehearsal-n15/validation.json) and [process resources](rehearsal-n15/resources.json)
- [Source and build metadata](rehearsal-n15/metadata.json)

Source aggregate SHA256: `47280a990159efc055115869573e7637c13e6bfedd2290e1b7541243fa4f68a3`.

Linux binary SHA256: `d1d96a28b5726b9d4eee6ff1aa6d4d085011dadc375f5845549deac84e554b68`.

Run began at `2026-09-16T03:41:38.868987+00:00` and finished at `2026-09-16T04:24:10.849245+00:00`.

Exact invocation:

```sh
python3 scripts/run_experiment.py --trace-log 15 --threads 8 --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7,8,9,10 --sequence-len 40 --seed 20260909 --baseline-mode shared --offline --numa-interleave --output /home/ubuntu/bench-results/prep-20260915/rehearsal-n15
```

The prep instance is ready to image after this successful rehearsal. AMI creation, stopping this instance and launching the large instance are separate steps; none is performed by the preparation script.
