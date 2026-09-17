# EC2 experiment rehearsal results

The latest [2^15 proof-size sweep](ec2-proof-size-results.md) records complete
baseline, initial and post-twelve-update proofs alongside prover times, using
the optimized code. The older measurements below contain timings only.

The [optimized 2^15 rerun](../benchmark-results/ec2-rehearsal-n15-optimized-20260909/before-after.md)
includes all subsequent prover optimizations and compares the same workload with
the original measurements below.

Local validation on September 9, 2026. These runs check proof generation, verification, measurement, and artifact recovery. They do not measure x8i or Linux performance.

## 2^15 gates, update sizes 1–128

- Status: complete; 193/193 proof measurements verified.
- Benchmark elapsed time: 492.715 seconds (8.21 minutes), excluding compilation.
- Peak process RSS: 3.223 GiB.
- BN254, identity permutation, WHIR 64 first / 16 subsequent, 8 Rayon workers, seed 20260909.
- One full initial proof: 23.338 seconds; independent sequences of 12 updates for each size.
- Paired baseline mode: 96 baseline proofs and 96 updates, plus one initial proof.
- Recorded source-tree SHA256: `08c3a3740107c76196870721a8cafc9c0f8ee4c7eb126997af973fc08307cdfd`.
- [Result archive](../benchmark-results/ec2-rehearsal-n15.tar.gz), [raw timings](../benchmark-results/ec2-rehearsal-n15/samples.csv), [completion check](../benchmark-results/ec2-rehearsal-n15/validation.json).

| Updated gates | Baseline mean (s) | Update mean (s) | Baseline / update |
| ---: | ---: | ---: | ---: |
| 1 | 1.261469 | 0.141624 | 8.907 |
| 2 | 1.230994 | 0.263765 | 4.667 |
| 4 | 1.240330 | 0.508849 | 2.438 |
| 8 | 1.243511 | 0.995308 | 1.249 |
| 16 | 1.245918 | 2.021376 | 0.616 |
| 32 | 1.252271 | 4.202659 | 0.298 |
| 64 | 1.257113 | 7.454388 | 0.169 |
| 128 | 1.262182 | 12.772148 | 0.099 |

Each mean includes all twelve revisions, including the first and the expensive hierarchy compositions. The sequence average measures amortization over these twelve updates.

## 2^11 gates, all eleven update sizes

- Status: complete; 145/145 proof measurements verified.
- Benchmark elapsed time: 867.210 seconds (14.45 minutes), excluding compilation.
- Peak process RSS: 4.156 GiB.
- BN254, identity permutation, WHIR 64 first / 16 subsequent, 8 Rayon workers, seed 20260909.
- One full initial proof: 1.396474 seconds; eleven independent 12-update sequences.
- Shared baseline mode: 12 baseline proofs on the one-gate sequence, 132 updates and one initial proof.
- Recorded source-tree SHA256: `e6d2c1f808fe46e9c7f64fc9941253653d4d21c54f46e2d8c73f8d870a486d80`.
- [Result archive](../benchmark-results/ec2-rehearsal-n11.tar.gz), [raw timings](../benchmark-results/ec2-rehearsal-n11/samples.csv), [completion check](../benchmark-results/ec2-rehearsal-n11/validation.json).

| Updated gates | Shared baseline mean (s) | Update mean (s) |
| ---: | ---: | ---: |
| 1 | 0.080712 | 0.121928 |
| 2 | 0.080712 | 0.225694 |
| 4 | 0.080712 | 0.379549 |
| 8 | 0.080712 | 0.631049 |
| 16 | 0.080712 | 1.048982 |
| 32 | 0.080712 | 1.836041 |
| 64 | 0.080712 | 3.709780 |
| 128 | 0.080712 | 6.530137 |
| 256 | 0.080712 | 12.254171 |
| 512 | 0.080712 | 16.937480 |
| 1024 | 0.080712 | 27.896202 |

## Scope and checks

- The full 2^15 sweep projects 60.25 GiB peak and does not pass the 16 GiB Mac memory guard. The local trial is split across circuit sizes; a full 2^15 EC2 rehearsal is included in the guide.
- The 2^24 parameter/workload preflight succeeded without constructing the large proof tables. It projects 1,788 GiB peak; the first FFT domain is 2^28. Actual 2^24 memory and runtime have not been measured.
- Production WHIR configuration and commit/open/verify tests passed with the default features and with the 64-way experiment feature.
- Coordinate-only sparse-DAG estimates were checked against materialized DAGs and a materialized transition.
- Five Python result-validation tests passed, including exact sample counts, shared baseline comparisons, duplicate/unverified samples, missing records, and interrupted final writes.
- Both result archives were extracted separately. All sixteen file checksums matched for 2^15 and all seventeen matched for 2^11; completeness remained 193/193 and 145/145, respectively.
- A source archive was extracted separately and resolved with offline locked Cargo metadata, including the experiment target and vendored dependency patch.
- An actual full-2^15 launch was deliberately checked on the Mac: the memory guard refused it before proving, returned a failed status with zero verified samples, and preserved its diagnostics in a result archive.
- The Ubuntu bootstrap passes shell syntax validation. No EC2 host was provisioned or accessed during these local checks.
