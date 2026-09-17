# Optimized 2^15-gate sweep — September 9, 2026

All 193 proof measurements verified: one complete initial proof, 96 updates and 96 paired baseline proofs. The run contains twelve consecutive updates for each size 1, 2, 4, 8, 16, 32, 64 and 128; every size starts from the same fully proved initial state.

BN254, identity permutation, 256 public inputs, WHIR 64-way first interleaving / 16-way subsequent folding, seed 20260909, eight Rayon workers, Rust 1.92 release build. There are no discarded warmups. Verification and case-reset cloning are outside prover timers; indexing is recorded separately.

| Measurement | Previous run | Optimized run | Speedup |
| --- | ---: | ---: | ---: |
| Full initial proof | 23.338 s | 9.616 s | 2.43× |
| Baseline mean (96 proofs) | 1.249224 s | 0.297334 s | 4.20× |
| Entire benchmark, excluding compilation | 492.715 s | 142.296 s | 3.46× |
| Peak process RSS | 3.223 GiB | 3.661 GiB | — |

## Update means across all twelve revisions

| Updated gates | Previous mean (s) | Optimized mean (s) | Speedup |
| ---: | ---: | ---: | ---: |
| 1 | 0.141624 | 0.048874 | 2.90× |
| 2 | 0.263765 | 0.086271 | 3.06× |
| 4 | 0.508849 | 0.160281 | 3.17× |
| 8 | 0.995308 | 0.309109 | 3.22× |
| 16 | 2.021376 | 0.609847 | 3.31× |
| 32 | 4.202659 | 1.211283 | 3.47× |
| 64 | 7.454388 | 2.098099 | 3.55× |
| 128 | 12.772148 | 3.626651 | 3.52× |

## Included optimizations and comparison checks

- All 100 files in the latest optimization source manifest match this run, including the shared parallel prover code, streamed STIR query weights, field-aware WHIR scheduling, optimized scalar Poseidon recurrence, tighter local constraint degree and batched terminal column claims.
- The experiment JSON, full workload CSV and workload fingerprints match the previous 2^15 run exactly. Rust version, Cargo features, build flags and worker count also match. Source files remained unchanged during the run.
- The previous run is historical; this is one rerun, not an alternating repeated A/B study. The ratios describe these measured runs and include the combined implementation changes. They are not an EC2 scaling forecast.
- Peak RAM increased even though runtime fell. The tighter local degree also changes update-proof messages; this run generated fresh proofs and verified them with the current implementation.
- The individual records are in `samples.csv`, current baseline/update comparisons in `comparison.csv`, and old/new phase means in `before-after.csv`. `source.tar.gz` contains the current source, including the vendored p3-sumcheck patch.

## Reproduce

```bash
env -u DYNAMIC_SNARK_PROFILE -u DYNAMIC_SNARK_PROFILE_DETAIL \
  python3 scripts/run_experiment.py --trace-log 15 \
  --update-logs 0,1,2,3,4,5,6,7 --sequence-len 12 --seed 20260909 \
  --threads 8 --baseline-mode paired --offline \
  --output benchmark-results/ec2-rehearsal-n15-optimized-rerun
```
