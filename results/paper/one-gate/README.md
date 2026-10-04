# 1-gate update amortization

The maximum over revisions 1–10,000 is **147.419× at 10,000 updates**. At 10,000 updates the speedup is **147.419×**. This is the observed maximum in this run and window, not a claim about larger update counts or a noise-free optimum.

Including circuit setup on both sides as well, the maximum is **144.324× at 10,000 updates**, and the final speedup is **144.324×**. This adds 11.672271 s to the dynamic total and 2.830866 s to the baseline total. The first setup-inclusive break-even is revision 40. The dashed curve includes these costs; the solid curve follows the existing prover-time convention.

![Initialization-inclusive cumulative speedup](speedup.png)

Formula: `n * mean(sampled baseline) / (initial + sum(update[1:n]))`. The numerator uses update count times sampled baseline mean. The baseline mean is 8011.393 ms from 101 fresh proofs of this same update trajectory. With a sampled baseline, its mean is fixed across the curve, so it scales the speedup but does not determine the maximizing revision.

Initialization took 311.265688 s. Every one of the 10,000 dynamic updates was measured, including 4 polynomial promotions and their hierarchy merges. No dynamic timings are extrapolated. One full dynamic initialization is charged to the sequence; the baseline proves each updated state and is charged no extra initial-state proof, matching the preceding baseline comparison.

First break-even: **39 updates**. Speedup stays at least 1× through the end from revision **39**.

| Prefix | Baseline total (s) | Dynamic including init (s) | Amortized dynamic (ms/update) | Speedup |
| --- | ---: | ---: | ---: | ---: |
| 1 | 8.011 | 311.266 | 311265.969 | 0.026× |
| 10 | 80.114 | 311.269 | 31126.872 | 0.257× |
| 40 | 320.456 | 311.280 | 7781.995 | 1.029× |
| 100 | 801.139 | 311.312 | 3113.117 | 2.573× |
| 400 | 3204.557 | 311.805 | 779.513 | 10.277× |
| 1,000 | 8011.393 | 316.028 | 316.028 | 25.350× |
| 2,000 | 16022.786 | 341.387 | 170.693 | 46.934× |
| 5,000 | 40056.965 | 417.681 | 83.536 | 95.903× |
| 10,000 | 80113.930 | 543.444 | 54.344 | 147.419× |

Circuit: 2^23 = 8,388,608 gates, half addition and half multiplication, identity wiring, 256 public inputs, seed 20260909. Each revision selects 1 distinct gates uniformly without replacement and supplies the complete three-wire tuple of every selected gate. A gate can recur in later revisions. Full ordinary HyperPlonk and the dynamic system both use the existing native GF(2^128) / Ligerito Fast configuration.

The run used 32 workers, a 2048 KiB direct-tail cap, and a base-2 hierarchy with up to 1 tables per size level, and baseline cadence 100 (also including both endpoints). Sampled-pair execution order alternates. Timers include witness construction and hierarchy work; setup/indexing, verification, serialization, statistics, workload generation and I/O are outside the prover timers. `setup.json` records indexing costs separately; the setup-inclusive curve adds these measured costs once on each side. All timings are retained; there are no discarded warmups.

All 10,102 measured proofs verified. The existing runner also serializes, decodes and reverifies initialization, baseline snapshots, polynomial promotions, and first/final dynamic proofs. `curve.csv` contains all integer prefixes; `summary.json` contains the exact maximum, promotion revisions, memory measurements and run metadata. `run-a/` retains raw evidence.
