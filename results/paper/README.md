# Final paper experiments

These are the authoritative measurements for the current paper: a 40-revision update-size sweep, 10,000 one-gate updates and 1,000 128-gate updates, each starting from a separate complete dynamic initialization. The circuit has 2^23 = 8,388,608 identity-wired gates and 256 fixed public inputs. Every one of the **11,845 measured proofs was verified** by the benchmark.

The shared backend uses GF(2^128), 64-byte Poseidon2b compression, one committed checkpoint after round 33, factored hash sumcheck coefficients and Ligerito Fast. The hierarchy has base 2 and a 2 MiB accumulated direct tail. The measured host was an r7a.8xlarge with AMD EPYC 9R14, 32 physical-core workers and 256 GiB RAM, running Ubuntu 24.04 x86-64. Rust 1.92.0 release code used `-C target-cpu=native`.

| Experiment | Gates per update | Updates | Baseline proofs | Verified proofs |
|---|---|---:|---:|---:|
| [Sweep](sweep/) | 1, 2, 4, 8, 16, 32, 64, 128 | 40 per size | 320 paired proofs | 641 |
| [One gate](one-gate/README.md) | 1 | 10,000 | 101 sampled proofs | 10,102 |
| [128 gates](128-gate/README.md) | 128 | 1,000 | 101 sampled proofs | 1,102 |

The sweep pairs a freshly recomputed full HyperPlonk proof with every dynamic revision. The long trajectories sample the baseline at revision 1 and every 100 or 10 revisions, respectively. The baseline estimate at prefix `n` is `n * mean(sampled baseline prover time)`. Dynamic totals include the full initialization and every measured update, promotion and hierarchy merge; the setup-inclusive curves also add measured indexing once on each side.

| Long trajectory | Initialization (s) | Total update proving (s) | Final speedup including initialization | Final speedup including indexing | Promotions |
|---|---:|---:|---:|---:|---:|
| One gate | 311.266 | 232.178 | 147.419× | 144.324× | 4 |
| 128 gates | 310.061 | 358.153 | 11.674× | 11.478× | 52 |

These are observed single-run results over the stated windows. Maximum benchmark-process RAM was **135.696 GiB**, measured as the larger of Linux `wait4` peak RSS and 100 ms RSS samples. Compilation and other processes are excluded.

The [main README](../../README.md) explains the workload, timers, proof-size convention, limitations and complete reproduction commands. To check this published evidence without a Rust build or external Python packages, run from the repository root:

```sh
python3 results/paper/verify.py
```

The audit checks lossless raw-record SHA-256 digests, all 11,845 recorded verification flags, exact revision/baseline coverage, suite and hash configuration, sweep aggregates, every cumulative prefix, promotion revisions and memory peaks. It audits recorded evidence; running the Rust experiment suite generates and cryptographically verifies new proofs.

| Public path | Contents |
|---|---|
| `suite-config.json`, `memory-plan.json`, `status.json` | Frozen suite settings, RAM plan and completion record |
| `metadata.json`, `source-manifest.json` | Host/build context and exact original source-snapshot provenance |
| `audit.json`, `memory-report.json`, `memory.*` | Original independent audit and memory findings/plots |
| `environment/` | Native compiler, CPU/NUMA and test provenance |
| Each stage's `run-a/samples.jsonl.gz` | Every original measured timing and proof-statistics record, losslessly compressed |
| Each stage's `run-a/` JSON and `memory-samples.csv` | Run/setup/hash/PCS configuration, workload fingerprints and measured RSS |
| `sweep/comparison.csv`, `sweep/validation.json`, `sweep/sweep.*` | Paired sweep aggregates, completeness checks and plots |
| Long stage's `curve.csv`, `summary.json`, `speedup.*` | All integer prefixes, maxima/break-even/promotions and plots |
| `checksums.json` | SHA-256/byte counts for the public files, plus original raw-record digests |

The public layout flattens the original run's `measurements/` directory: original `measurements/sweep`, `measurements/one-gate` and `measurements/128-gate` map directly to the three stage directories here. Metric values, trajectories and plot data are unchanged. `samples.jsonl.gz` decompresses byte-for-byte to each original `samples.jsonl`; duplicate stdout, proof-checkpoint binaries, native executables, backup bundles, rehearsal copies and remote orchestration records were removed. New reproduction runs recreate proof checkpoints and native binaries.

The original source-tree SHA-256 is `a92422f12b6b8bb3c379897a6b7f726de6aa5effeefd85666bff12b283253bed`, and the measured native binary SHA-256 is `d45675391706555b49937b05b54133af9a2f58c8670f04fb416cd8e1cf5db693`. [source-manifest.json](source-manifest.json) records the original per-file source hashes. Repository publication cleanup changes paths, documentation and result handling, so a newly packaged public checkout can have a different source-tree digest. Rebuild for the target CPU when reproducing.

Earlier investigations are separately described under [archive/results](../../archive/results/README.md); their selected summaries are outside the final paper measurements.
