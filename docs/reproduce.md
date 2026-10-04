# Reproduce the final paper experiments

The complete evaluated source is in `final/dynamic-ligerito/` and
`final/poseidon2b-compress-ligerito/`, with arithmetic and Ligerito vendored in
`vendor/flock-core/`. Each crate has its own lockfile. The recorded paper data
are in [results/paper](../results/paper/); [archive](../archive/) contains only
selected summaries of earlier Ligerito investigations.

## Recorded configuration

Ubuntu 24.04 x86-64, Rust 1.92.0, release mode, `-C target-cpu=native`, and
32 Rayon workers on an AWS r7a.8xlarge (AMD EPYC 9R14, 32 physical cores,
256 GiB RAM). The circuit has 2^23 arithmetic gates, half addition and half
multiplication, identity wiring, 256 fixed public inputs, and seed `20260909`.

Both provers use GF(2^128) and Ligerito Fast (rate 1/2, JohnsonOod,
100-bit per-round target). Relation trees use width-four Poseidon2b compression,
8 full and 58 partial rounds, an x^7 S-box, and a 32-byte digest. Initialization
and polynomial transitions use one round-33 checkpoint and the factored GKR
kernel. The suite uses a base-2 hierarchy and a 2 MiB direct tail.

## Install and build

Clone the public repository and run these commands from its root. Bootstrap
installs Ubuntu packages, the pinned Rust toolchain, plotting dependencies,
and locked Cargo dependencies, then builds the benchmark without running it.
Internet access is needed to install packages and fetch dependencies; subsequent
builds can use `--offline`.

```sh
bash scripts/bootstrap_ligerito_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
```

To build manually on a host with Rust 1.92.0 and Python already available:

```sh
cargo +1.92.0 fetch --locked --manifest-path final/dynamic-ligerito/Cargo.toml
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --release --locked --offline \
  --manifest-path final/dynamic-ligerito/Cargo.toml --bin whole_system
```

The default executable is `final/dynamic-ligerito/target/release/whole_system`.
Python plotting requires `matplotlib`; `--no-plot` disables plots while retaining
measurement and analysis files. The measurement, analysis, and validation tools
otherwise use the Python standard library.

## Rehearse and measure

Use a fresh absolute output directory for each run. A short rehearsal uses
2^10 gates and a 64 KiB tail to force promotions. It runs all three stages and
validates 777 proofs. The following rehearsal can run on a smaller development
machine; its 8 GiB cutoff must be at most 90% of detected physical/cgroup memory.

```sh
python3 final/dynamic-ligerito/scripts/ec2_suite.py \
  /tmp/dynamic-snarks-rehearsal --smoke --threads 8 --memory-limit-gib 8
```

For the full paper suite, use at least 240 GiB usable physical/cgroup memory,
swap disabled, and enough currently available RAM for the suite's preflight
estimate. Use 32 workers to match the paper. Do not run simultaneous benchmarks.
The suite checks memory estimates before launch and monitors process RSS with
a 216 GiB cutoff. The recorded maximum was 135.696 GiB; peaks vary with platform
and allocator. The cutoff is sampled every 100 ms.

```sh
BENCH_RESULTS="$HOME/bench-results/paper-ligerito"
python3 final/dynamic-ligerito/scripts/ec2_suite.py \
  "$BENCH_RESULTS/measurements" \
  --trace-log 23 --threads 32 --memory-limit-gib 216 --hierarchy-base 2
```

All stages run sequentially, each with full initialization:

| Stage | Updates | Baseline schedule | Verified samples |
|---|---|---|---:|
| sweep | 40 each at 1, 2, 4, 8, 16, 32, 64, 128 gates | Every revision for every size | 641 |
| one-gate | 10,000 one-gate revisions | Revision 1 and every 100 revisions | 10,102 |
| 128-gate | 1,000 128-gate revisions | Revision 1 and every 10 revisions | 1,102 |

The sweep restarts each size from a copy of the same proved initial state. Both
long stages measure every dynamic update and use 101 fresh baseline proofs.
Every full retained dynamic proof is verified; saved checkpoints are also
serialized, decoded, and reverified. The runner prints `SUITE_COMPLETE` only
after the analysis validates all 11,845 samples.

## Validate and interpret results

```sh
jq -e '.status == "complete" and .verified_samples == 11845' \
  "$BENCH_RESULTS/measurements/status.json"
jq -e '.complete and .verified_samples == 641' \
  "$BENCH_RESULTS/measurements/sweep/validation.json"
jq -e '.verified_samples == 10102' \
  "$BENCH_RESULTS/measurements/one-gate/summary.json"
jq -e '.verified_samples == 1102' \
  "$BENCH_RESULTS/measurements/128-gate/summary.json"
```

`sweep/comparison.csv` reports paired mean/max prover time, verification time,
and complete serialized proof size. Each long stage contains `curve.csv` with
every integer prefix, `summary.json` with promotions and break-even points, and
PNG/SVG/PDF plots. Raw measurements, workload fingerprints, memory samples,
setup costs, logs, and proof checkpoints are under each stage's `run-a/`.

Sweep speedup excludes initialization. Long-sequence speedup is
`n * mean(sampled baseline prover time) / (initialization + sum(update[1:n]))`.
Baseline totals are estimated from the sampled mean; every dynamic timing is
measured. A second curve adds measured indexing once on both sides. Prover
curves exclude verification, serialization, workload generation, and I/O.

The original measured paper data can be checked without Rust or a benchmark host:

```sh
python3 results/paper/verify.py
```

Public raw samples are losslessly gzip-compressed. Analysis tools support both
plain `samples.jsonl` from new runs and `samples.jsonl.gz` from published data.
Original execution source hashes and binary hashes remain provenance records;
relocation and source cleanup change the current source inventory. Floating-point
timings depend on hardware and load, so successful reproduction means the same
workload, verified proofs, and accounting, rather than identical timings or
executable hashes.

## Resume and package

Repeat the same suite command with `--resume` to reuse validated completed
stages. A partial trajectory cannot recover its in-memory prover state and must
restart from initialization; preserve or remove the incomplete stage directory
before retrying. `suite-config.json` and the frozen binary must match.

`scripts/package_ligerito_ec2.py` packages the final sources for transfer, and
`scripts/run_ligerito_ec2.sh` adds rehearsal, native 2^20 memory calibration,
and a sealed result archive. Run the bootstrap first when using that wrapper.
A normal clone can also run the suite directly, as above.

See [publication notes](../PUBLICATION.md) for preparing a clean source snapshot
without local build products, private metadata, or the existing Git history.
