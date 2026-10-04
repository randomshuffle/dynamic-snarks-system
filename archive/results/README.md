# Historical experiments and results

The three final paper experiments are in [results/paper](../../results/paper/README.md), with complete measured timing records, configurations, validation and plots.

This archive keeps short descriptions and selected small aggregate summaries or plots from the GF(2^128)/Poseidon2b/Ligerito investigations beginning September 19. Earlier BN254/WHIR experiments and results were removed. Historical raw trajectories, binaries, proof checkpoints, source snapshots, logs and backup bundles were also removed; these summaries do not provide complete historical-run reproductions.

| Directory | Experiment |
|---|---|
| [2026-09-19-dynamic-ligerito](2026-09-19-dynamic-ligerito/EXPERIMENT.md) | Early complete Ligerito sweeps |
| [2026-09-19-hash-checkpoints](2026-09-19-hash-checkpoints/EXPERIMENT.md) | BN254 hash checkpoint comparison |
| [2026-09-19-hash-compression64](2026-09-19-hash-compression64/EXPERIMENT.md) | 64-byte hash compression comparison |
| [2026-09-19-hash-proving](2026-09-19-hash-proving/EXPERIMENT.md) | Standalone hash prover survey |
| [2026-09-19-poseidon2b-ligerito](2026-09-19-poseidon2b-ligerito/EXPERIMENT.md) | Binary-field Poseidon2b/Ligerito pilot |
| [2026-09-20-checkpoint-profiles](2026-09-20-checkpoint-profiles/EXPERIMENT.md) | Hash checkpoint profiling |
| [2026-09-20-dynamic-ligerito-n19](2026-09-20-dynamic-ligerito-n19/EXPERIMENT.md) | 2^19-gate Ligerito one-gate pilot |
| [2026-09-20-factored-default](2026-09-20-factored-default/EXPERIMENT.md) | Factored-kernel correctness validation |
| [2026-09-20-hash-granularity](2026-09-20-hash-granularity/EXPERIMENT.md) | Hash parallelism granularity A/B |
| [2026-09-20-ligerito-update-profile](2026-09-20-ligerito-update-profile/EXPERIMENT.md) | Ligerito update bottleneck profile |
| [2026-09-20-n20-memory-preflight](2026-09-20-n20-memory-preflight/EXPERIMENT.md) | 2^20-gate memory preflight |
| [2026-09-20-poseidon2b-parameters](2026-09-20-poseidon2b-parameters/EXPERIMENT.md) | Exploratory Poseidon2b round selection |
| [2026-09-20-sumcheck-kernels](2026-09-20-sumcheck-kernels/EXPERIMENT.md) | Hash sumcheck kernel comparison |
| [2026-09-21-direct-tail](2026-09-21-direct-tail/EXPERIMENT.md) | Direct-tail implementation validation |
| [2026-09-21-direct-tail-400](2026-09-21-direct-tail-400/EXPERIMENT.md) | Direct-tail cap comparison over 400 updates |
| [2026-09-21-direct-tail-matrix](2026-09-21-direct-tail-matrix/EXPERIMENT.md) | Direct-tail cap comparison over 40 updates |
| [2026-09-21-plaintext-budget](2026-09-21-plaintext-budget/EXPERIMENT.md) | Per-transition plaintext budget validation |
| [2026-09-21-plaintext-profile](2026-09-21-plaintext-profile/EXPERIMENT.md) | Plaintext update profiling |
| [2026-09-21-split-oracles](2026-09-21-split-oracles/EXPERIMENT.md) | Split update-oracle layout A/B |
| [2026-09-21-update-polynomial-profile](2026-09-21-update-polynomial-profile/EXPERIMENT.md) | One-gate and 32-gate transition profiles |
| [2026-09-22-64-gate-amortization](2026-09-22-64-gate-amortization/EXPERIMENT.md) | Partial 64-gate amortization sequence |
| [2026-09-22-baseline-comparison](2026-09-22-baseline-comparison/EXPERIMENT.md) | 2 MiB tail versus sampled full baselines |
| [2026-09-22-compute-keccak](2026-09-22-compute-keccak/EXPERIMENT.md) | Cancelled large compute-then-prove trial |
| [2026-09-22-compute-keccak-n16](2026-09-22-compute-keccak-n16/EXPERIMENT.md) | 65,536-hash compute-then-prove comparison |
| [2026-09-22-flock-poseidon](2026-09-22-flock-poseidon/EXPERIMENT.md) | Flock-style PIOP versus checkpointed GKR |
| [2026-09-22-gkr-packing](2026-09-22-gkr-packing/EXPERIMENT.md) | Hash checkpoint packing experiment |
| [2026-09-22-gkr-protocol-ablations](2026-09-22-gkr-protocol-ablations/EXPERIMENT.md) | GKR Frobenius and checkpoint ablations |
| [2026-09-22-hash-scaling](2026-09-22-hash-scaling/EXPERIMENT.md) | Standalone hash prover scaling |
| [2026-09-22-one-gate-amortization](2026-09-22-one-gate-amortization/EXPERIMENT.md) | Early one-gate amortization sequence |
| [2026-09-23-hierarchy-growth](2026-09-23-hierarchy-growth/EXPERIMENT.md) | Hierarchy bases 4 and 8 comparison |
| [2026-09-27-i4i-preparation](2026-09-27-i4i-preparation/EXPERIMENT.md) | Initial EC2 paper-suite preparation |
| [2026-09-27-r7a-n19](2026-09-27-r7a-n19/EXPERIMENT.md) | EC2 2^19-gate suite pilot |
| [2026-09-27-r7a-n23](2026-09-27-r7a-n23/EXPERIMENT.md) | Interrupted first 2^23-gate EC2 launch |
| [2026-09-27-r7a-n23-additional](2026-09-27-r7a-n23-additional/EXPERIMENT.md) | Additional 2–64-gate long trajectories |
| [2026-09-27-r7a-n23-retry1](2026-09-27-r7a-n23-retry1/EXPERIMENT.md) | Original completed paper-suite provenance |
| [2026-09-27-r7a-preparation](2026-09-27-r7a-preparation/EXPERIMENT.md) | AMD r7a paper-suite preparation |
