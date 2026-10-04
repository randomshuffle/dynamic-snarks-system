# Final paper implementation

- [dynamic-ligerito](dynamic-ligerito/): full dynamic SNARK, ordinary HyperPlonk
  baseline, and the runner for the sweep, 10,000 one-gate updates, and 1,000
  128-gate updates.
- [poseidon2b-compress-ligerito](poseidon2b-compress-ligerito/): the width-four
  Poseidon2b compression, shared GF(2^128)/PCS helpers, and independent hash
  reference tests used by the dynamic system.

These are standalone Rust crates with their own committed lockfiles. Build from
the repository root using `--manifest-path final/dynamic-ligerito/Cargo.toml`.
The arithmetic/PCS dependency is vendored under `vendor/flock-core/`. No final
source depends on archived experiments.

See the [main README](../README.md) and [reproduction guide](../docs/reproduce.md)
for exact parameters, commands, and recorded results. Historical implementations
and tuning benchmarks are in [archive](../archive/).
