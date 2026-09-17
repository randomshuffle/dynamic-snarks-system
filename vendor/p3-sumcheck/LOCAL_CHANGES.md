# Local scheduling and STIR accumulation changes

Based on the published `p3-sumcheck` 0.6.2 crate. Two Rust files differ:

- `src/strategy.rs`: coefficient reductions use a field-size-aware parallel
  work threshold instead of the fixed element-count cutoff. Both prefix and
  suffix kernels use `max(8, 4096 / size_of::<B>())` pairs. BN254 therefore
  switches at 128 pairs. Rayon uses the configured worker pool.
- `src/constraints/statement/select.rs`: scalar STIR constraints accumulate
  weighted query powers in disjoint output blocks. Each task seeds the powers
  at its starting index and advances them while summing. This eliminates the
  full `2^k × query_count` power matrix, uses O(query_count) scratch per active
  task, and takes one multiplication per query/output to advance powers after
  block seeding. The generic SIMD-packed path is unchanged; BN254 uses scalar
  packing. Task size adapts to the worker count and number of queries.

No CPU model or worker limit is hard-coded. Field results, interpolation, proof
format, variable order, and transcripts are unchanged. Workspace tests compare
both coefficient kernels with scalar sums at threshold/tile boundaries, compare
STIR weights against direct powers including zero/unit challenges, duplicate
queries and nonzero accumulators, and compare complete baseline, initial and
update proofs across 1, 8 and 96 workers. The patch applies equally to every
proof path through `[patch.crates-io]`.
