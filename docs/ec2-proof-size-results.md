# Proof sizes and prover times: 2^15 rehearsal

The September 9, 2026 run completed all **193 verified samples** and saved **17
proof checkpoints**. It used 32,768 gate rows, BN254, identity wiring, first
interleaving 64 and later folding 16, eight Rayon workers, seed 20260909, and
independent sequences of 12 updates for each size. Baselines were paired with
each updated witness. The workload and all 80 production source/vendor files
match the preceding optimized rerun.

## Full proof sizes

One MiB is 1,048,576 bytes. **Payload** counts every BN254 element and every
BLAKE3 digest at 32 bytes each, including Merkle authentication paths, opened
leaves, sumcheck messages and commitments. Poseidon roots and siblings are
already included in the BN254 count. **Complete CBOR** is the actual
uncompressed serialized file size, including all indices, dimensions, tags and
encoding overhead. It uses the existing Serde representations, which do not
minimize byte-array encoding. Both measurements are recorded; payload alone is
not a complete wire-format size.

| Proof | BN254 elements | BLAKE3 digests | Payload (MiB) | Complete CBOR (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Baseline HyperPlonk (mean of 96) | 33,708 | 8,018 | 1.273 | 1.599 |
| Dynamic initial | 50,375 | 15,083 | 1.998 | 2.593 |
| After 12 × 1-gate updates | 95,078 | 24,867 | 3.660 | 4.661 |
| After 12 × 2-gate updates | 97,920 | 27,147 | 3.817 | 4.895 |
| After 12 × 4-gate updates | 100,232 | 29,203 | 3.950 | 5.097 |
| After 12 × 8-gate updates | 102,544 | 31,396 | 4.088 | 5.310 |
| After 12 × 16-gate updates | 104,856 | 33,726 | 4.229 | 5.528 |
| After 12 × 32-gate updates | 107,168 | 36,193 | 4.375 | 5.755 |
| After 12 × 64-gate updates | 108,101 | 37,367 | 4.439 | 5.859 |
| After 12 × 128-gate updates | 109,480 | 38,797 | 4.525 | 5.992 |

Each updated row measures the **whole proof retained at revision 12**, including
the initial HyperPlonk proof, initial Merkle CAIR, active transition proofs,
hierarchy commitments and public-input multiproof. It is neither a sum nor an
average of the twelve revision sizes. Separately supplied public inputs,
verification keys, witness and prover state are excluded. All dynamic rows
contain 537 Poseidon roots/digests, as a subset of their BN254 counts.

For example, the final 128-gate case contains the following components:

| Component | Payload bytes | Serialized bytes |
| --- | ---: | ---: |
| Hierarchy commitments | 576 | 883 |
| Retained initial HyperPlonk proof | 1,335,264 | 1,676,407 |
| Retained initial Merkle CAIR | 742,208 | 1,011,764 |
| Active transition proofs | 2,650,208 | 3,563,644 |
| Public-input Merkle multiproof | 16,608 | 29,897 |
| Outer map/key framing | 0 | 79 |
| **Total** | **4,744,864** | **6,282,674** |

The baseline payload was exactly 1,335,232 bytes for every sample; CBOR sizes
varied slightly with hash-byte values. The initial proof was 2,094,656 payload
bytes and 2,719,048 serialized bytes.

## Prover times from the same run

Initial proving took **9.867664 seconds**. The baseline mean over all 96 proofs
was **0.344584 seconds**. Each row below averages exactly twelve revisions.
Serialization, counting and checkpoint decode/verification are outside these
timers.

| Updated gates per revision | Paired baseline mean (s) | Dynamic update mean (s) |
| ---: | ---: | ---: |
| 1 | 0.299840 | 0.048250 |
| 2 | 0.295940 | 0.087168 |
| 4 | 0.303801 | 0.163128 |
| 8 | 0.298275 | 0.310462 |
| 16 | 0.295822 | 0.607213 |
| 32 | 0.319123 | 1.287537 |
| 64 | 0.300080 | 2.146373 |
| 128 | 0.643794 | 3.993144 |

The 128-gate baseline includes a 4.367154-second sample at revision 8, compared
with roughly 0.30 seconds for its other revisions. It remains in the requested
twelve-sample average; the cause was not established. Use the raw measurements
and the [preceding optimized timing comparison](../benchmark-results/ec2-rehearsal-n15-optimized-20260909/before-after.md)
when assessing laptop timing variability.

Total benchmark process wall time was **162.930 seconds** and peak RSS was
**3.326 GiB**. These include proof serialization and checkpoint checks but exclude
compilation and final archive packaging. They do not establish EC2 performance.

## Validation and artifacts

All 193 generated proofs verified. The initial proof and the final baseline and
dynamic proof for each of eight cases were additionally decoded and verified
before saving. Component totals match each complete proof. A separate archive
extraction passed all 38 original file checksums and all 108 source-file hashes;
the result archive also includes the subsequent audit report. All final proofs
retain the same initial proof and CAIR component sizes. The Rust serialization
and twelve-update round-trip tests passed (2 tests), as did the result-validation
tests (9 tests).

- [Result archive, including proof files](../benchmark-results/ec2-proof-sizes-n15-20260909.tar.gz)
- [Proof-size comparison](../benchmark-results/ec2-proof-sizes-n15-20260909/proof-size-comparison.csv)
- [Individual measurements](../benchmark-results/ec2-proof-sizes-n15-20260909/samples.csv)
- [Component breakdown](../benchmark-results/ec2-proof-sizes-n15-20260909/proof-components.csv)
- [Prover-time comparison](../benchmark-results/ec2-proof-sizes-n15-20260909/comparison.csv)
- [Completion validation](../benchmark-results/ec2-proof-sizes-n15-20260909/validation.json)
- [Artifact audit](../benchmark-results/ec2-proof-sizes-n15-20260909/artifact-audit.json)

The recorded benchmark source-tree SHA256 is
`88a48acbd8e79ef7b7345474d16b18d7924917cfb311e7b4b78f8c0f2fb0238d`.

## Applying this to 2^24 on EC2

The [EC2 step-by-step guide](ec2-2p24-experiment.md) now records proof sizes
automatically with the same run commands. The default shared-baseline sweep
through 1,024 updated gates produces 145 size/timing samples and 13 saved
checkpoints: one initial, one baseline and eleven final dynamic proofs. Every
final proof is measured after its own sequence of twelve updates.

The updated 2^24 preflight passed with 96 configured Rayon workers, all eleven
update sizes and the same field/interleaving settings. It generated no proofs;
actual 2^24 proof sizes, memory and timings still require the EC2 run.

Use the [new source package with proof-size recording](../benchmark-results/ec2-experiment-source-with-proof-sizes-20260909.tar.gz)
or create a fresh package using the guide. Earlier source packages predate this
instrumentation. The new package includes the benchmark changes, locked CBOR
dependency, optimizations and updated guide. The exact source used for the local
measurement remains preserved separately in its result archive.
