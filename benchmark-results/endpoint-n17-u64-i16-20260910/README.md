# 2^17 gates, updates through 64: endpoint-GKR sweep

Completed September 10, 2026: **97/97 verified proof measurements**, with all
97 proof sizes recorded and **nine saved proof checkpoints**. The full benchmark
process ran for **143.578 seconds** (2.39 minutes).

## Configuration

- 131,072 gates; BN254; identity permutation; 256 public inputs, each equal to nine.
- WHIR interleaving **16 in the first round and 16 thereafter**, fixed half-rate,
  configured security target 127 bits, and zero proof-of-work bits.
- Default endpoint-GKR initial and update PIOPs, with **eight Rayon workers**.
- One complete initial proof. Each of seven update sizes starts from this same
  fully proved state and applies twelve consecutive random updates.
- Update sizes: **1, 2, 4, 8, 16, 32, 64 gates**; seed **20260909**.
- The shared baseline contains twelve complete regular HyperPlonk proofs on the
  one-gate sequence; their mean is the reference for all seven sizes.
- No checkpoint/recomputation or other prover algorithm changes were made for
  this run. The captured production source files remained unchanged.

## Prover times and complete proof sizes

Prover and verifier timers exclude serialization, size counting and the extra
checkpoint decode/verification checks. Initial time is one observation; baseline
and update times are means across twelve revisions. Update proof sizes are the
**entire retained proof after revision twelve** of that case, including the
initial proof, initial Merkle CAIR, active transitions and public-input multiproof.

| Proof / updated gates per revision | Prover time (s) | Field/hash payload (MiB) | Complete CBOR (MiB) |
| --- | ---: | ---: | ---: |
| Baseline HyperPlonk, mean | 1.373418 | 1.070 | 1.573 |
| Dynamic initialization | 42.638832 | 1.752 | 2.478 |
| 1 | 0.083386 | 3.001 | 4.162 |
| 2 | 0.133065 | 3.154 | 4.388 |
| 4 | 0.221329 | 3.358 | 4.682 |
| 8 | 0.396130 | 3.553 | 4.968 |
| 16 | 0.722344 | 3.683 | 5.166 |
| 32 | 1.404313 | 3.830 | 5.388 |
| 64 | 2.672378 | 4.051 | 5.715 |

One MiB is 1,048,576 bytes. Payload counts all BN254 elements and BLAKE3 digests
at 32 bytes each, including Merkle paths, opened leaves, commitments and sumcheck
messages. Poseidon roots and siblings are included once in the field count.
Complete CBOR adds indices, dimensions, tags and encoding overhead; it uses the
existing Serde representations rather than a minimized protocol encoding.
Separately supplied public inputs, verification keys, witness and prover state
are excluded from proof size.

These are twelve sequential updates rather than independent repetitions of the
whole experiment. Composition cost varies by revision. All measured revisions
remain in the means. Previous scalar-trace/64-way runs used different protocol
settings and circuit sizes, so they are not matched performance comparisons.

## Memory

The benchmark child's macOS `wait4().ru_maxrss` reports **3,117,940,736
bytes = 2.904 GiB = 3.118 decimal GB** peak
resident memory. This is below both an 8 GiB and an 8 billion-byte RSS ceiling.
The compiler's memory is excluded. The benchmark total includes indexing,
serialization and checkpoint validation, while compilation and final packaging
are outside its process wall time.

RSS measures resident pages. It does not include compressed or swapped-out pages
and does not establish the absence of memory compression or paging. Those were
not instrumented in this run. The current initial prover still constructs 65
width-three state layers, representing 6.094 GiB of field buffers at this circuit
size. The conservative preflight estimate is 7.3125 GiB. These allocation and
planning quantities differ from the recorded resident-memory high-water mark;
the low RSS should not be extrapolated as a new allocation bound for larger runs.

## Validation and artifacts

All original proofs verified. The initial proof, the final baseline and the seven
final dynamic proofs were also decoded and verified before saving. The component
counts and bytes sum to each saved complete proof. Separate archive extraction
validated all 30 original result-file checksums and all
117 captured source-file hashes. The archive was repacked with this report
and its audit record after the run; timing and proof data were retained unchanged.

- [Individual timings, field/hash counts and proof sizes](samples.csv)
- [Prover-time comparison](comparison.csv)
- [Proof-size comparison](proof-size-comparison.csv)
- [Component breakdown](proof-components.csv)
- [Actual resource measurement](resources.json)
- [Completion validation](validation.json)
- [Artifact audit](artifact-audit.json)
- [Configuration](experiment.json), [host and source manifest](metadata.json)
- Saved proofs are under `proofs/`; the exact measured sources are in `source.tar.gz`.

Source-tree SHA256: `c43e70fd119f4b9543b5e44023e139e9f5104a7e7a8e2a8364cb5b2fd9890080`.

## Reproduction

```bash
env -u DYNAMIC_SNARK_PROFILE -u DYNAMIC_SNARK_PROFILE_DETAIL \
  python3 scripts/run_experiment.py --trace-log 17 --threads 8 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6 \
  --sequence-len 12 --seed 20260909 --baseline-mode shared --offline \
  --output "benchmark-results/endpoint-n17-u64-$(date -u +%Y%m%dT%H%M%SZ)"
```

Each run requires a new output directory and creates a sibling `.tar.gz` archive.
