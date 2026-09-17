# 2^18 gates, updates through 64: monitored local sweep

Completed September 10, 2026: **97/97 proof measurements verified**, with sizes
for all proofs and **nine saved binary proof checkpoints**. Runtime was
**212.879 seconds** (3.55 minutes), excluding compilation and packaging.

**Memory footprint reached 13.303 GiB (14.283 decimal GB).**
This exceeds the earlier 8 GB footprint target. The run stayed below its explicit
8 billion-byte RSS cutoff: kernel peak RSS was 3.272 GiB.
RSS alone understates the memory charged to this task on macOS.

## Configuration and method

- 262,144 gate rows; BN254; identity permutation; 256 public inputs equal to nine.
- First interleaving 16, subsequent folding 16; rate 1/2 in each WHIR round;
  configured security target 127 bits and zero proof-of-work bits.
- Eight Rayon workers; default endpoint-GKR initial and update PIOPs.
- One complete initial proof; seven independent sequences of twelve random
  updates, with sizes 1, 2, 4, 8, 16, 32 and 64 gates. Seed 20260909.
- Twelve shared baseline HyperPlonk proofs on the one-gate sequence, used as the
  reference for all update sizes. Total: one initial, twelve baseline and 84 updates.
- All 83 production source/vendor files match the preceding 2^17 run.
  No checkpointing, recomputation or other prover algorithm changes were made.
- The launcher sampled this process every 0.2 seconds using macOS
  `proc_pid_rusage`, recording resident size and physical footprint. An explicit
  RSS-monitored mode permitted the trial despite its 14.625 GiB planning estimate
  exceeding the default 11.2 GiB allowance. The normal guard remains unchanged.

Monitoring runs outside the prover process. It introduces a small amount of
concurrent diagnostic activity, which was absent from the preceding 2^17 run.
No claim of zero monitoring overhead or absence of paging is made. The sampled
cutoff is a stop condition, not an OS-enforced hard allocation limit; transient
overshoot is possible. Neither sampled RSS nor the kernel RSS high-water mark
exceeded the cutoff in this run.

## Timing and proof-size results

Prover times are means of twelve revisions except for the single initialization.
The updated proof size is the **entire retained proof after revision twelve**,
including the initial arithmetic proof, initial Merkle CAIR, active transitions,
commitments and public-input Merkle multiproof. Baseline size is its twelve-proof
mean; initialization size is measured once.

| Phase / update size | Prover time (s) | Field/hash payload (MiB) | Complete CBOR (MiB) |
| --- | ---: | ---: | ---: |
| Initial computation | 91.328120 | 1.876 | 2.673 |
| Baseline HyperPlonk | 2.647023 | 1.145 | 1.698 |
| 1 gates | 0.097155 | 3.125 | 4.357 |
| 2 gates | 0.166789 | 3.278 | 4.583 |
| 4 gates | 0.231025 | 3.482 | 4.876 |
| 8 gates | 0.407157 | 3.678 | 5.162 |
| 16 gates | 0.727949 | 3.807 | 5.360 |
| 32 gates | 1.407029 | 3.954 | 5.583 |
| 64 gates | 2.724652 | 4.175 | 5.909 |

Payload counts each BN254 element and BLAKE3 digest at 32 bytes, including
Merkle authentication paths, opened leaves, commitments and sumcheck messages.
Poseidon roots and digests are included in the field count. Complete CBOR also
includes indices, dimensions, tags and encoding overhead; it is not a minimized
protocol encoding. One MiB is 1,048,576 bytes. Public inputs supplied separately,
verification keys, witness and retained prover state are excluded from proof size.
Serialization, size accounting and extra checkpoint decode/verification checks
are outside the reported prover and verifier timers.

## Comparison with 2^17 gates

Both runs use the same production source, protocol settings, worker count and
update-size/revision schedule. The circuit size and random positions differ.
The new run includes external memory monitoring. These are individual sequences,
not repeated trials establishing confidence intervals or isolated scaling laws.

| Phase / update size | 2^17 prover (s) | 2^18 prover (s) | Time ratio |
| --- | ---: | ---: | ---: |
| Initial computation | 42.638832 | 91.328120 | 2.142 |
| Baseline HyperPlonk | 1.373418 | 2.647023 | 1.927 |
| 1 gates | 0.083386 | 0.097155 | 1.165 |
| 2 gates | 0.133065 | 0.166789 | 1.253 |
| 4 gates | 0.221329 | 0.231025 | 1.044 |
| 8 gates | 0.396130 | 0.407157 | 1.028 |
| 16 gates | 0.722344 | 0.727949 | 1.008 |
| 32 gates | 1.404313 | 1.407029 | 1.002 |
| 64 gates | 2.672378 | 2.724652 | 1.020 |

## Memory results

| Metric | Bytes | GiB |
| --- | ---: | ---: |
| Kernel peak RSS (`wait4`) | 3,512,795,136 | 3.272 |
| Peak sampled RSS | 3,489,660,928 | 3.250 |
| Peak sampled physical footprint | 14,283,484,928 | 13.303 |
| Conservative allocation preflight | 15,703,474,176 | 14.625 |

RSS counts resident pages. macOS footprint accounting includes memory charged
to the process that can be compressed; it is a different measure. The footprint
peak is sampled and may miss short-lived peaks. No swap-traffic counter was
collected, so these results cannot identify how much of the difference came
from compression or paging.

The previous 2^17 run recorded only kernel peak RSS (2.904 GiB), so its physical
footprint cannot be reconstructed from that measurement. Its initial state
layers alone represent 6.094 GiB of field storage. The 2^18 layers represent
12.1875 GiB. These results support keeping 2^17 as the smaller planned workload
for the earlier memory budget; they do not support treating 2^18 as an 8 GB
footprint experiment.

## Validation and saved artifacts

All proofs verified. The nine saved checkpoints were additionally decoded and
verified. Component totals match each saved proof. Separate archive extraction
checked all 31 original result-file checksums and all 119 source hashes.
All 1031 memory samples were checked against the summary peaks. The archive was
then repacked with this report, the cross-size comparison and the audit record.
Original timing, proof and memory measurements were retained unchanged.

The monitor passed tests for normal completion, actual over-limit process
termination and termination on sampling failure. All twelve Python monitor and
result-validation tests passed. The unmonitored 2^18 configuration was separately
checked: the original guard still refuses before generating a proof.

- [Raw timings and proof sizes](samples.csv)
- [Prover-time comparison](comparison.csv)
- [Proof-size comparison](proof-size-comparison.csv)
- [2^17 versus 2^18 comparison](comparison-n17-n18.csv)
- [Memory timeline](memory-samples.csv), [resource summary](resources.json)
- [Proof component breakdown](proof-components.csv)
- [Completion validation](validation.json), [artifact audit](artifact-audit.json)
- [Configuration](experiment.json), [host/build/source manifest](metadata.json)
- Binary proofs: `proofs/`; exact measured source snapshot: `source.tar.gz`.

Source-tree SHA256: `522979ae26d10d0c748828866c56ed4fbf716b9be4c9d1f722a4fb0f434d5fb6`.

## Reproduction

```bash
env -u DYNAMIC_SNARK_PROFILE -u DYNAMIC_SNARK_PROFILE_DETAIL \
  python3 scripts/run_experiment.py --trace-log 18 --threads 8 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6 \
  --sequence-len 12 --seed 20260909 --baseline-mode shared \
  --rss-limit-gb 8 --offline \
  --output "benchmark-results/endpoint-n18-u64-$(date -u +%Y%m%dT%H%M%SZ)"
```

This command limits sampled RSS, not footprint. Omit `--rss-limit-gb` to retain
the default conservative allocation guard. Use a new output directory each time.
