# Poseidon2b 64-byte compression with Flock's field and Ligerito

This crate supplies the **64-byte to 32-byte Poseidon2b compression** used by the current [dynamic SNARK implementation](../dynamic-ligerito/). It also exposes a standalone committed-computation benchmark with one proof per message batch. It uses Flock's GF(2^128) implementation, Ligerito Fast profiles with a 100-bit per-round parameter target, and coefficient-form GKR. The [earlier 72-byte sponge experiment](../../archive/experiments/poseidon2b-ligerito/EXPERIMENT.md) is archived.

The [benchmark report](../../archive/results/2026-09-19-hash-compression64/EXPERIMENT.md) compares zero, one, and three committed intermediate states against Flock Keccak-256, also on 64-byte messages.

## Hash definition

Use the published **n=128, t=4, x^7, RF=8, RP=58** Poseidon2b permutation, including the initial external linear layer. Interpret the message as four little-endian polynomial-basis field elements `x`, then compute:

```text
digest = first_two_words(P(x) + x)
```

This is the compression construction in [Poseidon(2)b §3.1.2](https://eprint.iacr.org/2025/1893.pdf). There is one 66-round permutation, no message padding, and no hash-domain prefix. The output is 32 bytes. All 512 input bits map bijectively to four GF(2^128) words; this adapter needs no byte-range restriction beyond those field words.

The field modulus is `X^128 + X^7 + X^2 + X + 1`, exactly Flock's GHASH basis. Constants are regenerated from the authors' [Sage recipe](https://github.com/Poseidon-Hash/Poseidon2b/blob/7072a9438cf48f1b38ad0092cda5452626914068/sage-ref/Poseidon2b.sage): TurboSHAKE256, seed `Poseidon2b` followed by the little-endian u64 chunks of `2^128`, and 17-byte rejection sampling. The first 264 accepted words are arranged into 66 rows of four; they are not the first four columns of the width-six round-constant table. Matrices also use the width-four recipe.

An independent Python implementation checks all 264 constants and five compression vectors. Matrix tests check every square minor of the external matrix, internal invertibility, and internal observability in the GHASH basis. These are implementation checks, not a new cryptanalysis of the instantiation.

## GKR and feed-forward

| Segments | Committed round boundaries | Segment round counts | GKR depth | Logical columns (padded) | Evaluation claims |
|---:|---|---|---:|---|---:|
| 1 | None | 66 | 66 | 6 (8) | 8 |
| 2 | 33 | 33, 33 | 33 | 10 (16) | 16 |
| 4 | 17, 33, 50 | 17, 16, 17, 16 | 17 | 18 (32) | 32 |

All 66 round transitions are constrained. The two shorter segments in the four-segment variant get one identity step at their output ends, allowing all segments to share the same GKR depth and row point. These are two identity constraints, not additional permutation rounds.

The witness table contains four input columns, four columns per middle boundary, and two digest columns. To constrain feed-forward without carrying extra columns through every round, the proof also supplies the first two input-word evaluations at the initial GKR output point. The verifier subtracts these from the digest claims (addition in characteristic two) before reducing the permutation, and **authenticates both evaluations in the same Ligerito opening**. They enter the transcript before the GKR batching challenges. Every middle boundary is opened at both the initial and terminal GKR points.

The degree-eight coefficient-form sumcheck, boundary-claim batching, native-F128 PCS, and transcript conventions follow the earlier backend. The new hash mode has its own transcript label, and the batch size, segment count, round count, PCS parameters, and commitment root are bound. Hash-domain-prefix removal does not remove transcript domain separation.

At batch 2,048, the initial committed tables contain 16,384, 32,768, and 65,536 field elements. For small batches, only the PCS table is zero-padded to the minimum 8,192-element Fast profile; the GKR hash count is unchanged.

## Build and run

From the repository root:

```sh
RUSTFLAGS='-C target-cpu=native' cargo build --locked --release --manifest-path final/poseidon2b-compress-ligerito/Cargo.toml
RAYON_NUM_THREADS=4 RUSTFLAGS='-C target-cpu=native' cargo test --locked --release --manifest-path final/poseidon2b-compress-ligerito/Cargo.toml
RAYON_NUM_THREADS=4 final/poseidon2b-compress-ligerito/target/release/poseidon2b-compress-ligerito-experiment
```

Use `--offline` with cached crates. The default binary runs batches `8,32,128,512,2048`, segments `1,2,4`, and seven samples after one warmup. Override with `HASH_PROOF_BATCHES`, `HASH_PROOF_SEGMENTS`, and `HASH_PROOF_SAMPLES`. Optional `HASH_PROOF_INPUT_DIR` writes the exact messages and independent RustCrypto Keccak-256 digests used to validate the Flock benchmark. `HASH_PROOF_CONFIG_DIR` saves the derived Ligerito configurations. Batch sizes must be powers of two of at least two.

Regenerate the reference vectors with:

```sh
python3 final/poseidon2b-compress-ligerito/scripts/reference.py
```

Library entry points are `Backend::new(rows, segments)`, `prove(&[[u8;64]])`, `verify(&Proof)`, and `hash::hash64`. The current `math.rs`, `pcs.rs`, and independent Python reference primitives are local to this crate; the Flock dependency is shared at [`vendor/flock-core`](../../vendor/flock-core/UPSTREAM.md). Its own Cargo lockfile fixes the dependency resolution.

## Scope

The standalone binary measures committed hash computation. The integrated dynamic SNARK uses `hash::hash64` for leaves and parents and enforces public-input binding, tree shape, coordinates, and routing in its surrounding relations. The compression itself adds no application domain prefix.

The 100-bit target refers to the validated Ligerito Fast parameter configuration. Test coverage includes full-byte compression vectors, feed-forward omission and tampering, every checkpoint transition, altered and truncated GKR/PCS proofs, wrong batch and segment counts, and identical serialized proofs on one and four threads.
