# Aligned arithmetic and Merkle polynomial oracles

All indices are zero-based; field constants below are embedded in the BN254 scalar field. This is the implemented layout, used by both dynamic initialization and the ordinary HyperPlonk baseline.

## Assignment layout

There are `n` addition gates and `n` multiplication gates, in alternating rows, and `n0 <= n` public-input occurrences. Write

\[
z\in\mathbb F^m,\qquad m=6n+n_0,\qquad
N=2^{\lceil\log_2(2n)\rceil},\qquad M=4N.
\]

For a valid assignment, `z[6g..6g+3]` is an addition triple and `z[6g+3..6g+6]` is a multiplication triple. The public-input suffix is `z[6n..m]`. Wiring is a permutation `sigma` of the `m` logical positions, with `z[i] = z[sigma(i)]`.

The fixed injection from logical positions to physical Merkle leaves is

\[
\phi(i)=
\begin{cases}
4\lfloor i/3\rfloor+(i\bmod3),&0\le i<6n,\\
4(i-6n)+3,&6n\le i<m.
\end{cases}
\]

Its image consists of columns 0–2 in the actual gate rows and column 3 in the first `n0` rows. Every other physical position is padding.

## W and P tables

For `0 <= r < N`, `0 <= c < 4`, define

\[
w_{r,c}=
\begin{cases}
z_{3r+c},&c<3\text{ and }r<2n,\\
z_{6n+r},&c=3\text{ and }r<n_0,\\
0,&\text{otherwise}.
\end{cases}
\]

Thus each actual gate row contains its two inputs, output, and one public-input occurrence or zero. There are no duplicate assignment-view columns. The flattened vector is `B[4r+c] = w[r,c]`.

Extend the conjugated wiring to a permutation `pi` of all `M` physical positions:

\[
\pi(\phi(i))=\phi(\sigma(i)),\qquad
\pi(t)=t\quad\text{for padding positions }t.
\]

The preprocessing table is exactly

\[
p_{r,c}=\pi(4r+c)+1.
\]

The `+1` is the one-based label convention used by PermCheck. This retains the original cycle order under `sigma`; no cycle expansion or sorting of occurrences is needed. `P` depends only on the circuit. `W` depends on the witness.

## Multilinear polynomial oracles

Let `ell = log2(N)`. Write the binary digits of an integer with its least significant bit first. For a Boolean vector `b`, define

\[
\chi_b(x)=\prod_j\big((1-b_j)(1-x_j)+b_jx_j\big).
\]

For any table `a[r,c]`, its unique multilinear extension is

\[
\widetilde a(C,X)=
\sum_{r=0}^{N-1}\sum_{c=0}^{3}
a_{r,c}\,\chi_{\operatorname{bits}_2(c)}(C)
\chi_{\operatorname{bits}_\ell(r)}(X).
\]

The oracles are `W = MLE(w)` and `P = MLE(p)`, each on `ell+2` variables with `4N` Boolean evaluations and degree at most one in each variable. The low two address bits select the column; the remaining bits select the row. A polynomial-oracle query supplies any field point `(C,X)` and requests its evaluation; WHIR authenticates the terminal queries obtained from the PIOP.

The identity-label polynomial is public:

\[
I(C,X)=1+C_0+2C_1+4\sum_{j=0}^{\ell-1}2^jX_j.
\]

The gate ZeroCheck enforces addition on even actual rows and multiplication on odd actual rows. It also enforces `w[r,0]=w[r,1]=w[r,2]=0` in padded gate rows and `w[r,3]=0` after the public-input range. For the baseline, it additionally enforces `w[r,3]=public[r]` for `r<n0`. All masks are public interval-indicator MLEs evaluated in logarithmic time; their descriptions are bound into Fiat–Shamir.

PermCheck checks the random compression of

\[
\prod_{r,c}(w_{r,c}+\beta(4r+c+1)+\gamma)
=
\prod_{r,c}(w_{r,c}+\beta p_{r,c}+\gamma).
\]

It uses the existing `2N`-entry HyperPlonk product oracle `V`. With four columns, the product ZeroCheck has individual sumcheck degree bound six, including its equality weight. The gate ZeroCheck retains the generic degree-eight bound. There are `ell` gate sumcheck rounds and `ell+1` product sumcheck rounds, followed by batched PCS openings. There are four `P` claims, eight standard `W` claims, and five `V` claims; initialization appends one additional `W` claim for the Merkle link.

## Merkle link

The assignment vector commitment is now the Merkle commitment to the entire `M`-entry vector `B`. Leaf `t` hashes `(B[t], t, leaf_domain)`. The indexed permutation tree commits to `pi[t]`, which is the corresponding `P` table entry minus one.

The initial Merkle PIOP proves this tree's complete Poseidon computation. Its leaf-value claim is directly a query to `W` at the same point; no extra column bit selects another assignment view. Static padding constraints fix every unused entry of `B` to zero.

The default initial PIOP commits only the digest heap: one column on
`H=2M=8N` rows. A shared 64-round hash reduction checks all Poseidon2 instances;
its inputs are derived from the heap and `W`, so no routing sumcheck is needed.
See the [exact digest and input formulas](initial-endpoint-experiment.md).
The legacy scalar trace, available with `--no-default-features`, has 64 columns
on the same heap, or `512N` evaluations. Some non-power-of-two circuit shapes
need one more tree level than the older dense packing; these are tested.

## Propagation to the sparse update oracles

The public update API continues to accept logical `(i,new_value)` pairs in the original `z` indexing. The prover maps each position through `phi` and sorts physical positions before updating or opening the tree. The update hierarchy still uses the logical count `m` and the number of logical update entries; padding does not create updateable positions.

Every committed sparse node uses a physical Merkle address. At an update link for logical position `i`, the three authenticated values are:

- Old/new assignment at `p=phi(i)`.
- The fixed wiring value `s=pi(p)=phi(sigma(i))` at physical position `p` in the permutation tree.
- The new assignment at physical position `s` in the neighbor tree.

The link constraint requires the new value at `p` to equal the authenticated neighbor value. Gate links and gate-row routing use

\[
p=8g+4t+o,\qquad 0\le g<n,\quad t\in\{0,1\},\quad o\in\{0,1,2\},
\]

where `t=0` denotes addition and `t=1` multiplication. Public links use

\[
p=4j+3,\qquad 0\le j<n_0.
\]

Boolean offset selectors and bit-decomposed range checks enforce these formulas, excluding padding and gate/public aliases. Public-input Merkle openings use positions `4j+3`. Both the compact polynomial constraints and their generic gate-program reference implementation use these same formulas.

### Current compact layout

The default `compact-merkle` prover commits three polynomial oracles. Its node
table has 14 columns padded to 16: old/new hash input triples and outputs, row
type, tree id, level, heap address, and two auxiliary fields. The auxiliary
fields contain old/new boundary digests, or a level inverse for computed
internal nodes. Three designated roots and child references `(tree, level-1,
2J+b, old_digest, new_digest)` connect every node to its root. Requiring a
nonzero internal level replaces per-node bit decompositions.

Let `k=|U|` count updated assignment positions and `g` count affected gates.
Update links, gate records, and their index range witnesses occupy a separate
table with `S=nextpow2(max(2,k+g))` rows and
`nextpow2(17+max(b(n),b(n0)))` columns, where
`b(x)=max(1,ceil(log2(max(1,x))))`. Only the node table is padded to the
`R=O(k log N)` partial-tree domain, giving `16R` main-oracle fields and
`O(k log N)` update-oracle fields.

The update table shares one range-bit block between gate-pair and public-input
indices. The row's role selects the range bound; unused high bits for that
role are constrained to zero. Copies of the two integer indices are reconstructed
from these bits, and the neighbor opening authenticates the new value directly.
The old node flag and reserved zero field are omitted. Its exact zero-based
column layout is:

| Columns | Update row | Gate-check row |
|---|---|---|
| 0–1 | Update/gate-check row flags `(1,0)` | `(0,1)` |
| 2–3 | Gate-position/public-input flags | Addition/multiplication flags |
| 4–5 | Addition/multiplication flags | Gate-pair index, physical gate start |
| 6–8 | One-hot left/right/output position flags | Left input, right input, output |
| 9 | Physical updated position | Unused |
| 10–11 | Old/new assignment values | Unused |
| 12 | Physical permutation target | Unused |
| 13–16 | Old/new assignment, permutation, neighbor leaf digests | Unused |
| 17 onward | Shared bits: gate-pair or public-input index | Gate-pair index bits |

For 32,768 gate pairs and 256 public inputs, this is exactly 32 used columns,
with no column padding, compared with the previous 45 used columns padded to
64. The routing sumcheck degree stays nine. Compact transition transcript
version 2 distinguishes the new layout; existing roots and keys retain their
meaning, while update proofs must be regenerated.

After both commitments are fixed, routing challenges determine the shared
product oracle with `R*nextpow2(14+2log2(R))` fields. Each of its eight factor
columns multiplies a node-record factor by an update-record factor, with the
update columns zero-extended to `R` only for the routing sumcheck. The verifier
authenticates that extension using the update oracle and a public prefix mask.
The node, update, and product oracles each have one batched WHIR opening. No
dense `4N`-entry witness is recommitted. See the
[32-column one-gate comparison](../benchmark-results/2026-09-15-update-table-32-ab/README.md)
and the earlier [node-table comparison](../benchmark-results/2026-09-11-compact-update-ab/README.md).

### Previous combined endpoint layout

The previous prover, selected with `--no-default-features --features poseidon-gkr`,
uses two witness-dependent polynomial oracles:

Let `R=2^s` be the sparse table row count, `h=log2(M)`, and `b(x)=max(1,ceil(log2(max(1,x))))`. The compact row width is

\[
c=22+b(n)+b(n_0)+b(h+1).
\]

The 22 fields are three row-type flags and 19 payload fields shared by node, update-link, or gate rows. The remaining fields are range-check bits. All index-valued payloads and derived routing tuples now use the physical addresses described above.

Write this compact table as `C[R,c]`. Each sparse row has two hash slots,
old and new, including dummy hashes when necessary. Let `E[R,8]` hold their
endpoints in this order: old input `x,y,d`, old digest, new input `x,y,d`, new
digest. With `K=next_power_of_two(c+8)`, its main update table is

\[
A_{r,j}=\begin{cases}
E_{r,j},&j<8,\\
C_{r,j-8},&8\le j<c+8,\\
0,&j\ge c+8.
\end{cases}
\]

Its oracle `U=MLE(A)` has `RK` evaluations and `log2(R)+log2(K)` variables.
For the benchmarked shapes, `K=64`, so it has `64R` evaluations. The hash PIOP
reduces all `2R` hash computations to four endpoint evaluations of `U`.
The local sumcheck connects these endpoints to the compact routing witness.
See the [endpoint protocol](poseidon-endpoint-experiment.md) for query layouts.
The legacy scalar trace has `2R` rows and `next_power_of_two(c+65)` columns,
or `256R` evaluations for the benchmarked shapes.

After committing `U`, Fiat–Shamir supplies the routing-compression challenges. A second table `Q` contains, per sparse row, four compressed producer factors, four compressed reference factors, four pairwise products, and the two four-factor products. Each of `s` further stages contributes two columns containing the next level of the producer/reference product trees, with zero padding after that level's active prefix. Its oracle has

\[
R\cdot\operatorname{nextpow2}(14+2\log_2R)
\]

Boolean evaluations. The product-tree root equality and routing sumcheck bind these factors to the physical-index tuples derived from `U`. The two oracles are still committed separately because the second depends on challenges sampled after the first commitment. Their WHIR parameters and native Poseidon2 hash function are unchanged.

## Compatibility and validation

The static transcript version is 5. The endpoint initial, combined endpoint
transition, and compact transition PIOPs use distinct transcript domains and
proof representations. Assignment and indexed-wiring commitments describe
`M=4N` physical entries, so their `Commitment.len` is `M`; logical assignments
and update indices retain their original API meaning. Compact transitions
retain this vector encoding but require newly generated transition proofs.
Keys, Merkle roots, and proofs from the older logical vector encoding must be regenerated.

Validation covers exact `W`/`P` entries with a nontrivial cycle order, analytic selectors at non-Boolean points, zero-padding constraints, baseline public inputs, mixed gate/public updates whose physical order differs from logical order, a non-power-of-two shape with an extra tree level, and rejection of padding/gate/public aliases. The original generic gate-program path is retained.

The [benchmark report](../benchmark-results/aligned-comparison.md) records the new timings and dimensions. In particular, the 65,536-gate, 16-gate-update case crosses a sparse-row padding threshold from 512 to 1,024 rows, increasing update cost even though the column layout is unchanged.
