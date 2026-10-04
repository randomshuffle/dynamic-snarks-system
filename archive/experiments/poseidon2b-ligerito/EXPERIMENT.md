# Historical 72-byte Poseidon2b experiment

This exploratory experiment compared width-six Poseidon2b hashing over Flock's GF(2^128) with Ligerito against BN254/WHIR and Flock Keccak. Each 72-byte message used a two-permutation sponge; zero, one, and three committed checkpoints were compared. The current paper instead uses width-four, 64-byte compression, whose implementation is self-contained under `final/poseidon2b-compress-ligerito`.

The obsolete standalone source has been removed from the publication tree. Selected later reports, where retained, are under `archive/results/`.
