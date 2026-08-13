//! Dynamic SNARK compiler from Section 4 of the accompanying paper.
//!
//! The implementation uses the BN254 scalar field, Poseidon2 commitments, and
//! Plonky3's multilinear WHIR PCS. It is sequential by default; enabling the
//! `parallel` feature selects Plonky3's parallel polynomial backends without
//! changing protocol code.

#![forbid(unsafe_code)]

mod cair;
pub mod circuit;
pub mod dynamic;
#[cfg(test)]
mod gkr;
pub mod hash;
pub mod merkle;
mod multiset;
mod poseidon_sumcheck;
mod sparse_dag;
pub mod static_snark;
mod transcript;
mod transition_cair;
mod transition_relation;
mod wiring;

/// Scalar field used by every protocol layer.
pub type Field = p3_bn254::Bn254;
