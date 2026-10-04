//! Experimental full dynamic SNARK over Flock GF(2^128) and Ligerito Fast100.
#![forbid(unsafe_code)]
pub mod circuit;
pub mod field;
mod parallel;
pub mod static_snark;
mod transcript;
pub type Field = field::F;

mod endpoint_gkr;
pub mod hash;
pub mod merkle;
mod multiset;
mod sparse_dag;
mod transition_cair;
mod transition_relation;
mod wiring;

mod cair;
pub mod dynamic;

mod direct_transition;
mod hash_gkr;
