//! Fiat--Shamir compression for sparse-DAG routing multisets.

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use crate::sparse_dag::{RouteTuple, RoutingTable};
use crate::static_snark::{TraceCommitment, commitment_seed};
use crate::transcript::RawTranscript;

const TRANSCRIPT_DOMAIN: u64 = 0x524f_5554_455f_4d53;
const STATEMENT_TAG: u64 = 1;
const TABLE_COMMITMENT_TAG: u64 = 2;
const THETA_LABEL: u64 = 1;
const GAMMA_LABEL: u64 = 2;

/// Fiat--Shamir challenges used by the routing multiset argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RoutingChallenges {
    /// Random linear-combination challenge for six-field route tuples.
    pub(crate) theta: Bn254,
    /// Additive product shift.
    pub(crate) gamma: Bn254,
}

impl RoutingChallenges {
    /// Derive challenges after the routing table has been committed.
    pub(crate) fn derive(statement: &[Bn254], table: &TraceCommitment) -> Self {
        let mut transcript = RawTranscript::new(TRANSCRIPT_DOMAIN);
        transcript.absorb_message(STATEMENT_TAG, statement);
        transcript.absorb_message(TABLE_COMMITMENT_TAG, &commitment_seed(table));
        Self {
            theta: transcript.challenge(THETA_LABEL),
            gamma: transcript.challenge(GAMMA_LABEL),
        }
    }
}

/// Shifted factors whose two products assert route-multiset equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductFactors {
    pub(crate) producers: Vec<Bn254>,
    pub(crate) references: Vec<Bn254>,
}

impl ProductFactors {
    pub(crate) fn from_table(table: &RoutingTable, challenges: RoutingChallenges) -> Self {
        let mut producers = Vec::with_capacity(table.row_count());
        let mut references = Vec::with_capacity(table.row_count());
        for row in 0..table.row_count() {
            producers.push(
                challenges.gamma + compress_optional(table.producers().get(row), challenges.theta),
            );
            references.push(
                challenges.gamma + compress_optional(table.references().get(row), challenges.theta),
            );
        }
        Self {
            producers,
            references,
        }
    }

    pub(crate) fn from_field_rows(
        producers: &[[Bn254; 6]],
        references: &[[Bn254; 6]],
        challenges: RoutingChallenges,
    ) -> Self {
        assert_eq!(producers.len(), references.len());
        Self {
            producers: producers
                .iter()
                .map(|fields| challenges.gamma + compress_fields(*fields, challenges.theta))
                .collect(),
            references: references
                .iter()
                .map(|fields| challenges.gamma + compress_fields(*fields, challenges.theta))
                .collect(),
        }
    }

    pub(crate) fn claims(&self) -> ProductClaims {
        ProductClaims {
            producer: self.producers.iter().copied().product(),
            reference: self.references.iter().copied().product(),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), Error> {
        self.claims().verify()
    }

    /// Interleave both factor vectors into the regular product-circuit layout.
    pub(crate) fn gkr_input(&self) -> Vec<Bn254> {
        assert_eq!(self.producers.len(), self.references.len());
        let mut input = Vec::with_capacity(4 * self.producers.len());
        for (&producer, &reference) in self.producers.iter().zip(&self.references) {
            input.extend([producer, reference, Bn254::ONE, Bn254::ONE]);
        }
        input
    }
}

/// The two terminal values of a routing product tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductClaims {
    pub(crate) producer: Bn254,
    pub(crate) reference: Bn254,
}

impl ProductClaims {
    pub(crate) fn verify(self) -> Result<(), Error> {
        if self.producer == self.reference {
            Ok(())
        } else {
            Err(Error::ProductMismatch)
        }
    }
}

/// A failed routing multiset product claim.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum Error {
    #[error("producer and reference routing products differ")]
    ProductMismatch,
}

/// Compress `[present, tree, level, index, old_digest, new_digest]` in a
/// fixed order. Padding rows are the all-zero tuple and therefore compress to
/// zero before the common additive shift.
pub(crate) fn compress_fields(fields: [Bn254; 6], theta: Bn254) -> Bn254 {
    fields
        .into_iter()
        .rev()
        .fold(Bn254::ZERO, |accumulator, field| {
            accumulator * theta + field
        })
}

fn compress_optional(tuple: Option<&RouteTuple>, theta: Bn254) -> Bn254 {
    tuple.map_or(Bn254::ZERO, |tuple| compress_fields(tuple.fields(), theta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::sparse_dag::{SparseMerkleDag, TreeId};
    use crate::static_snark::commit_mle;

    fn route_table() -> RoutingTable {
        let old_values = (0..19).map(Bn254::from_usize).collect::<Vec<_>>();
        let old = MerkleTree::new(old_values).unwrap();
        let mut new = old.clone();
        new.update(&[(2, Bn254::from_u64(52)), (17, Bn254::from_u64(67))])
            .unwrap();
        let assignment = SparseMerkleDag::paired(TreeId::Assignment, &old, &new, &[2, 17]).unwrap();
        RoutingTable::from_dags(&[assignment]).unwrap()
    }

    #[test]
    fn valid_routes_have_equal_compressed_products_with_padding() {
        let table = route_table();
        let committed = commit_mle(table.evaluations()).unwrap();
        let challenges = RoutingChallenges::derive(
            &[Bn254::from_u64(19), Bn254::from_u64(2)],
            committed.commitment(),
        );
        let factors = ProductFactors::from_table(&table, challenges);
        assert_eq!(factors.producers.len(), table.row_count());
        assert_eq!(factors.references.len(), table.row_count());
        factors.verify().unwrap();
    }

    #[test]
    fn product_check_detects_changed_tuple_and_multiplicity() {
        let table = route_table();
        let committed = commit_mle(table.evaluations()).unwrap();
        let challenges = RoutingChallenges::derive(&[], committed.commitment());
        let mut factors = ProductFactors::from_table(&table, challenges);
        factors.references[0] += Bn254::ONE;
        assert_eq!(factors.verify().unwrap_err(), Error::ProductMismatch);

        let mut factors = ProductFactors::from_table(&table, challenges);
        factors.references.swap(0, 1);
        factors.verify().unwrap();
        factors.references.pop();
        assert_eq!(factors.verify().unwrap_err(), Error::ProductMismatch);
    }

    #[test]
    fn challenges_bind_statement_and_committed_table() {
        let table = route_table();
        let first = commit_mle(table.evaluations()).unwrap();
        let base = RoutingChallenges::derive(&[Bn254::from_u64(19)], first.commitment());
        let changed_statement =
            RoutingChallenges::derive(&[Bn254::from_u64(20)], first.commitment());
        assert_ne!(base, changed_statement);

        let mut changed_evaluations = table.evaluations();
        changed_evaluations[0] += Bn254::ONE;
        let second = commit_mle(changed_evaluations).unwrap();
        let changed_commitment =
            RoutingChallenges::derive(&[Bn254::from_u64(19)], second.commitment());
        assert_ne!(base, changed_commitment);
    }

    #[test]
    fn tuple_order_and_presence_bit_are_bound() {
        let theta = Bn254::from_u64(13);
        let fields = [
            Bn254::ONE,
            Bn254::from_u64(2),
            Bn254::from_u64(3),
            Bn254::from_u64(5),
            Bn254::from_u64(7),
            Bn254::from_u64(11),
        ];
        let mut reordered = fields;
        reordered.swap(1, 2);
        assert_ne!(
            compress_fields(fields, theta),
            compress_fields(reordered, theta)
        );
        assert_eq!(compress_fields([Bn254::ZERO; 6], theta), Bn254::ZERO);
        assert_ne!(compress_fields(fields, theta), Bn254::ZERO);
    }
}
