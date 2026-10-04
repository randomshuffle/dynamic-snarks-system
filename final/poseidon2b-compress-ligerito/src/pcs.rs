//! Direct GF(2^128) MLE claims over Flock's unchanged Ligerito core.
//! Ring-switching is unnecessary: the GKR already works in the PCS field.
use crate::{gkr::Claim, hash, math};
use flock_core::{
    challenger::Challenger,
    field::F128 as F,
    pcs::{
        self, Commitment, PcsParams, ProverData,
        ligerito::{
            self, LigeritoProfile, LigeritoProof, LigeritoSecurityConfig, ProverConfig,
            VerifierConfig,
        },
    },
};
use rayon::prelude::*;
pub struct Config {
    pub variables: usize,
    pub params: PcsParams,
    pub prover: ProverConfig,
    pub verifier: VerifierConfig,
    pub security: LigeritoSecurityConfig,
}
impl Config {
    pub fn new(rows: usize, segments: usize) -> Result<Self, String> {
        if rows < 2 || !rows.is_power_of_two() || ![1, 2, 4].contains(&segments) {
            return Err("invalid PCS shape".into());
        }
        let columns = (hash::WIDTH * segments + 2).next_power_of_two();
        // Same smallest feasible initial_k=6 Fast profile as the earlier Flock
        // experiment. Pad only the committed table, never the GKR hash count.
        let variables = (rows.ilog2() + columns.ilog2()).max(13) as usize;
        let security =
            LigeritoSecurityConfig::derive_profile(variables + 7, LigeritoProfile::Fast)?;
        let (prover, verifier) = security.to_prover_verifier_configs()?;
        let params = PcsParams {
            m: variables + 7,
            log_inv_rate: 1,
            log_batch_size: 6,
            profile: LigeritoProfile::Fast,
            merkle_hash: Default::default(),
        };
        Ok(Self {
            variables,
            params,
            prover,
            verifier,
            security,
        })
    }
    pub fn commit(&self, columns: &[Vec<F>]) -> (Vec<F>, Commitment, ProverData) {
        let mut table: Vec<_> = columns.iter().flatten().copied().collect();
        table.resize(1 << self.variables, F::ZERO);
        let (c, d) = pcs::commit(&table, &self.params);
        (table, c, d)
    }
    pub fn points(&self, claims: &[Claim]) -> Vec<Vec<F>> {
        claims
            .iter()
            .map(|c| {
                let mut point = c.point.clone();
                let bits = self.variables - point.len();
                assert!(c.column < 1 << bits);
                point.extend((0..bits).map(|bit| {
                    if c.column >> bit & 1 == 0 {
                        F::ZERO
                    } else {
                        F::ONE
                    }
                }));
                point
            })
            .collect()
    }
    fn combine(&self, claims: &[Claim], t: &mut impl Challenger) -> (Vec<Vec<F>>, Vec<F>, F) {
        let points = self.points(claims);
        t.observe_label(b"poseidon2b-ligerito-direct-open-v1");
        t.observe_bytes(&(claims.len() as u64).to_le_bytes());
        for (point, c) in points.iter().zip(claims) {
            t.observe_f128_slice(point);
            t.observe_f128(c.value);
        }
        let weights = t.sample_f128_vec(claims.len());
        let target = weights
            .iter()
            .zip(claims)
            .fold(F::ZERO, |a, (&w, c)| a + w * c.value);
        (points, weights, target)
    }
    pub fn open(
        &self,
        table: Vec<F>,
        data: ProverData,
        claims: &[Claim],
        t: &mut impl Challenger,
    ) -> LigeritoProof {
        let (points, weights, target) = self.combine(claims, t);
        // Cache row equality tables shared by all columns at a row point.
        // Columns sit above row bits, and every column coordinate is Boolean.
        let row_vars = claims[0].point.len();
        let rows = 1 << row_vars;
        let mut basis = vec![F::ZERO; 1 << self.variables];
        let mut cache: Vec<(Vec<F>, Vec<F>)> = Vec::new();
        for (c, &w) in claims.iter().zip(&weights) {
            let idx = cache
                .iter()
                .position(|(p, _)| *p == c.point)
                .unwrap_or_else(|| {
                    cache.push((c.point.clone(), math::eq_table(&c.point)));
                    cache.len() - 1
                });
            let eq = &cache[idx].1;
            let column = &mut basis[c.column * rows..(c.column + 1) * rows];
            if rows < 256 || rayon::current_num_threads() == 1 {
                column.iter_mut().zip(eq).for_each(|(a, &e)| *a += w * e);
            } else {
                column
                    .par_iter_mut()
                    .zip(eq)
                    .for_each(|(a, &e)| *a += w * e);
            }
        }
        debug_assert_eq!(
            table
                .iter()
                .zip(&basis)
                .fold(F::ZERO, |s, (&x, &b)| s + x * b),
            target
        );
        let _ = points; // The verifier uses full points; prover exploits Boolean columns.
        ligerito::recursive_prover_with_basis(
            &self.prover,
            table,
            basis,
            target,
            &data.codeword,
            &data.merkle_tree,
            t,
        )
    }
    pub fn verify(
        &self,
        root: &[u8; 32],
        proof: &LigeritoProof,
        claims: &[Claim],
        t: &mut impl Challenger,
    ) -> Result<(), String> {
        if proof.final_proof.yr.len() != 1 << self.security.final_block.yr_log_n
            || proof.recursive_roots.len() != self.verifier.recursive_steps
            || proof.recursive_proofs.len() + 1 != self.verifier.recursive_steps
        {
            return Err("Ligerito proof shape".into());
        }
        let (points, weights, target) = self.combine(claims, t);
        let evaluator = |prefix: &[F], remaining: usize| {
            let mut out = vec![F::ZERO; 1 << remaining];
            for (point, &weight) in points.iter().zip(&weights) {
                let scale = weight * math::eq(&point[..prefix.len()], prefix);
                let suffix = math::eq_table(&point[prefix.len()..]);
                for (v, e) in out.iter_mut().zip(suffix) {
                    *v += scale * e;
                }
            }
            out
        };
        if ligerito::recursive_verifier_with_basis_succinct(
            &self.verifier,
            proof,
            self.variables,
            target,
            root,
            evaluator,
            t,
        ) {
            Ok(())
        } else {
            Err("Ligerito rejected".into())
        }
    }
}
