//! Arbitrary MLE openings via the unchanged Flock Ligerito core.
//! Names retained at the old internal interface to make the arithmetic port auditable.
use crate::field::{F, Point};
use flock_core::{
    challenger::{Challenger, FsChallenger},
    field::F128,
    pcs::{
        self, PcsParams, ProverData,
        ligerito::{
            self, LigeritoProfile, LigeritoProof, LigeritoSecurityConfig, ProverConfig,
            VerifierConfig,
        },
    },
};
use poseidon2b_compress_ligerito_experiment::math;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
pub(crate) type Commitment = [u8; 32];
pub(crate) struct CommittedBatch {
    pub commitment: Commitment,
    table: Vec<F128>,
    data: Option<ProverData>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OpeningProof {
    pub evaluations: Vec<F>,
    pub payload: OpeningData,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum OpeningData {
    Ligerito(LigeritoProof),
    Plain(Vec<F128>),
}
fn plain_root(vars: usize, table: &[F128]) -> Commitment {
    let mut h = blake3::Hasher::new();
    h.update(b"dynamic-gf128-plaintext-oracle-v1");
    h.update(&(vars as u64).to_le_bytes());
    for &v in table {
        h.update(&F(v).bytes());
    }
    *h.finalize().as_bytes()
}
impl OpeningProof {
    pub(crate) fn plaintext_bytes(&self) -> usize {
        match &self.payload {
            OpeningData::Plain(v) => 16 * v.len(),
            _ => 0,
        }
    }
    pub fn payload_size_bytes(&self) -> usize {
        bincode::serialized_size(self).unwrap() as usize
    }
}
pub(crate) struct LigeritoPcs {
    vars: usize,
    plain: bool,
    padded: usize,
    params: PcsParams,
    prover: ProverConfig,
    verifier: VerifierConfig,
    security: LigeritoSecurityConfig,
}
impl LigeritoPcs {
    pub fn new(vars: usize) -> Result<Self, String> {
        Self::with_plain(vars, false)
    }
    pub fn with_plain(vars: usize, plain: bool) -> Result<Self, String> {
        if plain && vars >= 12 {
            return Err("plaintext oracle must contain fewer than 4096 elements".into());
        }
        let padded = vars.max(13);
        let security = LigeritoSecurityConfig::derive_profile(padded + 7, LigeritoProfile::Fast)?;
        let (prover, verifier) = security.to_prover_verifier_configs()?;
        let params = PcsParams {
            m: padded + 7,
            log_inv_rate: 1,
            log_batch_size: 6,
            profile: LigeritoProfile::Fast,
            merkle_hash: Default::default(),
        };
        Ok(Self {
            vars,
            plain,
            padded,
            params,
            prover,
            verifier,
            security,
        })
    }
    pub fn commit_evaluations(&self, v: Vec<F>) -> Result<CommittedBatch, String> {
        if v.len() != 1 << self.vars {
            return Err("MLE length".into());
        }
        let mut table: Vec<_> = v.into_iter().map(|x| x.0).collect();
        RECORDS.lock().unwrap().push(self.vars);
        if self.plain {
            return Ok(CommittedBatch {
                commitment: plain_root(self.vars, &table),
                table,
                data: None,
            });
        }
        table.resize(1 << self.padded, F128::ZERO);
        let (c, data) = pcs::commit(&table, &self.params);
        Ok(CommittedBatch {
            commitment: c.root,
            table,
            data: Some(data),
        })
    }
    fn points(&self, p: &[Point<F>]) -> Result<Vec<Vec<F128>>, String> {
        p.iter()
            .map(|p| {
                if p.0.len() != self.vars {
                    return Err("MLE point arity".into());
                }
                let mut q: Vec<_> = p.0.iter().rev().map(|x| x.0).collect();
                q.resize(self.padded, F128::ZERO);
                Ok(q)
            })
            .collect()
    }
    fn transcript(&self, root: &Commitment, p: &[Vec<F128>], v: &[F], seed: &[F]) -> FsChallenger {
        let mut t = FsChallenger::new(b"dynamic-gf128-ligerito-direct-mle-v1");
        t.observe_bytes(&(self.vars as u64).to_le_bytes());
        t.observe_bytes(&bincode::serialize(&self.params).unwrap());
        t.observe_bytes(root);
        t.observe_bytes(&(seed.len() as u64).to_le_bytes());
        for x in seed {
            t.observe_f128(x.0);
        }
        t.observe_bytes(&(p.len() as u64).to_le_bytes());
        for (p, v) in p.iter().zip(v) {
            t.observe_f128_slice(p);
            t.observe_f128(v.0);
        }
        t
    }
    pub fn open(&self, batch: CommittedBatch, points: &[Point<F>], seed: &[F]) -> OpeningProof {
        let plain = batch.data.is_none();
        let mut points = self.points(points).unwrap();
        if plain {
            for p in &mut points {
                p.truncate(self.vars);
            }
        }
        assert!(!points.is_empty());
        let sparse: Vec<_> = points.iter().map(|p| SparseEq::new(p)).collect();
        let evaluations: Vec<_> = sparse
            .par_iter()
            .map(|s| F(s.evaluate(&batch.table)))
            .collect();
        if plain {
            return OpeningProof {
                evaluations,
                payload: OpeningData::Plain(batch.table),
            };
        }
        let data = batch.data.as_ref().unwrap();
        let mut t = self.transcript(&batch.commitment, &points, &evaluations, seed);
        let weights = t.sample_f128_vec(points.len());
        let mut basis = vec![F128::ZERO; 1 << self.padded];
        for (s, w) in sparse.iter().zip(&weights) {
            s.add_to(&mut basis, *w);
        }
        let target = evaluations
            .iter()
            .zip(&weights)
            .fold(F128::ZERO, |a, (v, w)| a + v.0 * *w);
        let ligerito = ligerito::recursive_prover_with_basis(
            &self.prover,
            batch.table,
            basis,
            target,
            &data.codeword,
            &data.merkle_tree,
            &mut t,
        );
        OpeningProof {
            evaluations,
            payload: OpeningData::Ligerito(ligerito),
        }
    }
    pub fn open_with_checkpoints(
        &self,
        b: CommittedBatch,
        p: &[Point<F>],
        s: &[F],
        _: &str,
    ) -> OpeningProof {
        self.open(b, p, s)
    }
    pub fn verify(
        &self,
        root: &Commitment,
        points: &[Point<F>],
        proof: &OpeningProof,
        seed: &[F],
    ) -> Result<(), String> {
        if points.is_empty() || points.len() != proof.evaluations.len() {
            return Err("MLE claim count".into());
        }
        let mut points = self.points(points)?;
        let p = match &proof.payload {
            OpeningData::Plain(table) => {
                if self.vars >= 12
                    || table.len() != 1 << self.vars
                    || plain_root(self.vars, table) != *root
                {
                    return Err("plaintext oracle shape or binding".into());
                }
                for p in &mut points {
                    p.truncate(self.vars);
                }
                if points
                    .iter()
                    .zip(&proof.evaluations)
                    .any(|(p, v)| SparseEq::new(p).evaluate(table) != v.0)
                {
                    return Err("plaintext evaluation mismatch".into());
                }
                return Ok(());
            }
            OpeningData::Ligerito(p) => p,
        };
        if p.final_proof.yr.len() != 1 << self.security.final_block.yr_log_n
            || p.recursive_roots.len() != self.verifier.recursive_steps
            || p.recursive_proofs.len() + 1 != self.verifier.recursive_steps
        {
            return Err("Ligerito shape".into());
        }
        let mut t = self.transcript(root, &points, &proof.evaluations, seed);
        let w = t.sample_f128_vec(points.len());
        let target = proof
            .evaluations
            .iter()
            .zip(&w)
            .fold(F128::ZERO, |a, (v, w)| a + v.0 * *w);
        let eval = |prefix: &[F128], remaining: usize| {
            let mut out = vec![F128::ZERO; 1 << remaining];
            for (p, w) in points.iter().zip(&w) {
                let scale = *w * math::eq(&p[..prefix.len()], prefix);
                let e = math::eq_table(&p[prefix.len()..]);
                for (a, b) in out.iter_mut().zip(e) {
                    *a += scale * b;
                }
            }
            out
        };
        if ligerito::recursive_verifier_with_basis_succinct(
            &self.verifier,
            p,
            self.padded,
            target,
            root,
            eval,
            &mut t,
        ) {
            Ok(())
        } else {
            Err("Ligerito rejected".into())
        }
    }
}
// Exploit Boolean column coordinates and zero padding without changing the
// arbitrary-point statement. This also handles wholly non-Boolean points.
struct SparseEq {
    offset: usize,
    stride: usize,
    eq: Vec<F128>,
}
impl SparseEq {
    fn new(p: &[F128]) -> Self {
        let boolean = |x: F128| x == F128::ZERO || x == F128::ONE;
        let lo = p.iter().take_while(|&&x| boolean(x)).count();
        let hi = p[lo..].iter().rev().take_while(|&&x| boolean(x)).count();
        let end = p.len() - hi;
        let mut offset = 0;
        for (i, x) in p.iter().enumerate() {
            if (i < lo || i >= end) && *x == F128::ONE {
                offset |= 1 << i;
            }
        }
        Self {
            offset,
            stride: 1 << lo,
            eq: math::eq_table(&p[lo..end]),
        }
    }
    fn evaluate(&self, v: &[F128]) -> F128 {
        self.eq.iter().enumerate().fold(F128::ZERO, |a, (i, e)| {
            a + v[self.offset + i * self.stride] * *e
        })
    }
    fn add_to(&self, v: &mut [F128], w: F128) {
        for (i, e) in self.eq.iter().enumerate() {
            v[self.offset + i * self.stride] += w * *e;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_oracles_bind_all_values_length_and_points() {
        for vars in [3, 11] {
            let pcs = LigeritoPcs::with_plain(vars, true).unwrap();
            let table = (0..1 << vars).map(|i| F::from_usize(i * i + 7)).collect();
            let b = pcs.commit_evaluations(table).unwrap();
            let root = b.commitment;
            let points = vec![
                Point::new((0..vars).map(|i| F::from_usize(i + 2)).collect()),
                Point::new(vec![F::ONE; vars]),
            ];
            let p = pcs.open(b, &points, &[F::ONE]);
            pcs.verify(&root, &points, &p, &[F::ONE]).unwrap();
            assert_eq!(p.plaintext_bytes(), 16 * (1 << vars));
            let mut bad = p.clone();
            if let OpeningData::Plain(v) = &mut bad.payload {
                v[0] += F128::ONE;
            }
            assert!(pcs.verify(&root, &points, &bad, &[]).is_err());
            let mut bad = p.clone();
            if let OpeningData::Plain(v) = &mut bad.payload {
                v.pop();
            }
            assert!(pcs.verify(&root, &points, &bad, &[]).is_err());
            let mut bad = p.clone();
            bad.evaluations[0] += F::ONE;
            assert!(pcs.verify(&root, &points, &bad, &[]).is_err());
            let mut other = points.clone();
            other[0].0[0] += F::ONE;
            assert!(pcs.verify(&root, &other, &p, &[]).is_err());
        }
        assert!(LigeritoPcs::with_plain(12, true).is_err());
        assert!(LigeritoSecurityConfig::derive_profile(12 + 7, LigeritoProfile::Fast).is_err());
        assert!(LigeritoSecurityConfig::derive_profile(13 + 7, LigeritoProfile::Fast).is_ok());
    }
    #[test]
    fn arbitrary_points_and_padding_are_bound() {
        for vars in [3, 13] {
            let pcs = LigeritoPcs::new(vars).unwrap();
            let v = (0..1 << vars).map(|i| F::from_usize(i * i + 7)).collect();
            let b = pcs.commit_evaluations(v).unwrap();
            let root = b.commitment;
            let p = vec![
                Point::new((0..vars).map(|i| F::from_usize(i + 2)).collect()),
                Point::new(vec![F::ONE; vars]),
            ];
            let proof = pcs.open(b, &p, &[F::ONE]);
            pcs.verify(&root, &p, &proof, &[F::ONE]).unwrap();
            let mut bad = proof.clone();
            bad.evaluations[0] += F::ONE;
            assert!(pcs.verify(&root, &p, &bad, &[F::ONE]).is_err());
            assert!(pcs.verify(&root, &p, &proof, &[F::TWO]).is_err());
        }
    }
}

static RECORDS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());
pub(crate) fn take_records() -> Vec<usize> {
    std::mem::take(&mut *RECORDS.lock().unwrap())
}
pub(crate) fn config_json(vars: usize) -> serde_json::Value {
    let c = LigeritoPcs::new(vars).unwrap();
    serde_json::json!({"logical_variables":vars,"committed_variables":c.padded,"params":c.params,"security":c.security})
}
