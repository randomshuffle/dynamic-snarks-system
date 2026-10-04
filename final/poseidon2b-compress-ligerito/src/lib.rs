//! Poseidon2b 64-byte compression, Flock-GHASH GKR, and Ligerito composition.
pub mod gkr;
pub mod hash;
pub mod math;
pub mod pcs;
use flock_core::{
    challenger::{Challenger, FsChallenger},
    field::F128,
    pcs::ligerito::LigeritoProof,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub root: [u8; 32],
    pub gkr: gkr::Proof,
    pub opening: LigeritoProof,
}
#[derive(Default, Clone, Copy)]
pub struct Timings {
    pub witness_ms: f64,
    pub commit_ms: f64,
    pub reduction_ms: f64,
    pub open_ms: f64,
}
impl Timings {
    pub fn total_ms(self) -> f64 {
        self.witness_ms + self.commit_ms + self.reduction_ms + self.open_ms
    }
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
pub struct Backend {
    pub rows: usize,
    pub segments: usize,
    pub pcs: pcs::Config,
}
impl Backend {
    pub fn new(rows: usize, segments: usize) -> Result<Self, String> {
        Ok(Self {
            rows,
            segments,
            pcs: pcs::Config::new(rows, segments)?,
        })
    }
    pub fn transcript(&self, root: &[u8; 32]) -> FsChallenger {
        let mut t = FsChallenger::new(b"poseidon2b-n128-t4-ghash-compress64-gkr-ligerito-v1");
        for x in [self.rows, self.segments, 100, hash::HASH_ROUNDS] {
            t.observe_bytes(&(x as u64).to_le_bytes());
        }
        t.observe_bytes(&bincode::serialize(&self.pcs.params).unwrap());
        t.observe_bytes(root);
        t
    }
    pub fn prove(&self, messages: &[[u8; 64]]) -> Result<(Proof, Timings), String> {
        if messages.len() != self.rows {
            return Err("message batch length".into());
        }
        let mut times = Timings::default();
        let t = Instant::now();
        let witness = gkr::witness(messages, self.segments)?;
        times.witness_ms = ms(t);
        let t = Instant::now();
        let (table, commit, data) = self.pcs.commit(&witness.columns);
        times.commit_ms = ms(t);
        let mut transcript = self.transcript(&commit.root);
        let t = Instant::now();
        let (gkr, claims) = gkr::prove(witness, self.segments, &mut transcript)?;
        times.reduction_ms = ms(t);
        let t = Instant::now();
        let opening = self.pcs.open(table, data, &claims, &mut transcript);
        times.open_ms = ms(t);
        Ok((
            Proof {
                root: commit.root,
                gkr,
                opening,
            },
            times,
        ))
    }
    pub fn verify(&self, p: &Proof) -> Result<(), String> {
        let mut t = self.transcript(&p.root);
        let claims = gkr::verify(&p.gkr, self.rows.ilog2() as usize, self.segments, &mut t)?;
        self.pcs.verify(&p.root, &p.opening, &claims, &mut t)
    }
    /// Original message/digest column values at the GKR boundary points, useful
    /// to bind this standalone committed computation into a larger statement.
    pub fn boundary_claims(&self, p: &Proof) -> Result<Vec<gkr::Claim>, String> {
        gkr::verify(
            &p.gkr,
            self.rows.ilog2() as usize,
            self.segments,
            &mut self.transcript(&p.root),
        )
    }
}
pub fn digest_bytes(d: [F128; 2]) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, x) in d.iter().enumerate() {
        out[16 * i..16 * i + 16].copy_from_slice(&hash::integer(*x).to_le_bytes());
    }
    out
}
