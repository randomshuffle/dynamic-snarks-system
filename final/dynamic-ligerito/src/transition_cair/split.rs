//! Compact hash/boundary/update oracles with uncommitted routing product trees.
pub(crate) use super::Error;
use super::product_gkr as pg;
use super::*;
use crate::transition_relation::{packed as auxiliary, split as relation};
use crate::{endpoint_gkr, static_snark::commit_mle_with_plain};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    rows: [usize; 3],
    update_count: usize,
    gate_count: usize,
    openings: [MleOpeningProof; 3],
    local: [SumcheckProof; 3],
    products: [pg::Proof; 3],
    route: [SumcheckProof; 3],
    hash: endpoint_gkr::Proof,
}
impl Proof {
    pub(crate) fn statistics(&self) -> serde_json::Value {
        let widths = [16, 8, self.openings[2].opening.evaluations.len() / 2];
        let names = ["computed_nodes", "boundaries", "updates"];
        let mut polys = Vec::new();
        for i in 0..3 {
            let logical = self.rows[i] * widths[i].next_power_of_two();
            let plain = self.openings[i].opening.plaintext_bytes();
            polys.push(serde_json::json!({"role":names[i],"rows":self.rows[i],"logical_elements":logical,"pcs_elements":if plain>0{0}else{logical.max(8192)},"plaintext_bytes":plain}));
        }
        polys.push(self.hash.statistics(self.rows[0]));
        serde_json::json!({"hashes":self.rows[0],"polynomials":polys,"plaintext_bytes":self.plaintext_bytes(),"serialized_bytes":bincode::serialized_size(self).unwrap(),"routing_product_polynomials":0})
    }

    pub(crate) fn plaintext_bytes(&self) -> usize {
        self.hash.plaintext_bytes()
            + self
                .openings
                .iter()
                .map(|p| p.opening.plaintext_bytes())
                .sum::<usize>()
    }
}
fn weighted(v: &[F], w: &[F]) -> F {
    v.iter().zip(w).map(|(&a, &b)| a * b).sum()
}
fn boolean_eq(i: usize, p: &[F]) -> F {
    p.iter()
        .enumerate()
        .map(|(b, &x)| if i >> b & 1 == 0 { F::ONE + x } else { x })
        .product()
}
fn prefix(n: usize, p: &[F]) -> F {
    if n == 1 << p.len() {
        return F::ONE;
    }
    let (mut a, mut equal) = (F::ZERO, F::ONE);
    for b in (0..p.len()).rev() {
        if n >> b & 1 == 0 {
            equal *= F::ONE + p[b]
        } else {
            a += equal * (F::ONE + p[b]);
            equal *= p[b];
        }
    }
    a
}
fn known(domain: usize, rows: usize, k: usize, g: usize) -> Vec<Vec<F>> {
    match domain {
        0 => (0..4)
            .map(|i| (0..rows).map(|j| F::from_bool(i == j)).collect())
            .collect(),
        1 => vec![],
        2 => vec![
            (0..rows).map(|i| F::from_bool(i < k)).collect(),
            (0..rows)
                .map(|i| F::from_bool(i >= k && i < k + g))
                .collect(),
        ],
        _ => unreachable!(),
    }
}
fn known_at(domain: usize, p: &[F], k: usize, g: usize) -> Vec<F> {
    match domain {
        0 => (0..4).map(|i| boolean_eq(i, p)).collect(),
        1 => vec![],
        2 => vec![prefix(k, p), prefix(k + g, p) + prefix(k, p)],
        _ => unreachable!(),
    }
}
fn residuals(domain: usize, v: &[F], known: &[F], s: Statement) -> Vec<F> {
    match domain {
        0 => relation::computed_residuals(v, known, s),
        1 => relation::boundary_residuals(v),
        2 => auxiliary::auxiliary_residuals(v, known, s),
        _ => unreachable!(),
    }
}
fn degree(domain: usize, s: Statement) -> usize {
    if domain == 2 {
        auxiliary::auxiliary_degree(s).max(8)
    } else {
        8
    }
}
fn factors(domain: usize, v: &[F], s: Statement, r: RoutingChallenges) -> [F; 8] {
    relation::routes(domain, v, s).map(|tuple| r.gamma + compress_fields(tuple, r.theta))
}
fn route_value(
    domain: usize,
    v: &[F],
    s: Statement,
    r: RoutingChallenges,
    lane: &[F],
    beta: F,
) -> F {
    let f = factors(domain, v, s, r);
    (0..4).map(|i| lane[i] * (f[i] + beta * f[4 + i])).sum()
}
fn transcript(
    s: Statement,
    shape: CircuitShape,
    level: usize,
    lower: usize,
    capacity: usize,
    rows: [usize; 3],
    k: usize,
    g: usize,
    roots: [TraceCommitment; 3],
) -> RawTranscript {
    let mut t = RawTranscript::new(0x53504c49544f5231);
    let mut v = vec![
        F::from_usize(shape.gate_pairs),
        F::from_usize(shape.public_inputs),
        F::from_usize(shape.assignment_len),
        F::from_usize(s.height),
        F::from_usize(level),
        F::from_usize(lower),
        F::from_usize(capacity),
        F::from_usize(k),
        F::from_usize(g),
    ];
    v.extend(rows.map(F::from_usize));
    v.extend(s.old_assignment.root);
    v.extend(s.new_assignment.root);
    v.extend(s.permutation.root);
    for root in roots {
        v.extend(commitment_seed(&root));
    }
    t.absorb_message(1, &v);
    t
}
fn local_setup(
    t: &mut RawTranscript,
    domain: usize,
    rows: usize,
    columns: usize,
    s: Statement,
) -> (Vec<F>, Vec<F>) {
    t.absorb_message(0x4c4f43414c, &[F::from_usize(domain)]);
    let n = residuals(
        domain,
        &vec![F::ZERO; columns],
        &vec![
            F::ZERO;
            if domain == 0 {
                4
            } else if domain == 2 {
                2
            } else {
                0
            }
        ],
        s,
    )
    .len();
    (
        challenges(t, 0x1000, n),
        challenges(t, 0x2000, rows.ilog2() as usize),
    )
}
fn hash_points(c: &endpoint_gkr::Claims) -> Vec<Vec<F>> {
    (0..4)
        .map(|i| table_point(i, &c.input_point, 16))
        .chain((0..2).map(|i| table_point(4 + i, &c.output_point, 16)))
        .chain((0..2).map(|i| table_point(i, &c.output_point, 16)))
        .collect()
}
fn plain_policy(lengths: [usize; 4]) -> [bool; 4] {
    if std::env::var("DYNAMIC_SMALL_ORACLE").as_deref() == Ok("ligerito") {
        return [false; 4];
    }
    // Try all eligible tables up to the disclosure cap. The completed proof,
    // after removing their PCS openings, determines whether the ratio fits.
    let mut budget = 65536;
    let mut order = [0, 1, 2, 3];
    order.sort_by_key(|&i| lengths[i]);
    let mut plain = [false; 4];
    for i in order {
        let bytes = lengths[i] * 16;
        if lengths[i] < 4096 && bytes <= budget {
            plain[i] = true;
            budget -= bytes;
        }
    }
    plain
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    c: &Circuit,
    permutation: &MerkleTree,
    old: &MerkleTree,
    new: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_root: Commitment,
    new_root: Commitment,
) -> Result<Proof, Error> {
    prove_with_checkpoints(
        c,
        permutation,
        old,
        new,
        level,
        lower,
        capacity,
        updates,
        old_root,
        new_root,
        1,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_checkpoints(
    c: &Circuit,
    permutation: &MerkleTree,
    old: &MerkleTree,
    new: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_root: Commitment,
    new_root: Commitment,
    checkpoints: usize,
) -> Result<Proof, Error> {
    prove_with_plain_budget(
        c,
        permutation,
        old,
        new,
        level,
        lower,
        capacity,
        updates,
        old_root,
        new_root,
        checkpoints,
        0,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_plain_budget(
    c: &Circuit,
    permutation: &MerkleTree,
    old: &MerkleTree,
    new: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_root: Commitment,
    new_root: Commitment,
    checkpoints: usize,
    other_proof_credit: i128,
) -> Result<Proof, Error> {
    prove_with_oracle_policy(
        c,
        permutation,
        old,
        new,
        level,
        lower,
        capacity,
        updates,
        old_root,
        new_root,
        checkpoints,
        other_proof_credit,
        true,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_oracle_policy(
    c: &Circuit,
    permutation: &MerkleTree,
    old: &MerkleTree,
    new: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_root: Commitment,
    new_root: Commitment,
    checkpoints: usize,
    other_proof_credit: i128,
    allow_plain: bool,
) -> Result<Proof, Error> {
    if ![1, 3, 7].contains(&checkpoints) {
        return Err(Error::TableShape);
    }
    validate_level_size(updates.len(), lower, capacity)?;
    authenticate_roots(old, new, old_root, new_root)?;
    let table = TransitionTable::build(c, permutation, old, new, updates)?;
    let s = table.statement();
    let w = table.split_witness();
    let rows = std::array::from_fn(|i| w.columns[i][0].len());
    let widths = [16, 8, auxiliary::auxiliary_columns(s).next_power_of_two()];
    let lengths = [
        rows[0] * 16,
        rows[1] * 8,
        rows[2] * widths[2],
        rows[0] * (4 * checkpoints).next_power_of_two(),
    ];
    let mut plain = if allow_plain {
        plain_policy(lengths)
    } else {
        [false; 4]
    };
    loop {
        let proof = prove_witness(
            c,
            s,
            &w,
            rows,
            widths,
            level,
            lower,
            capacity,
            checkpoints,
            plain,
        )?;
        if fits_plain_budget(&proof, other_proof_credit)? {
            return Ok(proof);
        }
        // Changing an oracle root changes Fiat-Shamir challenges: rebuild the
        // proof, never replace an opening in an already generated transcript.
        let Some(i) = (0..4).filter(|&i| plain[i]).max_by_key(|&i| lengths[i]) else {
            return Err(Error::TableShape);
        };
        plain[i] = false;
    }
}
#[allow(clippy::too_many_arguments)]
fn prove_witness(
    c: &Circuit,
    s: Statement,
    w: &relation::Witness,
    rows: [usize; 3],
    widths: [usize; 3],
    level: usize,
    lower: usize,
    capacity: usize,
    checkpoints: usize,
    plain: [bool; 4],
) -> Result<Proof, Error> {
    let committed = w
        .columns
        .par_iter()
        .enumerate()
        .map(|(i, c)| {
            commit_mle_with_plain(pack_columns(rows[i], widths[i], c.iter()), plain[i])
                .map_err(pcs_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let roots = std::array::from_fn(|i| *committed[i].commitment());
    let mut t = transcript(
        s,
        CircuitShape::from_circuit(c),
        level,
        lower,
        capacity,
        rows,
        w.update_count,
        w.gate_count,
        roots,
    );
    let routing = RoutingChallenges {
        theta: t.challenge(0x5448455441),
        gamma: t.challenge(0x47414d4d41),
    };
    let mut locals = Vec::new();
    let mut local_points = Vec::new();
    for domain in 0..3 {
        let count = w.columns[domain].len();
        let (weights, target) = local_setup(&mut t, domain, rows[domain], count, s);
        let mut cols = w.columns[domain].clone();
        cols.extend(known(domain, rows[domain], w.update_count, w.gate_count));
        cols.push(eq_evaluations(&target));
        let (p, point, _) = pg::prove_sc(cols, degree(domain, s), F::ZERO, &mut t, |v| {
            v[v.len() - 1]
                * weighted(
                    &residuals(domain, &v[..count], &v[count..v.len() - 1], s),
                    &weights,
                )
        })?;
        locals.push(p);
        local_points.push(point);
    }
    let (hash, claims) = endpoint_gkr::prove_with_policy(
        std::array::from_fn(|j| w.columns[0][j].clone()),
        &[w.columns[0][4].clone(), w.columns[0][5].clone()],
        &mut t,
        checkpoints,
        plain[3],
    )
    .map_err(|_| Error::Sumcheck)?;
    let mut products = Vec::new();
    let mut routes = Vec::new();
    let mut route_points = Vec::new();
    for domain in 0..3 {
        t.absorb_message(0x524f555445, &[F::from_usize(domain)]);
        let fs: Vec<_> = (0..rows[domain])
            .into_par_iter()
            .map(|i| {
                let v = w.columns[domain].iter().map(|c| c[i]).collect::<Vec<_>>();
                factors(domain, &v, s, routing)
            })
            .collect();
        let p = fs.iter().flat_map(|f| f[..4].iter().copied()).collect();
        let q = fs.iter().flat_map(|f| f[4..].iter().copied()).collect();
        let (product, target, values) = pg::prove(pg::Witness::new(p, q), &mut t)?;
        let beta = t.challenge(0x464143544f52);
        let lane = eq_evaluations(&target[..2]);
        let mut cols = w.columns[domain].clone();
        cols.push(eq_evaluations(&target[2..]));
        let (sc, point, _) = pg::prove_sc(cols, 7, values[0] + beta * values[1], &mut t, |v| {
            v[v.len() - 1] * route_value(domain, &v[..v.len() - 1], s, routing, &lane, beta)
        })?;
        products.push(product);
        routes.push(sc);
        route_points.push(point);
    }
    if products.iter().map(|p| p.roots[0]).product::<F>()
        != products.iter().map(|p| p.roots[1]).product::<F>()
    {
        return Err(Error::ProductMismatch);
    }
    let seed = vec![t.challenge(0x4f50454e)];
    let openings = committed
        .into_par_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut points: Vec<_> = [&local_points[i], &route_points[i]]
                .into_iter()
                .flat_map(|p| (0..w.columns[i].len()).map(move |j| table_point(j, p, widths[i])))
                .collect();
            if i == 0 {
                points.extend(hash_points(&claims));
            }
            c.open(
                &points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &role_seed(&seed, i as u64),
            )
        })
        .collect::<Vec<_>>();
    let proof = Proof {
        rows,
        update_count: w.update_count,
        gate_count: w.gate_count,
        openings: openings.try_into().ok().unwrap(),
        local: locals.try_into().ok().unwrap(),
        products: products.try_into().ok().unwrap(),
        route: routes.try_into().ok().unwrap(),
        hash,
    };
    check_plain_cap(&proof)?;
    Ok(proof)
}
fn fits_plain_budget(p: &Proof, other_proof_credit: i128) -> Result<bool, Error> {
    let total = bincode::serialized_size(p).map_err(|_| Error::TableShape)? as i128;
    Ok(2 * p.plaintext_bytes() as i128 <= total + other_proof_credit)
}
fn check_plain_cap(p: &Proof) -> Result<(), Error> {
    if p.plaintext_bytes() > 65536 {
        return Err(Error::TableShape);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    shape: CircuitShape,
    permutation: Commitment,
    old: Commitment,
    new: Commitment,
    level: usize,
    lower: usize,
    capacity: usize,
    p: &Proof,
) -> Result<(), Error> {
    let physical = shape.assignment_tree_len();
    if [permutation.len, old.len, new.len]
        .iter()
        .any(|&x| x != physical)
    {
        return Err(Error::AssignmentAuthentication);
    }
    validate_level_size(p.update_count, lower, capacity)?;
    if p.update_count > shape.assignment_len
        || p.gate_count > p.update_count
        || p.rows[0] < 4
        || p.rows
            .iter()
            .any(|&r| r < 2 || !r.is_power_of_two() || r > 16usize.saturating_mul(physical))
        || p.rows[2] != (p.update_count + p.gate_count).max(2).next_power_of_two()
    {
        return Err(Error::TableShape);
    }
    // The complete dynamic-proof verifier checks the aggregate plaintext ratio.
    // A standalone transition still enforces the per-transition disclosure cap.
    check_plain_cap(p)?;
    let s = Statement {
        gate_pairs: shape.gate_pairs,
        public_inputs: shape.public_inputs,
        assignment_len: shape.assignment_len,
        height: shape.merkle_height,
        permutation,
        old_assignment: old,
        new_assignment: new,
    };
    let counts = [12, 7, auxiliary::auxiliary_columns(s)];
    let widths = [16, 8, counts[2].next_power_of_two()];
    let roots = std::array::from_fn(|i| p.openings[i].commitment);
    let mut t = transcript(
        s,
        shape,
        level,
        lower,
        capacity,
        p.rows,
        p.update_count,
        p.gate_count,
        roots,
    );
    let routing = RoutingChallenges {
        theta: t.challenge(0x5448455441),
        gamma: t.challenge(0x47414d4d41),
    };
    let mut local_points = Vec::new();
    for i in 0..3 {
        if p.openings[i].opening.evaluations.len() != 2 * counts[i] + if i == 0 { 8 } else { 0 } {
            return Err(Error::TableShape);
        }
        let (weights, target) = local_setup(&mut t, i, p.rows[i], counts[i], s);
        let (claim, point) = pg::verify_sc(
            &p.local[i],
            degree(i, s),
            p.rows[i].ilog2() as usize,
            F::ZERO,
            &mut t,
        )?;
        let values = &p.openings[i].opening.evaluations[..counts[i]];
        let known = known_at(i, &point, p.update_count, p.gate_count);
        if claim != eq_eval(&target, &point) * weighted(&residuals(i, values, &known, s), &weights)
        {
            return Err(Error::Terminal);
        }
        local_points.push(point);
    }
    let claims = endpoint_gkr::verify(&p.hash, p.rows[0].ilog2() as usize, &mut t)
        .map_err(|_| Error::Sumcheck)?;
    let expected: Vec<_> = claims
        .inputs
        .into_iter()
        .chain(claims.outputs)
        .chain(claims.feed_forward)
        .collect();
    if p.openings[0].opening.evaluations[24..] != expected {
        return Err(Error::Terminal);
    }
    let mut route_points = Vec::new();
    for i in 0..3 {
        t.absorb_message(0x524f555445, &[F::from_usize(i)]);
        let (target, values) = pg::verify(&p.products[i], p.rows[i].ilog2() as usize + 2, &mut t)?;
        let beta = t.challenge(0x464143544f52);
        let lane = eq_evaluations(&target[..2]);
        let (claim, point) = pg::verify_sc(
            &p.route[i],
            7,
            p.rows[i].ilog2() as usize,
            values[0] + beta * values[1],
            &mut t,
        )?;
        if claim
            != eq_eval(&target[2..], &point)
                * route_value(
                    i,
                    &p.openings[i].opening.evaluations[counts[i]..2 * counts[i]],
                    s,
                    routing,
                    &lane,
                    beta,
                )
        {
            return Err(Error::Terminal);
        }
        route_points.push(point);
    }
    if p.products.iter().map(|p| p.roots[0]).product::<F>()
        != p.products.iter().map(|p| p.roots[1]).product::<F>()
    {
        return Err(Error::ProductMismatch);
    }
    let seed = vec![t.challenge(0x4f50454e)];
    for i in 0..3 {
        let mut points: Vec<_> = [&local_points[i], &route_points[i]]
            .into_iter()
            .flat_map(|r| (0..counts[i]).map(move |j| table_point(j, r, widths[i])))
            .collect();
        if i == 0 {
            points.extend(hash_points(&claims));
        }
        verify_mle_opening(
            p.rows[i] * widths[i],
            &points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &p.openings[i],
            &role_seed(&seed, i as u64),
        )
        .map_err(pcs_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_transition_binds_oracles_routes_shapes_and_roots() {
        let n = 11;
        let public = 5;
        let c = Circuit::new(n, public, (0..6 * n + public).collect()).unwrap();
        let old = MerkleTree::new(vec![F::ZERO; c.assignment_tree_len()]).unwrap();
        let perm = MerkleTree::new(
            c.encoded_permutation()
                .into_iter()
                .map(F::from_usize)
                .collect(),
        )
        .unwrap();
        let u = [
            (0, F::ZERO, F::from_u64(5)),
            (1, F::ZERO, F::TWO),
            (2, F::ZERO, F::from_u64(7)),
        ];
        let new = old
            .updated(
                &u.iter()
                    .map(|&(i, _, v)| (c.assignment_leaf_index(i), v))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let p = prove(
            &c,
            &perm,
            &old,
            &new,
            2,
            2,
            3,
            &u,
            old.commitment(),
            new.commitment(),
        )
        .unwrap();
        let check = |p: &Proof| {
            verify(
                CircuitShape::from_circuit(&c),
                perm.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                p,
            )
        };
        check(&p).unwrap();
        assert!(p.plaintext_bytes() > 0);
        // Exercise both sides of the aggregate ratio boundary, then force the
        // prover to rebuild a transcript with fewer revealed tables.
        let needed_credit =
            2 * p.plaintext_bytes() as i128 - bincode::serialized_size(&p).unwrap() as i128;
        assert!(fits_plain_budget(&p, needed_credit).unwrap());
        assert!(!fits_plain_budget(&p, needed_credit - 1).unwrap());
        let fallback = prove_with_plain_budget(
            &c,
            &perm,
            &old,
            &new,
            2,
            2,
            3,
            &u,
            old.commitment(),
            new.commitment(),
            1,
            needed_credit - 1,
        )
        .unwrap();
        assert!(fallback.plaintext_bytes() < p.plaintext_bytes());
        assert!(fits_plain_budget(&fallback, needed_credit - 1).unwrap());
        check(&fallback).unwrap();
        for i in 0..3 {
            let mut bad = p.clone();
            bad.openings[i].opening.evaluations[0] += F::ONE;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.openings[i].commitment[0] ^= 1;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.products[i].roots[0] += F::ONE;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.route[i].rounds[0][2] += F::ONE;
            assert!(check(&bad).is_err());
            let mut bad = p.clone();
            bad.rows[i] *= 2;
            assert!(check(&bad).is_err());
        }
        let mut bad = p.clone();
        bad.gate_count = 0;
        assert!(check(&bad).is_err());
        let mut bad = p.clone();
        bad.update_count = 2;
        assert!(check(&bad).is_err());
        let mut wrong = new.commitment();
        wrong.root[0] += F::ONE;
        assert!(
            verify(
                CircuitShape::from_circuit(&c),
                perm.commitment(),
                old.commitment(),
                wrong,
                2,
                2,
                3,
                &p
            )
            .is_err()
        );
    }
    #[test]
    fn invalid_copy_update_is_rejected_by_routing() {
        let mut sigma: Vec<_> = (0..24).collect();
        sigma.swap(0, 3);
        let c = Circuit::new(4, 0, sigma).unwrap();
        let old = MerkleTree::new(vec![F::ZERO; c.assignment_tree_len()]).unwrap();
        let perm = MerkleTree::new(
            c.encoded_permutation()
                .into_iter()
                .map(F::from_usize)
                .collect(),
        )
        .unwrap();
        let u = [
            (0, F::ZERO, F::from_u64(5)),
            (1, F::ZERO, F::TWO),
            (2, F::ZERO, F::from_u64(7)),
        ];
        let new = old
            .updated(
                &u.iter()
                    .map(|&(i, _, v)| (c.assignment_leaf_index(i), v))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert!(matches!(
            prove(
                &c,
                &perm,
                &old,
                &new,
                2,
                2,
                3,
                &u,
                old.commitment(),
                new.commitment()
            ),
            Err(Error::ProductMismatch)
        ));
    }
    #[test]
    fn compact_one_gate_n19_layout_and_budget() {
        let h = 21;
        let c = Circuit::new(1 << 18, 256, (0..3 * (1 << 19) + 256).collect()).unwrap();
        let shape = crate::transition_relation::split::estimate_shape(&c, &[0, 1, 2]).unwrap();
        assert_eq!(shape, (128, 16, 128));
        assert_eq!(c.assignment_tree_len(), 1 << h);
        let policy = plain_policy([2048, 512, 256, 512]);
        assert_eq!(policy, [true; 4]);
        assert_eq!(plain_policy([2048; 4]), [true, true, false, false]);
        assert_eq!(
            plain_policy([4096, 8192, 2048, 512]),
            [false, false, true, true]
        );
    }
}
