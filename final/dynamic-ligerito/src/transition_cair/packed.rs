//! Fourteen-column paired partial trees, independent update records, shared routing product.
pub(crate) use super::Error;
use super::*;
use crate::endpoint_gkr;
use crate::transition_relation::packed as relation;

const VERSION: u64 = 0x5041_434b_0000_0002;
const AUX_TAG: u64 = 0x4155_585f_4c4f_434c;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    row_count: usize,
    update_count: usize,
    gate_count: usize,
    main_opening: MleOpeningProof,
    auxiliary_opening: MleOpeningProof,
    product_opening: MleOpeningProof,
    local: SumcheckProof,
    auxiliary: SumcheckProof,
    poseidon: endpoint_gkr::Proof,
    product: SumcheckProof,
}

fn node_layout() -> MainLayout {
    MainLayout {
        compact_width: 22,
        width: relation::NODE_WIDTH,
    }
}
fn auxiliary_rows(k: usize, g: usize) -> usize {
    (k + g).max(2).next_power_of_two()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    circuit: &Circuit,
    permutation_tree: &MerkleTree,
    old_tree: &MerkleTree,
    new_tree: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_commitment: Commitment,
    new_commitment: Commitment,
) -> Result<Proof, Error> {
    prove_with_checkpoints(
        circuit,
        permutation_tree,
        old_tree,
        new_tree,
        level,
        lower,
        capacity,
        updates,
        old_commitment,
        new_commitment,
        1,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_checkpoints(
    circuit: &Circuit,
    permutation_tree: &MerkleTree,
    old_tree: &MerkleTree,
    new_tree: &MerkleTree,
    level: usize,
    lower: usize,
    capacity: usize,
    updates: &[(usize, F, F)],
    old_commitment: Commitment,
    new_commitment: Commitment,
    hash_checkpoints: usize,
) -> Result<Proof, Error> {
    validate_level_size(updates.len(), lower, capacity)?;
    authenticate_roots(old_tree, new_tree, old_commitment, new_commitment)?;
    let phase = Instant::now();
    let table = TransitionTable::build(circuit, permutation_tree, old_tree, new_tree, updates)?;
    let statement = table.statement();
    let witness = table.packed_witness();
    let row_count = witness.nodes[0].len();
    let aux_rows = witness.updates[0].len();
    let aux_columns = relation::auxiliary_columns(statement);
    let aux_width = aux_columns.next_power_of_two();
    let product_layout = ProductLayout::new(row_count);
    eprintln!(
        "transition compact shape: updated_positions={}, gates={}, rows={row_count}, main_width=32, auxiliary_rows={aux_rows}, auxiliary_width={aux_width}, product_width={}",
        updates.len(),
        witness.gate_count,
        product_layout.width
    );
    profile_checkpoint("transition compact: witness construction", phase);
    let phase = Instant::now();
    let (main_committed, aux_committed) = join(
        || commit_mle(pack_columns(row_count, 32, witness.nodes.iter())).map_err(pcs_error),
        || commit_mle(pack_columns(aux_rows, aux_width, witness.updates.iter())).map_err(pcs_error),
    );
    let main_committed = main_committed?;
    let aux_committed = aux_committed?;
    profile_checkpoint("transition compact: node/update commitments", phase);
    let public_seed = public_seed(
        CircuitShape::from_circuit(circuit),
        level,
        lower,
        capacity,
        statement,
        row_count,
        witness.update_count,
        witness.gate_count,
        main_committed.commitment(),
        aux_committed.commitment(),
    );
    let routing = RoutingChallenges::derive(&public_seed, main_committed.commitment());
    let extended_aux = witness
        .updates
        .iter()
        .map(|c| {
            let mut c = c.clone();
            c.resize(row_count, F::ZERO);
            c
        })
        .collect::<Vec<_>>();
    let route_columns = witness
        .nodes
        .iter()
        .cloned()
        .chain(extended_aux)
        .collect::<Vec<_>>();
    let mut producers = Vec::with_capacity(4 * row_count);
    let mut references = Vec::with_capacity(4 * row_count);
    for row in 0..row_count {
        let values = route_columns.iter().map(|c| c[row]).collect::<Vec<_>>();
        let factors = route_factors(&values, statement, routing);
        producers.extend_from_slice(&factors[..4]);
        references.extend_from_slice(&factors[4..]);
    }
    if producers.iter().copied().product::<F>() != references.iter().copied().product::<F>() {
        return Err(Error::ProductMismatch);
    }
    let product_columns = product_trace(row_count, product_layout, &producers, &references);
    let product_committed = commit_mle(pack_columns(
        row_count,
        product_layout.width,
        product_columns.iter(),
    ))
    .map_err(pcs_error)?;
    let product_seed = commitment_seed(product_committed.commitment());
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let node_weights = challenges(
        &transcript,
        0x1000,
        relation::node_residuals(&[F::ZERO; 22], &[F::ZERO; 3], statement).len(),
    );
    let node_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let mut node_columns = witness.nodes.clone();
    node_columns.extend((0..3).map(|row| {
        let mut c = vec![F::ZERO; row_count];
        c[row] = F::ONE;
        c
    }));
    let (local, local_point) = prove_local(
        node_columns,
        relation::NODE_DEGREE,
        &node_weights,
        &node_target,
        LOCAL_ROUND_TAG,
        0x1200,
        &mut transcript,
        |v| relation::node_residuals(&v[..22], &v[22..], statement),
    )?;
    let aux_weights = challenges(
        &transcript,
        0x1300,
        relation::auxiliary_residuals(&vec![F::ZERO; aux_columns], &[F::ZERO; 2], statement).len(),
    );
    let aux_target = challenges(&transcript, 0x1400, aux_rows.ilog2() as usize);
    let mut aux_local = witness.updates.clone();
    aux_local.push(
        (0..aux_rows)
            .map(|i| F::from_bool(i < witness.update_count))
            .collect(),
    );
    aux_local.push(
        (0..aux_rows)
            .map(|i| {
                F::from_bool(
                    i >= witness.update_count && i < witness.update_count + witness.gate_count,
                )
            })
            .collect(),
    );
    let (auxiliary, aux_point) = prove_local(
        aux_local,
        relation::auxiliary_degree(statement),
        &aux_weights,
        &aux_target,
        AUX_TAG,
        0x1500,
        &mut transcript,
        |v| relation::auxiliary_residuals(&v[..aux_columns], &v[aux_columns..], statement),
    )?;
    let (poseidon, claims) = endpoint_gkr::prove_with_checkpoints(
        std::array::from_fn(|word| witness.hash_inputs[word].clone()),
        &[
            witness.hash_inputs[4].clone(),
            witness.hash_inputs[5].clone(),
        ],
        &mut transcript,
        hash_checkpoints,
    )
    .map_err(|_| Error::Sumcheck)?;
    let product_weights = challenges(&transcript, 0x3000, product_layout.used_columns);
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let cross = cross_work(&product_columns, row_count, product_layout);
    let (product, product_point) = prove_product(
        product_columns,
        route_columns,
        cross,
        statement,
        routing,
        &product_weights,
        &product_target,
        &mut transcript,
    )?;
    let seed = opening_seed(
        &public_seed,
        &product_seed,
        &local,
        &auxiliary,
        &poseidon,
        &product,
    );
    let main_points = main_points(&local_point, &product_point, &claims);
    let aux_points = auxiliary_points(
        aux_columns,
        aux_width,
        &aux_point,
        &product_point[..aux_point.len()],
    );
    let product_points = product_opening_points(product_layout, &product_point);
    let (main_opening, (auxiliary_opening, product_opening)) = join(
        || {
            main_committed.open_with_checkpoints(
                &main_points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &role_seed(&seed, 1),
                "compact node opening",
            )
        },
        || {
            join(
                || {
                    aux_committed.open_with_checkpoints(
                        &aux_points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                        &role_seed(&seed, 3),
                        "compact update opening",
                    )
                },
                || {
                    product_committed.open_with_checkpoints(
                        &product_points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                        &role_seed(&seed, 2),
                        "compact product opening",
                    )
                },
            )
        },
    );
    Ok(Proof {
        row_count,
        update_count: witness.update_count,
        gate_count: witness.gate_count,
        main_opening,
        auxiliary_opening,
        product_opening,
        local,
        auxiliary,
        poseidon,
        product,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    shape: CircuitShape,
    permutation_commitment: Commitment,
    old_commitment: Commitment,
    new_commitment: Commitment,
    level: usize,
    lower: usize,
    capacity: usize,
    proof: &Proof,
) -> Result<(), Error> {
    let physical_len = shape.assignment_tree_len();
    if permutation_commitment.len != physical_len
        || old_commitment.len != physical_len
        || new_commitment.len != physical_len
    {
        return Err(Error::AssignmentAuthentication);
    }
    validate_level_size(proof.update_count, lower, capacity)?;
    if proof.update_count > shape.assignment_len
        || proof.gate_count > proof.update_count
        || proof.row_count < 4
        || !proof.row_count.is_power_of_two()
        || proof.row_count > 16usize.checked_mul(physical_len).ok_or(Error::TableShape)?
    {
        return Err(Error::TableShape);
    }
    let aux_rows = auxiliary_rows(proof.update_count, proof.gate_count);
    if aux_rows > proof.row_count {
        return Err(Error::TableShape);
    }
    let statement = Statement {
        gate_pairs: shape.gate_pairs,
        public_inputs: shape.public_inputs,
        assignment_len: shape.assignment_len,
        height: physical_len.ilog2() as usize,
        permutation: permutation_commitment,
        old_assignment: old_commitment,
        new_assignment: new_commitment,
    };
    let aux_columns = relation::auxiliary_columns(statement);
    let aux_width = aux_columns.next_power_of_two();
    let product_layout = ProductLayout::new(proof.row_count);
    let public_seed = public_seed(
        shape,
        level,
        lower,
        capacity,
        statement,
        proof.row_count,
        proof.update_count,
        proof.gate_count,
        &proof.main_opening.commitment,
        &proof.auxiliary_opening.commitment,
    );
    let routing = RoutingChallenges::derive(&public_seed, &proof.main_opening.commitment);
    let product_seed = commitment_seed(&proof.product_opening.commitment);
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let node_weights = challenges(
        &transcript,
        0x1000,
        relation::node_residuals(&[F::ZERO; 22], &[F::ZERO; 3], statement).len(),
    );
    let node_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let (node_claim, node_point) = verify_sumcheck(
        &proof.local,
        relation::NODE_DEGREE,
        interpolate,
        product_layout.row_variables,
        LOCAL_ROUND_TAG,
        0x1200,
        &mut transcript,
    )?;
    let aux_weights = challenges(
        &transcript,
        0x1300,
        relation::auxiliary_residuals(&vec![F::ZERO; aux_columns], &[F::ZERO; 2], statement).len(),
    );
    let aux_target = challenges(&transcript, 0x1400, aux_rows.ilog2() as usize);
    let (aux_claim, aux_point) = verify_sumcheck(
        &proof.auxiliary,
        relation::auxiliary_degree(statement),
        interpolate,
        aux_target.len(),
        AUX_TAG,
        0x1500,
        &mut transcript,
    )?;
    let claims = endpoint_gkr::verify(
        &proof.poseidon,
        product_layout.row_variables + 1,
        &mut transcript,
    )
    .map_err(|_| Error::Sumcheck)?;
    let product_weights = challenges(&transcript, 0x3000, product_layout.used_columns);
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let (product_claim, product_point) = verify_sumcheck(
        &proof.product,
        relation::ROUTE_DEGREE,
        interpolate,
        product_layout.row_variables,
        PRODUCT_ROUND_TAG,
        0x3200,
        &mut transcript,
    )?;
    let seed = opening_seed(
        &public_seed,
        &product_seed,
        &proof.local,
        &proof.auxiliary,
        &proof.poseidon,
        &proof.product,
    );
    let main_points = main_points(&node_point, &product_point, &claims);
    let aux_points = auxiliary_points(
        aux_columns,
        aux_width,
        &aux_point,
        &product_point[..aux_point.len()],
    );
    let product_points = product_opening_points(product_layout, &product_point);
    for (size, points, opening, role) in [
        (proof.row_count * 32, &main_points, &proof.main_opening, 1),
        (
            aux_rows * aux_width,
            &aux_points,
            &proof.auxiliary_opening,
            3,
        ),
        (
            proof.row_count * product_layout.width,
            &product_points,
            &proof.product_opening,
            2,
        ),
    ] {
        verify_mle_opening(
            size,
            &points.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            opening,
            &role_seed(&seed, role),
        )
        .map_err(pcs_error)?;
    }
    let nodes = &proof.main_opening.opening.evaluations;
    let aux = &proof.auxiliary_opening.opening.evaluations;
    if nodes.len() != 60 || aux.len() != 2 * aux_columns {
        return Err(Error::TableShape);
    }
    check_hash_links(&nodes[44..], &claims)?;
    let roots = (0..3)
        .map(|i| boolean_eq(i, &node_point))
        .collect::<Vec<_>>();
    if eq_eval(&node_target, &node_point)
        * weighted(
            &relation::node_residuals(&nodes[..22], &roots, statement),
            &node_weights,
        )
        != node_claim
    {
        return Err(Error::Terminal);
    }
    let selectors = [
        prefix(proof.update_count, &aux_point),
        prefix(proof.update_count + proof.gate_count, &aux_point)
            - prefix(proof.update_count, &aux_point),
    ];
    if eq_eval(&aux_target, &aux_point)
        * weighted(
            &relation::auxiliary_residuals(&aux[..aux_columns], &selectors, statement),
            &aux_weights,
        )
        != aux_claim
    {
        return Err(Error::Terminal);
    }
    let extension = product_point[aux_point.len()..]
        .iter()
        .fold(F::ONE, |p, &x| p * (F::ONE - x));
    let route_values = nodes[22..44]
        .iter()
        .copied()
        .chain(aux[aux_columns..].iter().map(|&x| extension * x))
        .collect::<Vec<_>>();
    let product = &proof.product_opening.opening.evaluations;
    if product.len() != product_layout.used_columns + 4 * product_layout.row_variables + 2 {
        return Err(Error::TableShape);
    }
    if product[product.len() - 2] != product[product.len() - 1] {
        return Err(Error::ProductMismatch);
    }
    let general = &product[..product_layout.used_columns];
    let transformed = &product[product_layout.used_columns..product.len() - 2];
    let mut crosses = Vec::new();
    let mut meta = Vec::new();
    let mut cursor = 0;
    for stage in 0..product_layout.row_variables {
        let low = product_layout.row_variables - stage - 1;
        let selector = product_point[low..]
            .iter()
            .fold(F::ONE, |p, &x| p * (F::ONE - x));
        for side in 0..2 {
            crosses.push([
                selector * transformed[cursor],
                selector * transformed[cursor + 1],
            ]);
            cursor += 2;
            meta.push(CrossWork {
                output_column: product_layout.cross_column(stage, side),
                left: Vec::new(),
                right: Vec::new(),
            });
        }
    }
    if eq_eval(&product_target, &product_point)
        * product_residual(
            general,
            &route_values,
            &crosses,
            &meta,
            statement,
            routing,
            &product_weights,
        )
        != product_claim
    {
        return Err(Error::Terminal);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn public_seed(
    shape: CircuitShape,
    level: usize,
    lower: usize,
    capacity: usize,
    statement: Statement,
    rows: usize,
    k: usize,
    g: usize,
    main: &crate::static_snark::TraceCommitment,
    auxiliary: &crate::static_snark::TraceCommitment,
) -> Vec<F> {
    let mut seed = statement_seed(
        shape,
        level,
        lower,
        capacity,
        statement.permutation,
        statement.old_assignment,
        statement.new_assignment,
        rows,
        node_layout(),
        main,
    );
    seed.extend([
        F::from_u64(VERSION),
        F::from_usize(k),
        F::from_usize(g),
        F::from_usize(auxiliary_rows(k, g)),
        F::from_usize(relation::auxiliary_columns(statement).next_power_of_two()),
    ]);
    seed.extend(commitment_seed(auxiliary));
    seed
}

fn weighted(values: &[F], weights: &[F]) -> F {
    values.iter().zip(weights).map(|(&x, &w)| x * w).sum()
}
fn boolean_eq(index: usize, point: &[F]) -> F {
    point.iter().enumerate().fold(F::ONE, |p, (bit, &x)| {
        p * if index & (1 << bit) == 0 {
            F::ONE - x
        } else {
            x
        }
    })
}
fn prefix(bound: usize, point: &[F]) -> F {
    if bound == 1usize << point.len() {
        return F::ONE;
    }
    let mut result = F::ZERO;
    let mut equal = F::ONE;
    for bit in (0..point.len()).rev() {
        if bound & (1 << bit) == 0 {
            equal *= F::ONE - point[bit];
        } else {
            result += equal * (F::ONE - point[bit]);
            equal *= point[bit];
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn prove_local(
    mut columns: Vec<Vec<F>>,
    degree: usize,
    weights: &[F],
    target: &[F],
    tag: u64,
    challenge: u64,
    transcript: &mut RawTranscript,
    residuals: impl Fn(&[F]) -> Vec<F> + Sync,
) -> Result<(SumcheckProof, Vec<F>), Error> {
    let mut eq = eq_evaluations(target);
    let mut point = Vec::new();
    let mut rounds = Vec::new();
    let mut claim = F::ZERO;
    for round in 0..target.len() {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            degree + 1,
            (degree + 1) * columns.len(),
            || vec![F::ZERO; columns.len()],
            |values, pair, t| {
                for (v, c) in values.iter_mut().zip(&columns) {
                    *v = lerp(c[2 * pair], c[2 * pair + 1], t);
                }
                lerp(eq[2 * pair], eq[2 * pair + 1], t) * weighted(&residuals(values), weights)
            },
        );
        finish_prover_round(
            &evaluations,
            &mut claim,
            &mut point,
            round,
            tag,
            challenge,
            interpolate,
            transcript,
        )?;
        fold(&mut eq, point[round]);
        crate::parallel::fold_columns(&mut columns, point[round]);
        rounds.push(evaluations);
    }
    Ok((SumcheckProof { rounds }, point))
}

fn route_factors(values: &[F], statement: Statement, routing: RoutingChallenges) -> [F; 8] {
    let node = relation::node_routes(&values[..22], statement);
    let auxiliary = relation::auxiliary_routes(&values[22..], statement);
    std::array::from_fn(|lane| {
        let first = node[8 * lane..8 * lane + 8].try_into().unwrap();
        let second = auxiliary[8 * lane..8 * lane + 8].try_into().unwrap();
        (routing.gamma + compress_fields(first, routing.theta))
            * (routing.gamma + compress_fields(second, routing.theta))
    })
}

#[allow(clippy::too_many_arguments)]
fn product_residual(
    product: &[F],
    routes: &[F],
    crosses: &[[F; 2]],
    meta: &[CrossWork],
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[F],
) -> F {
    let factors = route_factors(routes, statement, routing);
    let mut result = (0..8)
        .map(|i| weights[i] * (product[i] - factors[i]))
        .sum::<F>();
    let pair_residuals = [
        product[8] - product[0] * product[1],
        product[9] - product[2] * product[3],
        product[10] - product[4] * product[5],
        product[11] - product[6] * product[7],
        product[12] - product[8] * product[9],
        product[13] - product[10] * product[11],
    ];
    for (i, r) in pair_residuals.into_iter().enumerate() {
        result += weights[8 + i] * r;
    }
    for (i, (v, m)) in crosses.iter().zip(meta).enumerate() {
        result += weights[14 + i] * (product[m.output_column] - v[0] * v[1]);
    }
    result
}

fn opening_seed(
    public: &[F],
    product_seed: &[F],
    local: &SumcheckProof,
    auxiliary: &SumcheckProof,
    poseidon: &endpoint_gkr::Proof,
    product: &SumcheckProof,
) -> Vec<F> {
    let mut seed = vec![F::from_u64(VERSION), F::from_usize(public.len())];
    seed.extend_from_slice(public);
    seed.push(F::from_usize(product_seed.len()));
    seed.extend_from_slice(product_seed);
    for proof in [local, auxiliary, product] {
        seed.push(F::from_usize(proof.rounds.len()));
        for r in &proof.rounds {
            seed.push(F::from_usize(r.len()));
            seed.extend_from_slice(r);
        }
    }
    poseidon.append_transcript(&mut seed);
    seed
}

fn hash_links(c: &endpoint_gkr::Claims) -> Vec<(usize, &[F], F)> {
    (0..4)
        .map(|i| (i, c.input_point.as_slice(), c.inputs[i]))
        .chain((0..2).map(|i| (4 + i, c.output_point.as_slice(), c.outputs[i])))
        .chain((0..2).map(|i| (i, c.output_point.as_slice(), c.feed_forward[i])))
        .collect()
}
fn main_points(local: &[F], product: &[F], c: &endpoint_gkr::Claims) -> Vec<Vec<F>> {
    let mut points = (0..22)
        .map(|i| table_point(i, local, 32))
        .collect::<Vec<_>>();
    points.extend((0..22).map(|i| table_point(i, product, 32)));
    for (word, p, _) in hash_links(c) {
        for side in 0..2 {
            points.push(table_point(6 * side + word, &p[1..], 32));
        }
    }
    points
}
fn check_hash_links(v: &[F], c: &endpoint_gkr::Claims) -> Result<(), Error> {
    for (i, (_, p, value)) in hash_links(c).iter().enumerate() {
        if lerp(v[2 * i], v[2 * i + 1], p[0]) != *value {
            return Err(Error::Terminal);
        }
    }
    Ok(())
}
fn auxiliary_points(columns: usize, width: usize, local: &[F], product: &[F]) -> Vec<Vec<F>> {
    [local, product]
        .into_iter()
        .flat_map(|p| (0..columns).map(move |c| table_point(c, p, width)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn prove_product(
    mut product: Vec<Vec<F>>,
    mut routes: Vec<Vec<F>>,
    mut cross: Vec<CrossWork>,
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[F],
    target: &[F],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<F>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = F::ZERO;
    for round in 0..variables {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            relation::ROUTE_DEGREE + 1,
            (relation::ROUTE_DEGREE + 1) * (product.len() + routes.len() + 2 * cross.len()),
            || {
                (
                    vec![F::ZERO; product.len()],
                    vec![F::ZERO; routes.len()],
                    vec![[F::ZERO; 2]; cross.len()],
                )
            },
            |scratch, pair, t| {
                let (product_values, route_values, cross_values) = scratch;

                for (value, column) in product_values.iter_mut().zip(&product) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                for (value, column) in route_values.iter_mut().zip(&routes) {
                    *value = lerp(column[2 * pair], column[2 * pair + 1], t);
                }
                for (value, work) in cross_values.iter_mut().zip(&cross) {
                    *value = [
                        lerp(work.left[2 * pair], work.left[2 * pair + 1], t),
                        lerp(work.right[2 * pair], work.right[2 * pair + 1], t),
                    ];
                }
                lerp(eq[2 * pair], eq[2 * pair + 1], t)
                    * product_residual(
                        &product_values,
                        &route_values,
                        &cross_values,
                        &cross,
                        statement,
                        routing,
                        weights,
                    )
            },
        );
        finish_prover_round(
            &evaluations,
            &mut claim,
            &mut point,
            round,
            PRODUCT_ROUND_TAG,
            0x3200,
            interpolate,
            transcript,
        )?;
        fold(&mut eq, point[round]);
        product
            .par_iter_mut()
            .chain(routes.par_iter_mut())
            .for_each(|column| fold(column, point[round]));
        cross.par_iter_mut().for_each(|work| {
            fold(&mut work.left, point[round]);
            fold(&mut work.right, point[round]);
        });
        rounds.push(evaluations);
        checkpoint("product", round, variables, started);
    }
    Ok((SumcheckProof { rounds }, point))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_transition_rejects_changed_roots_counts_and_oracles() {
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
        let u = vec![
            (0, F::ZERO, F::from_u64(5)),
            (1, F::ZERO, F::TWO),
            (2, F::ZERO, F::from_u64(7)),
        ];
        let native: Vec<_> = u
            .iter()
            .map(|&(i, _, v)| (c.assignment_leaf_index(i), v))
            .collect();
        let new = old.updated(&native).unwrap();
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
        let mut bad = p.clone();
        bad.main_opening.opening.evaluations[5] += F::ONE;
        assert!(check(&bad).is_err());
        let mut bad = p.clone();
        bad.auxiliary_opening.commitment[0] ^= 1;
        assert!(check(&bad).is_err());
        let mut bad = p.clone();
        bad.product_opening.commitment[0] ^= 1;
        assert!(check(&bad).is_err());
        let mut bad = p.clone();
        bad.update_count = 2;
        assert!(check(&bad).is_err());
        let mut bad = p.clone();
        bad.gate_count = 0;
        assert!(check(&bad).is_err());
        let mut wrong = new.commitment();
        wrong.root[1] += F::ONE;
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
}
