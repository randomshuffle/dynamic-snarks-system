//! Fourteen-column paired partial trees, independent update records, shared routing product.
pub(crate) use super::Error;
use super::*;
use crate::poseidon_scalar::round_reduction as endpoint_gkr;
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
        compact_width: 6,
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
    updates: &[(usize, Bn254, Bn254)],
    old_commitment: Commitment,
    new_commitment: Commitment,
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
        "transition compact shape: updated_positions={}, gates={}, rows={row_count}, main_width=16, auxiliary_rows={aux_rows}, auxiliary_width={aux_width}, product_width={}",
        updates.len(),
        witness.gate_count,
        product_layout.width
    );
    profile_checkpoint("transition compact: witness construction", phase);
    let phase = Instant::now();
    let (main_committed, aux_committed) = join(
        || commit_mle(pack_columns(row_count, 16, witness.nodes.iter())).map_err(whir_error),
        || {
            commit_mle(pack_columns(aux_rows, aux_width, witness.updates.iter()))
                .map_err(whir_error)
        },
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
            c.resize(row_count, Bn254::ZERO);
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
    if producers.iter().copied().product::<Bn254>() != references.iter().copied().product::<Bn254>()
    {
        return Err(Error::ProductMismatch);
    }
    let product_columns = product_trace(row_count, product_layout, &producers, &references);
    let product_committed = commit_mle(pack_columns(
        row_count,
        product_layout.width,
        product_columns.iter(),
    ))
    .map_err(whir_error)?;
    let product_seed = commitment_seed(product_committed.commitment());
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let node_weights = challenges(
        &transcript,
        0x1000,
        relation::node_residuals(&[Bn254::ZERO; 14], &[Bn254::ZERO; 3], statement).len(),
    );
    let node_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let mut node_columns = witness.nodes.clone();
    node_columns.extend((0..3).map(|row| {
        let mut c = vec![Bn254::ZERO; row_count];
        c[row] = Bn254::ONE;
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
        |v| relation::node_residuals(&v[..14], &v[14..], statement),
    )?;
    let aux_weights = challenges(
        &transcript,
        0x1300,
        relation::auxiliary_residuals(
            &vec![Bn254::ZERO; aux_columns],
            &[Bn254::ZERO; 2],
            statement,
        )
        .len(),
    );
    let aux_target = challenges(&transcript, 0x1400, aux_rows.ilog2() as usize);
    let mut aux_local = witness.updates.clone();
    aux_local.push(
        (0..aux_rows)
            .map(|i| Bn254::from_bool(i < witness.update_count))
            .collect(),
    );
    aux_local.push(
        (0..aux_rows)
            .map(|i| {
                Bn254::from_bool(
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
    let (poseidon, claims) = endpoint_gkr::prove(
        std::array::from_fn(|word| witness.hash_inputs[word].clone()),
        &witness.hash_inputs[3],
        &mut transcript,
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
        relation::node_residuals(&[Bn254::ZERO; 14], &[Bn254::ZERO; 3], statement).len(),
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
        relation::auxiliary_residuals(
            &vec![Bn254::ZERO; aux_columns],
            &[Bn254::ZERO; 2],
            statement,
        )
        .len(),
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
        (proof.row_count * 16, &main_points, &proof.main_opening, 1),
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
        .map_err(whir_error)?;
    }
    let nodes = &proof.main_opening.opening.evaluations;
    let aux = &proof.auxiliary_opening.opening.evaluations;
    if nodes.len() != 32 || aux.len() != 2 * aux_columns {
        return Err(Error::TableShape);
    }
    if nodes[28..31] != claims.inputs || nodes[31] != claims.output {
        return Err(Error::Terminal);
    }
    let roots = (0..3)
        .map(|i| boolean_eq(i, &node_point))
        .collect::<Vec<_>>();
    if eq_eval(&node_target, &node_point)
        * weighted(
            &relation::node_residuals(&nodes[..14], &roots, statement),
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
        .fold(Bn254::ONE, |p, &x| p * (Bn254::ONE - x));
    let route_values = nodes[14..28]
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
            .fold(Bn254::ONE, |p, &x| p * (Bn254::ONE - x));
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
) -> Vec<Bn254> {
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
        Bn254::from_u64(VERSION),
        Bn254::from_usize(k),
        Bn254::from_usize(g),
        Bn254::from_usize(auxiliary_rows(k, g)),
        Bn254::from_usize(relation::auxiliary_columns(statement).next_power_of_two()),
    ]);
    seed.extend(commitment_seed(auxiliary));
    seed
}

fn weighted(values: &[Bn254], weights: &[Bn254]) -> Bn254 {
    values.iter().zip(weights).map(|(&x, &w)| x * w).sum()
}
fn boolean_eq(index: usize, point: &[Bn254]) -> Bn254 {
    point.iter().enumerate().fold(Bn254::ONE, |p, (bit, &x)| {
        p * if index & (1 << bit) == 0 {
            Bn254::ONE - x
        } else {
            x
        }
    })
}
fn prefix(bound: usize, point: &[Bn254]) -> Bn254 {
    if bound == 1usize << point.len() {
        return Bn254::ONE;
    }
    let mut result = Bn254::ZERO;
    let mut equal = Bn254::ONE;
    for bit in (0..point.len()).rev() {
        if bound & (1 << bit) == 0 {
            equal *= Bn254::ONE - point[bit];
        } else {
            result += equal * (Bn254::ONE - point[bit]);
            equal *= point[bit];
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn prove_local(
    mut columns: Vec<Vec<Bn254>>,
    degree: usize,
    weights: &[Bn254],
    target: &[Bn254],
    tag: u64,
    challenge: u64,
    transcript: &mut RawTranscript,
    residuals: impl Fn(&[Bn254]) -> Vec<Bn254> + Sync,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let mut eq = eq_evaluations(target);
    let mut point = Vec::new();
    let mut rounds = Vec::new();
    let mut claim = Bn254::ZERO;
    for round in 0..target.len() {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            degree + 1,
            (degree + 1) * columns.len(),
            || vec![Bn254::ZERO; columns.len()],
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

fn route_factors(values: &[Bn254], statement: Statement, routing: RoutingChallenges) -> [Bn254; 8] {
    let node = relation::node_routes(&values[..14], statement);
    let auxiliary = relation::auxiliary_routes(&values[14..], statement);
    std::array::from_fn(|lane| {
        let first = node[6 * lane..6 * lane + 6].try_into().unwrap();
        let second = auxiliary[6 * lane..6 * lane + 6].try_into().unwrap();
        (routing.gamma + compress_fields(first, routing.theta))
            * (routing.gamma + compress_fields(second, routing.theta))
    })
}

#[allow(clippy::too_many_arguments)]
fn product_residual(
    product: &[Bn254],
    routes: &[Bn254],
    crosses: &[[Bn254; 2]],
    meta: &[CrossWork],
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[Bn254],
) -> Bn254 {
    let factors = route_factors(routes, statement, routing);
    let mut result = (0..8)
        .map(|i| weights[i] * (product[i] - factors[i]))
        .sum::<Bn254>();
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
    public: &[Bn254],
    product_seed: &[Bn254],
    local: &SumcheckProof,
    auxiliary: &SumcheckProof,
    poseidon: &endpoint_gkr::Proof,
    product: &SumcheckProof,
) -> Vec<Bn254> {
    let mut seed = vec![Bn254::from_u64(VERSION), Bn254::from_usize(public.len())];
    seed.extend_from_slice(public);
    seed.push(Bn254::from_usize(product_seed.len()));
    seed.extend_from_slice(product_seed);
    for proof in [local, auxiliary, product] {
        seed.push(Bn254::from_usize(proof.rounds.len()));
        for r in &proof.rounds {
            seed.push(Bn254::from_usize(r.len()));
            seed.extend_from_slice(r);
        }
    }
    poseidon.append_transcript(&mut seed);
    seed
}

fn main_points(
    local: &[Bn254],
    product: &[Bn254],
    claims: &endpoint_gkr::Claims,
) -> Vec<Vec<Bn254>> {
    let mut points = (0..14)
        .map(|c| table_point(c, local, 16))
        .collect::<Vec<_>>();
    points.extend((0..14).map(|c| table_point(c, product, 16)));
    for field in 0..4 {
        let hash_point = if field == 3 {
            &claims.output_point
        } else {
            &claims.input_point
        };
        let mut point = table_point(field, &hash_point[1..], 16);
        point[2] = hash_point[0];
        points.push(point);
    }
    points
}
fn auxiliary_points(
    columns: usize,
    width: usize,
    local: &[Bn254],
    product: &[Bn254],
) -> Vec<Vec<Bn254>> {
    [local, product]
        .into_iter()
        .flat_map(|p| (0..columns).map(move |c| table_point(c, p, width)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn prove_product(
    mut product: Vec<Vec<Bn254>>,
    mut routes: Vec<Vec<Bn254>>,
    mut cross: Vec<CrossWork>,
    statement: Statement,
    routing: RoutingChallenges,
    weights: &[Bn254],
    target: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(SumcheckProof, Vec<Bn254>), Error> {
    let started = Instant::now();
    let variables = target.len();
    let mut eq = eq_evaluations(target);
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);
    let mut claim = Bn254::ZERO;
    for round in 0..variables {
        let evaluations = crate::parallel::sumcheck(
            eq.len() / 2,
            relation::ROUTE_DEGREE + 1,
            (relation::ROUTE_DEGREE + 1) * (product.len() + routes.len() + 2 * cross.len()),
            || {
                (
                    vec![Bn254::ZERO; product.len()],
                    vec![Bn254::ZERO; routes.len()],
                    vec![[Bn254::ZERO; 2]; cross.len()],
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
#[allow(dead_code)]
#[path = "../../benches/support/proof_size.rs"]
mod proof_size;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_transition_roundtrip_tampering_and_parallel_determinism() {
        let (circuit, permutation, old, new, updates) = super::super::tests::fixture();
        let make = || {
            prove(
                &circuit,
                &permutation,
                &old,
                &new,
                2,
                2,
                3,
                &updates,
                old.commitment(),
                new.commitment(),
            )
            .unwrap()
        };
        let check = |proof: &Proof| {
            verify(
                CircuitShape::from_circuit(&circuit),
                permutation.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                proof,
            )
        };
        let proof = make();
        check(&proof).unwrap();
        let encoded = proof_size::encode(&proof).unwrap();
        let decoded: Proof = proof_size::decode(&encoded.bytes).unwrap();
        check(&decoded).unwrap();
        #[cfg(feature = "parallel")]
        for threads in [1, 8] {
            let result = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(make);
            assert_eq!(
                serde_json::to_vec(&result).unwrap(),
                serde_json::to_vec(&proof).unwrap()
            );
            check(&result).unwrap();
        }
        for mutation in 0..10 {
            let mut bad = proof.clone();
            match mutation {
                0 => bad.local.rounds[0][0] += Bn254::ONE,
                1 => bad.auxiliary.rounds[0][0] += Bn254::ONE,
                2 => bad.product.rounds[0][0] += Bn254::ONE,
                3 => bad.poseidon.tamper_for_test(),
                4 => bad.main_opening.opening.evaluations[0] += Bn254::ONE,
                5 => bad.auxiliary_opening.opening.evaluations[0] += Bn254::ONE,
                6 => bad.product_opening.opening.evaluations[0] += Bn254::ONE,
                7 => bad.row_count *= 2,
                8 => bad.update_count += 1,
                _ => bad.gate_count += 1,
            }
            assert!(check(&bad).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn packed_sumcheck_degree_bounds_hold_off_cube() {
        let (circuit, permutation, old, new, updates) = super::super::tests::fixture();
        let statement = TransitionTable::build(&circuit, &permutation, &old, &new, &updates)
            .unwrap()
            .statement();
        let routing = RoutingChallenges {
            theta: Bn254::from_u64(7),
            gamma: Bn254::from_u64(11),
        };
        let affine = |len: usize, t: Bn254| {
            (0..len)
                .map(|i| Bn254::from_usize(13 + 19 * i) + t * Bn254::from_usize(23 + 31 * i))
                .collect::<Vec<_>>()
        };
        let evaluate_node = |t: Bn254| {
            let v = affine(17, t);
            let residuals = relation::node_residuals(&v[..14], &v[14..], statement);
            let weights = (0..residuals.len())
                .map(|i| Bn254::from_usize(i + 1))
                .collect::<Vec<_>>();
            (Bn254::ONE + t) * weighted(&residuals, &weights)
        };
        let evaluate_routes = |t: Bn254| {
            let v = affine(14 + relation::auxiliary_columns(statement), t);
            let factors = route_factors(&v, statement, routing);
            (Bn254::ONE + t)
                * factors
                    .iter()
                    .enumerate()
                    .map(|(i, &x)| Bn254::from_usize(i + 1) * x)
                    .sum::<Bn254>()
        };
        let evaluate_auxiliary = |t: Bn254| {
            let columns = relation::auxiliary_columns(statement);
            let v = affine(columns + 2, t);
            let residuals = relation::auxiliary_residuals(&v[..columns], &v[columns..], statement);
            let weights = (0..residuals.len())
                .map(|i| Bn254::from_usize(i + 1))
                .collect::<Vec<_>>();
            (Bn254::ONE + t) * weighted(&residuals, &weights)
        };
        for (degree, evaluate) in [
            (
                relation::NODE_DEGREE,
                &evaluate_node as &dyn Fn(Bn254) -> Bn254,
            ),
            (
                relation::ROUTE_DEGREE,
                &evaluate_routes as &dyn Fn(Bn254) -> Bn254,
            ),
            (
                relation::auxiliary_degree(statement),
                &evaluate_auxiliary as &dyn Fn(Bn254) -> Bn254,
            ),
        ] {
            let evaluations = (0..=degree)
                .map(|i| evaluate(Bn254::from_usize(i)))
                .collect::<Vec<_>>();
            for t in [17, 43, 97] {
                assert_eq!(
                    interpolate(&evaluations, Bn254::from_u64(t)),
                    evaluate(Bn254::from_u64(t))
                );
            }
        }
    }

    #[test]
    fn packed_neighbor_opening_still_rejects_a_false_copy_constraint() {
        let mut permutation = (0..12).collect::<Vec<_>>();
        permutation.swap(0, 6);
        let circuit = Circuit::new(2, 0, permutation).unwrap();
        let permutation = MerkleTree::new(
            circuit
                .encoded_permutation()
                .into_iter()
                .map(Bn254::from_usize)
                .collect(),
        )
        .unwrap();
        let old = MerkleTree::new(vec![Bn254::ZERO; circuit.assignment_tree_len()]).unwrap();
        // The changed addition gate is valid, but its first input disagrees
        // with the unchanged copy at logical position 6. The neighbor value
        // has no separate column now: its Merkle reference must bind beta.
        let new = old.updated(&[(0, Bn254::ONE), (2, Bn254::ONE)]).unwrap();
        let updates = [
            (0, Bn254::ZERO, Bn254::ONE),
            (1, Bn254::ZERO, Bn254::ZERO),
            (2, Bn254::ZERO, Bn254::ONE),
        ];
        assert!(matches!(
            prove(
                &circuit,
                &permutation,
                &old,
                &new,
                2,
                2,
                3,
                &updates,
                old.commitment(),
                new.commitment()
            ),
            Err(Error::ProductMismatch)
        ));
    }

    #[test]
    fn packed_native_constraints_routes_and_adversarial_labels() {
        let (circuit, permutation, old, new, updates) = super::super::tests::fixture();
        let table = TransitionTable::build(&circuit, &permutation, &old, &new, &updates).unwrap();
        let statement = table.statement();
        let w = table.packed_witness();
        let rows = w.nodes[0].len();
        let routing = RoutingChallenges {
            theta: Bn254::from_u64(17),
            gamma: Bn254::from_u64(29),
        };
        let row = |i: usize| w.nodes.iter().map(|c| c[i]).collect::<Vec<_>>();
        let valid = |v: &[Bn254], i: usize| {
            relation::node_residuals(
                v,
                &(0..3).map(|r| Bn254::from_bool(r == i)).collect::<Vec<_>>(),
                statement,
            )
            .iter()
            .all(|&x| x == Bn254::ZERO)
        };
        for i in 0..rows {
            assert!(valid(&row(i), i), "node {i}");
        }
        for i in 0..w.updates[0].len() {
            let v = w.updates.iter().map(|c| c[i]).collect::<Vec<_>>();
            let selectors = [
                Bn254::from_bool(i < w.update_count),
                Bn254::from_bool(i >= w.update_count && i < w.update_count + w.gate_count),
            ];
            assert!(
                relation::auxiliary_residuals(&v, &selectors, statement)
                    .iter()
                    .all(|&x| x == Bn254::ZERO)
            );
        }
        let internal = (3..rows)
            .find(|&i| row(i)[8] == Bn254::from_u64(3))
            .unwrap();
        let boundary = (3..rows).find(|&i| row(i)[8] == Bn254::TWO).unwrap();
        let leaf = (3..rows).find(|&i| row(i)[8] == Bn254::ONE).unwrap();
        for (i, column) in [
            (0, 11),
            (0, 10),
            (0, 9),
            (boundary, 13),
            (leaf, 11),
            (leaf, 10),
            (internal, 12),
        ] {
            let mut v = row(i);
            v[column] += Bn254::ONE;
            assert!(!valid(&v, i), "row {i} column {column}");
        }
        let mut zero_level = row(internal);
        zero_level[10] = Bn254::ZERO;
        zero_level[2] = Bn254::ONE;
        zero_level[6] = Bn254::ONE;
        assert!(!valid(&zero_level, internal));
        let product = |node_rows: &Vec<Vec<Bn254>>, aux_rows: &Vec<Vec<Bn254>>| {
            let mut p = [Bn254::ONE; 2];
            for i in 0..rows {
                let v = node_rows
                    .iter()
                    .map(|c| c[i])
                    .chain(
                        aux_rows
                            .iter()
                            .map(|c| c.get(i).copied().unwrap_or(Bn254::ZERO)),
                    )
                    .collect::<Vec<_>>();
                let factors = route_factors(&v, statement, routing);
                p[0] *= factors[..4].iter().copied().product::<Bn254>();
                p[1] *= factors[4..].iter().copied().product::<Bn254>();
            }
            p
        };
        let products = product(&w.nodes, &w.updates);
        assert_eq!(products[0], products[1]);
        // Moving a boundary to a disconnected address satisfies its local hash
        // and type checks, but must fail authenticated parent routing.
        let mut detached = w.nodes.clone();
        detached[11][boundary] += Bn254::from_u64(100);
        assert!(valid(
            &detached.iter().map(|c| c[boundary]).collect::<Vec<_>>(),
            boundary
        ));
        let p = product(&detached, &w.updates);
        assert_ne!(p[0], p[1]);
        // A locally valid leaf value with its correctly recomputed digest still
        // cannot detach from the update tuple or its parent digest reference.
        let mut changed = w.nodes.clone();
        changed[0][leaf] += Bn254::ONE;
        changed[4][leaf] += Bn254::ONE;
        let position = (0..circuit.assignment_tree_len())
            .find(|&i| Bn254::from_usize(i) == changed[1][leaf])
            .unwrap();
        changed[3][leaf] = crate::hash::hash_leaf(position, changed[0][leaf]);
        changed[7][leaf] = crate::hash::hash_leaf(position, changed[4][leaf]);
        assert!(valid(
            &changed.iter().map(|c| c[leaf]).collect::<Vec<_>>(),
            leaf
        ));
        let p = product(&changed, &w.updates);
        assert_ne!(p[0], p[1]);
        let mut link = w.updates.clone();
        link[10][0] += Bn254::ONE; // Old assignment value in the repacked E row.
        let p = product(&w.nodes, &link);
        assert_ne!(p[0], p[1]);
    }
}
