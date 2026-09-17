//! Sparse PIOP with hash endpoint oracles and 64 GKR reductions.
//! A row has eight endpoints (old x,y,d,h; new x,y,d,h), then the unchanged
//! compact routing witness. There are R rows, with zero padding in columns.
//! The independent, challenge-dependent product table is unchanged.

pub(crate) use super::Error;
use super::*;
use crate::poseidon_scalar::round_reduction as endpoint_gkr;

const ENDPOINT_VERSION: u64 = 0x454e_4450_0000_0001;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    row_count: usize,
    main_opening: MleOpeningProof,
    product_opening: MleOpeningProof,
    local: SumcheckProof,
    poseidon: endpoint_gkr::Proof,
    product: SumcheckProof,
}

fn endpoint_layout(statement: Statement) -> MainLayout {
    let compact_width = compact_column_count(statement);
    MainLayout {
        compact_width,
        width: (compact_width + LOCAL_HASH_FIELDS).next_power_of_two(),
    }
}

/// Prove one hierarchy-level transition with endpoint GKR and sparse routing.
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
    let phase = Instant::now();
    validate_level_size(updates.len(), lower, capacity)?;
    authenticate_roots(old_tree, new_tree, old_commitment, new_commitment)?;
    profile_checkpoint("transition CAIR: statement/tree authentication", phase);
    let phase = Instant::now();
    let table = TransitionTable::build(circuit, permutation_tree, old_tree, new_tree, updates)?;
    profile_checkpoint("transition CAIR: sparse DAG/table construction", phase);
    let row_count = table.row_count();
    let statement = table.statement();
    let main_layout = endpoint_layout(statement);
    eprintln!(
        "transition CAIR shape: updated_positions={}, level={level}, rows={row_count}, main_width={}, product_width={}",
        updates.len(),
        main_layout.width,
        ProductLayout::new(row_count).width,
    );
    let phase = Instant::now();
    let compact = table.compact_witness();
    profile_checkpoint("transition CAIR: compact witness columns", phase);
    let phase = Instant::now();
    let endpoints = local_hash_columns(&compact.hash_inputs, row_count);
    let main_table = pack_columns(
        row_count,
        main_layout.width,
        endpoints.iter().chain(&compact.columns),
    );
    profile_checkpoint("transition CAIR: packed main table", phase);
    let commitment_started = Instant::now();
    let main_committed = commit_mle(main_table).map_err(whir_error)?;
    eprintln!(
        "transition CAIR checkpoint: main commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );

    let mut public_seed = statement_seed(
        CircuitShape::from_circuit(circuit),
        level,
        lower,
        capacity,
        permutation_tree.commitment(),
        old_commitment,
        new_commitment,
        row_count,
        main_layout,
        main_committed.commitment(),
    );
    public_seed.push(Bn254::from_u64(ENDPOINT_VERSION));
    let routing_challenges = RoutingChallenges::derive(&public_seed, main_committed.commitment());
    let phase = Instant::now();
    let factors = table.product_factors(routing_challenges);
    factors.verify().map_err(|_| Error::ProductMismatch)?;
    profile_checkpoint("transition CAIR: routing product factors", phase);
    let product_layout = ProductLayout::new(row_count);
    let phase = Instant::now();
    let product_columns = product_trace(
        row_count,
        product_layout,
        &factors.producers,
        &factors.references,
    );
    profile_checkpoint("transition CAIR: product-tree trace", phase);
    let phase = Instant::now();
    let product_table = pack_columns(row_count, product_layout.width, product_columns.iter());
    profile_checkpoint("transition CAIR: packed product table", phase);
    let commitment_started = Instant::now();
    let product_committed = commit_mle(product_table).map_err(whir_error)?;
    eprintln!(
        "transition CAIR checkpoint: product commitment complete in {:.3}s",
        commitment_started.elapsed().as_secs_f64(),
    );

    let product_seed = commitment_seed(product_committed.commitment());
    let mut transcript = transition_transcript(&public_seed, &product_seed);
    let phase = Instant::now();
    let local_constraint_count = compact_residuals(
        &vec![Bn254::ZERO; main_layout.compact_width],
        &[Bn254::ZERO; LOCAL_HASH_FIELDS],
        statement,
    )
    .len();
    let local_weights = challenges(&transcript, 0x1000, local_constraint_count);
    let local_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let local_hash_columns = local_hash_columns(&compact.hash_inputs, row_count);
    let local_columns = compact
        .columns
        .clone()
        .into_iter()
        .chain(local_hash_columns)
        .collect();
    profile_checkpoint("transition CAIR: local sumcheck preparation", phase);
    let phase = Instant::now();
    let (local, local_point) = prove_local_sumcheck(
        local_columns,
        main_layout.compact_width,
        statement,
        &local_weights,
        &local_target,
        &mut transcript,
    )?;
    profile_checkpoint("transition CAIR: local sumcheck total", phase);

    let phase = Instant::now();
    let (poseidon, poseidon_claims) = endpoint_gkr::prove(
        std::array::from_fn(|word| compact.hash_inputs[word].clone()),
        &compact.hash_inputs[3],
        &mut transcript,
    )
    .map_err(|_| Error::Sumcheck)?;
    profile_checkpoint("transition CAIR: all-round endpoint reduction", phase);

    let phase = Instant::now();
    let product_weights = challenges(
        &transcript,
        0x3000,
        PRODUCT_BASE_COLUMNS + 2 * product_layout.row_variables,
    );
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let route_columns = crate::parallel::clone_columns(&compact.columns);
    let cross_work = cross_work(&product_columns, row_count, product_layout);
    profile_checkpoint("transition CAIR: product sumcheck preparation", phase);
    let phase = Instant::now();
    let (product, product_point) = prove_product_sumcheck(
        product_columns,
        route_columns,
        cross_work,
        statement,
        routing_challenges,
        &product_weights,
        &product_target,
        &mut transcript,
    )?;
    profile_checkpoint("transition CAIR: product sumcheck total", phase);

    let phase = Instant::now();
    let opening_seed =
        endpoint_opening_seed(&public_seed, &product_seed, &local, &poseidon, &product);
    let main_points =
        endpoint_opening_points(main_layout, &local_point, &product_point, &poseidon_claims);
    let product_points = product_opening_points(product_layout, &product_point);
    let main_seed = role_seed(&opening_seed, 1);
    let product_opening_seed = role_seed(&opening_seed, 2);
    let main_refs = main_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let product_refs = product_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    profile_checkpoint("transition CAIR: opening preparation", phase);
    let (main_opening, product_opening) = join(
        || {
            main_committed.open_with_checkpoints(
                &main_refs,
                &main_seed,
                "transition CAIR main checkpoint",
            )
        },
        || {
            product_committed.open_with_checkpoints(
                &product_refs,
                &product_opening_seed,
                "transition CAIR product checkpoint",
            )
        },
    );
    Ok(Proof {
        row_count,
        main_opening,
        product_opening,
        local,
        poseidon,
        product,
    })
}

/// Verify one sparse transition in public-input plus polylogarithmic work.
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
    let assignment_len = shape.assignment_len;
    let physical_len = shape.assignment_tree_len();
    if permutation_commitment.len != physical_len
        || old_commitment.len != physical_len
        || new_commitment.len != physical_len
    {
        return Err(Error::AssignmentAuthentication);
    }
    let max_rows = 16usize.checked_mul(physical_len).ok_or(Error::TableShape)?;
    if proof.row_count < 2 || !proof.row_count.is_power_of_two() || proof.row_count > max_rows {
        return Err(Error::TableShape);
    }
    let statement = Statement {
        gate_pairs: shape.gate_pairs,
        public_inputs: shape.public_inputs,
        assignment_len,
        height: physical_len.trailing_zeros() as usize,
        permutation: permutation_commitment,
        old_assignment: old_commitment,
        new_assignment: new_commitment,
    };
    let main_layout = endpoint_layout(statement);
    let product_layout = ProductLayout::new(proof.row_count);
    let mut public_seed = statement_seed(
        shape,
        level,
        lower,
        capacity,
        permutation_commitment,
        old_commitment,
        new_commitment,
        proof.row_count,
        main_layout,
        &proof.main_opening.commitment,
    );
    public_seed.push(Bn254::from_u64(ENDPOINT_VERSION));
    let routing_challenges =
        RoutingChallenges::derive(&public_seed, &proof.main_opening.commitment);
    let product_seed = commitment_seed(&proof.product_opening.commitment);
    let mut transcript = transition_transcript(&public_seed, &product_seed);

    let local_constraint_count = compact_residuals(
        &vec![Bn254::ZERO; main_layout.compact_width],
        &[Bn254::ZERO; LOCAL_HASH_FIELDS],
        statement,
    )
    .len();
    let local_weights = challenges(&transcript, 0x1000, local_constraint_count);
    let local_target = challenges(&transcript, 0x1100, product_layout.row_variables);
    let (local_claim, local_point) = verify_sumcheck(
        &proof.local,
        compact_constraint_degree(statement),
        interpolate,
        product_layout.row_variables,
        LOCAL_ROUND_TAG,
        0x1200,
        &mut transcript,
    )?;
    let poseidon_claims = endpoint_gkr::verify(
        &proof.poseidon,
        product_layout.row_variables + 1,
        &mut transcript,
    )
    .map_err(|_| Error::Sumcheck)?;
    let product_weights = challenges(
        &transcript,
        0x3000,
        PRODUCT_BASE_COLUMNS + 2 * product_layout.row_variables,
    );
    let product_target = challenges(&transcript, 0x3100, product_layout.row_variables);
    let (product_claim, product_point) = verify_sumcheck(
        &proof.product,
        PRODUCT_DEGREE,
        interpolate,
        product_layout.row_variables,
        PRODUCT_ROUND_TAG,
        0x3200,
        &mut transcript,
    )?;

    let opening_seed = endpoint_opening_seed(
        &public_seed,
        &product_seed,
        &proof.local,
        &proof.poseidon,
        &proof.product,
    );
    let main_points =
        endpoint_opening_points(main_layout, &local_point, &product_point, &poseidon_claims);
    let product_points = product_opening_points(product_layout, &product_point);
    let main_refs = main_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let product_refs = product_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
    verify_mle_opening(
        proof.row_count * main_layout.width,
        &main_refs,
        &proof.main_opening,
        &role_seed(&opening_seed, 1),
    )
    .map_err(whir_error)?;
    verify_mle_opening(
        proof.row_count * product_layout.width,
        &product_refs,
        &proof.product_opening,
        &role_seed(&opening_seed, 2),
    )
    .map_err(whir_error)?;

    let main_values = &proof.main_opening.opening.evaluations;
    let expected_main_values = 2 * main_layout.compact_width + LOCAL_HASH_FIELDS + 4;
    if main_values.len() != expected_main_values {
        return Err(Error::TableShape);
    }
    let mut cursor = 0;
    let local_values = &main_values[cursor..cursor + main_layout.compact_width];
    cursor += main_layout.compact_width;
    let local_hash_values = &main_values[cursor..cursor + LOCAL_HASH_FIELDS];
    cursor += LOCAL_HASH_FIELDS;
    let route_values = &main_values[cursor..cursor + main_layout.compact_width];
    cursor += main_layout.compact_width;
    let endpoint_values = &main_values[cursor..];
    if endpoint_values[..3] != poseidon_claims.inputs
        || endpoint_values[3] != poseidon_claims.output
    {
        return Err(Error::Terminal);
    }

    let local_terminal = eq_eval(&local_target, &local_point)
        * combined_local_residual(local_values, local_hash_values, statement, &local_weights);
    if local_terminal != local_claim {
        return Err(Error::Terminal);
    }
    let product_values = &proof.product_opening.opening.evaluations;
    let expected_product_values =
        product_layout.used_columns + 4 * product_layout.row_variables + 2;
    if product_values.len() != expected_product_values {
        return Err(Error::TableShape);
    }
    let general = &product_values[..product_layout.used_columns];
    let transformed = &product_values[product_layout.used_columns
        ..product_layout.used_columns + 4 * product_layout.row_variables];
    let roots = &product_values[product_values.len() - 2..];
    if roots[0] != roots[1] {
        return Err(Error::ProductMismatch);
    }
    let product_terminal = eq_eval(&product_target, &product_point)
        * combined_product_terminal(
            general,
            transformed,
            route_values,
            &product_point,
            product_layout,
            statement,
            routing_challenges,
            &product_weights,
        );
    if product_terminal != product_claim {
        return Err(Error::Terminal);
    }
    Ok(())
}

fn endpoint_opening_seed(
    public: &[Bn254],
    product_seed: &[Bn254],
    local: &SumcheckProof,
    poseidon: &endpoint_gkr::Proof,
    product: &SumcheckProof,
) -> Vec<Bn254> {
    let mut seed = vec![
        Bn254::from_u64(ENDPOINT_VERSION),
        Bn254::from_usize(public.len()),
    ];
    seed.extend_from_slice(public);
    seed.push(Bn254::from_usize(product_seed.len()));
    seed.extend_from_slice(product_seed);
    for sumcheck in [local, product] {
        seed.push(Bn254::from_usize(sumcheck.rounds.len()));
        for round in &sumcheck.rounds {
            seed.push(Bn254::from_usize(round.len()));
            seed.extend_from_slice(round);
        }
    }
    poseidon.append_transcript(&mut seed);
    seed
}

fn endpoint_opening_points(
    layout: MainLayout,
    local: &[Bn254],
    product: &[Bn254],
    claims: &endpoint_gkr::Claims,
) -> Vec<Vec<Bn254>> {
    let mut points = (0..layout.compact_width)
        .map(|column| table_point(8 + column, local, layout.width))
        .collect::<Vec<_>>();
    points.extend((0..8).map(|column| table_point(column, local, layout.width)));
    points.extend(
        (0..layout.compact_width).map(|column| table_point(8 + column, product, layout.width)),
    );
    // Old/new is the low bit of the hash-row domain. In A it becomes bit 2
    // of the endpoint column, so one non-Boolean column query mixes both sides.
    for field in 0..4 {
        let hash_point = if field == 3 {
            &claims.output_point
        } else {
            &claims.input_point
        };
        let mut point = table_point(field, &hash_point[1..], layout.width);
        point[2] = hash_point[0];
        points.push(point);
    }
    points
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_transition_roundtrip_and_tamper_rejection() {
        let (circuit, permutation, old, new, updates) = super::super::tests::fixture();
        let proof = prove(
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
        .unwrap();
        let check = |p: &Proof| {
            verify(
                CircuitShape::from_circuit(&circuit),
                permutation.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                p,
            )
        };
        check(&proof).unwrap();
        let bytes = serde_json::to_vec(&proof).unwrap();
        let decoded: Proof = serde_json::from_slice(&bytes).unwrap();
        check(&decoded).unwrap();
        #[cfg(feature = "parallel")]
        for threads in [1, 8] {
            let parallel = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
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
                });
            assert_eq!(serde_json::to_vec(&parallel).unwrap(), bytes);
            check(&parallel).unwrap();
        }
        let mut bad = proof.clone();
        bad.poseidon.tamper_for_test();
        assert!(check(&bad).is_err());
        let mut bad = proof.clone();
        bad.local.rounds[0][0] += Bn254::ONE;
        assert!(check(&bad).is_err());
        let mut bad = proof.clone();
        bad.product.rounds[0][0] += Bn254::ONE;
        assert!(check(&bad).is_err());
        let mut bad = proof.clone();
        bad.main_opening.opening.evaluations[0] += Bn254::ONE;
        assert!(check(&bad).is_err());
        let mut bad = proof.clone();
        bad.row_count *= 2;
        assert!(check(&bad).is_err());
        let mut wrong = new.commitment();
        wrong.root += Bn254::ONE;
        assert!(
            verify(
                CircuitShape::from_circuit(&circuit),
                permutation.commitment(),
                old.commitment(),
                wrong,
                2,
                2,
                3,
                &proof
            )
            .is_err()
        );
        assert!(
            verify(
                CircuitShape::from_circuit(&circuit),
                old.commitment(),
                old.commitment(),
                new.commitment(),
                2,
                2,
                3,
                &proof
            )
            .is_err()
        );
    }
}
