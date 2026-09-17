//! Batched GKR for all 64 rounds, with only endpoint oracles.
//! Each degree-six sumcheck reduces a claim about a round output to three
//! claims at one point about its input. Fresh weights batch these claims only
//! after their values have been absorbed. The caller authenticates both ends.

use super::*;

const ROUNDS: usize = 64;
const DOMAIN: u64 = 0x454e_4450_4f49_4e54;
const OUTPUT_TAG: u64 = 0x454e_4400;
const MESSAGE_TAG: u64 = 0x454e_4500;
const INPUT_TAG: u64 = 0x454e_4600;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Proof {
    output: Bn254,
    layers: Vec<Layer>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Layer {
    rounds: Vec<Vec<Bn254>>,
    inputs: [Bn254; 3],
}

pub(crate) struct Claims {
    pub(crate) output_point: Vec<Bn254>,
    pub(crate) output: Bn254,
    pub(crate) input_point: Vec<Bn254>,
    pub(crate) inputs: [Bn254; 3],
}

impl Proof {
    pub(crate) fn append_transcript(&self, seed: &mut Vec<Bn254>) {
        seed.extend([
            Bn254::from_u64(DOMAIN),
            self.output,
            Bn254::from_usize(self.layers.len()),
        ]);
        for layer in &self.layers {
            seed.push(Bn254::from_usize(layer.rounds.len()));
            for round in &layer.rounds {
                seed.push(Bn254::from_usize(round.len()));
                seed.extend_from_slice(round);
            }
            seed.extend(layer.inputs);
        }
    }

    #[cfg(test)]
    pub(crate) fn tamper_for_test(&mut self) {
        self.layers[32].inputs[1] += Bn254::ONE;
    }
}

fn weights(transcript: &RawTranscript, depth: usize) -> [Bn254; 3] {
    if depth == 0 {
        [Bn254::ONE, Bn254::ZERO, Bn254::ZERO]
    } else {
        std::array::from_fn(|word| transcript.challenge(0x9000 + (3 * depth + word) as u64))
    }
}

fn round_line(round: usize, zero: [Bn254; 3], one: [Bn254; 3]) -> [[Bn254; 3]; 7] {
    let parameters = parameters();
    if !(4..60).contains(&round) {
        return full_round_line_evaluations(round, zero, one, parameters);
    }
    let constant = parameters.internal[round - 4];
    let powered = poseidon_sumcheck::fifth_line_evaluations(zero[0] + constant, one[0] + constant);
    let b = poseidon_sumcheck::line_evaluations(zero[1], one[1]);
    let c = poseidon_sumcheck::line_evaluations(zero[2], one[2]);
    std::array::from_fn(|i| partial_round_from_u([Bn254::ZERO, b[i], c[i]], powered[i]))
}

/// Build transient layers, then consume them in reverse order. No intermediate
/// state is committed. The implementation uses O(rows * rounds) witness RAM.
pub(crate) fn prove(
    inputs: StateColumns,
    digests: &[Bn254],
    transcript: &mut RawTranscript,
) -> Result<(Proof, Claims), Error> {
    let rows = digests.len();
    if rows < 2 || !rows.is_power_of_two() || inputs.iter().any(|c| c.len() != rows) {
        return Err(Error::TraceShape);
    }
    let variables = rows.trailing_zeros() as usize;
    let mut layers = vec![inputs];
    for round in 0..ROUNDS {
        let previous = layers.last().unwrap();
        let mut next: StateColumns = std::array::from_fn(|_| vec![Bn254::ZERO; rows]);
        crate::parallel::rows_mut(
            &mut next.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
            0..rows,
            8,
            |start, columns| {
                for row in 0..columns[0].len() {
                    let state = poseidon_round(
                        round,
                        std::array::from_fn(|w| previous[w][start + row]),
                        parameters(),
                    );
                    for word in 0..3 {
                        columns[word][row] = state[word];
                    }
                }
            },
        );
        layers.push(next);
    }
    if layers.pop().unwrap()[0] != digests {
        return Err(Error::TraceShape);
    }
    transcript.absorb_message(DOMAIN, &[Bn254::from_usize(variables)]);
    let output_point = challenges(transcript, 0x8000, variables);
    let output = evaluate_column(digests, &output_point);
    transcript.absorb_message(OUTPUT_TAG, &[output]);
    let mut current = [output, Bn254::ZERO, Bn254::ZERO];
    let mut target = output_point.clone();
    let mut proofs = Vec::with_capacity(ROUNDS);
    for depth in 0..ROUNDS {
        let round = ROUNDS - 1 - depth;
        let weights = weights(transcript, depth);
        let mut claim = dot(weights, current);
        let mut inputs = layers.pop().unwrap();
        let mut eq = eq_evaluations(&target);
        let mut point = Vec::with_capacity(variables);
        let mut messages = Vec::with_capacity(variables);
        for variable in 0..variables {
            let evaluations = poseidon_sumcheck::sum_pairs(eq.len() / 2, |pair| {
                let expected = round_line(
                    round,
                    std::array::from_fn(|w| inputs[w][2 * pair]),
                    std::array::from_fn(|w| inputs[w][2 * pair + 1]),
                );
                let eq_line = poseidon_sumcheck::line_evaluations(eq[2 * pair], eq[2 * pair + 1]);
                std::array::from_fn(|i| eq_line[i] * dot(weights, expected[i]))
            });
            if evaluations[0] + evaluations[1] != claim {
                return Err(Error::Sumcheck);
            }
            // Depth and variable are explicit framing; labels never overlap.
            transcript.absorb_message(
                MESSAGE_TAG,
                &[Bn254::from_usize(depth), Bn254::from_usize(variable)],
            );
            transcript.absorb_message(MESSAGE_TAG + 1, &evaluations);
            let challenge = transcript.challenge(0xa000);
            claim = poseidon_sumcheck::interpolate(&evaluations, challenge);
            fold(&mut eq, challenge);
            crate::parallel::fold_columns(&mut inputs, challenge);
            point.push(challenge);
            messages.push(evaluations.to_vec());
        }
        current = std::array::from_fn(|w| inputs[w][0]);
        if claim
            != eq_eval(&target, &point) * dot(weights, poseidon_round(round, current, parameters()))
        {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(INPUT_TAG, &current);
        target = point;
        proofs.push(Layer {
            rounds: messages,
            inputs: current,
        });
    }
    Ok((
        Proof {
            output,
            layers: proofs,
        },
        Claims {
            output_point,
            output,
            input_point: target,
            inputs: current,
        },
    ))
}

pub(crate) fn verify(
    proof: &Proof,
    variables: usize,
    transcript: &mut RawTranscript,
) -> Result<Claims, Error> {
    if variables == 0 || proof.layers.len() != ROUNDS {
        return Err(Error::Sumcheck);
    }
    transcript.absorb_message(DOMAIN, &[Bn254::from_usize(variables)]);
    let output_point = challenges(transcript, 0x8000, variables);
    transcript.absorb_message(OUTPUT_TAG, &[proof.output]);
    let mut current = [proof.output, Bn254::ZERO, Bn254::ZERO];
    let mut target = output_point.clone();
    for (depth, layer) in proof.layers.iter().enumerate() {
        if layer.rounds.len() != variables {
            return Err(Error::Sumcheck);
        }
        let weights = weights(transcript, depth);
        let mut claim = dot(weights, current);
        let mut point = Vec::with_capacity(variables);
        for (variable, message) in layer.rounds.iter().enumerate() {
            if message.len() != 7 || message[0] + message[1] != claim {
                return Err(Error::Sumcheck);
            }
            transcript.absorb_message(
                MESSAGE_TAG,
                &[Bn254::from_usize(depth), Bn254::from_usize(variable)],
            );
            transcript.absorb_message(MESSAGE_TAG + 1, message);
            let challenge = transcript.challenge(0xa000);
            claim = poseidon_sumcheck::interpolate(message, challenge);
            point.push(challenge);
        }
        current = layer.inputs;
        if claim
            != eq_eval(&target, &point)
                * dot(weights, poseidon_round(63 - depth, current, parameters()))
        {
            return Err(Error::Sumcheck);
        }
        transcript.absorb_message(INPUT_TAG, &current);
        target = point;
    }
    Ok(Claims {
        output_point,
        output: proof.output,
        input_point: target,
        inputs: current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_symmetric::Permutation;

    #[test]
    fn endpoint_reduction_matches_native_and_rejects_tampering() {
        let inputs: StateColumns =
            std::array::from_fn(|w| (0..8).map(|i| Bn254::from_usize(11 * w + i)).collect());
        let digests = (0..8)
            .map(|i| {
                let mut state = std::array::from_fn(|w| inputs[w][i]);
                crate::hash::poseidon2().permute_mut(&mut state);
                state[0]
            })
            .collect::<Vec<_>>();
        let (proof, _) = prove(inputs.clone(), &digests, &mut RawTranscript::new(7)).unwrap();
        let claims = verify(&proof, 3, &mut RawTranscript::new(7)).unwrap();
        assert_eq!(
            claims.output,
            evaluate_column(&digests, &claims.output_point)
        );
        for w in 0..3 {
            assert_eq!(
                claims.inputs[w],
                evaluate_column(&inputs[w], &claims.input_point)
            );
        }
        assert!(verify(&proof, 3, &mut RawTranscript::new(8)).is_err());
        for depth in [0, 1, 31, 63] {
            let mut bad = proof.clone();
            bad.layers[depth].inputs[2] += Bn254::ONE;
            assert!(verify(&bad, 3, &mut RawTranscript::new(7)).is_err());
            let mut bad = proof.clone();
            bad.layers[depth].rounds[1][2] += Bn254::ONE;
            assert!(verify(&bad, 3, &mut RawTranscript::new(7)).is_err());
        }
        let mut bad = proof.clone();
        bad.output += Bn254::ONE;
        assert!(verify(&bad, 3, &mut RawTranscript::new(7)).is_err());
        let mut bad = proof.clone();
        bad.layers.pop();
        assert!(verify(&bad, 3, &mut RawTranscript::new(7)).is_err());
        for round in 0..64 {
            let zero = [Bn254::from_u64(3), Bn254::from_u64(8), Bn254::from_u64(19)];
            let one = [
                Bn254::from_u64(11),
                Bn254::from_u64(17),
                Bn254::from_u64(23),
            ];
            let actual = round_line(round, zero, one);
            let points = poseidon_sumcheck::line_evaluations(Bn254::ZERO, Bn254::ONE);
            for i in 0..7 {
                assert_eq!(
                    actual[i],
                    poseidon_round(
                        round,
                        std::array::from_fn(|w| zero[w] + points[i] * (one[w] - zero[w])),
                        parameters()
                    )
                );
            }
        }
    }
}
