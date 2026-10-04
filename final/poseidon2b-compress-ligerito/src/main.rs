use poseidon2b_compress_ligerito_experiment::{Backend, hash};
use std::{error::Error, time::Instant};
fn main() -> Result<(), Box<dyn Error>> {
    flock_core::init_perf_thread_pool();
    // Reusable public parameter generation is excluded, as circuit setup is.
    let _ = hash::constants();
    let samples: usize = std::env::var("HASH_PROOF_SAMPLES")
        .unwrap_or("7".into())
        .parse()?;
    let batches = std::env::var("HASH_PROOF_BATCHES").unwrap_or("8,32,128,512,2048".into());
    let segments = std::env::var("HASH_PROOF_SEGMENTS").unwrap_or("1,2,4".into());
    println!(
        "algorithm,security_bits,batch,segments,gkr_layers,pcs_elements,sample,setup_ms,witness_ms,commit_ms,reduction_ms,open_ms,prover_ms,verify_ms,serialized_bytes,threads"
    );
    for b in batches.split(',') {
        let batch = b.parse::<usize>()?;
        let messages: Vec<_> = (0..batch).map(hash::dataset).collect();
        if let Ok(dir) = std::env::var("HASH_PROOF_INPUT_DIR") {
            use sha3::Digest;
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                format!("{dir}/inputs-{batch}.bin"),
                messages.iter().flatten().copied().collect::<Vec<_>>(),
            )?;
            std::fs::write(
                format!("{dir}/keccak-{batch}.bin"),
                messages
                    .iter()
                    .flat_map(|m| sha3::Keccak256::digest(m))
                    .collect::<Vec<_>>(),
            )?;
        }
        for s in segments.split(',') {
            let s = s.parse::<usize>()?;
            let t = Instant::now();
            let backend = Backend::new(batch, s)?;
            let setup_ms = t.elapsed().as_secs_f64() * 1000.;
            if let Ok(dir) = std::env::var("HASH_PROOF_CONFIG_DIR") {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(
                    format!("{dir}/log{}-fast.toml", backend.pcs.variables),
                    backend.pcs.security.to_toml_string()?,
                )?;
            }
            eprintln!(
                "batch={batch} segments={s} gkr_layers={} PCS log_n={} m={} rows_padded=0",
                poseidon2b_compress_ligerito_experiment::gkr::layer_count(s),
                backend.pcs.variables,
                backend.pcs.params.m
            );
            for sample in 0..=samples {
                let (proof, times) = backend.prove(&messages)?;
                let t = Instant::now();
                backend.verify(&proof)?;
                let verify = t.elapsed().as_secs_f64() * 1000.;
                let bytes = bincode::serialize(&proof)?;
                if sample == 0 {
                    let w = poseidon2b_compress_ligerito_experiment::gkr::witness(&messages, s)?;
                    for i in 0..batch {
                        let d = hash::hash64(&messages[i]);
                        assert_eq!(
                            d,
                            [
                                w.columns[hash::WIDTH * s][i],
                                w.columns[hash::WIDTH * s + 1][i]
                            ]
                        );
                    }
                    let mut bad = proof.clone();
                    bad.root[0] ^= 1;
                    assert!(backend.verify(&bad).is_err());
                    let mut bad = proof.clone();
                    bad.gkr.outputs[0] += flock_core::field::F128::ONE;
                    assert!(backend.verify(&bad).is_err());
                    eprintln!("warmup verified; changed root and output rejected");
                } else {
                    println!(
                        "poseidon2b-compress64-ghash-ligerito,100,{batch},{s},{},{},{sample},{setup_ms:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{verify:.6},{},{}",
                        poseidon2b_compress_ligerito_experiment::gkr::layer_count(s),
                        1usize << backend.pcs.variables,
                        times.witness_ms,
                        times.commit_ms,
                        times.reduction_ms,
                        times.open_ms,
                        times.total_ms(),
                        bytes.len(),
                        rayon::current_num_threads()
                    );
                }
                std::hint::black_box(proof);
            }
        }
    }
    Ok(())
}
