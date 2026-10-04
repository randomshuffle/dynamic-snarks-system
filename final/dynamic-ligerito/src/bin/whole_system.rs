use dynamic_ligerito_experiment::{Field as F, circuit::Circuit, dynamic, static_snark};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};
#[path = "workload.inc"]
mod workload;
fn initial(c: &Circuit) -> Vec<F> {
    let mut z = Vec::new();
    for p in 0..c.n {
        let a = F::from_usize(p + 1);
        let m = F::from_usize(p + 2);
        let b = F::TWO;
        z.extend([a, b, a + b, m, b, m * b]);
    }
    z.extend(vec![F::from_u64(9); c.num_public_inputs]);
    z
}
fn save<T: Serialize>(
    out: &PathBuf,
    name: &str,
    p: &T,
) -> Result<usize, Box<dyn std::error::Error>> {
    let bytes = bincode::serialize(p)?;
    let n = bytes.len();
    fs::write(out.join(name), bytes)?;
    Ok(n)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    let log: usize = a.get(1).ok_or("trace log")?.parse()?;
    let out = PathBuf::from(a.get(2).ok_or("output")?);
    let sequence: usize = a.get(3).map_or(Ok(12), |x| x.parse())?;
    let max_update_log: usize = a.get(4).map_or(Ok(6), |x| x.parse())?;
    let hash_checkpoints: usize = a.get(5).map_or(Ok(1), |x| x.parse())?;
    let plaintext_kib: usize = std::env::var("DYNAMIC_PLAINTEXT_KIB")
        .unwrap_or_else(|_| "64".into())
        .parse()?;
    let plaintext_cap = if std::env::var("DYNAMIC_SMALL_ORACLE").as_deref() == Ok("ligerito") {
        0
    } else {
        plaintext_kib * 1024
    };
    let baseline_every: usize = std::env::var("DYNAMIC_BASELINE_EVERY")
        .unwrap_or_else(|_| "1".into())
        .parse()?;
    let baseline_first = std::env::var("DYNAMIC_BASELINE_FIRST").as_deref() == Ok("1");
    let hierarchy_base: usize = std::env::var("DYNAMIC_HIERARCHY_BASE")
        .unwrap_or_else(|_| "2".into())
        .parse()?;
    if ![1, 3, 7].contains(&hash_checkpoints) {
        return Err("hash checkpoints must be 1, 3 or 7".into());
    }
    let hash_kernel = std::env::var("DYNAMIC_GKR_KERNEL").unwrap_or_else(|_| "factored".into());
    if !["coefficients", "factored", "evaluations"].contains(&hash_kernel.as_str()) {
        return Err("DYNAMIC_GKR_KERNEL must be coefficients, factored or evaluations".into());
    }
    fs::create_dir_all(&out)?;
    let mut samples = BufWriter::new(fs::File::create_new(out.join("samples.jsonl"))?);
    let mut shapes = BTreeSet::new();
    let gates = 1 << log;
    let public = vec![F::from_u64(9); 256];
    let c = Circuit::new(
        gates / 2,
        public.len(),
        (0..3 * gates + public.len()).collect(),
    )?;
    let assignment = initial(&c);
    let start = Instant::now();
    let baseline_keys = if baseline_every > 0 {
        let template = dynamic::regular_hyperplonk_program(&c, &assignment)?;
        Some(static_snark::setup(&template)?)
    } else {
        None
    };
    let baseline_setup = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let (pk, vk) = dynamic::index_with_hierarchy(c.clone(), plaintext_cap, hierarchy_base)?;
    let dynamic_setup = start.elapsed().as_secs_f64();
    static_snark::take_commitment_arities();
    fs::write(
        out.join("setup.json"),
        serde_json::to_vec_pretty(
            &json!({"baseline_s":baseline_setup,"dynamic_s":dynamic_setup,"plaintext_cap_bytes":plaintext_cap,"baseline_every":baseline_every,"baseline_first":baseline_first,"hierarchy_base":hierarchy_base,"hierarchy_levels":pk.hierarchy_levels(),"hierarchy_slots":pk.hierarchy_slots(),"tables_per_level":hierarchy_base-1}),
        )?,
    )?;
    let start = Instant::now();
    let base = dynamic::initialize(&pk, assignment.clone())?;
    let prove_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    dynamic::verify(&vk, &public, base.proof())?;
    let verify_s = start.elapsed().as_secs_f64();
    let arities = static_snark::take_commitment_arities();
    shapes.extend(arities.iter().copied());
    let bytes = save(&out, "initial.bin", base.proof())?;
    let decoded: dynamic::Proof = bincode::deserialize(&fs::read(out.join("initial.bin"))?)?;
    dynamic::verify(&vk, &public, &decoded)?;
    drop(decoded);
    let record = json!({"phase":"initial","gates":gates,"update_gates":0,"revision":0,"prove_s":prove_s,"verify_s":verify_s,"verified":true,"serialized_bytes":bytes,"commitment_arities":arities,"hash_checkpoints":1,"hierarchy_base":hierarchy_base});
    writeln!(samples, "{record}")?;
    samples.flush()?;
    println!("{record}");
    fs::write(
        out.join("hash-config.json"),
        serde_json::to_vec_pretty(&json!({
            "initial_checkpoints":1,"update_checkpoints":hash_checkpoints,
            "segments":hash_checkpoints+1,"gkr_depth":66usize.div_ceil(hash_checkpoints+1),
            "boundaries":(0..=hash_checkpoints+1).map(|i| (66*i).div_ceil(hash_checkpoints+1)).collect::<Vec<_>>(),
            "checkpoint_width":(4*hash_checkpoints).next_power_of_two(),
            "hash_kernel":hash_kernel
        }))?,
    )?;
    let mut fingerprints = serde_json::Map::new();
    let selected: Option<Vec<usize>> = std::env::var("DYNAMIC_UPDATE_LOGS").ok().map(|v| {
        v.split(',')
            .map(|x| x.parse().expect("update log"))
            .collect()
    });
    for klog in 0..=max_update_log {
        if selected.as_ref().is_some_and(|s| !s.contains(&klog)) {
            continue;
        }
        let k = 1 << klog;
        let revisions =
            workload::revisions(gates, k, sequence, 20260909, workload::Pattern::Random);
        fingerprints.insert(k.to_string(), json!(workload::fingerprint(&revisions)));
        let mut state = base.clone();
        let mut z = assignment.clone();
        let mut seen = BTreeSet::new();
        let mut baseline_sample_index = 0;
        for (r, u) in revisions.iter().enumerate() {
            let rev = r + 1;
            for &(i, v) in u {
                z[i] = v;
                seen.insert(i / 3);
            }
            // Sample across every selected update size, retaining both endpoints.
            let run_baseline =
                baseline_every > 0 && (rev == 1 || rev == sequence || rev % baseline_every == 0);
            if run_baseline {
                baseline_sample_index += 1;
            }
            // Alternate by sampled pair, not revision parity: a cadence of 20
            // would otherwise always put the baseline first.
            let order = if (baseline_sample_index % 2 == 1) != baseline_first {
                ["update", "baseline"]
            } else {
                ["baseline", "update"]
            };
            for phase in order {
                if phase == "baseline" && !run_baseline {
                    continue;
                }
                static_snark::take_commitment_arities();
                let start = Instant::now();
                let (prove_s, verify_s, bytes) = if phase == "update" {
                    dynamic::update_with_hash_checkpoints(&pk, &mut state, u, hash_checkpoints)?;
                    let ps = start.elapsed().as_secs_f64();
                    let now = Instant::now();
                    dynamic::verify(&vk, &public, state.proof())?;
                    let vs = now.elapsed().as_secs_f64();
                    let bytes = bincode::serialized_size(state.proof())? as usize;
                    if rev == 1
                        || rev == sequence
                        || state.last_update_statistics().unwrap().mode == "polynomial"
                    {
                        let name = format!("update-{k}-revision-{rev}.bin");
                        save(&out, &name, state.proof())?;
                        let decoded: dynamic::Proof =
                            bincode::deserialize(&fs::read(out.join(name))?)?;
                        dynamic::verify(&vk, &public, &decoded)?;
                    }
                    if rev == sequence {
                        let name = format!("update-{k}-final.bin");
                        save(&out, &name, state.proof())?;
                        let p: dynamic::Proof = bincode::deserialize(&fs::read(out.join(name))?)?;
                        dynamic::verify(&vk, &public, &p)?;
                    }
                    (ps, vs, bytes)
                } else {
                    let (bpk, bvk) = baseline_keys.as_ref().unwrap();
                    let program = dynamic::regular_hyperplonk_program(&c, &z)?;
                    let p = static_snark::prove(&bpk, &program, &public)?;
                    let ps = start.elapsed().as_secs_f64();
                    let now = Instant::now();
                    static_snark::verify(&bvk, &public, &p)?;
                    let vs = now.elapsed().as_secs_f64();
                    let bytes = bincode::serialized_size(&p)? as usize;
                    let name = format!("baseline-{k}-revision-{rev}.bin");
                    save(&out, &name, &p)?;
                    let decoded: static_snark::Proof =
                        bincode::deserialize(&fs::read(out.join(name))?)?;
                    static_snark::verify(&bvk, &public, &decoded)?;
                    (ps, vs, bytes)
                };
                let arities = static_snark::take_commitment_arities();
                shapes.extend(arities.iter().copied());
                let record = json!({"phase":phase,"gates":gates,"update_gates":k,"revision":rev,"prove_s":prove_s,"verify_s":verify_s,"verified":true,"serialized_bytes":bytes,"cumulative_distinct_gates":seen.len(),"commitment_arities":arities,"hash_checkpoints":if phase == "update" {hash_checkpoints} else {1}});
                let mut record = record;
                record["hierarchy_base"] = json!(hierarchy_base);
                record["baseline_sampled"] = json!(run_baseline);
                record["execution_order"] = if run_baseline {
                    json!(order)
                } else {
                    json!(["update"])
                };
                if phase == "update" {
                    record["oracle_statistics"] = state.proof().oracle_statistics();
                    let mut retained = vec![0usize; pk.hierarchy_levels()];
                    for transition in record["oracle_statistics"]["transition_oracles"]
                        .as_array()
                        .unwrap()
                    {
                        retained[transition["level"].as_u64().unwrap() as usize
                            / (hierarchy_base - 1)] += 1;
                    }
                    record["retained_tables_by_level"] = json!(retained);
                    record["update_statistics"] =
                        serde_json::to_value(state.last_update_statistics())?;
                }
                writeln!(samples, "{record}")?;
                samples.flush()?;
                println!("{record}");
            }
            assert_eq!(state.current_assignment(), z);
        }
    }
    fs::write(
        out.join("workload-fingerprints.json"),
        serde_json::to_vec_pretty(&fingerprints)?,
    )?;
    let configs: Vec<_> = shapes
        .into_iter()
        .map(static_snark::ligerito_configuration)
        .collect();
    fs::write(
        out.join("pcs-configs.json"),
        serde_json::to_vec_pretty(&configs)?,
    )?;
    println!("EXPERIMENT_COMPLETE");
    Ok(())
}
