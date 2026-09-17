"""Create an isolated first-update profiling build; never edit registry sources.

Usage: python3 scripts/prepare_update_profile.py /tmp/update-internals-profile
Run the resulting first_update example with DYNAMIC_SNARK_PROFILE_DETAIL=1.
"""

from pathlib import Path
import json
import shutil
import sys

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(parents=True, exist_ok=False)
for directory in ("src", "vendor", "examples", "benches", "tests"):
    shutil.copytree(SOURCE / directory, DEST / directory)
for name in ("Cargo.toml", "Cargo.lock"):
    shutil.copy2(SOURCE / name, DEST / name)
registry = next((Path.home() / ".cargo/registry/src").glob("*/p3-whir-0.6.2")).parent
for crate in ("p3-whir", "p3-sumcheck"):
    shutil.copytree(registry / f"{crate}-0.6.2", DEST / "vendor" / crate)
manifest = (DEST / "Cargo.toml").read_text().replace(
    "[patch.crates-io]", '[patch.crates-io]\np3-whir = { path = "vendor/p3-whir" }\np3-sumcheck = { path = "vendor/p3-sumcheck" }'
)
(DEST / "Cargo.toml").write_text(manifest)

HELPER = r'''
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("DYNAMIC_SNARK_PROFILE_DETAIL").is_some())
}

pub(crate) struct Timer {
    component: &'static str,
    context: String,
    started: Option<Instant>,
}
impl Timer {
    pub(crate) fn new(component: &'static str, context: String) -> Self {
        Self { component, context, started: enabled().then(Instant::now) }
    }
    pub(crate) fn mark(&mut self, phase: &str) {
        if let Some(started) = self.started {
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            std::eprintln!("detail,{},{},{},{:.6}", self.component, phase, self.context, elapsed);
            self.started = Some(Instant::now());
        }
    }
}

pub(crate) struct Buckets {
    times: [Duration; 6],
}
impl Buckets {
    pub(crate) fn new() -> Self { Self { times: [Duration::ZERO; 6] } }
    pub(crate) fn start(&self) -> Option<Instant> { enabled().then(Instant::now) }
    pub(crate) fn add(&mut self, bucket: usize, start: Option<Instant>) {
        if let Some(start) = start { self.times[bucket] += start.elapsed(); }
    }
    pub(crate) fn print(&self, component: &str, context: &str, names: &[&str]) {
        if enabled() {
            for (name, time) in names.iter().zip(self.times) {
                std::eprintln!("detail,{component},{name},{context},{:.6}", time.as_secs_f64()*1000.0);
            }
        }
    }
}
'''
for folder in (DEST / "src", DEST / "vendor/p3-whir/src", DEST / "vendor/p3-sumcheck/src"):
    code = HELPER
    if "vendor" in folder.parts:
        code = "use std::string::String;\n" + code
    (folder / "profile_detail.rs").write_text(code)
    p = folder / "lib.rs"
    code = p.read_text()
    if "vendor" in folder.parts:
        code = code.replace("extern crate alloc;", "extern crate alloc;\nextern crate std;\nmod profile_detail;")
    else:
        code += "\nmod profile_detail;\n"
    p.write_text(code)


def edit(path, replacements):
    p = DEST / path
    code = p.read_text()
    for old, new, count in replacements:
        assert code.count(old) == count, (str(path), old[:90], code.count(old), count)
        code = code.replace(old, new)
    p.write_text(code)


def edit_function(path, start, end, replacements):
    p = DEST / path
    code = p.read_text()
    left = code.index(start)
    right = code.index(end, left)
    part = code[left:right]
    for old, new, count in replacements:
        assert part.count(old) == count, (str(path), start, old[:90], part.count(old), count)
        part = part.replace(old, new)
    p.write_text(code[:left] + part + code[right:])


# Local sumcheck: separately time interpolation, residual construction, weighting,
# transcript/interpolation, and in-place table folding. Per-pair times aggregate.
path = "src/transition_cair.rs"
edit_function(path, "fn prove_local_sumcheck(", "fn prove_poseidon_sumcheck(", [
    ("    for round in 0..variables {", '''    if crate::profile_detail::enabled() {
        eprintln!("detail-meta,local,degree={degree},constraints={},columns={},rows={}", weights.len(), columns.len(), eq.len());
    }
    for round in 0..variables {
        let mut profile = crate::profile_detail::Buckets::new();
        let context = format!("r{round}-pairs{}", eq.len()/2);''', 1),
    ("            for pair in 0..eq.len() / 2 {", "            for pair in 0..eq.len() / 2 {\n                let tick = profile.start();", 1),
    ("                *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)\n                    * combined_local_residual(\n                        &values[..compact_width],\n                        &values[compact_width..],\n                        statement,\n                        weights,\n                    );", '''                profile.add(0, tick);
                if crate::profile_detail::enabled() {
                    let tick = profile.start();
                    let residuals = compact_residuals(&values[..compact_width], &values[compact_width..], statement);
                    profile.add(1, tick);
                    let tick = profile.start();
                    let combined = residuals.into_iter().zip(weights).fold(Bn254::ZERO, |sum, (residual, &weight)| sum + weight * residual);
                    *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t) * combined;
                    profile.add(2, tick);
                } else {
                    *evaluation += lerp(eq[2 * pair], eq[2 * pair + 1], t)
                        * combined_local_residual(&values[..compact_width], &values[compact_width..], statement, weights);
                }''', 1),
    ("        finish_prover_round(", "        let tick = profile.start();\n        finish_prover_round(", 1),
    ("        fold(&mut eq, point[round]);", "        profile.add(3, tick);\n        let tick = profile.start();\n        fold(&mut eq, point[round]);", 1),
    ('        checkpoint("local", round, variables, started);', '''        profile.add(4, tick);
        profile.print("local", &context, &["row_interpolation", "constraint_residuals", "residual_weighting", "message_and_challenge", "table_folding"]);
        checkpoint("local", round, variables, started);''', 1),
])

# Other relation sumchecks: distinguish the pair kernels from message and folding.
for name, end, label in (
    ("prove_poseidon_sumcheck", "#[allow(clippy::too_many_arguments)]\nfn prove_product_sumcheck", "poseidon"),
    ("prove_product_sumcheck", "#[allow(clippy::too_many_arguments)]\nfn finish_prover_round", "product"),
):
    edit_function(path, f"fn {name}(", end, [
        ("    for round in 0..variables {", f'''    for round in 0..variables {{
        let mut detail = crate::profile_detail::Timer::new("{label}", format!("r{{round}}-pairs{{}}", eq.len()/2));''', 1),
        ("        finish_prover_round(", '        detail.mark("pair_kernel");\n        finish_prover_round(', 1),
        ("        fold(&mut eq, point[round]);", '        detail.mark("message_and_challenge");\n        fold(&mut eq, point[round]);', 1),
        ("        checkpoint(", '        detail.mark("table_folding");\n        checkpoint(', 1),
    ])

edit_function("src/poseidon_scalar.rs", "    pub(crate) fn prove_full_rounds(", "\nimpl TraceBuilder {", [
    ("            for variable in 0..variables {", '''            for variable in 0..variables {
                let mut detail = crate::profile_detail::Timer::new("full_round", format!("d{depth}-r{variable}-pairs{}", initial_eq.len()/2));''', 1),
    ("                if evaluations[0] + evaluations[1] != claim {", '                detail.mark("pair_kernel");\n                if evaluations[0] + evaluations[1] != claim {', 1),
    ("                fold(&mut initial_eq, challenge);", '                detail.mark("message_and_challenge");\n                fold(&mut initial_eq, challenge);', 1),
    ("                rounds.push(evaluations.to_vec());", '                detail.mark("table_folding");\n                rounds.push(evaluations.to_vec());', 1),
])

# Identify each opening in logs and split OOD, column evaluation, and claim weights.
edit_function("src/static_snark/pcs.rs", "    fn open_inner(", "    pub(crate) fn verify(", [
    ("        let started = Instant::now();", '''        let mut detail = crate::profile_detail::Timer::new("opening", format!("n{}", self.pcs.config.num_variables));
        if crate::profile_detail::enabled() { eprintln!("detail-begin,opening,n{}", self.pcs.config.num_variables); }
        let started = Instant::now();''', 1),
    ("        let evaluations = points", '        detail.mark("ood_and_transcript_setup");\n        let evaluations = points', 1),
    ("        let evaluations_elapsed = evaluations_started.elapsed();", '        detail.mark("terminal_claims");\n        let evaluations_elapsed = evaluations_started.elapsed();', 1),
    ("        let proof_elapsed = proof_started.elapsed();", '        detail.mark("proximity_proof");\n        let proof_elapsed = proof_started.elapsed();', 1),
])

wp = "vendor/p3-whir/src/pcs/prover/mod.rs"
edit_function(wp, "    fn round(", "    #[instrument(skip_all)]\n    fn final_round(", [
    ("        let round_params = &self.round_parameters[round_index];", '''        let mut detail = crate::profile_detail::Timer::new("whir_round", std::format!("n{}-r{round_index}", self.num_variables));
        let round_params = &self.round_parameters[round_index];''', 1),
    ("        // Observe the round commitment.", '        detail.mark("commit_folded_polynomial");\n        // Observe the round commitment.', 1),
    ("        // PoW grinding:", '        detail.mark("ood_and_commitment_transcript");\n        // PoW grinding:', 1),
    ("        // Open Merkle proofs and evaluate", '        detail.mark("query_sampling");\n        // Open Merkle proofs and evaluate', 1),
    ("        let constraint = Constraint::new(", '        detail.mark("merkle_queries_and_leaf_folds");\n        let constraint = Constraint::new(', 1),
    ("        // Update round state for next iteration.", '        detail.mark("constraint_and_folding_sumcheck");\n        // Update round state for next iteration.', 1),
])
edit_function(wp, "    fn final_round(", "\n}\n", [
    ("        // Send final polynomial coefficients", '''        let mut detail = crate::profile_detail::Timer::new("whir_final", std::format!("n{}-r{round_index}", self.num_variables));
        // Send final polynomial coefficients''', 1),
    ("        // Final STIR queries.", '        detail.mark("final_polynomial_and_transcript");\n        // Final STIR queries.', 1),
    ("        // Open Merkle proofs at", '        detail.mark("query_sampling");\n        // Open Merkle proofs at', 1),
    ("        // Optional final sumcheck.", '        detail.mark("merkle_queries");\n        // Optional final sumcheck.', 1),
    ("            proof.set_final_sumcheck_data(sumcheck_data);", '            proof.set_final_sumcheck_data(sumcheck_data);\n            detail.mark("final_sumcheck");', 1),
])

writer = "vendor/p3-whir/src/pcs/committer/writer.rs"
edit(writer, [
    ("    let num_variables = poly.num_variables();", '''    let num_variables = poly.num_variables();
    let mut detail = crate::profile_detail::Timer::new("whir_commit", std::format!("n{num_variables}"));''', 1),
    ('            info_span!("dft",', '            detail.mark("transpose_and_pad");\n            info_span!("dft",', 2),
    ('    info_span!("commit_matrix").in_scope(|| extension_mmcs.commit_matrix(encoded))', '''    detail.mark("fft");
    let result = info_span!("commit_matrix").in_scope(|| extension_mmcs.commit_matrix(encoded));
    detail.mark("merkle_commit");
    result''', 1),
])

sp = "vendor/p3-sumcheck/src/strategy.rs"
edit_function(sp, "    pub fn compute_sumcheck_polynomials<Challenger>(", "\n}\n", [
    ("        // Optional constraint absorption:", '''        let mut detail = crate::profile_detail::Timer::new("whir_sumcheck", std::format!("n{}-fold{folding_factor}", self.num_variables()));
        // Optional constraint absorption:''', 1),
    ("        // Drive `folding_factor`", '        detail.mark("new_constraint_weights");\n        // Drive `folding_factor`', 1),
    ("        Point::new(res)", '        detail.mark("rounds_total");\n        Point::new(res)', 1),
])
pp = "vendor/p3-sumcheck/src/product_polynomial.rs"
edit_function(pp, "    pub fn round<Challenger>(", "    /// Computes the plain", [
    ("        // Step 1:", '''        let mut detail = crate::profile_detail::Timer::new("whir_sumcheck_round", std::format!("n{}", self.num_variables()));
        // Step 1:''', 1),
    ("        // Step 2-4:", '        detail.mark("coefficients");\n        // Step 2-4:', 1),
    ("        // Step 5:", '        detail.mark("transcript_and_challenge");\n        // Step 5:', 1),
    ("        // Step 6:", '        detail.mark("table_folding");\n        // Step 6:', 1),
])

edit_function("vendor/p3-sumcheck/src/constraints/mod.rs", "    pub fn combine(&self,", "    /// Combines constraint polynomials", [
    ("        // Combine equality constraints", '''        let mut detail = crate::profile_detail::Timer::new("whir_constraint", std::format!("n{}", self.num_variables()));
        // Combine equality constraints''', 1),
    ("        // Combine select constraints", '        detail.mark("ood_equality_weights");\n        // Combine select constraints', 1),
    ("            .combine(combined, eval, self.challenge, self.eq_statement.len());", '            .combine(combined, eval, self.challenge, self.eq_statement.len());\n        detail.mark("stir_select_weights");', 1),
])
edit_function("vendor/p3-sumcheck/src/constraints/statement/select.rs", "    pub fn combine(\n", "    /// SIMD-packed variant", [
    ("        let k = self.num_variables();", '''        let k = self.num_variables();
        let mut detail = crate::profile_detail::Timer::new("whir_select", std::format!("n{k}-queries{n}"));''', 1),
    ("        let mut acc = F::zero_vec", '        detail.mark("power_map");\n        let mut acc = F::zero_vec', 1),
    ("        // Precompute [gamma^shift", '        detail.mark("power_table_expansion");\n        // Precompute [gamma^shift', 1),
    ("            dot_product::<EF, _, _>(challenges.into_iter(), self.evaluations.iter().copied());", '            dot_product::<EF, _, _>(challenges.into_iter(), self.evaluations.iter().copied());\n        detail.mark("challenge_weighted_reduction");', 1),
])

(DEST / "profile-source.json").write_text(json.dumps({"source": str(SOURCE), "registry": str(registry)}, indent=2))
print(DEST)
