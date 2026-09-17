"""Parse the matched one-update runs and record their reproducibility inputs."""
import csv
import datetime
import hashlib
import json
import pathlib
import platform
import subprocess
import tarfile

report = pathlib.Path(__file__).resolve().parent
repo = report.parents[1]


def parse(name):
    lines = (report / f"{name}.stdout").read_text().splitlines()
    result = {}
    for line in lines:
        if line.startswith(("config,", "oracles,")):
            for entry in line.split(",")[1:]:
                key, value = entry.split("=", 1)
                if value.isdigit():
                    value = int(value)
                elif value in ("true", "false"):
                    value = value == "true"
                result[key] = value
    header = next(i for i, line in enumerate(lines) if line.startswith("variant,update_ms,"))
    for key, value in next(csv.DictReader(lines[header:header + 2])).items():
        result[key] = value if key == "variant" else (float(value) if key.endswith("_ms") else int(value))
    result["verified"] = "verification=passed,cbor_roundtrip_verification=passed" in lines
    assert result["verified"]
    return result


before, after = parse("before"), parse("after")
for key in ("gates", "seed", "changed_gates", "positions", "threads", "parallel",
            "rows", "main_width", "main_fields", "product_fields", "hash_slots",
            "active_hashes", "outer_sumcheck_rounds", "workload_fingerprint",
            "sumcheck_node_degree", "sumcheck_product_degree"):
    assert before[key] == after[key], (key, before[key], after[key])
assert (before["auxiliary_width"], after["auxiliary_width"]) == (64, 32)
assert (before["auxiliary_rows"], after["auxiliary_rows"]) == (4, 4)

with tarfile.open(report / "source-after.tar.gz") as source:
    hashes = {member.name: hashlib.sha256(source.extractfile(member).read()).hexdigest()
              for member in sorted(source.getmembers(), key=lambda m: m.name) if member.isfile()}
(report / "source-after.sha256").write_text("".join(f"{digest}  {path}\n" for path, digest in hashes.items()))
archives = ["source-before.tar.gz", "source-after.tar.gz", "before.bin", "after.bin"]
metrics = ("update_ms", "verify_ms", "payload_bytes", "serialized_bytes", "total_committed_fields")
result = {
    "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host": platform.platform(),
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "source_state": "dirty workspace; complete build-source archives retained",
    "before": before,
    "after": after,
    "used_update_columns": {"before": 45, "after": 32},
    "compact_transcript_version": {"before": 1, "after": 2},
    "update_opening_requests": {"before": 90, "after": 64},
    "change_percent": {key: 100 * (after[key] / before[key] - 1) for key in metrics},
    "sha256": {name: hashlib.sha256((report / name).read_bytes()).hexdigest() for name in archives},
    "build_command": "cargo build --offline --release --features parallel --example poseidon_piop_ab",
    "scope": "One update of one random gate per variant, eight threads, sequential processes. Includes tree maintenance and public opening; excludes indexing, trusted-base setup, serialization, decoded-proof verification, and destruction. No baseline or initial proof benchmark.",
    "memory": "Allocation estimates only; no process-RSS measurement.",
    "validation": {"unit_tests": 94, "integration_tests": 7, "proofs_and_cbor_roundtrips_verified": True},
}
(report / "results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({key: result[key] for key in ("change_percent", "validation")}, indent=2))
