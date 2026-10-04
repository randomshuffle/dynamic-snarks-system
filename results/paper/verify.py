#!/usr/bin/env python3
"""Audit the published paper data using only Python's standard library.

This checks the lossless raw-record digests, sample coverage, recorded verification
flags, configuration, aggregates, cumulative curves and memory observations. It
is an evidence audit; cryptographic proof generation and verification happen in
the Rust benchmark when reproducing the experiments.
"""
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parent
RAW_SHA256 = {
    "sweep": "db82c461eb9089bc951d7e2d33deecd159f53764df8feb498350cba5a8fa2d62",
    "one-gate": "c2d3d2dd7e15dc864977aa74739ee6d432b7e3a35ca98831cba62a59e3adf48d",
    "128-gate": "2ea7e4e671e319f5055caf060c531db10a18c8924ecebea3266abdbda8f3a26d",
}

def read_json(path):
    return json.loads(path.read_text())

def close(actual, expected, label):
    assert math.isclose(float(actual), float(expected), rel_tol=1e-11, abs_tol=1e-12), label

def check_file_digests():
    manifest = read_json(ROOT / "checksums.json")
    for name, record in manifest["files"].items():
        path = ROOT / name
        assert path.is_file() and path.stat().st_size == record["bytes"], name + ": byte count"
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024**2):
                digest.update(chunk)
        assert digest.hexdigest() == record["sha256"], name + ": published SHA-256"

def audit():
    check_file_digests()
    config = read_json(ROOT / "suite-config.json")
    expected_config = dict(trace_log=23, threads=32, memory_limit_gib=216,
                           hierarchy_base=2, plaintext_kib=2048, sweep_revisions=40,
                           one_gate_revisions=10000, large_gate_revisions=1000,
                           one_gate_baseline_every=100, large_gate_baseline_every=10,
                           seed=20260909, smoke=False)
    for key, value in expected_config.items():
        assert config[key] == value, key
    status = read_json(ROOT / "status.json")
    assert status["status"] == "complete" and status["verified_samples"] == 11845
    report = read_json(ROOT / "memory-report.json")
    original_audit = read_json(ROOT / "audit.json")
    assert original_audit["complete"] and original_audit["verified_samples"] == 11845
    source = read_json(ROOT / "source-manifest.json")
    assert source["source_tree_sha256"] == original_audit["source_tree_sha256"]
    checked = []
    for name, count in [("sweep", 641), ("one-gate", 10102), ("128-gate", 1102)]:
        stage = ROOT / name
        raw = stage / "run-a"
        meta = read_json(raw / "run.json")
        assert meta["exit_code"] == 0 and meta["threads"] == 32 and meta["trace_log"] == 23
        assert meta["binary_sha256"] == config["binary_sha256"]
        assert meta["hierarchy_base"] == 2 and meta["plaintext_cap_kib"] == 2048
        assert not meta["memory_monitor"]["error"] and not meta["memory_monitor"]["limit_exceeded"]
        hash_config = read_json(raw / "hash-config.json")
        assert hash_config["boundaries"] == [0, 33, 66] and hash_config["hash_kernel"] == "factored"
        assert hash_config["initial_checkpoints"] == hash_config["update_checkpoints"] == 1
        expected = {("initial", 0, 0)}
        if name == "sweep":
            expected.update((phase, 2**k, revision) for phase in ("baseline", "update")
                            for k in range(8) for revision in range(1, 41))
        else:
            k, revisions, cadence = (1, 10000, 100) if name == "one-gate" else (128, 1000, 10)
            expected.update(("update", k, revision) for revision in range(1, revisions + 1))
            expected.update(("baseline", k, revision) for revision in {1, *range(cadence, revisions + 1, cadence)})
        records = {}
        digest = hashlib.sha256()
        modes = {}
        with gzip.open(raw / "samples.jsonl.gz", "rb") as handle:
            for line in handle:
                digest.update(line)
                row = json.loads(line)
                assert row["verified"] and row["gates"] == 2**23 and row["hierarchy_base"] == 2
                assert all(math.isfinite(row[key]) and row[key] > 0 for key in ("prove_s", "verify_s", "serialized_bytes"))
                key = (row["phase"], row["update_gates"], row["revision"])
                assert key not in records
                records[key] = row
                if row["phase"] == "update":
                    mode = row["update_statistics"]["mode"]
                    modes[mode] = modes.get(mode, 0) + 1
        assert digest.hexdigest() == RAW_SHA256[name], f"{name}: original raw-record SHA-256"
        assert len(records) == count and records.keys() == expected, f"{name}: coverage"
        initial = records["initial", 0, 0]
        if name == "sweep":
            validation = read_json(stage / "validation.json")
            assert validation["complete"] and validation["verified_samples"] == count
            with (stage / "comparison.csv").open(newline="") as handle:
                comparisons = list(csv.DictReader(handle))
            assert {int(row["update_gates"]) for row in comparisons} == {2**k for k in range(8)}
            for row in comparisons:
                k = int(row["update_gates"])
                assert int(row["updates"]) == 40
                for phase in ["baseline", "update"]:
                    values = [records[phase, k, revision] for revision in range(1, 41)]
                    for field in ["prove_s", "verify_s", "serialized_bytes"]:
                        close(row[f"{phase}_{field}_mean"], statistics.mean(r[field] for r in values), f"sweep {k}: {phase} {field} mean")
                        close(row[f"{phase}_{field}_max"], max(r[field] for r in values), f"sweep {k}: {phase} {field} max")
                    close(row[f"{phase}_final_serialized_bytes"], values[-1]["serialized_bytes"], f"sweep {k}: final proof size")
                close(row["initial_prove_s"], initial["prove_s"], "sweep: initialization")
                close(row["prover_speedup"], float(row["baseline_prove_s_mean"]) / float(row["update_prove_s_mean"]), f"sweep {k}: speedup")
        else:
            summary = read_json(stage / "summary.json")
            assert summary["verified_samples"] == count and summary["updates"] == revisions
            baseline = statistics.mean(r["prove_s"] for (phase, _, _), r in records.items() if phase == "baseline")
            close(summary["baseline_mean_s"], baseline, name + ": baseline")
            setup = read_json(raw / "setup.json")
            update_total = 0.0
            curve = []
            with (stage / "curve.csv").open(newline="") as handle:
                for revision, point in enumerate(csv.DictReader(handle), 1):
                    assert int(point["updates"]) == revision
                    update = records["update", k, revision]
                    update_total += update["prove_s"]
                    dynamic = initial["prove_s"] + update_total
                    close(point["update_prove_s"], update["prove_s"], name + ": update time")
                    assert point["mode"] == update["update_statistics"]["mode"]
                    for column, value in {
                        "cumulative_update_s": update_total, "initial_s": initial["prove_s"],
                        "dynamic_total_s": dynamic, "baseline_total_s": revision * baseline,
                        "speedup": revision * baseline / dynamic,
                        "dynamic_total_with_setup_s": dynamic + setup["dynamic_s"],
                        "baseline_total_with_setup_s": revision * baseline + setup["baseline_s"],
                        "speedup_with_setup": (revision * baseline + setup["baseline_s"]) / (dynamic + setup["dynamic_s"]),
                    }.items():
                        close(point[column], value, f"{name}: revision {revision} {column}")
                    curve.append((revision, revision * baseline / dynamic))
            assert len(curve) == revisions
            maximum = max(curve, key=lambda point: point[1])
            assert summary["maximum"]["updates"] == maximum[0]
            close(summary["maximum"]["speedup"], maximum[1], name + ": maximum")
            close(summary["final"]["speedup"], curve[-1][1], name + ": final")
            promotions = sorted(r["revision"] for (phase, _, _), r in records.items() if phase == "update" and r["update_statistics"]["mode"] == "polynomial")
            assert promotions == [row["revision"] for row in summary["promotions"]]
        with (raw / "memory-samples.csv").open(newline="") as handle:
            peak = max(int(row["rss_bytes"]) for row in csv.DictReader(handle))
        assert peak == meta["memory_monitor"]["peak_sampled_rss_bytes"]
        memory = next(row for row in report["experiments"] if row["experiment"] == name)
        assert memory["peak_rss_bytes"] == max(peak, meta["maximum_rss_bytes"])
        checked.append(dict(experiment=name, verified_samples=count, modes=modes, peak_rss_bytes=memory["peak_rss_bytes"]))
    assert report["maximum_peak_rss_gib"] == max(row["peak_rss_gib"] for row in report["experiments"])
    print(json.dumps(dict(complete=True, verified_samples=sum(row["verified_samples"] for row in checked), experiments=checked), indent=2))

if __name__ == "__main__":
    audit()
