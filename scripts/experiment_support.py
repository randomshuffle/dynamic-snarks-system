"""Source snapshots and result validation for the EC2 experiment (stdlib only)."""

import csv
import hashlib
import io
import json
import math
import statistics
import tarfile
from pathlib import Path

from proof_size_results import summarize_sizes, validate_components, validate_size

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = ("Cargo.toml", "Cargo.lock", "README.md", "rust-toolchain.toml",
                "src", "benches", "tests", "vendor", "examples", "scripts", "docs")


def source_files():
    for name in SOURCE_PATHS:
        path = ROOT / name
        candidates = sorted(path.rglob("*")) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.is_symlink():
                raise ValueError(f"Source archive does not accept symlinks: {candidate}")
            if candidate.is_file() and "__pycache__" not in candidate.parts:
                yield candidate


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest():
    files = {str(path.relative_to(ROOT)): sha256(path) for path in source_files()}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"sha256": digest, "files": files}


def snapshot(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "x:gz") as archive:
        for path in source_files():
            archive.add(path, arcname="dynamic-snarks-system/" + str(path.relative_to(ROOT)), recursive=False)
    return source_manifest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def summarize(directory, require_complete=False):
    """Reject duplicates/invalid records; never label a partial sweep complete."""
    directory = Path(directory)
    config = json.loads((directory / "experiment.json").read_text())
    baseline_path = directory / "baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {"mode": "paired"}
    if baseline["mode"] not in ("paired", "shared"):
        raise ValueError("Invalid baseline mode")
    reference_gates = baseline.get("reference_gates", 1 << config["update_logs"][0])
    if baseline["mode"] == "shared" and reference_gates != 1 << config["update_logs"][0]:
        raise ValueError("Shared baseline must reference the first update size")
    path = directory / "samples.csv"
    sizes_enabled = (directory / "proof-size-format.json").exists()
    if config.get("schema_version", 1) >= 2 and not sizes_enabled:
        raise ValueError("Missing proof-size encoding specification")
    rows = []
    incomplete_tail = False
    if path.exists():
        raw = path.read_text()
        incomplete_tail = bool(raw) and not raw.endswith("\n")
        if incomplete_tail:
            # Each successfully persisted record ends in a newline. An abrupt
            # termination may leave a partial final write; never count it.
            raw = raw.rsplit("\n", 1)[0] + "\n" if "\n" in raw else ""
        rows = list(csv.DictReader(io.StringIO(raw)))
    groups = {}
    observed = set()
    expected = {("initial", 0, 0)}
    for log in config["update_logs"]:
        for revision in range(1, config["sequence_len"] + 1):
            gates = 1 << log
            expected.add(("update", gates, revision))
            if baseline["mode"] == "paired" or gates == reference_gates:
                expected.add(("baseline", gates, revision))
    for row in rows:
        key = (row["phase"], int(row["update_gates"]), int(row["revision"]))
        if key not in expected or key in observed or row["verified"] != "true":
            raise ValueError(f"Invalid/duplicate/unverified sample: {key}")
        observed.add(key)
        if sizes_enabled:
            validate_size(row, directory, config["sequence_len"])
        for column in ("prove_seconds", "verify_seconds"):
            value = float(row[column])
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid timing: {key} {column}")
        groups.setdefault(key[:2], []).append(row)
    with (directory / "summary.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(("phase", "update_gates", "samples", "expected_samples", "complete",
                         "mean_seconds", "median_seconds", "min_seconds", "max_seconds",
                         "sample_stddev_seconds", "mean_verify_seconds", "max_verify_seconds"))
        for (phase, gates), samples in sorted(groups.items()):
            times = [float(row["prove_seconds"]) for row in samples]
            count = 1 if phase == "initial" else config["sequence_len"]
            writer.writerow((phase, gates, len(samples), count, len(samples) == count,
                             statistics.mean(times), statistics.median(times), min(times), max(times),
                             statistics.stdev(times) if len(times) > 1 else "",
                             statistics.mean(float(row["verify_seconds"]) for row in samples),
                             max(float(row["verify_seconds"]) for row in samples)))
    with (directory / "comparison.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(("update_gates", "revisions", "baseline_mean_seconds", "update_mean_seconds",
                         "baseline_over_update", "first_update_seconds",
                         "baseline_max_seconds", "update_max_seconds",
                         "initial_prove_seconds", "initial_verify_seconds",
                         "baseline_mean_verify_seconds", "baseline_max_verify_seconds",
                         "update_mean_verify_seconds", "update_max_verify_seconds"))
        initial = groups.get(("initial", 0), [])
        for log in config["update_logs"]:
            gates = 1 << log
            baseline_gates = reference_gates if baseline["mode"] == "shared" else gates
            reference, update = groups.get(("baseline", baseline_gates), []), groups.get(("update", gates), [])
            if not initial or len(reference) != config["sequence_len"] or len(update) != config["sequence_len"]:
                continue
            baseline_mean = statistics.mean(float(row["prove_seconds"]) for row in reference)
            update_mean = statistics.mean(float(row["prove_seconds"]) for row in update)
            first = next(float(row["prove_seconds"]) for row in update if row["revision"] == "1")
            writer.writerow((gates, len(update), baseline_mean, update_mean,
                             baseline_mean / update_mean if update_mean else "", first,
                             max(float(row["prove_seconds"]) for row in reference),
                             max(float(row["prove_seconds"]) for row in update),
                             initial[0]["prove_seconds"], initial[0]["verify_seconds"],
                             statistics.mean(float(row["verify_seconds"]) for row in reference),
                             max(float(row["verify_seconds"]) for row in reference),
                             statistics.mean(float(row["verify_seconds"]) for row in update),
                             max(float(row["verify_seconds"]) for row in update)))
    complete = observed == expected and not incomplete_tail
    validation = {"complete": complete, "verified_samples": len(observed),
                  "ignored_incomplete_tail": incomplete_tail,
                  "expected_samples": len(expected), "missing_samples": sorted(expected - observed)}
    if sizes_enabled:
        summarize_sizes(directory, config, baseline, groups)
        validation["proof_checkpoints"] = validate_components(directory, groups)
        validation["proof_size_samples"] = len(observed)
    write_json(directory / "validation.json", validation)
    if require_complete and not complete:
        raise ValueError(f"Incomplete experiment: {len(observed)}/{len(expected)} verified samples")
    return validation


def pack_results(directory):
    directory = Path(directory)
    paths = sorted(path for path in directory.rglob("*") if path.is_file()
                   and path.name != "SHA256SUMS")
    with (directory / "SHA256SUMS").open("w") as output:
        for path in paths:
            output.write(f"{sha256(path)}  {path.relative_to(directory)}\n")
    destination = directory.with_name(directory.name + ".tar.gz")
    temporary = destination.with_suffix(".gz.tmp")
    with tarfile.open(temporary, "w:gz") as archive:
        archive.add(directory, arcname=directory.name)
    temporary.replace(destination)
    return destination
