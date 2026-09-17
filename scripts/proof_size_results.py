"""Validate current complete-proof sizes and summarize every measured revision."""

import csv
import io
import statistics

SIZE_COLUMNS = ("proof_field_elements", "proof_blake3_hashes", "proof_poseidon_hashes",
                "proof_payload_bytes", "proof_serialized_bytes", "proof_overhead_bytes")


def validate_size(row, directory, sequence_len):
    try:
        values = {column: int(row[column]) for column in SIZE_COLUMNS}
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Missing or invalid proof size") from error
    if any(value < 0 for value in values.values()):
        raise ValueError("Negative proof size")
    if values["proof_field_elements"] == 0 or values["proof_blake3_hashes"] == 0:
        raise ValueError("Proof must include field elements and WHIR Merkle hashes")
    if values["proof_poseidon_hashes"] > values["proof_field_elements"]:
        raise ValueError("Poseidon digests must be a subset of field elements")
    payload = 32 * (values["proof_field_elements"] + values["proof_blake3_hashes"])
    if values["proof_payload_bytes"] != payload:
        raise ValueError("Proof payload does not match field/hash counts")
    if values["proof_serialized_bytes"] != payload + values["proof_overhead_bytes"]:
        raise ValueError("Proof serialization total does not match payload plus overhead")
    final = row["phase"] == "initial" or int(row["revision"]) == sequence_len
    expected = f"proofs/{row['phase']}-g{row['update_gates']}-r{row['revision']}.cbor" if final else ""
    if row.get("proof_file") != expected:
        raise ValueError("Missing or unexpected proof checkpoint path")
    if final:
        path = directory / expected
        if path.is_symlink() or not path.is_file() or path.stat().st_size != values["proof_serialized_bytes"]:
            raise ValueError(f"Missing or size-mismatched proof artifact: {expected}")


def summarize_sizes(directory, config, baseline, groups):
    mean = lambda rows, column: statistics.mean(int(row[column]) for row in rows)
    with (directory / "proof-sizes.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(("phase", "update_gates", "samples", "expected_samples", "complete",
                         "mean_field_elements", "mean_blake3_hashes", "mean_poseidon_hashes",
                         "mean_payload_bytes", "min_payload_bytes", "max_payload_bytes",
                         "mean_serialized_bytes", "min_serialized_bytes", "max_serialized_bytes"))
        for (phase, gates), rows in sorted(groups.items()):
            expected = 1 if phase == "initial" else config["sequence_len"]
            writer.writerow((phase, gates, len(rows), expected, len(rows) == expected,
                             *(mean(rows, column) for column in SIZE_COLUMNS[:3]),
                             mean(rows, "proof_payload_bytes"),
                             min(int(row["proof_payload_bytes"]) for row in rows),
                             max(int(row["proof_payload_bytes"]) for row in rows),
                             mean(rows, "proof_serialized_bytes"),
                             min(int(row["proof_serialized_bytes"]) for row in rows),
                             max(int(row["proof_serialized_bytes"]) for row in rows)))
    with (directory / "proof-size-comparison.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(("update_gates", "revisions", "baseline_mean_payload_bytes", "baseline_mean_serialized_bytes",
                         "initial_payload_bytes", "initial_serialized_bytes", "dynamic_final_payload_bytes",
                         "dynamic_final_serialized_bytes", "final_over_baseline_payload", "final_over_baseline_serialized",
                         "increment_over_initial_payload_bytes", "initial_proof_file", "baseline_proof_file", "dynamic_final_proof_file",
                         "baseline_max_payload_bytes", "baseline_max_serialized_bytes",
                         "dynamic_mean_payload_bytes", "dynamic_max_payload_bytes",
                         "dynamic_mean_serialized_bytes", "dynamic_max_serialized_bytes"))
        initial = groups.get(("initial", 0), [])
        for log in config["update_logs"]:
            gates = 1 << log
            reference = baseline.get("reference_gates", 1 << config["update_logs"][0]) if baseline["mode"] == "shared" else gates
            baselines = groups.get(("baseline", reference), [])
            updates = groups.get(("update", gates), [])
            if not initial or len(baselines) != config["sequence_len"] or len(updates) != config["sequence_len"]:
                continue
            final = next(row for row in updates if int(row["revision"]) == config["sequence_len"])
            baseline_final = next(row for row in baselines if int(row["revision"]) == config["sequence_len"])
            payload, encoded = int(final["proof_payload_bytes"]), int(final["proof_serialized_bytes"])
            baseline_payload, baseline_encoded = mean(baselines, "proof_payload_bytes"), mean(baselines, "proof_serialized_bytes")
            writer.writerow((gates, config["sequence_len"], baseline_payload, baseline_encoded,
                             initial[0]["proof_payload_bytes"], initial[0]["proof_serialized_bytes"], payload, encoded,
                             payload / baseline_payload, encoded / baseline_encoded,
                             payload - int(initial[0]["proof_payload_bytes"]),
                             initial[0]["proof_file"], baseline_final["proof_file"], final["proof_file"],
                             max(int(row["proof_payload_bytes"]) for row in baselines),
                             max(int(row["proof_serialized_bytes"]) for row in baselines),
                             mean(updates, "proof_payload_bytes"),
                             max(int(row["proof_payload_bytes"]) for row in updates),
                             mean(updates, "proof_serialized_bytes"),
                             max(int(row["proof_serialized_bytes"]) for row in updates)))


def validate_components(directory, groups):
    """Every saved full proof must equal the sum of its stored components."""
    checkpoints = {(phase, gates, int(row["revision"])): row
                   for (phase, gates), rows in groups.items() for row in rows if row["proof_file"]}
    path = directory / "proof-components.csv"
    if not checkpoints:
        return 0
    raw = path.read_text()
    if raw and not raw.endswith("\n"):
        raw = raw.rsplit("\n", 1)[0] + "\n" if "\n" in raw else ""
    rows = list(csv.DictReader(io.StringIO(raw)))
    totals, seen = {}, set()
    columns = ("field_elements", "blake3_hashes", "poseidon_hashes", "payload_bytes", "serialized_bytes")
    for row in rows:
        key = (row["phase"], int(row["update_gates"]), int(row["revision"]))
        # A process may be interrupted after syncing a checkpoint but before
        # its verified sample row. Do not count orphaned components as proofs.
        if key not in checkpoints:
            continue
        component = (*key, row["component"])
        if component in seen:
            raise ValueError("Duplicate proof component")
        seen.add(component)
        values = [int(row[column]) for column in columns]
        if any(value < 0 for value in values):
            raise ValueError("Negative proof component size")
        prior = totals.setdefault(key, [0] * len(columns))
        totals[key] = [left + right for left, right in zip(prior, values)]
    for key, sample in checkpoints.items():
        if totals.get(key) != [int(sample['proof_' + column]) for column in columns]:
            raise ValueError(f"Proof component totals do not match complete proof: {key}")
    return len(checkpoints)
