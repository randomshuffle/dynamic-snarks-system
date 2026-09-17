"""Proof sizes cover all current proofs, including peaks before the final revision."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiment_support import summarize


class ProofSizeResultsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "proofs").mkdir()
        (self.path / "experiment.json").write_text(json.dumps({"schema_version": 3, "update_logs": [0, 1], "sequence_len": 40}))
        (self.path / "proof-size-format.json").write_text('{"version":1}')
        (self.path / "baseline.json").write_text('{"mode":"shared","reference_gates":1}')
        keys = [("initial", 0, 0)]
        keys += [("baseline", 1, r) for r in range(1, 41)]
        keys += [("update", g, r) for g in (1, 2) for r in range(1, 41)]
        self.rows, components = [], []
        for phase, gates, revision in keys:
            # Sizes fall after each composition; the last proof is not largest.
            fields = 2 if phase == "baseline" else 3 + revision % 8
            payload = 32 * (fields + 1)
            encoded = payload + 20
            filename = f"proofs/{phase}-g{gates}-r{revision}.cbor" if phase == "initial" or revision == 40 else ""
            if filename:
                (self.path / filename).write_bytes(bytes(encoded))
                components.append([phase, gates, revision, "test_component", fields, 1, 0, payload, encoded])
            self.rows.append(dict(phase=phase, update_gates=gates, revision=revision, prove_seconds=1,
                                  verify_seconds=0.1, verified="true", cumulative_distinct_gates=revision,
                                  proof_field_elements=fields, proof_blake3_hashes=1, proof_poseidon_hashes=0,
                                  proof_payload_bytes=payload, proof_serialized_bytes=encoded, proof_overhead_bytes=20,
                                  proof_file=filename))
        self.write_samples()
        with (self.path / "proof-components.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(("phase", "update_gates", "revision", "component", "field_elements", "blake3_hashes", "poseidon_hashes", "payload_bytes", "serialized_bytes"))
            w.writerows(components)

    def write_samples(self):
        with (self.path / "samples.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self.rows[0].keys())
            w.writeheader()
            w.writerows(self.rows)

    def test_shared_baseline_and_full_proofs_across_forty_revisions(self):
        result = summarize(self.path, require_complete=True)
        self.assertEqual(result["proof_size_samples"], 121)
        self.assertEqual(result["proof_checkpoints"], 4)
        with (self.path / "proof-size-comparison.csv").open() as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(float(row["baseline_mean_payload_bytes"]), 96)
            self.assertEqual(int(row["initial_payload_bytes"]), 128)
            self.assertEqual(float(row["baseline_max_payload_bytes"]), 96)
            self.assertEqual(float(row["baseline_mean_serialized_bytes"]), 116)
            self.assertEqual(float(row["baseline_max_serialized_bytes"]), 116)
            self.assertEqual(float(row["dynamic_mean_payload_bytes"]), 240)
            self.assertEqual(int(row["dynamic_max_payload_bytes"]), 352)
            self.assertEqual(float(row["dynamic_mean_serialized_bytes"]), 260)
            self.assertEqual(int(row["dynamic_max_serialized_bytes"]), 372)
            self.assertEqual(int(row["dynamic_final_payload_bytes"]), 128)
            self.assertEqual(int(row["dynamic_final_serialized_bytes"]), 148)
        with (self.path / "proof-sizes.csv").open() as f:
            updates = [row for row in csv.DictReader(f) if row["phase"] == "update"]
        self.assertEqual(len(updates), 2)
        for row in updates:
            self.assertEqual(int(row["samples"]), 40)
            self.assertEqual(float(row["mean_payload_bytes"]), 240)
            self.assertEqual(int(row["max_payload_bytes"]), 352)
            self.assertEqual(float(row["mean_serialized_bytes"]), 260)
            self.assertEqual(int(row["max_serialized_bytes"]), 372)

    def test_missing_checkpoint_is_rejected(self):
        (self.path / self.rows[-1]["proof_file"]).unlink()
        with self.assertRaisesRegex(ValueError, "artifact"):
            summarize(self.path, require_complete=True)

    def test_omitted_hash_bytes_and_inconsistent_components_are_rejected(self):
        self.rows[-1]["proof_payload_bytes"] -= 32
        self.write_samples()
        with self.assertRaisesRegex(ValueError, "payload"):
            summarize(self.path)
        self.rows[-1]["proof_payload_bytes"] += 32
        self.write_samples()
        p = self.path / "proof-components.csv"
        p.write_text(p.read_text().rsplit("\n", 2)[0] + "\n")
        with self.assertRaisesRegex(ValueError, "component totals"):
            summarize(self.path)

    def test_partial_sweep_does_not_publish_final_size_comparison(self):
        self.rows.pop()
        self.write_samples()
        result = summarize(self.path)
        self.assertFalse(result["complete"])
        with (self.path / "proof-size-comparison.csv").open() as f:
            self.assertEqual(len(list(csv.DictReader(f))), 1)


if __name__ == "__main__":
    unittest.main()
