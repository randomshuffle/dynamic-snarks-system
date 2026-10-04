"""Sanitation must preserve measurements and the original private artifact."""

import gzip
import json
import tempfile
import unittest
from pathlib import Path

from audit_anonymity import audit
from sanitize_public_metadata import BACKUP_DIR, sanitize


class PublicMetadataSanitationTests(unittest.TestCase):
    def test_gzip_measurements_and_provenance_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = {"cwd": "/" + "Users/private-person/project", "prover_ms": 1234.125,
                    "revision": 37, "git_head": "original-execution-revision",
                    "source_sha256": "original-source-digest"}
            path = root / "samples.jsonl.gz"
            with gzip.open(path, "wt") as output:
                output.write(json.dumps(data) + "\n")
            original = path.read_bytes()
            report = sanitize(root, write=True)
            self.assertEqual(len(report["changed_files"]), 1)
            self.assertEqual((root / BACKUP_DIR / path.name).read_bytes(), original)
            with gzip.open(path, "rt") as source:
                sanitized = json.loads(source.read())
            self.assertEqual(sanitized.pop("cwd"), "/path/to/project")
            data.pop("cwd")
            self.assertEqual(sanitized, data)
            self.assertTrue(audit(root)["passed"])

    def test_dry_run_leaves_original_bytes_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "run.json"
            original = b'{"cwd":"/' + b'Users/private-person/project"}\n'
            path.write_bytes(original)
            report = sanitize(root, write=False)
            self.assertEqual(len(report["changed_files"]), 1)
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((root / BACKUP_DIR).exists())

    def test_cloud_control_details_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "host.json"
            path.write_text(json.dumps({"public_ip": ".".join(("18", "123", "45", "67")),
                                        "instance_id": "i-" + "a" * 17,
                                        "resource": "arn:aws:ec2:region:" + "123456789012:instance",
                                        "gates": 8388608, "memory_gib": 256}))
            report = sanitize(root, write=True)
            self.assertEqual(len(report["changed_files"]), 1)
            sanitized = json.loads(path.read_text())
            self.assertEqual(sanitized["public_ip"], "192.0.2.1")
            self.assertEqual(sanitized["gates"], 8388608)
            self.assertEqual(sanitized["memory_gib"], 256)
            self.assertTrue(audit(root)["passed"])


if __name__ == "__main__":
    unittest.main()
