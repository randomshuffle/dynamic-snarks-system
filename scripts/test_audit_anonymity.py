"""Publication audit coverage for streaming and excluded private artifacts."""

import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from audit_anonymity import audit, private_patterns, scan_stream


class PublicationAuditTests(unittest.TestCase):
    def test_pattern_crosses_chunk_boundary(self):
        secret = b"AK" + b"IA" + b"X" * 16
        data = b"a" * 1019 + b" " + secret + b" " * 4096
        self.assertEqual(scan_stream(io.BytesIO(data), private_patterns(), 1024),
                         {"AWS access key"})

    def test_gzip_jsonl_is_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with gzip.open(root / "samples.jsonl.gz", "wb") as stream:
                stream.write(b'{"cwd":"/' + b'Users/private-person/project"}\n')
            result = audit(root)
            self.assertFalse(result["passed"])
            self.assertEqual(result["gzip_files_checked"], 1)
            self.assertEqual(result["findings"][0]["category"], "personal macOS home path")

    def test_private_store_and_builds_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ("archive/local-artifacts/raw.txt", "final/crate/target/raw.txt",
                             ".git/config", "output/report.txt", "build/report.txt",
                             "tmp/report.txt", "ec2-build/report.txt"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"AK" + b"IA" + b"X" * 16)
            (root / "README.md").write_text("Public files")
            result = audit(root)
            self.assertTrue(result["passed"])
            self.assertEqual(result["files_checked"], 1)

    def test_tar_owner_metadata_is_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tarfile.open(root / "source.tar.gz", "w:gz") as archive:
                member = tarfile.TarInfo("source.txt")
                member.uid = 501
                member.size = 4
                archive.addfile(member, io.BytesIO(b"safe"))
            result = audit(root)
            self.assertEqual(result["tar_archives_checked"], 1)
            self.assertEqual(result["findings"], [{"path": "source.tar.gz::source.txt",
                                                 "category": "archive owner metadata"}])

    def test_original_revision_is_preserved_as_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "SOURCE-MANIFEST.json").write_text('{"git_head":"recorded-revision"}')
            self.assertTrue(audit(root)["passed"])


if __name__ == "__main__":
    unittest.main()
