#!/usr/bin/env python3
"""Redact publication metadata, preserving originals in the private local store.

Run with --write after reorganizing artifacts. Measurements, execution revisions,
and recorded source hashes are preserved. New checksums describe public copies.
"""

import argparse
import collections
import gzip
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

from audit_anonymity import identity_terms, private_patterns, public_paths, scan_stream

BACKUP_DIR = Path("archive/local-artifacts/private-metadata")
REPORT_NAME = "PUBLICATION-SANITATION.json"
CHECKSUM_NAME = "PUBLICATION-CHECKSUMS.sha256"
BINARY_SUFFIXES = {".bin", ".cbor", ".proof", ".pdf", ".png", ".jpg", ".jpeg", ".gif"}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def replace_metadata(line, patterns, counts):
    replacements = {
        "personal macOS home path": b"/path/to",
        "EC2 instance hostname": b"benchmark.example.invalid",
        "EC2 internal hostname": b"benchmark-host",
        "AWS access key": b"<redacted-aws-key>",
        "GitHub token": b"<redacted-github-token>",
        "Slack token": b"<redacted-slack-token>",
        "AWS resource identifier": b"<redacted-cloud-resource>",
        "AWS account identifier": b"arn:aws:redacted:000000000000:",
        "local author or repository identity": b"anonymous",
    }
    for category, pattern in patterns.items():
        if category == "private key":
            continue
        if category in {"benchmark host IP address", "SSH IP destination"}:
            replacement = lambda match: re.sub(
                rb"(?:\d{1,3}\.){3}\d{1,3}\b", b"192.0.2.1", match.group())
        else:
            replacement = replacements[category]
        line, count = pattern.subn(replacement, line)
        counts[category] += count
    return line


def sanitize_file(path, root, patterns, write):
    """Stream complete text records so JSONL measurement rows stay intact."""
    if path.is_symlink() or path.suffix in BINARY_SUFFIXES or path.name.endswith((".tar.gz", ".tgz")):
        return None
    compressed = path.suffix == ".gz"
    opener = gzip.open if compressed else open
    with opener(path, "rb") as source:
        head = source.read(4096)
        if b"\0" in head:
            return None
        source.seek(0)
        # Do not rewrite or recompress lossless timing arrays with no metadata.
        if not scan_stream(source, patterns):
            return None
    counts = collections.Counter()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".sanitized-", delete=False) as raw:
        temporary = Path(raw.name)
        if compressed:
            output = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)
        else:
            output = raw
        try:
            with opener(path, "rb") as source:
                in_private_key = False
                for line in source:
                    if patterns["private key"].search(line):
                        counts["private key"] += 1
                        in_private_key = True
                        output.write(b"<redacted-private-key>\n")
                    if in_private_key:
                        if re.search(rb"-----END (?:[A-Z ]+)?PRIVATE KEY-----", line):
                            in_private_key = False
                        continue
                    output.write(replace_metadata(line, patterns, counts))
        finally:
            if compressed:
                output.close()
    counts = {category: count for category, count in sorted(counts.items()) if count}
    if not counts:
        temporary.unlink()
        return None
    relative = path.relative_to(root)
    entry = {"path": str(relative), "replacements": counts,
             "original_sha256": digest(path), "public_sha256": digest(temporary)}
    if write:
        backup = root / BACKUP_DIR / relative
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            shutil.copy2(path, backup)
        mode = path.stat().st_mode
        temporary.chmod(mode)
        temporary.replace(path)
    else:
        temporary.unlink()
    return entry


def sanitize(root, terms=(), write=False):
    root = Path(root).resolve()
    patterns = private_patterns(terms)
    changes = []
    for path in list(public_paths(root)):
        if path.name in {REPORT_NAME, CHECKSUM_NAME}:
            continue
        entry = sanitize_file(path, root, patterns, write)
        if entry:
            changes.append(entry)
    report = {"format_version": 1, "written": write,
              "measurement_values_preserved": True,
              "original_revision_and_source_hash_provenance_preserved": True,
              "original_backups": str(BACKUP_DIR), "changed_files": changes}
    if write and changes:
        (root / REPORT_NAME).write_text(json.dumps(report, indent=2) + "\n")
        (root / CHECKSUM_NAME).write_text("".join(
            f"{entry['public_sha256']}  {entry['path']}\n" for entry in changes))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--forbid-term", action="append", default=[])
    parser.add_argument("--write", action="store_true", help="Write sanitized copies and preserve originals")
    args = parser.parse_args()
    root = args.root.resolve()
    report = sanitize(root, identity_terms(root) | set(args.forbid_term), args.write)
    print(json.dumps({"written": report["written"],
                      "changed_files": len(report["changed_files"]),
                      "replacement_counts": dict(sum(
                          (collections.Counter(entry["replacements"]) for entry in report["changed_files"]),
                          collections.Counter()))}, indent=2))


if __name__ == "__main__":
    main()
