#!/usr/bin/env python3
"""Check publishable files and nested tar archives for identifying metadata."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    return result.stdout.decode(errors="replace") if result.returncode == 0 else ""


def identity_terms(root):
    """Read local identities without embedding them in the publication tools."""
    terms = set()
    for line in git(root, "log", "--format=%aN%x00%aE%x00%cN%x00%cE").splitlines():
        for value in line.split("\0"):
            terms.add(value)
            if "@" in value:
                terms.add(value.split("@")[0])
            else:
                terms.add(re.sub(r"\s+", "", value))
                terms.update(value.split())
    remote = git(root, "remote", "get-url", "origin").strip()
    match = re.search(r"github\.com[:/]([^/]+)/", remote)
    if match:
        terms.add(match[1])
    generic = {"anonymous", "redacted", "unknown", "author", "authors", "user",
               "noreply", "github", "github-actions[bot]"}
    return {t for t in terms if len(t) >= 5 and t.casefold() not in generic
            and not t.casefold().endswith("@example.invalid")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--forbid-term", action="append", default=[],
                        help="Additional private name, username, email, or URL to reject")
    args = parser.parse_args()
    root = args.root.resolve()
    patterns = {
        "personal macOS home path": re.compile(rb"/" + rb"Users/[^/\s\"\\]+"),
        "EC2 instance hostname": re.compile(rb"ec2-\d+-\d+-\d+-\d+\.[a-zA-Z0-9.-]+"),
        "private key": re.compile(rb"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----"),
        "AWS access key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
        "original Git revision metadata": re.compile(rb'"git_head"\s*:\s*"(?!anonymous")[^"]+"'),
    }
    terms = identity_terms(root) | set(args.forbid_term)
    if terms:
        patterns["local author or repository identity"] = re.compile(
            b"|".join(re.escape(t.encode()) for t in sorted(terms)), re.IGNORECASE)
    names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths = sorted({root / p for p in names.split("\0") if p}) if names else sorted(
        p for p in root.rglob("*") if p.is_file()
        and not {".git", "target", "__pycache__"}.intersection(p.relative_to(root).parts))
    seen = set()
    findings = []
    archive_count = 0

    def check(data, label):
        for category, pattern in patterns.items():
            if pattern.search(data):
                findings.append({"path": label, "category": category})

    def scan(data, label):
        nonlocal archive_count
        key = hashlib.sha256(data).digest()
        if key in seen:
            return
        seen.add(key)
        if data[:2] != b"\x1f\x8b":
            check(data, label)
            return
        archive_count += 1
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                child = label + "::" + member.name
                check(member.name.encode(), child)
                if member.uname or member.gname or member.uid or member.gid:
                    findings.append({"path": child, "category": "archive owner metadata"})
                if member.pax_headers:
                    check(json.dumps(member.pax_headers).encode(), child)
                if member.isfile():
                    scan(archive.extractfile(member).read(), child)
                elif not member.isdir():
                    findings.append({"path": child, "category": "archive link or special entry"})

    for path in paths:
        label = str(path.relative_to(root))
        check(label.encode(), label)
        if path.is_symlink():
            findings.append({"path": label, "category": "symlink requires manual review"})
        elif path.is_file():
            try:
                scan(path.read_bytes(), label)
            except (OSError, tarfile.TarError) as error:
                findings.append({"path": label, "category": "unreadable file or archive",
                                 "error_type": type(error).__name__})
    print(json.dumps({"passed": not findings, "files_checked": len(paths),
                      "unique_objects_checked": len(seen), "unique_archives_checked": archive_count,
                      "git_history_included": False, "findings": findings}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
