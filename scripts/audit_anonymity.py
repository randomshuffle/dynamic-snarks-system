#!/usr/bin/env python3
"""Stream the public working tree and gzip artifacts for private metadata.

Original execution revisions and source hashes are provenance, not identities.
The ignored local artifact store and Git history are outside this audit.
"""

import argparse
import gzip
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
EXCLUDED_DIR_NAMES = {".git", "target", "__pycache__", ".venv", "node_modules"}
EXCLUDED_ROOT_DIRS = {"output", "build", "tmp", "ec2-build"}


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    return result.stdout.decode(errors="replace") if result.returncode == 0 else ""


def identity_terms(root):
    """Read local identities without embedding them in publication tools."""
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


def private_patterns(terms=()):
    patterns = {
        "personal macOS home path": re.compile(rb"/" + rb"Users/[^/\s\"\\]+"),
        "EC2 instance hostname": re.compile(rb"ec2-\d+-\d+-\d+-\d+\.[a-zA-Z0-9.-]+"),
        "EC2 internal hostname": re.compile(rb"\bip-\d+-\d+-\d+-\d+(?:\.[a-zA-Z0-9.-]+)?\b"),
        "private key": re.compile(rb"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----"),
        "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
        "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
        "AWS resource identifier": re.compile(rb"\b(?:i|sg|subnet|vpc)-[0-9a-f]{8,17}\b"),
        "AWS account identifier": re.compile(rb"arn:aws[^\s\"]*:(?!000000000000:)[0-9]{12}:"),
        "benchmark host IP address": re.compile(
            rb"(?i)\b(?:host|hostname|ssh_host|ip_address|(?:public|private)[_-]?ip(?:[_-]?address)?)"
            rb"[\"']?\s*[:=]\s*[\"']?(?!192\.0\.2\.1\b|127\.0\.0\.1\b|0\.0\.0\.0\b)"
            rb"(?:\d{1,3}\.){3}\d{1,3}\b"),
        "SSH IP destination": re.compile(
            rb"\b(?:ssh|scp|rsync)[^\r\n]*?@(?!192\.0\.2\.1\b|127\.0\.0\.1\b)"
            rb"(?:\d{1,3}\.){3}\d{1,3}\b"),
    }
    if terms:
        patterns["local author or repository identity"] = re.compile(
            b"|".join(re.escape(t.encode()) for t in sorted(terms)), re.IGNORECASE)
    return patterns


def public_paths(root):
    """Use present files; Git's index can still contain paths moved in cleanup."""
    root = Path(root)
    for directory, dirs, names in os.walk(root, followlinks=False):
        relative = Path(directory).relative_to(root)
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIR_NAMES
                         and not (relative == Path(".") and d in EXCLUDED_ROOT_DIRS)
                         and relative / d != Path("archive/local-artifacts"))
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink():
                yield path
        for name in sorted(names):
            if name != ".DS_Store":
                yield Path(directory) / name


def scan_stream(stream, patterns, chunk_size=CHUNK_SIZE):
    """Find matches spanning chunks without loading whole logs into memory."""
    found = set()
    tail = b""
    overlap = max(4096, max((len(term.pattern) for term in patterns.values()), default=0))
    while chunk := stream.read(chunk_size):
        data = tail + chunk
        for category, pattern in patterns.items():
            if category not in found and pattern.search(data):
                found.add(category)
        tail = data[-overlap:]
    return found


def audit(root, terms=()):
    root = Path(root).resolve()
    patterns = private_patterns(terms)
    findings = []
    paths = list(public_paths(root))
    archive_count = 0
    gzip_count = 0

    def record(categories, label):
        findings.extend({"path": label, "category": c} for c in sorted(categories))

    def scan_archive(stream, label):
        nonlocal archive_count
        archive_count += 1
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                child = label + "::" + member.name
                record(scan_stream(io.BytesIO(member.name.encode()), patterns), child)
                if member.uname or member.gname or member.uid or member.gid:
                    record({"archive owner metadata"}, child)
                if member.pax_headers:
                    record(scan_stream(io.BytesIO(json.dumps(member.pax_headers).encode()), patterns), child)
                if member.isfile():
                    with archive.extractfile(member) as extracted:
                        if member.name.endswith((".tar.gz", ".tgz")):
                            scan_archive(extracted, child)
                        elif member.name.endswith(".gz"):
                            with gzip.GzipFile(fileobj=extracted) as uncompressed:
                                record(scan_stream(uncompressed, patterns), child)
                        else:
                            record(scan_stream(extracted, patterns), child)
                elif not member.isdir():
                    record({"archive link or special entry"}, child)

    for path in paths:
        label = str(path.relative_to(root))
        record(scan_stream(io.BytesIO(label.encode()), patterns), label)
        if path.is_symlink():
            record({"symlink requires manual review"}, label)
            continue
        try:
            with path.open("rb") as stream:
                if path.name.endswith((".tar.gz", ".tgz")):
                    scan_archive(stream, label)
                elif path.suffix == ".gz":
                    gzip_count += 1
                    with gzip.GzipFile(fileobj=stream) as uncompressed:
                        record(scan_stream(uncompressed, patterns), label)
                else:
                    record(scan_stream(stream, patterns), label)
        except (OSError, EOFError, tarfile.TarError) as error:
            findings.append({"path": label, "category": "unreadable file or archive",
                             "error_type": type(error).__name__})
    return {"passed": not findings, "files_checked": len(paths),
            "tar_archives_checked": archive_count, "gzip_files_checked": gzip_count,
            "git_history_included": False, "local_artifacts_included": False,
            "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--forbid-term", action="append", default=[],
                        help="Additional private name, username, email, or URL to reject")
    args = parser.parse_args()
    root = args.root.resolve()
    result = audit(root, identity_terms(root) | set(args.forbid_term))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
