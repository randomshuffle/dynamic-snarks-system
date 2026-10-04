#!/usr/bin/env python3
"""Create a clean public checkout without Git history or generated local files."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ('final', 'vendor', 'scripts', 'docs', 'results', 'archive')
ROOT_FILES = ('.gitignore', 'README.md', 'PUBLICATION.md', 'ANONYMITY.md',
              'NOTICE.md', 'LICENSE-MIT', 'LICENSE-APACHE',
              'PUBLICATION-CHECKSUMS.sha256', 'PUBLICATION-SANITATION.json')
EXCLUDED_PARTS = {'.git', 'target', '__pycache__', '.venv', 'local-artifacts'}
MAX_FILE_BYTES = 100 * 2**20


def public_files(root):
    for name in ROOT_FILES:
        path = root / name
        if path.is_file():
            yield path
    for name in DIRECTORIES:
        directory = root / name
        if not directory.exists():
            continue
        for path in sorted(directory.rglob('*')):
            if EXCLUDED_PARTS.intersection(path.relative_to(root).parts):
                continue
            if path.is_symlink():
                raise ValueError(f'Public source symlink is unsupported: {path.relative_to(root)}')
            if path.is_file() and path.suffix != '.pyc':
                yield path


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New directory; must not already exist')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error('Output already exists; choose a fresh directory')
    files = list(public_files(ROOT))
    oversized = [str(p.relative_to(ROOT)) for p in files if p.stat().st_size >= MAX_FILE_BYTES]
    if oversized:
        parser.error('Public files exceed the 100 MiB publication limit: ' + ', '.join(oversized))
    # Audit before writing any public copy. Audit reads the same public trees and
    # excludes build products, bulk originals, and generated release directories.
    subprocess.run([sys.executable, str(ROOT / 'scripts/audit_anonymity.py'),
                    '--root', str(ROOT)], check=True, stdout=subprocess.DEVNULL)
    output.mkdir(parents=True)
    records = {}
    for path in files:
        name = path.relative_to(ROOT)
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        records[str(name)] = dict(bytes=destination.stat().st_size, sha256=digest(destination))
    canonical = json.dumps(records, sort_keys=True, separators=(',', ':')).encode()
    manifest = dict(format_version=1, files=records,
                    source_tree_sha256=hashlib.sha256(canonical).hexdigest(),
                    git_history_included=False,
                    note='Checksums describe this public snapshot, not the original benchmark execution sources.')
    (output / 'RELEASE-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(directory=str(output), files=len(records),
                         total_bytes=sum(row['bytes'] for row in records.values()),
                         source_tree_sha256=manifest['source_tree_sha256'],
                         git_history_included=False), indent=2))


if __name__ == '__main__':
    main()
