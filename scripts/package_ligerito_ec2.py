#!/usr/bin/env python3
"""Package exact working sources, including the final crates and shared vendored Flock core."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ('dynamic-ligerito', 'poseidon2b-compress-ligerito')


def sources():
    roots = [ROOT / 'scripts', ROOT / 'docs', ROOT / 'vendor/flock-core'] + [ROOT / 'final' / p for p in PROJECTS]
    for name in ('README.md', 'ANONYMITY.md', 'LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE.md', 'PUBLICATION.md', 'final/README.md', 'rust-toolchain.toml', 'requirements.txt', '.gitignore'):
        path = ROOT / name
        if path.is_file():
            yield path
    for root in roots:
        for folder, directories, filenames in os.walk(root):
            directories[:] = sorted(d for d in directories if d not in ('target', '.git', '__pycache__', '.venv'))
            for filename in sorted(filenames):
                path = Path(folder) / filename
                if path.is_symlink():
                    raise ValueError(f'Source symlink is unsupported: {path}')
                if path.suffix in ('.rs', '.inc', '.toml', '.lock', '.py', '.sh', '.md', '.json') or filename.startswith('LICENSE'):
                    yield path


def source_manifest():
    checksums = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sources()}
    return dict(files=checksums,
                source_tree_sha256=hashlib.sha256(json.dumps(checksums, sort_keys=True).encode()).hexdigest(),
                note='Identifies the current working sources, including local changes.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    files = {str(f.relative_to(ROOT)): f.read_bytes() for f in sources()}
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    manifest = dict(files=checksums, source_tree_sha256=hashlib.sha256(json.dumps(checksums, sort_keys=True).encode()).hexdigest(),
                    note='Includes the current working sources; git HEAD alone does not identify this snapshot.')
    data = (json.dumps(manifest, indent=2) + '\n').encode()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(a.output, 'x:gz') as archive:
        for name, content in {**files, 'SOURCE-MANIFEST.json': data}.items():
            info = tarfile.TarInfo('dynamic-snarks-system/' + name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    manifest['archive_sha256'] = hashlib.sha256(a.output.read_bytes()).hexdigest()
    a.output.with_suffix(a.output.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(archive=str(a.output.resolve()), files=len(files), archive_sha256=manifest['archive_sha256']), indent=2))


if __name__ == '__main__':
    main()
