#!/usr/bin/env python3
"""Package the exact working-tree sources, including uncommitted experiment changes."""

import argparse
from pathlib import Path
from experiment_support import sha256, snapshot, write_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = snapshot(args.output)
    write_json(args.output.with_suffix(args.output.suffix + ".manifest.json"), manifest)
    print(f"Archive: {args.output.resolve()}")
    print(f"SHA256: {sha256(args.output)}")
    print(f"Source tree SHA256: {manifest['sha256']}")
