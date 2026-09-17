#!/usr/bin/env python3
"""Regenerate summaries from flushed samples, including an interrupted experiment."""

import argparse
import json
from experiment_support import summarize

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory, args.require_complete), indent=2))
