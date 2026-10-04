#!/usr/bin/env bash
# Rehearse, calibrate native Linux memory, then run all three experiments.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires Linux x86-64' >&2; exit 1; }
run_root=${1:?Usage: bash scripts/run_ligerito_ec2.sh /absolute/new/result-directory [hierarchy-base]}
hierarchy_base=${2:-2}
[[ "$run_root" == /* ]] || { echo 'Use an absolute output path' >&2; exit 1; }
[[ "$hierarchy_base" =~ ^(2|4|8)$ ]] || { echo 'Hierarchy base must be 2, 4, or 8' >&2; exit 1; }
[[ ! -e "$run_root" ]] || { echo 'Output already exists; choose a fresh directory' >&2; exit 1; }
mkdir -p "$run_root"
exec > >(tee -a "$run_root/launch.log") 2>&1
export RUSTFLAGS='-C target-cpu=native'
export MPLCONFIGDIR="$run_root/matplotlib-cache"
if [[ ! -d ec2-build ]]; then
  echo 'Build metadata is missing; run bash scripts/bootstrap_ligerito_ec2.sh first.' >&2
  exit 1
fi
cp -R ec2-build "$run_root/build"
# Recompute provenance from the checkout, including edits after extraction.
python3 - "$run_root/SOURCE-MANIFEST.json" <<'PYMANIFEST'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from package_ligerito_ec2 import source_manifest
Path(sys.argv[1]).write_text(json.dumps(source_manifest(), indent=2) + '\n')
PYMANIFEST
python3 - "$run_root" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from experiment_memory import memory_limit
ram = memory_limit()
if ram < 240 * 2**30:
    raise SystemExit('Expected at least 240 GiB usable RAM/cgroup; inspect this host before launch')
if len(Path('/proc/swaps').read_text().splitlines()) > 1:
    raise SystemExit('Swap is enabled. Disable it before a memory/timing experiment.')
Path(sys.argv[1], 'host.json').write_text(json.dumps(dict(memory_bytes=ram), indent=2))
PY
python3 final/dynamic-ligerito/scripts/ec2_suite.py "$run_root/rehearsal" --smoke --threads 32 --memory-limit-gib 16 --hierarchy-base "$hierarchy_base"
python3 final/dynamic-ligerito/scripts/run.py 20 "$run_root/calibration-n20" --threads 32 --memory-limit-gib 40 --sequence 1 --update-log 0 --update-logs 0 --plaintext-kib 2048 --hierarchy-base "$hierarchy_base"
python3 - "$run_root" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'final/dynamic-ligerito/scripts')
from one_gate_amortization import read_run
root = Path(sys.argv[1])
initial, updates, baselines, meta, gates = read_run(root / 'calibration-n20')
assert gates == 1 << 20
peak = max(meta['maximum_rss_bytes'], meta['memory_monitor']['peak_sampled_rss_bytes'])
projected = peak * 8 * 1.25
report = dict(measured_n20_peak_rss_gib=peak / 2**30, projected_n23_with_margin_gib=projected / 2**30,
              initial_s=initial, baseline_s=baselines[0]['prove_s'], passed=projected < 200 * 2**30)
(root / 'calibration.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
if not report['passed']:
    raise SystemExit('Native Linux calibration exceeds the 200 GiB planning budget; review before the full suite.')
PY
python3 final/dynamic-ligerito/scripts/ec2_suite.py "$run_root/measurements" --threads 32 --memory-limit-gib 216 --hierarchy-base "$hierarchy_base"
python3 - "$run_root" <<'PY'
import hashlib, json, sys, tarfile
from pathlib import Path
root = Path(sys.argv[1])
files = {}
for path in sorted(root.rglob('*')):
    if path.is_file() and path.name != 'launch.log':
        h = hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                h.update(chunk)
        files[str(path.relative_to(root))] = h.hexdigest()
(root / 'results-sha256.json').write_text(json.dumps(files, indent=2) + '\n')
# launch.log remains live while this script is running; exclude it from the sealed archive.
with tarfile.open(str(root) + '.tar.gz', 'x:gz') as archive:
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.name != 'launch.log':
            archive.add(path, arcname=str(Path(root.name) / path.relative_to(root)), recursive=False)
print(f'Complete: {root}.tar.gz')
PY
