#!/usr/bin/env bash
set -euo pipefail
umask 077
BENCH_RUN_ROOT=/home/ubuntu/dynamic-snark-n23-20260917-NfZT0lLE
cd "$BENCH_RUN_ROOT"
# This directory was newly created for this run. Never remove existing data.
exec 9> "$BENCH_RUN_ROOT/driver.lock"
flock -n 9 || exit 75
if [[ -e "$BENCH_RUN_ROOT/driver-started.txt" ]]; then
  echo 'This driver already started; refusing to repeat the experiment.' >&2
  exit 76
fi
date -u +%FT%TZ > "$BENCH_RUN_ROOT/driver-started.txt"
finish() {
  local result=$?
  printf '%s\n' "$result" > "$BENCH_RUN_ROOT/driver-exit.txt"
  date -u +%FT%TZ > "$BENCH_RUN_ROOT/driver-finished.txt"
  if [[ "$result" != 0 ]]; then printf 'failed: exit %s\n' "$result" > "$BENCH_RUN_ROOT/progress.txt"; fi
}
trap finish EXIT
stage() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" | tee "$BENCH_RUN_ROOT/progress.txt"; }
stage 'Checking the transferred source archive'
sha256sum -c ec2-experiment-r5-n23-u128-i16-r40-20260916.tar.gz.sha256
tar --keep-old-files -xzf ec2-experiment-r5-n23-u128-i16-r40-20260916.tar.gz
BENCH_BUILD_ROOT=$(mktemp -d /tmp/dynamic-snark-n23-build-XXXXXXXX)
printf '%s\n' "$BENCH_BUILD_ROOT" > "$BENCH_RUN_ROOT/build-directory.txt"
mkdir "$BENCH_BUILD_ROOT/cargo"
if [[ -d "$HOME/.cargo/registry" ]]; then cp -a "$HOME/.cargo/registry" "$BENCH_BUILD_ROOT/cargo/registry"; fi
export CARGO_HOME="$BENCH_BUILD_ROOT/cargo"
export CARGO_TARGET_DIR="$BENCH_BUILD_ROOT/target"
export RUSTUP_TOOLCHAIN=1.92.0
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTFLAGS='-C target-cpu=native'
export CARGO_BUILD_JOBS=48
unset DYNAMIC_SNARK_PROFILE DYNAMIC_SNARK_PROFILE_DETAIL
cd "$BENCH_RUN_ROOT/dynamic-snarks-system"
stage 'Fetching dependencies into the isolated build cache'
cargo fetch --locked
stage 'Checking result utilities and building for this CPU'
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/run_experiment.py --threads 48 --initial-interleaving 16 --build-only --offline --output "$BENCH_RUN_ROOT/build"
stage 'Checking the full experiment memory requirements without proving'
taskset -c 0-47 python3 scripts/run_experiment.py --trace-log 23 --threads 48 --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7 --sequence-len 40 --seed 20260909 --baseline-mode shared --preflight-only --offline --output "$BENCH_RUN_ROOT/preflight-n23"
stage 'Checking the executable on a separate 512-gate smoke test'
taskset -c 0-47 python3 scripts/run_experiment.py --trace-log 9 --threads 48 --initial-interleaving 16 --update-logs 0,7 --sequence-len 2 --seed 20260909 --baseline-mode shared --offline --numa-interleave --output "$BENCH_RUN_ROOT/smoke-n9"
jq -e '.state == "complete" and .exit_code == 0' "$BENCH_RUN_ROOT/smoke-n9/status.json"
jq -e '.complete and .verified_samples == 7 and .proof_size_samples == 7 and .proof_checkpoints == 4' "$BENCH_RUN_ROOT/smoke-n9/validation.json"
python3 - "$BENCH_RUN_ROOT" <<'PY'
import shutil,sys
free=shutil.disk_usage(sys.argv[1]).free
print(f'Results disk free: {free / 2**30:.3f} GiB')
assert free >= 2**30, 'Need at least 1 GiB free for results; existing files will not be removed.'
PY
stage 'Running the single full 2^23 experiment: 48 workers, updates 1..128, 40 revisions, no warmups'
taskset -c 0-47 python3 scripts/run_experiment.py --trace-log 23 --threads 48 --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7 --sequence-len 40 --seed 20260909 --baseline-mode shared --offline --numa-interleave --output "$BENCH_RUN_ROOT/full-n23-u128"
stage 'Validating the completed experiment and checksums'
jq -e '.state == "complete" and .exit_code == 0' "$BENCH_RUN_ROOT/full-n23-u128/status.json"
jq -e '.complete and .verified_samples == 361 and .proof_size_samples == 361 and .proof_checkpoints == 10' "$BENCH_RUN_ROOT/full-n23-u128/validation.json"
cd "$BENCH_RUN_ROOT/full-n23-u128"
sha256sum -c SHA256SUMS
cd "$BENCH_RUN_ROOT"
sha256sum full-n23-u128.tar.gz > full-n23-u128.tar.gz.sha256
stage 'complete: 361 verified samples and 10 proof checkpoints; ready to copy results'
