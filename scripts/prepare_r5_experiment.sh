#!/usr/bin/env bash
# Fresh Ubuntu setup for the 2^23 R5 experiment; only a small smoke test generates proofs.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Run this script on the Ubuntu x86-64 EC2 instance.' >&2
  exit 1
fi
BENCH_R5_PREP_DIR=$(realpath -m "${1:?Usage: bash scripts/prepare_r5_experiment.sh NEW_RESULTS_DIRECTORY}")
mkdir -p "$(dirname "$BENCH_R5_PREP_DIR")"
mkdir "$BENCH_R5_PREP_DIR"
finish() {
  local code=$?
  if [[ "$code" == 0 ]]; then
    printf 'complete: ready for worker calibration and the full run\n' > "$BENCH_R5_PREP_DIR/prep-status.txt"
  else
    printf 'failed (exit %s); inspect the preparation log\n' "$code" > "$BENCH_R5_PREP_DIR/prep-status.txt"
  fi
}
trap finish EXIT
stage() { printf '%s\n' "$1" | tee "$BENCH_R5_PREP_DIR/prep-status.txt"; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."

stage 'Installing dependencies and Rust 1.92.0'
bash scripts/bootstrap_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
unset DYNAMIC_SNARK_PROFILE DYNAMIC_SNARK_PROFILE_DETAIL

stage 'Checking the result and memory-monitor utilities'
python3 -m unittest discover -s scripts -p 'test_*.py'

stage 'Building the release benchmark for this CPU'
python3 scripts/run_experiment.py --threads 8 --initial-interleaving 16 \
  --build-only --offline --output "$BENCH_R5_PREP_DIR/build"

stage 'Checking 2^23 gates, updates through 128 gates, and forty revisions without proving'
python3 scripts/run_experiment.py --trace-log 23 --threads 48 \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7 \
  --sequence-len 40 --seed 20260909 --baseline-mode shared \
  --preflight-only --offline --output "$BENCH_R5_PREP_DIR/preflight-n23"

stage 'Running a short 512-gate smoke test with forty one-gate updates'
python3 scripts/run_experiment.py --trace-log 9 --threads 8 \
  --initial-interleaving 16 --update-logs 0 --sequence-len 40 \
  --seed 20260909 --baseline-mode shared --offline --numa-interleave \
  --output "$BENCH_R5_PREP_DIR/smoke-n9"

stage 'Checking the smoke-test results'
jq -e '.state == "complete" and .exit_code == 0' "$BENCH_R5_PREP_DIR/smoke-n9/status.json"
jq -e '.complete and .verified_samples == 81 and .proof_size_samples == 81 and .proof_checkpoints == 3' \
  "$BENCH_R5_PREP_DIR/smoke-n9/validation.json"
cd "$BENCH_R5_PREP_DIR/smoke-n9"
sha256sum -c SHA256SUMS
printf 'Preparation complete. Follow docs/ec2-r5-n23-20260916.md for calibration and the full run.\n'
