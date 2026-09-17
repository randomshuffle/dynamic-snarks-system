#!/usr/bin/env bash
# Prepare an Ubuntu x86-64 host and run the complete forty-revision rehearsal.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Run this script on the Ubuntu x86-64 EC2 prep instance.' >&2
  exit 1
fi
BENCH_PREP_DIR=$(realpath -m "${1:?Usage: bash scripts/prepare_ec2_experiment.sh NEW_RESULTS_DIRECTORY}")
BENCH_PREP_THREADS=${SNARK_PREP_THREADS:-$(nproc)}
mkdir -p "$(dirname "$BENCH_PREP_DIR")"
mkdir "$BENCH_PREP_DIR"
finish() {
  local code=$?
  if [[ "$code" == 0 ]]; then
    printf 'complete\n' > "$BENCH_PREP_DIR/prep-status.txt"
  else
    printf 'failed (exit %s); inspect the preparation log\n' "$code" > "$BENCH_PREP_DIR/prep-status.txt"
  fi
}
trap finish EXIT
stage() { printf '%s\n' "$1" | tee "$BENCH_PREP_DIR/prep-status.txt"; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."

stage 'Installing dependencies and Rust 1.92.0'
bash scripts/bootstrap_ec2.sh
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
unset DYNAMIC_SNARK_PROFILE DYNAMIC_SNARK_PROFILE_DETAIL

stage 'Checking result and memory-monitor tests on Linux'
python3 -m unittest discover -s scripts -p 'test_*.py'

stage 'Building the release benchmark'
python3 scripts/run_experiment.py --threads "$BENCH_PREP_THREADS" \
  --initial-interleaving 16 --build-only --offline \
  --output "$BENCH_PREP_DIR/build"

stage 'Checking the full 2^24 configuration without generating proofs'
python3 scripts/run_experiment.py --trace-log 24 --threads 48 \
  --initial-interleaving 16 --sequence-len 40 --baseline-mode shared \
  --preflight-only --offline --output "$BENCH_PREP_DIR/preflight-n24"

stage 'Checking the 2^15 rehearsal configuration'
python3 scripts/run_experiment.py --trace-log 15 --threads "$BENCH_PREP_THREADS" \
  --initial-interleaving 16 --sequence-len 40 --baseline-mode shared \
  --preflight-only --offline --output "$BENCH_PREP_DIR/preflight-n15"

stage 'Running the complete 2^15 rehearsal: 40 revisions at all 11 update sizes'
python3 scripts/run_experiment.py --trace-log 15 --threads "$BENCH_PREP_THREADS" \
  --initial-interleaving 16 --update-logs 0,1,2,3,4,5,6,7,8,9,10 \
  --sequence-len 40 --seed 20260909 --baseline-mode shared \
  --offline --numa-interleave --output "$BENCH_PREP_DIR/rehearsal-n15"

stage 'Validating the completed results and file checksums'
jq -e '.state == "complete" and .exit_code == 0' "$BENCH_PREP_DIR/rehearsal-n15/status.json"
jq -e '.complete and .verified_samples == 481 and .proof_size_samples == 481 and .proof_checkpoints == 13' \
  "$BENCH_PREP_DIR/rehearsal-n15/validation.json"
cd "$BENCH_PREP_DIR/rehearsal-n15"
sha256sum -c SHA256SUMS
printf 'Results archive: %s/rehearsal-n15.tar.gz\n' "$BENCH_PREP_DIR"
