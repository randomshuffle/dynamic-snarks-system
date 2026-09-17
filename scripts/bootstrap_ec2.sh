#!/usr/bin/env bash
# Run on the Ubuntu x86-64 EC2 host, from the transferred source directory.
set -euo pipefail
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This bootstrap script requires Linux x86-64.' >&2
  exit 1
fi
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates git python3 tmux numactl jq
if [[ ! -x "$HOME/.cargo/bin/rustup" ]]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/snark-rustup-init.sh
  sh /tmp/snark-rustup-init.sh -y --profile minimal --default-toolchain 1.92.0
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.92.0 --profile minimal
rustup override set 1.92.0
cargo fetch --locked
rustc -Vv
echo 'Ready. Source $HOME/.cargo/env in your shell before running the benchmark.'
