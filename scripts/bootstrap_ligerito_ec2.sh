#!/usr/bin/env bash
# Run inside the transferred source snapshot on Ubuntu 24.04 x86-64.
set -euo pipefail
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires Linux x86-64' >&2; exit 1; }
cd "$(dirname "$0")/.."
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates python3 python3-matplotlib tmux numactl jq
if [[ ! -x "$HOME/.cargo/bin/rustup" ]]; then
  installer=$(mktemp)
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$installer"
  sh "$installer" -y --profile minimal --default-toolchain 1.92.0
  rm "$installer"
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.92.0 --profile minimal
export RUSTFLAGS='-C target-cpu=native'
mkdir -p ec2-build
rustc +1.92.0 -Vv > ec2-build/rustc.txt
lscpu > ec2-build/lscpu.txt
free -b > ec2-build/memory.txt
numactl --hardware > ec2-build/numa.txt
python3 -c 'import matplotlib; print(matplotlib.__version__)' > ec2-build/matplotlib.txt
cargo +1.92.0 fetch --locked --manifest-path final/dynamic-ligerito/Cargo.toml
cargo +1.92.0 build --release --locked --offline --manifest-path final/dynamic-ligerito/Cargo.toml --bin whole_system > ec2-build/build.log 2>&1
sha256sum final/dynamic-ligerito/target/release/whole_system > ec2-build/binary-sha256.txt
python3 -m unittest discover -s final/dynamic-ligerito/scripts -p 'test_*.py' > ec2-build/python-tests.txt 2>&1
echo 'Ready. Run scripts/run_ligerito_ec2.sh in tmux; results should be on persistent EBS.'
