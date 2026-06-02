#!/bin/bash
# Start the flare HTTP/3 baseline. AOT-builds with mojo build
# -D ASSERT=none for fair head-to-head with the Rust h3 baselines
# (cargo build --release --locked). Mirrors the contract of
# benchmark/baselines/flare/run.sh.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"

export FLARE_BENCH_PORT="${FLARE_BENCH_PORT:-8443}"

OUT="$ROOT/target/bench_baselines/flare_h3"
mkdir -p "$(dirname "$OUT")"

cd "$ROOT"
# `mojo build` is idempotent but rerunning it incurs ~10-15s of
# parse + IR work. The bench harness invokes this script once per
# (target, workload, config) tuple so a per-invocation rebuild is
# in the noise vs a 5x30s measurement run.
mojo build -D ASSERT=none -I . "$DIR/main.mojo" -o "$OUT"
"$OUT" &
echo $! > "$PID_FILE"
