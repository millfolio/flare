#!/bin/bash
# Verify the flare-h3 baseline is up by probing with h2load
# --npn-list=h3. Mirrors the contract of the quinn / quiche
# baselines' check.sh so the harness can poll any h3 target
# with the same shell hook.
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8443}"
URL="https://127.0.0.1:$PORT/plaintext"

for _ in $(seq 1 120); do
    if h2load --npn-list=h3 -n 1 -c 1 \
            --connect-to "127.0.0.1:$PORT" "$URL" \
            > /dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: flare-h3 server did not answer after 60s at $URL"
exit 1
