#!/usr/bin/env bash
set -euo pipefail
echo "Press Ctrl+C to stop following the logs."
docker logs -f apqe-gateway-org1 &
P1=$!
docker logs -f apqe-gateway-org2 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null || true' EXIT
wait
