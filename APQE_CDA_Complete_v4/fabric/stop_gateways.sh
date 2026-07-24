#!/usr/bin/env bash
set -euo pipefail
docker rm -f apqe-gateway-org1 apqe-gateway-org2 >/dev/null 2>&1 || true
echo "APQE gateway containers stopped."
