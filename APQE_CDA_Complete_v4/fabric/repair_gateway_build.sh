#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "No host Go toolchain is required. Building in Docker..."
./fabric/start_gateways.sh
