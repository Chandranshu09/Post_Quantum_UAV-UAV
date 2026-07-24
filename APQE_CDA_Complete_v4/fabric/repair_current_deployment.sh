#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NETWORK="${TEST_NETWORK:-$HOME/apqe-lab/fabric-samples/test-network}"
CHAINCODE_NAME="${CHAINCODE_NAME:-apqe}"

cd "$ROOT/fabric/chaincode-go"
rm -rf vendor
go mod tidy
go mod vendor
test -s go.sum
test -s vendor/modules.txt
GOFLAGS=-mod=vendor go test ./...
rm -f "$TEST_NETWORK/${CHAINCODE_NAME}.tar.gz"

echo "Dependency repair completed. Run:"
echo "  cd $ROOT"
echo "  ./fabric/deploy.sh"
