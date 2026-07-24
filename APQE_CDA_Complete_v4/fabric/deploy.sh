#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NETWORK="${TEST_NETWORK:-$HOME/apqe-lab/fabric-samples/test-network}"
CHANNEL_NAME="${CHANNEL_NAME:-apqechannel}"
CHAINCODE_NAME="${CHAINCODE_NAME:-apqe}"
CHAINCODE_VERSION="${CHAINCODE_VERSION:-1.0}"
CHAINCODE_SEQUENCE="${CHAINCODE_SEQUENCE:-1}"
CHAINCODE_DIR="$ROOT/fabric/chaincode-go"

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required by Fabric's Go-chaincode deployment script." >&2
  echo "Install it with: sudo apt install -y golang-go" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not available in this WSL distribution." >&2
  exit 1
fi
if [[ ! -x "$TEST_NETWORK/network.sh" ]]; then
  echo "Fabric test network not found at: $TEST_NETWORK" >&2
  exit 1
fi
if ! docker network inspect fabric_test >/dev/null 2>&1; then
  echo "Fabric network is not running. Start it first:" >&2
  echo "  cd $TEST_NETWORK" >&2
  echo "  ./network.sh up createChannel -ca -c $CHANNEL_NAME" >&2
  exit 1
fi

# Fabric Go chaincode must have its external dependencies available when the
# package is installed. Generate go.sum and a complete vendor directory before
# calling network.sh. Do not allow the Fabric helper script to continue after a
# failed vendoring step.
echo "Preparing Go chaincode dependencies..."
(
  cd "$CHAINCODE_DIR"
  rm -rf vendor
  GO111MODULE=on go mod tidy
  GO111MODULE=on go mod vendor
  test -s go.sum
  test -s vendor/modules.txt
  GOFLAGS=-mod=vendor go test ./...
)
echo "Go chaincode dependencies are complete."

# Remove a package left by an earlier failed deployment attempt.
rm -f "$TEST_NETWORK/${CHAINCODE_NAME}.tar.gz"

cd "$TEST_NETWORK"
./network.sh deployCC \
  -c "$CHANNEL_NAME" \
  -ccn "$CHAINCODE_NAME" \
  -ccp "$CHAINCODE_DIR" \
  -ccl go \
  -ccv "$CHAINCODE_VERSION" \
  -ccs "$CHAINCODE_SEQUENCE"

echo "APQE chaincode deployed: channel=$CHANNEL_NAME name=$CHAINCODE_NAME"
