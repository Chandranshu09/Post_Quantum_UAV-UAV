#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NETWORK="${TEST_NETWORK:-$HOME/apqe-lab/fabric-samples/test-network}"
ORGANIZATIONS="$TEST_NETWORK/organizations"
IMAGE="apqe-fabric-gateway:1.0"

if [[ ! -d "$ORGANIZATIONS" ]]; then
  echo "Fabric organizations directory not found: $ORGANIZATIONS" >&2
  exit 1
fi
if ! docker network inspect fabric_test >/dev/null 2>&1; then
  echo "Docker network fabric_test is absent. Start the Fabric test network first." >&2
  exit 1
fi

GATEWAY_DIR="$ROOT/fabric/gateway-go"

echo "Building the Fabric gateway completely inside a Go 1.25 Docker stage..."
docker build --pull=false -t "$IMAGE" "$GATEWAY_DIR"

docker rm -f apqe-gateway-org1 apqe-gateway-org2 >/dev/null 2>&1 || true

docker run -d \
  --name apqe-gateway-org1 \
  --restart unless-stopped \
  --network fabric_test \
  -p 5002:5002/udp \
  -v "$ORGANIZATIONS:/organizations:ro" \
  -e ORG=1 \
  -e UDP_PORT=5002 \
  -e CHANNEL_NAME=apqechannel \
  -e CHAINCODE_NAME=apqe \
  "$IMAGE"

docker run -d \
  --name apqe-gateway-org2 \
  --restart unless-stopped \
  --network fabric_test \
  -p 5003:5003/udp \
  -v "$ORGANIZATIONS:/organizations:ro" \
  -e ORG=2 \
  -e UDP_PORT=5003 \
  -e CHANNEL_NAME=apqechannel \
  -e CHAINCODE_NAME=apqe \
  "$IMAGE"

echo "Gateways started: Org1 UDP 5002, Org2 UDP 5003"
docker ps --filter name=apqe-gateway --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
