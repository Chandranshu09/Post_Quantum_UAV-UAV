# APQE-CDA complete ESP32 and Hyperledger Fabric experiment

This package implements the complete three-message APQE-CDA flow on two
ESP32-WROOM-DA boards, with two Hyperledger Fabric gateway containers
representing nearby GCS nodes in Org1 and Org2.

The code defaults to the **literal 256-bit profile**. See
`docs/PAPER_INCONSISTENCIES.md` before using the results in a paper.

## Components

- `Arduino/APQE_UAV_A`: initiator sketch
- `Arduino/APQE_UAV_B`: responder sketch
- `Arduino/libraries/ApqeCdaProtocol`: shared ESP32 implementation
- `fabric/chaincode-go`: Fabric credential chaincode
- `fabric/gateway-go`: authenticated binary UDP to Fabric Gateway bridge
- `tools/vendor_kyber.py`: vendors the official Kyber reference CPA layer
- `tools/ping_gateways.py`: verifies both gateway containers
- `tools/parse_serial_results.py`: parses the final ESP32 CSV output

## 1. Copy the package into WSL

Assuming the ZIP was extracted to Windows Downloads:

```bash
cp -r /mnt/c/Users/chand/Downloads/APQE_CDA_Complete ~/apqe-lab/
cd ~/apqe-lab/APQE_CDA_Complete
```

Adjust the Windows username or extraction path when required.

## 2. Vendor the official Kyber CPA source

Run once:

```bash
python3 tools/vendor_kyber.py
```

The script checks out the official CRYSTALS-Kyber repository at commit
`441c0519a07e8b86c8d079954a6b10bd31d29efc` and copies only the portable
Kyber-512 IND-CPA files required by Arduino.

Confirm:

```bash
ls Arduino/libraries/ApqeCdaProtocol/src/vendor/kyber_ref/indcpa.c
cat Arduino/libraries/ApqeCdaProtocol/src/vendor/kyber_ref/VENDORED_COMMIT.txt
```

## 3. Start Fabric

Use the installed Fabric 2.5 test network:

```bash
cd ~/apqe-lab/fabric-samples/test-network
./network.sh down
./network.sh up createChannel -ca -c apqechannel
```

Confirm the peers and orderer are running:

```bash
docker ps
```

## 4. Install Go and deploy the APQE chaincode

Fabric's test-network deployment script vendors Go chaincode dependencies on the host. Install Go inside Ubuntu first:

```bash
sudo apt update
sudo apt install -y golang-go
go version
```

Then deploy:

```bash
cd ~/apqe-lab/APQE_CDA_Complete
./fabric/deploy.sh
```

For a later chaincode revision, increment both values:

```bash
CHAINCODE_VERSION=1.1 CHAINCODE_SEQUENCE=2 ./fabric/deploy.sh
```

## 5. Start the two Fabric gateway containers

```bash
./fabric/start_gateways.sh
python3 tools/ping_gateways.py
```

Expected:

```text
gateway 5002: status=0, ...
gateway 5003: status=0, ...
```

Follow gateway logs in another WSL terminal:

```bash
cd ~/apqe-lab/APQE_CDA_Complete
./fabric/logs.sh
```

The containers are published as:

- Org1/GCS1: UDP 5002
- Org2/GCS2: UDP 5003

## 6. Open the Windows firewall ports

Run Command Prompt as Administrator:

```bat
netsh advfirewall firewall add rule name="APQE Fabric Gateway UDP 5002" dir=in action=allow protocol=UDP localport=5002
netsh advfirewall firewall add rule name="APQE Fabric Gateway UDP 5003" dir=in action=allow protocol=UDP localport=5003
```

## 7. Copy the Arduino library and sketches to Windows

Run from the package root in WSL:

```bash
rm -rf /mnt/c/Users/chand/Documents/Arduino/libraries/ApqeCdaProtocol
cp -r Arduino/libraries/ApqeCdaProtocol /mnt/c/Users/chand/Documents/Arduino/libraries/
cp -r Arduino/APQE_UAV_A /mnt/c/Users/chand/Documents/Arduino/
cp -r Arduino/APQE_UAV_B /mnt/c/Users/chand/Documents/Arduino/
```

Restart Arduino IDE after copying the library.

The existing Arduino wolfSSL library is required for SHA-256 and HMAC-SHA-256.
Kyber CPA itself is compiled from the vendored official reference source and
does not call wolfSSL ML-KEM.

## 8. Edit the network settings

In both sketches, set:

```cpp
WIFI_SSID
WIFI_PASSWORD
LAPTOP_IP
```

`LAPTOP_IP` is the Windows laptop's active Wi-Fi IPv4 address, not the WSL
address and not an ESP32 address.

In UAV-A also set:

```cpp
UAV_B_IP
```

## 9. Upload order with one laptop USB port

1. Upload `APQE_UAV_B.ino` to UAV-B.
2. Confirm it connects, enrolls 20 records, and prints its Wi-Fi IP.
3. Move UAV-B to a 5 V USB power adapter. It reboots and confirms the same
   records. Never power one board from the laptop and adapter simultaneously.
4. Note UAV-B's current IP after reboot.
5. Put that IP in `UAV_B_IP` in UAV-A.
6. Upload `APQE_UAV_A.ino` to UAV-A.
7. Keep the Fabric network and both gateway containers running.

## 10. Expected output

A successful session prints:

```text
SESSION 1 SUCCESS, credential slot=0
Direct UAV application bytes: 3296 (M1=3104, M2=128, M3=64)
Direct fragment-framed UDP payload bytes observed: 3380
```

The runtime Fabric byte totals should normally be:

- UAV-A: 2110 bytes for two queries
- UAV-B: 1055 bytes for one query
- combined: 3165 bytes

Enrollment traffic and Fabric writes are outside runtime timing.

## 11. Save and parse results

Copy UAV-A Serial Monitor output to a text file, then run:

```bash
python3 tools/parse_serial_results.py uav_a_apqe_serial.txt
```

The parser creates a CSV and prints mean, minimum, and maximum values.

## Troubleshooting

### Gateway ping works in WSL but ESP32 query fails

Check Windows firewall rules and make sure the ESP32 uses the Windows Wi-Fi IPv4
address. Docker Desktop publishes UDP 5002 and 5003 to Windows.

### Fabric gateway container exits

```bash
docker logs apqe-gateway-org1
docker logs apqe-gateway-org2
```

The most common causes are a stopped Fabric network, absent crypto material, or
chaincode not deployed on `apqechannel`.

### Arduino reports missing `vendor/kyber_ref/params.h`

Run `python3 tools/vendor_kyber.py` before copying the Arduino library to
Windows.

### Chaincode already exists

Use a higher lifecycle sequence and version, or bring the test network down and
create a clean channel.

## Research-use warning

This package is for controlled benchmarking. The software PUF model preserves
the algebra required by the protocol but is not a physical PUF security
implementation. The official Kyber reference implementation prioritizes
clarity and portability and is not an ESP32-specific optimized implementation.

## Chaincode dependency preparation

The deployment script now runs `go mod tidy`, `go mod vendor`, and a local compile check before Fabric packages the Go chaincode. This prevents an incomplete package from being installed if `go.sum` or vendored dependencies are missing. If an earlier v1 deployment failed during vendoring, run `./fabric/repair_current_deployment.sh` once and then rerun `./fabric/deploy.sh`.

## Docker build networking note

The gateway build vendors its Go dependencies on the WSL host before invoking Docker. The Docker build itself uses `-mod=vendor` and does not contact `proxy.golang.org` or `sum.golang.org`. This avoids Docker Desktop build failures where the container cannot reach the Go checksum service even though WSL can.

For an existing extracted package, run:

```bash
./fabric/repair_gateway_build.sh
./fabric/start_gateways.sh
```



## Gateway build note for restricted networks

The gateway is built entirely inside the pinned `golang:1.25-alpine` Docker stage. The host WSL Go installation is not used. The Docker build fetches pinned Go modules directly from their upstream repositories because some networks block `proxy.golang.org` or `sum.golang.org`.

e5ce42fd7025e101ac9e10c2b6de3c8df23e17ec993fb1b35df5371cb2f511eb  ./Arduino/APQE_UAV_A/APQE_UAV_A.ino
26634bed98199204bb3690e398726dd427722d69b94587a5c6e36d577d760473  ./Arduino/APQE_UAV_B/APQE_UAV_B.ino
66e91eb1cffb6753446580bf3d84bb621866eb021c343ee779c923cbf09f3a44  ./Arduino/libraries/ApqeCdaProtocol/library.properties
128edbc3ebac0b5107af45907d8122ff5bf68aa86d2037083ee8382f2a900e53  ./Arduino/libraries/ApqeCdaProtocol/src/ApqeCdaAll.h
b6f4ee1a81541016c9142b309a3f8dae2a785c06cc2b04597344f760f9b79964  ./Arduino/libraries/ApqeCdaProtocol/src/ApqeConstants.h
d810f76b513f59d0b23cf3c0c69540039fe43c8c49b560e11807b1608f363157  ./Arduino/libraries/ApqeCdaProtocol/src/ApqeProtocol.cpp
c35252de29e43f76e11c12229d37f26c6cf6525d0d4f6a6f2a8cb26150eb3cad  ./Arduino/libraries/ApqeCdaProtocol/src/ApqeProtocol.h
ab65881d4c9c07b50fbeb4e831ba0005b1615457a629f71bafe11bc3a21bf594  ./Arduino/libraries/ApqeCdaProtocol/src/CryptoHelpers.cpp
7b2b673ca0e299c40dcb696cb8e84ede32ce8f61a41307201c0e231e0109ad35  ./Arduino/libraries/ApqeCdaProtocol/src/CryptoHelpers.h
9b32cacfe9ff48db4019aec3487888bb76c4ee20510b9fb826d157a90b055208  ./Arduino/libraries/ApqeCdaProtocol/src/FabricUdpClient.cpp
c9bf27cb94ac2113ffaee45d5a0d105f1dfb0edb05f5c08d78e50320aa399336  ./Arduino/libraries/ApqeCdaProtocol/src/FabricUdpClient.h
bba13e9ca2ce8739dfba04609c5f50d0350acae2fc9f5fce9f26911a2d3c46a0  ./Arduino/libraries/ApqeCdaProtocol/src/FragmentedUdp.cpp
0acf1e5c1849be93efccd7cb0978038728f6df1a366ee18df0a2fe017a3d1391  ./Arduino/libraries/ApqeCdaProtocol/src/FragmentedUdp.h
0828cdc54fe394ba241aa8a177f7f884e2d6e9d7eda3ae332c7f0e422e6a5ff1  ./Arduino/libraries/ApqeCdaProtocol/src/KyberCpaWrapper.cpp
3c51ad98a1dcbe7a8b49f795354b7f7d5c59768f08e7943842e0c49fe6f1bcc5  ./Arduino/libraries/ApqeCdaProtocol/src/KyberCpaWrapper.h
71851eb3ad5397188c858e39fbb7cce886079b54a5bb1de9e3ded49c6f08002d  ./Arduino/libraries/ApqeCdaProtocol/src/SoftwarePuf.cpp
6679c6e0931b6c1b4ba7ac5c2bf5b6277a6c34f77f014dc695c71f50b8321853  ./Arduino/libraries/ApqeCdaProtocol/src/SoftwarePuf.h
bfe3c1fddf646d49855ba0cf6cbff7fcce4d89dcbc82be39a27c58a7407b2ccb  ./Arduino/libraries/ApqeCdaProtocol/src/vendor/kyber_ref/README_VENDOR_REQUIRED.txt
1d37aa079cef2575c38390cfeff9d3947b7bed3e06c6190c8fb3c8a2541c2f5d  ./README.md
10e240367d13655886538df97259a107480a9419d4d98409237fd9d34e2f6e8c  ./docs/EXPERIMENT_BOUNDARY.md
a6849956fb2a57c8d2010e241fecec2c39aadc118a6dfe7d149803ea3a0542a2  ./docs/MESSAGE_LAYOUT.md
19276649428ad0da1521c8875bb3c9e012dc0ce51d9e52226369af32736fe5a1  ./docs/PAPER_INCONSISTENCIES.md
658bcf06e21dcb3ab92f3d568c6cfb70ea417a874a69352a46f8df4f40f1dcfb  ./fabric/chaincode-go/go.mod
956c1ac0c7a73cec819dc5ba7cec8b9c3269df19e93fa1412767fe687f123ad9  ./fabric/chaincode-go/main.go
32df89641b61d3e9e1f7ea18faf1b9f7549d24d370e1087e7a4b6f6680e406e0  ./fabric/deploy.sh
5975462ac849aa088e59977c7a0a1a7c03f1a025cc7ad496691705c586109666  ./fabric/gateway-go/Dockerfile
fff0c1056b54bc1b84ef176f8eb983fe05d2f00085e3e899fd19bd2ceeec1691  ./fabric/gateway-go/go.mod
5542e541ad2e63c45c1a3ee34672732a11416991ba268dbed468b04ab543d515  ./fabric/gateway-go/main.go
c328c5558808de53751da0bfab7bfda2a2daaace0fcb52c8c2f276aa370f22dc  ./fabric/logs.sh
4f39675e2a53db1e07d9c5042b9110ee7a96db6d3f8f571eb6b02d1f2c8a7faf  ./fabric/repair_current_deployment.sh
af8eb832c5887a0c9d274e8378e7cf9a673af90c2de284d78c2f95032891628f  ./fabric/repair_gateway_build.sh
682156a8f2f9b7fd38cc4800da9c296d5298c985dc963d345bcb92880aa37cac  ./fabric/start_gateways.sh
10fd08df40149bd48ef7f1c387e8cea6a49e85b61fe5f279c29ed5e302ca7e6e  ./fabric/stop_gateways.sh
3404dc7f8fae51636f063ba839624377fee08429974ffd32697586f75426a23f  ./tools/__pycache__/check_package.cpython-313.pyc
7bba854cb62389e2c51a72383d34b269005f684608e7744ceb5c582ea3f074ce  ./tools/__pycache__/parse_serial_results.cpython-313.pyc
28bb38b4755a4a67058f3099939d75a4500ef7f76d1bb2fc947881f07431b42a  ./tools/__pycache__/ping_gateways.cpython-313.pyc
331aa574b7572ecedfbf035218f5ddfcdde3f3a07bd4ad4f15f3ef3a9fc017d0  ./tools/__pycache__/vendor_kyber.cpython-313.pyc
6e6c96808ef1a34cc9b1b2c37c58e2bba1c8c07c55b1fa0d3bede7523ef6703b  ./tools/check_package.py
c4cbfa7eccd9c9574e673f325b7911db90543e2836ebe9637783fc7b63711981  ./tools/parse_serial_results.py
1ee5ac6da76eafac4ed81ac6b4ced09e23c40144103756815c5be8c4cf477d9f  ./tools/ping_gateways.py
aafde5cf94d3018b36cad9a2b10ee38844dce3ec36b35f10d67bd2ca7f5cdc39  ./tools/vendor_kyber.py
