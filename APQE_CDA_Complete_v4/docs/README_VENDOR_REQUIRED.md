# Measurement boundary

## Included in ESP32 local cryptographic computation

- SHA-256 operations explicitly executed by APQE-CDA;
- Kyber-512 CPA key generation;
- four CPA encryptions on UAV-A;
- four CPA decryptions on UAV-B;
- software BS-PUF mapping and inversion time;
- software SRAM/fuzzy-reconstruction emulation time.

## Reported separately

- Fabric query wall time observed by each ESP32;
- Fabric `EvaluateTransaction` time measured inside the laptop gateway;
- direct UAV application bytes;
- fragment-framed direct UDP payload bytes;
- runtime ESP32-to-gateway application bytes;
- end-to-end protocol latency.

## Excluded from APQE runtime

- initial credential registration and Fabric writes;
- chaincode deployment;
- Docker/Fabric startup;
- measurement-only RESULT message;
- Serial printing.

## Physical PUF limitation

The two ESP32-WROOM-DA boards do not contain the paper's FPGA BS-PUF. Fixed,
device-distinct values drive deterministic software mappings that preserve the
required reversible and commutative algebra. The experiment therefore does not
measure physical PUF entropy, reliability, environmental stability,
unclonability, tamper response, or FPGA execution latency.
