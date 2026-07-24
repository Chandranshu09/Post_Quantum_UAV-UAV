# ESP32 proposed protocol, revised package v4

This package contains the corrected ESP32 implementation of the five-message
UAV-to-UAV post-quantum authenticated key-establishment protocol. It supports
both LMS authentication-path delivery modes discussed in the paper.

## Which modes must be run?

The exact byte costs follow directly from the serialized message formats, so a
hardware run is not required merely to establish those sizes. A real ESP32 run
is required for any reported latency, success rate, RAM use, Wi-Fi variability,
or repository-delay result.

For a measured comparison of both deployments, run both sketch pairs:

1. `UAV_A_Repository_Assisted` with `UAV_B_Repository_Assisted`
2. `UAV_A_Signer_Carried` with `UAV_B_Signer_Carried`

Each pair is configured for 500 sessions. The two modes use independent LMS
versions, identifiers, and NVS namespaces, so their one-time indices do not
collide.

## Implemented corrections

The v4 code corrects the earlier protocol/code mismatches:

- `SID0` is now SHA-256 over a domain-separated canonical encoding of both
  `M0` and `M1`.
- `M1` carries `ID_B` followed by `ID_A`, matching the protocol definition.
- The LM-OTS signed object explicitly binds `q` through the
  `LMOTS-SIGN` wrapper.
- The transcript binds `SID0`, `M0`, `M1`, the actual `M2`, and the actual
  inner `M3` using type and length separation.
- HKDF derives 96 bytes as `SK || K_A_confirm || K_B_confirm`.
- `tau_A` and `tau_B` use distinct direction-specific confirmation keys.
- Public root records include version, LMS identifier, root, profile/suite,
  status, and optional expiry.
- Repository-assisted mode retrieves the required 320-byte peer path during
  each handshake. It does not pre-cache every peer path.
- Signer-carried mode places each 320-byte path directly in `M2` or `M3`.
- The one-time index is persisted before a signature is released. This is
  crash-safe reservation, not malicious rollback resistance.
- The temporary LMS build seed is erased after the public tree is built.

See `docs/PROTOCOL_AUDIT.md` for unresolved limitations that were not silently
changed.

## PUF and fuzzy-extractor hook

The sketches intentionally retain the earlier hardcoded 32-byte PUF values.
They also contain hardcoded local helper-data placeholders. The helper value is
not transmitted or used by peer verification.

In this package, `timedRuntimeSeed()` treats `hardcodedPufRoot` as the stable
32-byte value that the physical APUF and Python fuzzy extractor will later
reconstruct. Replace that input with the output of the external APUF/FE code,
then retain the existing LMS-tree seed derivation:

```text
physical APUF response + local FE helper
              -> reconstructed 32-byte PUF root
              -> HKDF(device ID, LMS version, LMS identifier)
              -> one LMS master seed
              -> indexed RFC 8554 LM-OTS private values
```

The physical APUF and Python FE execution are not implemented or timed here.
Final hardware-rooted latency results must include that external execution if
it lies on the runtime path.

## Authentication-path modes and byte costs

For LMS height 10, one authentication path is `10 x 32 = 320` bytes.

### Mode A, repository-assisted

- Direct five-message traffic: 6334 bytes
- Cryptographic path payload downloaded: 640 bytes for two paths
- Implemented repository protocol traffic without retries:
  - each query: 112-byte request + 400-byte authenticated response
  - both queries: 1024 application bytes
- Complete implemented application traffic: 7358 bytes
- Runtime public-repository access: required

The repository and its paths are untrusted. A modified path produces a root
mismatch. Suppression can cause denial of service but cannot produce false
acceptance.

### Mode C, signer-carried

- Direct five-message traffic: 6974 bytes
- Runtime repository traffic: 0 bytes
- Complete application traffic: 6974 bytes
- Runtime public-repository access: not required, assuming an authenticated
  root/status record was synchronized previously

Both modes use the same signature and root verification logic. Only path
delivery changes.

## Public and private data

Private or temporary:

- physical PUF response and reconstructed PUF root
- LMS master seed and LM-OTS private chain values
- ML-KEM decapsulation key and shared secret
- session and confirmation keys

Public:

- identities, nonces, suite/profile identifier, versions, and one-time indices
- ML-KEM encapsulation key and ciphertext
- LM-OTS signatures
- LMS tree identifier, root, tree nodes, and authentication paths
- credential status and expiry
- key-confirmation tags

The full local LMS tree is public verification material. Each ESP32 retains its
own tree so it can extract paths. It does not retain the peer's tree or all peer
paths.

## Folder layout

```text
Arduino/
  libraries/ProposedUavProtocol/
  UAV_A_Repository_Assisted/
  UAV_B_Repository_Assisted/
  UAV_A_Signer_Carried/
  UAV_B_Signer_Carried/
laptop_server/
docs/
tools/
```

## Software prerequisites

- ESP32 Arduino core
- the same working wolfSSL configuration used for the earlier ML-KEM-512 test
- Python 3 for the laboratory root/path service

The code uses these wolfSSL APIs:

- ML-KEM-512 key generation, encapsulation, and decapsulation
- SHA-256
- HMAC-SHA-256

Pin the exact wolfSSL version and configuration for the paper artifact.

## Running the laboratory public-state service

From `laptop_server`:

```bash
python gcs_ledger_server.py --host 0.0.0.0 --port 5001
```

This service separates:

- authenticated root/status records; and
- public LMS authentication paths.

It uses SQLite and an HMAC-authenticated UDP laboratory interface. It is not a
permissioned blockchain. The theoretical ledger can later publish the compact
root/status records, while IPFS, cloud storage, or another public repository
serves the paths.

## Running Mode A

1. Configure Wi-Fi and laptop IP in both repository-assisted sketches.
2. Start the Python service.
3. Upload `UAV_B_Repository_Assisted` first.
4. Copy its printed IP to `RESPONDER_IP` in `UAV_A_Repository_Assisted`.
5. Upload UAV A and save its complete Serial Monitor output.
6. Parse the log:

```bash
python parse_serial_results.py uav_a_repository_log.txt
```

Before the experiment, each board uploads 500 of its own public paths. During
each session, each verifier downloads the one required peer path.

## Running Mode C

1. Configure Wi-Fi and laptop IP in both signer-carried sketches.
2. Start the Python service. It is still used to provision/fetch root records.
3. Upload `UAV_B_Signer_Carried` first.
4. Set its address in `UAV_A_Signer_Carried` and upload UAV A.
5. Save and parse the Serial Monitor output.

No runtime path query occurs in Mode C.

## One-time-state warning

The package uses:

- Mode A: version 1 and namespaces `uavA_repo_v1`, `uavB_repo_v1`
- Mode C: version 2 and namespaces `uavA_carry_v2`, `uavB_carry_v2`

Each 500-session experiment consumes `q = 0...499`. Never reset and reuse those
indices under the same LMS seed/identifier. `RESET_Q_COUNTER=true` is only for
the first provisioning of a genuinely new laboratory tree. Change it back to
`false` immediately.

## Measurements printed per successful session

The initiator emits a machine-readable `CSV,...` line containing:

- path mode
- initiator and responder protocol times
- confirmed completion time including the measurement-only RESULT reply
- local cryptographic times
- runtime repository times
- direct and repository application bytes
- fragment-framed direct bytes
- RSSI and heap values

The parser reports mean, standard deviation, median, minimum, maximum, p95, and
a 95% confidence interval.

## Validation performed in this package

- Python modules compile successfully.
- Packet-format and byte-count self-tests pass.
- All C++ library sources and four sketches pass a host-side C++ syntax check
  using API stubs.

A real Arduino/wolfSSL build and execution on the two ESP32-WROOM-DA boards is
still required because this environment does not contain the user's Arduino
core and wolfSSL installation.
