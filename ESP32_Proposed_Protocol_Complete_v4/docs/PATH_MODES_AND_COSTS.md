# LMS authentication-path storage and delivery

## Local ESP32 storage

The height-10 LMS tree contains 2047 meaningful nodes, or 65,504 bytes at
32 bytes per node. The implementation allocates 2048 entries, or 65,536 bytes,
for simple one-based indexing.

Each UAV retains only its own public tree. It uses that tree to extract the
path for its current one-time index. It does not retain every peer tree or all
peer paths.

## Public repository storage in Mode A

The laboratory repository stores one 320-byte path for each enrolled
`(device, version, q)` record.

- 500 experiment paths per UAV: 160,000 raw path bytes
- all 1024 paths per UAV/version: 327,680 raw path bytes

SQLite indexing and record metadata add storage beyond these raw figures. A
production repository could instead store the 65,504-byte tree once and derive
paths on request. Both representations contain only public data.

## Ledger/root record

The trusted or authenticated record contains only compact lifecycle state:

```text
ID, version, LMS identifier, height, root, profile/suite,
status, expiry/checkpoint information
```

The large tree/path collection should normally remain in public object storage,
IPFS, cloud storage, or another repository rather than being replicated in full
inside every ledger node.

## Runtime Mode A

The signer sends no path in the direct message. After learning the peer's `q`,
the verifier requests the corresponding path from the untrusted repository.
The verifier computes the leaf from the signed message and LM-OTS signature,
then hashes the downloaded siblings to the authenticated root.

## Runtime Mode C

The signer extracts its own current path and appends it to its direct protocol
message. The verifier performs the identical root check but does not contact a
repository during the handshake.

## Cost summary

| Mode | Direct bytes | Raw path payload | Implemented repository bytes | Complete implemented application bytes |
|---|---:|---:|---:|---:|
| Repository-assisted | 6334 | 640 | 1024 | 7358 |
| Signer-carried | 6974 | 640 within direct traffic | 0 | 6974 |

The 1024 repository bytes in Mode A include two 112-byte requests and two
400-byte authenticated responses. Transport headers and retries are excluded.
