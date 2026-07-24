# Public repository, ledger, and laboratory server boundary

The protocol uses two logically different public services.

## Authenticated root/status service

It publishes compact public records containing the UAV identity, LMS version,
identifier, root, profile/suite, status, and freshness information. In a final
system this record can be maintained by a permissioned ledger or distributed as
a GSS-signed checkpoint.

## Untrusted path repository

It stores public LMS paths or public tree nodes. Confidentiality and intrinsic
trust are unnecessary because every path is checked against the authenticated
root. Corruption causes rejection. Suppression affects availability.

## What this package implements

`gcs_ledger_server.py` uses:

- SQLite tables for roots and paths
- HMAC-authenticated UDP laboratory packets
- a hash-chained JSONL audit log

It is a reproducible test service, not a blockchain deployment.

Mode A queries the path table during every session. Mode C uses the service only
before the handshake to enroll and fetch compact root records.
