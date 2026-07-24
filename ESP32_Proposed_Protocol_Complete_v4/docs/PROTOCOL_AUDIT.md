# Protocol and code audit

## Corrected in v4

1. `SID0` binds both M0 and M1 with domain and length separation.
2. The M1 identity order matches the protocol.
3. The selected one-time index `q` is inside the LM-OTS signed object.
4. Initiator and responder signatures use distinct signed-object domains.
5. The transcript binds both initial messages, the complete M2, and the
   complete inner M3.
6. HKDF derives a session key and two independent direction-specific
   confirmation keys.
7. Both confirmation tags cover the transcript with distinct role labels.
8. Peer roots are accepted only for the configured version/profile and active
   status, with optional expiry checking.
9. Mode A performs actual runtime path retrieval. Mode C carries paths in the
   direct messages.
10. q is durably incremented before a signature is released.
11. The temporary tree-construction seed is erased after the public tree is
    built.
12. Separate 500-session configurations avoid LM-OTS reuse across the two
    deployment modes.

## Deliberately retained placeholders

- The 32-byte PUF root is hardcoded.
- The helper data are hardcoded and local.
- No physical APUF evaluation or Python fuzzy-extractor call is present.
- The laptop service authenticates laboratory records with a pre-shared HMAC.

These must be described as placeholders until the user's external APUF/FE code
is integrated.

## Remaining design or implementation limitations

### Unauthenticated M1 and credential exhaustion

The initiator reserves an LM-OTS index after accepting M1. A network attacker
can therefore cause availability-only credential consumption. The package does
not silently add a pairwise admission MAC, stateless cookie, or authenticated
M1 because that would change the agreed protocol. The paper must either add and
implement such a gate or quantify rate limiting/version replenishment and state
this limitation.

### Retransmission cache

The cryptographic calculations support byte-identical retransmission in
principle, but this package does not implement a production retransmission
state machine or persistent M2/M3/M4 cache. A lost message can waste a reserved
credential. It cannot cause one index to sign two different messages because q
is advanced before release.

### Rollback resistance

ESP32 NVS gives crash-safe forward reservation. It does not prevent a physical
attacker from restoring an older flash/NVS image. A malicious-rollback claim
requires a hardware monotonic counter, trusted secure element, or a narrower
threat model.

### Revocation freshness

An optional expiry field is checked only when the ESP32 has a synchronized wall
clock. The current laboratory service does not implement signed monotonic
checkpoints or a production revocation dissemination policy. Offline acceptance
is therefore conditional on sufficiently fresh authenticated root/status state.

### Public-state backend

SQLite plus an HMAC audit interface is a test service, not Hyperledger Fabric
or Hyperledger Sawtooth. Do not describe it as a deployed permissioned ledger.

### ML-KEM input validation

Message length is fixed by the parser, and public-key decoding/encapsulation is
performed by wolfSSL. Pin and document the exact wolfSSL build, and include
negative tests for malformed/non-canonical ML-KEM inputs before making a
specific FIPS 203 validation claim.

### Hardware build status

Host-side syntax and packet tests cannot replace compilation against the user's
ESP32 Arduino core and wolfSSL configuration. The revised package must be built
and rerun on the physical boards before its new measurements are reported.
