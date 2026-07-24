# APQE-CDA paper ambiguities handled by this implementation

This package does not silently force the published equations into a byte layout
that cannot be executed. It uses a clearly labelled **literal 256-bit profile**.

## 1. Kyber CPA plaintext capacity

The paper defines

`Ei = TID_i || C_i || N_i || TID_j`

and separately assumes 256-bit temporary identities, challenges, and nonces.
This makes `Ei` 128 bytes. Kyber-512 CPAPKE encrypts one 32-byte message per
768-byte ciphertext. Therefore, the runnable literal profile encrypts `Ei` as
four independent CPA blocks:

- four 32-byte plaintext blocks;
- four 768-byte ciphertexts;
- one 32-byte H1 value.

Thus M1 is 3104 bytes rather than 800 bytes.

## 2. Width of Pj

The paper defines `Pj = TKji XOR (Cj, Nj)`. With 256-bit `Cj` and `Nj`, the
right-hand pair is 64 bytes while `TKji` is 32 bytes. The code makes the
serialization explicit by applying the 32-byte mask independently to both
32-byte halves. This produces a 64-byte `Pj`.

This is an explicit runnable interpretation, not a claim that the paper defines
the expansion unambiguously.

## 3. Session-key ordering

The initiator formula prints:

`SK = H(TKji || TKij || Ni || Nj)`

while the responder formula reverses both secret and nonce order. A normal hash
is not commutative, so those expressions do not produce the same key. Both
boards in this package use the initiator's canonical order:

`SK = H(TKji || TKij || Ni || Nj)`.

## 4. Computation-cost aggregate

The role-wise expressions each contain one Kyber key generation. Their sum
therefore contains two key generations. The paper's aggregate line prints only
one key generation and two encryption operations. The package measures the
operations actually executed by each role.

## Reporting rule

Report these separately:

1. the paper-claimed communication value: 960 bytes;
2. the runnable literal-256 implementation: 3296 direct UAV bytes;
3. runtime ESP32-to-Fabric gateway traffic;
4. physical PUF cost as not measured, because this package uses software PUF
   emulation.
