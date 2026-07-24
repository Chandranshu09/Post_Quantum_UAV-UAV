# APQE-CDA literal-256 message layout

All multibyte transport headers use network byte order. Cryptographic fields are
raw bytes and do not carry textual hex encoding between ESP32 boards.

## Direct UAV messages

### M1, UAV-A to UAV-B, 3104 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 768 | CPA ciphertext of TID_i |
| 768 | 768 | CPA ciphertext of C_i |
| 1536 | 768 | CPA ciphertext of N_i |
| 2304 | 768 | CPA ciphertext of TID_j |
| 3072 | 32 | H1 = SHA-256(TID_i || C_i || N_i || TID_j) |

### M2, UAV-B to UAV-A, 128 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 32 | TN_j = TK_j XOR N_i |
| 32 | 64 | P_j, masked C_j || N_j |
| 96 | 32 | H2 = SHA-256(TK_ji || TK_j || C_j || N_j) |

### M3, UAV-A to UAV-B, 64 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 32 | TN_i = TK_i XOR N_j |
| 32 | 32 | H3 = SHA-256(TK_ij || TK_i || SK) |

Total direct application payload:

`3104 + 128 + 64 = 3296 bytes`.

With 1000-byte fragments and a 14-byte experimental fragment header:

- M1 uses 4 datagrams: 3104 + 56 = 3160 bytes;
- M2 uses 1 datagram: 128 + 14 = 142 bytes;
- M3 uses 1 datagram: 64 + 14 = 78 bytes;
- total framed UDP payload: 3380 bytes.

UDP, IP, Wi-Fi MAC, retransmission, and physical-layer overhead are not included.

## Measurement-only RESULT

UAV-B sends one RESULT after accepting M3. It returns responder timing and a
SHA-256 digest of the established session key. RESULT is not an APQE protocol
message and is excluded from communication-cost totals.

## Fabric gateway binary protocol

A query request is 76 bytes:

- 12-byte request header;
- 32-byte identity hash or temporary identity;
- 32-byte HMAC-SHA-256.

A successful record response is 979 bytes:

- 19-byte response header, including measured Fabric evaluation time;
- 928-byte credential record;
- 32-byte HMAC-SHA-256.

One runtime query exchange therefore carries 1055 application bytes. The
initiator performs two queries and the responder performs one query, for 3165
runtime gateway application bytes per successful session.
