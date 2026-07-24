# Corrected message and transcript layout

All integers are big-endian. Every object begins with a one-byte protocol
version and a one-byte type/domain value.

The profile/suite field has two values of equal size:

- `0x00010001`: repository-assisted paths
- `0x00010002`: signer-carried paths

## M0, 86 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | M0 type |
| 2 | 32 | ID_A |
| 34 | 32 | ID_B |
| 66 | 16 | N_A |
| 82 | 4 | profile/suite ID |

## M1, 102 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | M1 type |
| 2 | 32 | ID_B |
| 34 | 32 | ID_A |
| 66 | 16 | N_A |
| 82 | 16 | N_B |
| 98 | 4 | profile/suite ID |

`SID0` is not `SHA256(M1)`. It is:

```text
SHA256(
  version || SID0-domain ||
  u16(86)  || M0 ||
  u16(102) || M1
)
```

## M2 base, 3022 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | M2 type |
| 2 | 32 | SID0 |
| 34 | 4 | v_A |
| 38 | 4 | q_A |
| 42 | 800 | ML-KEM-512 encapsulation key |
| 842 | 2180 | LM-OTS signature |

Mode C appends the 320-byte path at offset 3022, producing a 3342-byte M2.

The 902-byte `mu_A` is:

```text
version || INIT-domain || SID0 || ID_A || ID_B || v_A || ek_A
```

The actual 910-byte LM-OTS message is:

```text
version || LMOTS-SIGN-domain || u16(902) || mu_A || q_A
```

Thus the one-time index is cryptographically bound to the signature.

## M3 inner base, 2990 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | inner-response type |
| 2 | 32 | SID0 |
| 34 | 4 | v_B |
| 38 | 4 | q_B |
| 42 | 768 | ML-KEM-512 ciphertext |
| 810 | 2180 | LM-OTS signature |

Mode C appends the 320-byte path at offset 2990, producing a 3310-byte inner
message.

The 902-byte `mu_B` is:

```text
version || RESP-domain || SID0 || H(M2) || ID_A || ID_B || v_B || ct_B
```

The actual LM-OTS message is:

```text
version || LMOTS-SIGN-domain || u16(902) || mu_B || q_B
```

## M3 outer

Repository-assisted mode: 3058 bytes.

Signer-carried mode: 3378 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | M3 outer type |
| 2 | 32 | SID0 |
| 34 | 2 | inner length |
| 36 | variable | M3 inner |
| after inner | 32 | tau_B |

## Transcript

The transcript hash is a streaming canonical encoding:

```text
SHA256(
  version || TRANSCRIPT-domain || SID0 ||
  u16(|M0|)       || M0 ||
  u16(|M1|)       || M1 ||
  u16(|M2|)       || M2 ||
  u16(|M3-inner|) || M3-inner
)
```

The actual message lengths make the path-delivery profile part of the
transcript.

## Key derivation

HKDF-SHA-256 uses:

```text
salt = transcript_hash
IKM  = ML-KEM shared secret
info = version || UAV-AKE-domain || u16(32) || transcript_hash
L    = 96 bytes
```

The output is split as:

```text
SK || K_A_confirm || K_B_confirm
```

## Confirmation

```text
tau_B = HMAC-SHA256(
  K_B_confirm,
  version || B-CONFIRM-domain || u16(32) || transcript_hash
)

tau_A = HMAC-SHA256(
  K_A_confirm,
  version || A-CONFIRM-domain || u16(32) || transcript_hash
)
```

## M4, 66 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version |
| 1 | 1 | M4 type |
| 2 | 32 | SID0 |
| 34 | 32 | tau_A |
