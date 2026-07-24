#pragma once

#include <Arduino.h>

namespace puav {

static constexpr uint8_t PROTOCOL_VERSION = 1;

static constexpr size_t ID_BYTES = 32;
static constexpr size_t NONCE_BYTES = 16;
static constexpr size_t HASH_BYTES = 32;
static constexpr size_t HMAC_BYTES = 32;
static constexpr size_t FE_HELPER_PLACEHOLDER_BYTES = 32;

static constexpr size_t MLKEM_PUBLIC_KEY_BYTES = 800;
static constexpr size_t MLKEM_PRIVATE_KEY_BYTES = 1632;
static constexpr size_t MLKEM_CIPHERTEXT_BYTES = 768;
static constexpr size_t MLKEM_SHARED_SECRET_BYTES = 32;

static constexpr size_t LMOTS_SIGNATURE_BYTES = 2180;
static constexpr size_t LMS_PATH_BYTES = 320;
static constexpr size_t LMS_HEIGHT = 10;
static constexpr size_t LMS_LEAVES = 1u << LMS_HEIGHT;
static constexpr size_t LMS_TREE_NODES = 2u * LMS_LEAVES;

/*
  The two path-delivery modes use different SuiteID values so that a peer
  cannot silently reinterpret a repository-assisted transcript as a
  signer-carried transcript, or vice versa.
*/
enum class PathDeliveryMode : uint8_t {
    RepositoryAssisted = 1,
    SignerCarried = 2
};

static constexpr uint32_t SUITE_ID_REPOSITORY = 0x00010001UL;
static constexpr uint32_t SUITE_ID_CARRIED = 0x00010002UL;

inline uint32_t suiteIdForMode(PathDeliveryMode mode)
{
    return mode == PathDeliveryMode::SignerCarried
        ? SUITE_ID_CARRIED
        : SUITE_ID_REPOSITORY;
}

/* Fixed-size direct messages. */
static constexpr size_t M0_BYTES = 86;
static constexpr size_t M1_BYTES = 102;
static constexpr size_t M4_BYTES = 66;

/* M2 and M3 have an optional 320-byte LMS authentication path. */
static constexpr size_t M2_BASE_BYTES = 3022;
static constexpr size_t M2_CARRIED_BYTES =
    M2_BASE_BYTES + LMS_PATH_BYTES;
static constexpr size_t M2_MAX_BYTES = M2_CARRIED_BYTES;

static constexpr size_t M3_INNER_BASE_BYTES = 2990;
static constexpr size_t M3_INNER_CARRIED_BYTES =
    M3_INNER_BASE_BYTES + LMS_PATH_BYTES;
static constexpr size_t M3_INNER_MAX_BYTES = M3_INNER_CARRIED_BYTES;

static constexpr size_t M3_BASE_BYTES =
    36 + M3_INNER_BASE_BYTES + HMAC_BYTES;
static constexpr size_t M3_CARRIED_BYTES =
    36 + M3_INNER_CARRIED_BYTES + HMAC_BYTES;
static constexpr size_t M3_MAX_BYTES = M3_CARRIED_BYTES;

inline size_t m2BytesForMode(PathDeliveryMode mode)
{
    return mode == PathDeliveryMode::SignerCarried
        ? M2_CARRIED_BYTES
        : M2_BASE_BYTES;
}

inline size_t m3InnerBytesForMode(PathDeliveryMode mode)
{
    return mode == PathDeliveryMode::SignerCarried
        ? M3_INNER_CARRIED_BYTES
        : M3_INNER_BASE_BYTES;
}

inline size_t m3BytesForMode(PathDeliveryMode mode)
{
    return mode == PathDeliveryMode::SignerCarried
        ? M3_CARRIED_BYTES
        : M3_BASE_BYTES;
}

inline size_t expectedDirectApplicationBytes(PathDeliveryMode mode)
{
    return M0_BYTES + M1_BYTES + m2BytesForMode(mode) +
        m3BytesForMode(mode) + M4_BYTES;
}

/*
  Canonical signed objects. mu_A and mu_B are each 902 bytes. The final
  LM-OTS input wraps mu with a distinct LMOTS-SIGN domain and q.
*/
static constexpr size_t MU_A_BYTES = 902;
static constexpr size_t MU_B_BYTES = 902;
static constexpr size_t LMOTS_SIGNED_OBJECT_BYTES =
    1 + 1 + 2 + MU_A_BYTES + 4; /* version, domain, len, mu, q */

/* Canonical SID0 encoding length. */
static constexpr size_t SID0_INPUT_BYTES =
    1 + 1 + 2 + M0_BYTES + 2 + M1_BYTES;

static constexpr size_t SESSION_KEY_MATERIAL_BYTES = 96;

static constexpr uint16_t DEFAULT_PROTOCOL_PORT = 4210;
static constexpr uint16_t DEFAULT_GCS_PORT = 5001;
static constexpr uint16_t DEFAULT_GCS_LOCAL_PORT = 5210;

static constexpr uint16_t FRAGMENT_MAGIC = 0xA55A;
static constexpr size_t FRAGMENT_HEADER_BYTES = 14;
static constexpr size_t FRAGMENT_PAYLOAD_BYTES = 1000;
static constexpr size_t MAX_FRAGMENTS = 8;
static constexpr size_t MAX_PROTOCOL_MESSAGE_BYTES = M3_MAX_BYTES;

static constexpr uint32_t RECEIVE_TIMEOUT_MS = 8000;
static constexpr uint32_t GCS_TIMEOUT_MS = 3000;
static constexpr uint32_t GCS_RETRIES = 4;

/* Public-record status values. */
static constexpr uint8_t CREDENTIAL_STATUS_PENDING = 0;
static constexpr uint8_t CREDENTIAL_STATUS_ACTIVE = 1;
static constexpr uint8_t CREDENTIAL_STATUS_RETIRED = 2;
static constexpr uint8_t CREDENTIAL_STATUS_REVOKED = 3;

enum class Role : uint8_t {
    Initiator = 1,
    Responder = 2
};

enum MessageType : uint8_t {
    MSG_M0_REQ = 0x10,
    MSG_M1_CHAL = 0x11,
    MSG_M2_INIT = 0x12,
    MSG_M3_RESP_FIN = 0x13,
    MSG_M3_INNER = 0x14,
    MSG_M4_INIT_FIN = 0x15,
    MSG_RESULT = 0x7f
};

/* Internal domain tags used inside hashed/signed objects. */
enum DomainTag : uint8_t {
    DOMAIN_SID0 = 0x30,
    DOMAIN_INIT = 0x31,
    DOMAIN_RESP = 0x32,
    DOMAIN_LMOTS_SIGN = 0x33,
    DOMAIN_TRANSCRIPT = 0x34,
    DOMAIN_UAV_AKE = 0x35,
    DOMAIN_B_CONFIRM = 0x36,
    DOMAIN_A_CONFIRM = 0x37
};

enum ResultStatus : uint8_t {
    RESULT_OK = 0,
    RESULT_PARSE_ERROR = 1,
    RESULT_ID_ERROR = 2,
    RESULT_SID_ERROR = 3,
    RESULT_SIGNATURE_ERROR = 4,
    RESULT_KEM_ERROR = 5,
    RESULT_TAG_ERROR = 6,
    RESULT_STATE_ERROR = 7,
    RESULT_LEDGER_ERROR = 8
};

struct NodeConfig {
    Role role;
    PathDeliveryMode pathMode;
    const char* wifiSsid;
    const char* wifiPassword;
    IPAddress gcsIp;
    IPAddress responderIp;
    uint16_t protocolPort;
    uint16_t gcsPort;
    uint16_t gcsLocalPort;
    uint8_t deviceId[ID_BYTES];
    uint8_t peerId[ID_BYTES];

    /*
      Laboratory placeholders only. hardcodedPufRoot represents the stable
      output that the external APUF + Python fuzzy extractor will later
      reconstruct. hardcodedHelperData represents locally retained public
      helper material. This package does not claim to implement the physical
      PUF or the Python fuzzy extractor.
    */
    uint8_t hardcodedPufRoot[HASH_BYTES];
    uint8_t hardcodedHelperData[FE_HELPER_PLACEHOLDER_BYTES];

    uint8_t lmsIdentifier[16];
    uint32_t credentialVersion;
    uint32_t peerCredentialVersion;
    uint64_t credentialExpiryUnix; /* 0 disables wall-clock expiry in lab. */
    const char* nvsNamespace;
    uint32_t firstQ;
    uint32_t numberOfSessions;
    bool resetQCounter;
};

struct LocalMetrics {
    uint64_t shaUs = 0;
    uint64_t hmacUs = 0;
    uint64_t lmotsSignUs = 0;
    uint64_t lmotsVerifyUs = 0;
    uint64_t kemUs = 0;
    uint64_t pufFeUs = 0;
    uint64_t repositoryUs = 0;
    uint64_t totalCryptoUs = 0;
    uint64_t protocolUs = 0;
    uint32_t appTxBytes = 0;
    uint32_t appRxBytes = 0;
    uint32_t framedTxBytes = 0;
    uint32_t framedRxBytes = 0;
    uint32_t repositoryTxBytes = 0;
    uint32_t repositoryRxBytes = 0;
};

inline void putU16(uint8_t* out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value);
}

inline void putU32(uint8_t* out, uint32_t value)
{
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

inline void putU64(uint8_t* out, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

inline uint16_t getU16(const uint8_t* in)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(in[0]) << 8) |
        static_cast<uint16_t>(in[1]));
}

inline uint32_t getU32(const uint8_t* in)
{
    return
        (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) |
        static_cast<uint32_t>(in[3]);
}

inline uint64_t getU64(const uint8_t* in)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | in[i];
    }
    return value;
}

inline bool constantTimeEqual(
    const uint8_t* left,
    const uint8_t* right,
    size_t length)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= static_cast<uint8_t>(left[i] ^ right[i]);
    }
    return difference == 0;
}

/* Laboratory provisioning authentication key. */
static constexpr uint8_t GCS_LEDGER_HMAC_KEY[32] = {
    0x61, 0x94, 0x0d, 0x2f, 0x73, 0xe1, 0x48, 0xac,
    0xb5, 0x39, 0x8c, 0x14, 0xd0, 0x6e, 0x2a, 0xf7,
    0x83, 0x45, 0x1b, 0xc9, 0x56, 0xaa, 0x30, 0x7d,
    0x1e, 0x68, 0xf2, 0x04, 0x9b, 0xcd, 0x77, 0x35
};

} // namespace puav
