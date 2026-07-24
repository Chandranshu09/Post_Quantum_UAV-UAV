#pragma once

#include <Arduino.h>

namespace apqe {

static constexpr uint8_t PROTOCOL_VERSION = 1;
static constexpr uint16_t PROTOCOL_PORT = 4310;
static constexpr uint16_t GATEWAY_ORG1_PORT = 5002;
static constexpr uint16_t GATEWAY_ORG2_PORT = 5003;

static constexpr size_t ID_BYTES = 32;
static constexpr size_t HASH_BYTES = 32;
static constexpr size_t TID_BYTES = 32;
static constexpr size_t CHALLENGE_BYTES = 32;
static constexpr size_t NONCE_BYTES = 32;
static constexpr size_t PUF_BYTES = 32;

static constexpr size_t KYBER_PUBLIC_KEY_BYTES = 800;
static constexpr size_t KYBER_SECRET_KEY_BYTES = 768;
static constexpr size_t KYBER_CIPHERTEXT_BYTES = 768;
static constexpr size_t KYBER_MESSAGE_BYTES = 32;
static constexpr size_t KYBER_COINS_BYTES = 32;

/*
 * Literal 256-bit profile.
 * Ei = TID_i || C_i || N_i || TID_j = 128 bytes.
 * Kyber.CPAPKE encrypts exactly 32 bytes, therefore Ei is encrypted as four
 * independent Kyber-512 CPA ciphertext blocks. This is the directly runnable
 * interpretation of the paper's 256-bit field assumptions.
 */
static constexpr size_t EI_BLOCKS = 4;
static constexpr size_t EI_BYTES = EI_BLOCKS * KYBER_MESSAGE_BYTES;
static constexpr size_t M1_BYTES = EI_BLOCKS * KYBER_CIPHERTEXT_BYTES + HASH_BYTES; // 3104
static constexpr size_t PJ_BYTES = CHALLENGE_BYTES + NONCE_BYTES;                  // 64
static constexpr size_t M2_BYTES = PUF_BYTES + PJ_BYTES + HASH_BYTES;              // 128
static constexpr size_t M3_BYTES = PUF_BYTES + HASH_BYTES;                          // 64
static constexpr size_t DIRECT_APPLICATION_BYTES = M1_BYTES + M2_BYTES + M3_BYTES; // 3296

static constexpr uint16_t FRAGMENT_MAGIC = 0xA951;
static constexpr size_t FRAGMENT_HEADER_BYTES = 14;
static constexpr size_t FRAGMENT_PAYLOAD_BYTES = 1000;
static constexpr size_t MAX_FRAGMENTS = 5;
static constexpr size_t MAX_PROTOCOL_MESSAGE_BYTES = M1_BYTES;
static constexpr uint32_t DIRECT_RECEIVE_TIMEOUT_MS = 10000;

static constexpr uint16_t GATEWAY_MAGIC = 0xA952;
static constexpr uint8_t GATEWAY_VERSION = 1;
static constexpr size_t GATEWAY_REQUEST_HEADER_BYTES = 12;
static constexpr size_t GATEWAY_RESPONSE_HEADER_BYTES = 19;
static constexpr size_t GATEWAY_TAG_BYTES = 32;
static constexpr size_t FABRIC_RECORD_BYTES =
    ID_BYTES + TID_BYTES + KYBER_PUBLIC_KEY_BYTES + PUF_BYTES + HASH_BYTES; // 928
static constexpr size_t GATEWAY_MAX_REQUEST_BYTES =
    GATEWAY_REQUEST_HEADER_BYTES + FABRIC_RECORD_BYTES + GATEWAY_TAG_BYTES;
static constexpr size_t GATEWAY_MAX_RESPONSE_BYTES =
    GATEWAY_RESPONSE_HEADER_BYTES + FABRIC_RECORD_BYTES + GATEWAY_TAG_BYTES;
static constexpr uint32_t GATEWAY_TIMEOUT_MS = 5000;
static constexpr uint32_t GATEWAY_RETRIES = 6;

static constexpr uint32_t DEFAULT_SESSION_COUNT = 20;
static constexpr uint16_t RESULT_BYTES = 153;

/* Application-layer gateway traffic for one query with the fixed binary format. */
static constexpr size_t GATEWAY_QUERY_REQUEST_BYTES =
    GATEWAY_REQUEST_HEADER_BYTES + ID_BYTES + GATEWAY_TAG_BYTES; // 76
static constexpr size_t GATEWAY_QUERY_RESPONSE_BYTES =
    GATEWAY_RESPONSE_HEADER_BYTES + FABRIC_RECORD_BYTES + GATEWAY_TAG_BYTES; // 979
static constexpr size_t GATEWAY_QUERY_EXCHANGE_BYTES =
    GATEWAY_QUERY_REQUEST_BYTES + GATEWAY_QUERY_RESPONSE_BYTES; // 1055

static constexpr uint8_t GATEWAY_HMAC_KEY[32] = {
    0x7a, 0x0c, 0x9e, 0x51, 0x2b, 0xd8, 0x44, 0xf0,
    0xa1, 0x63, 0x37, 0x8d, 0xe4, 0x05, 0xc9, 0x72,
    0x19, 0xb6, 0x2f, 0xaa, 0x84, 0x33, 0xd1, 0x5c,
    0x68, 0xef, 0x90, 0x47, 0x12, 0xbc, 0x5a, 0x26
};

enum class Role : uint8_t {
    Initiator = 1,
    Responder = 2
};

enum MessageType : uint8_t {
    MSG_M1 = 0x21,
    MSG_M2 = 0x22,
    MSG_M3 = 0x23,
    MSG_RESULT = 0x7f
};

enum GatewayOp : uint8_t {
    GW_PUT_CREDENTIAL = 1,
    GW_QUERY_ID_SLOT = 2,
    GW_QUERY_TID = 3,
    GW_PING = 4
};

enum GatewayStatus : uint8_t {
    GW_OK = 0,
    GW_BAD_REQUEST = 1,
    GW_NOT_FOUND = 2,
    GW_FABRIC_ERROR = 3,
    GW_AUTH_ERROR = 4
};

struct FabricCredential {
    uint8_t identityHash[ID_BYTES];
    uint8_t tid[TID_BYTES];
    uint8_t publicKey[KYBER_PUBLIC_KEY_BYTES];
    uint8_t w[PUF_BYTES];
    uint8_t verifyHash[HASH_BYTES];
};

struct NodeConfig {
    Role role;
    const char* wifiSsid;
    const char* wifiPassword;
    IPAddress gatewayIp;
    uint16_t gatewayPort;
    uint16_t gatewayLocalPort;
    IPAddress responderIp;
    uint16_t protocolPort;
    uint8_t deviceId[ID_BYTES];
    uint8_t peerId[ID_BYTES];
    uint8_t emulatedSramRaw[HASH_BYTES];
    uint8_t emulatedSramHelper[HASH_BYTES];
    uint8_t emulatedBsPufSecret[HASH_BYTES];
    uint32_t numberOfSessions;
};

struct SessionMetrics {
    uint64_t protocolUs = 0;
    uint64_t confirmedUs = 0;
    uint64_t shaUs = 0;
    uint64_t pufUs = 0;
    uint64_t fuzzyReconstructionUs = 0;
    uint64_t kyberKeygenUs = 0;
    uint64_t kyberEncryptUs = 0;
    uint64_t kyberDecryptUs = 0;
    uint64_t fabricWallUs = 0;
    uint64_t fabricPeerUs = 0;
    uint32_t directAppTx = 0;
    uint32_t directAppRx = 0;
    uint32_t directFramedTx = 0;
    uint32_t directFramedRx = 0;
    uint32_t gatewayAppTx = 0;
    uint32_t gatewayAppRx = 0;
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
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

inline uint32_t getU32(const uint8_t* in)
{
    return (static_cast<uint32_t>(in[0]) << 24) |
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

inline bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t length)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return difference == 0;
}

} // namespace apqe
