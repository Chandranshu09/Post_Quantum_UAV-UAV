#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>

#include "ProtocolConstants.h"
#include "CryptoHelpers.h"
#include "LmotsLms.h"

namespace puav {

struct PeerPublicRecord {
    bool ready = false;
    uint32_t version = 0;
    uint8_t identifier[16] = {0};
    uint8_t root[HASH_BYTES] = {0};
    uint32_t suiteId = 0;
    uint8_t status = CREDENTIAL_STATUS_PENDING;
    uint64_t expiryUnix = 0;
};

struct RepositoryOperationMetrics {
    uint64_t elapsedUs = 0;
    uint32_t txBytes = 0;
    uint32_t rxBytes = 0;
};

class GcsLedgerClient {
public:
    GcsLedgerClient();

    bool begin(
        const IPAddress& gcsIp,
        uint16_t gcsPort,
        uint16_t localPort,
        const uint8_t deviceId[ID_BYTES],
        const uint8_t peerId[ID_BYTES]);

    bool enrollOwnRoot(
        const LmotsLms& lms,
        uint32_t version,
        uint32_t suiteId,
        uint8_t status,
        uint64_t expiryUnix);

    bool enrollOwnPaths(
        const LmotsLms& lms,
        uint32_t version,
        uint32_t firstQ,
        uint32_t count);

    bool fetchPeerRoot(
        uint32_t version,
        PeerPublicRecord& record);

    bool fetchPeerPath(
        uint32_t version,
        uint32_t q,
        uint8_t path[LMS_PATH_BYTES],
        RepositoryOperationMetrics* operationMetrics = nullptr);

    uint32_t txBytes() const;
    uint32_t rxBytes() const;

private:
    static constexpr uint8_t OP_ENROLL_ROOT = 1;
    static constexpr uint8_t OP_ENROLL_PATH = 2;
    static constexpr uint8_t OP_GET_ROOT = 3;
    static constexpr uint8_t OP_GET_PATH = 4;
    static constexpr uint8_t OP_ROOT_RECORD = 5;
    static constexpr uint8_t OP_PATH_RECORD = 6;
    static constexpr uint8_t OP_ACK = 7;
    static constexpr uint8_t OP_NOT_FOUND = 8;

    static constexpr size_t ROOT_RECORD_BYTES = 140;
    static constexpr size_t PATH_RECORD_BYTES = 400;
    static constexpr size_t GET_ROOT_BYTES = 108;
    static constexpr size_t GET_PATH_BYTES = 112;
    static constexpr size_t ACK_BYTES = 84;
    static constexpr size_t MAX_GCS_PACKET_BYTES = PATH_RECORD_BYTES;

    WiFiUDP m_udp;
    IPAddress m_gcsIp;
    uint16_t m_gcsPort;
    uint16_t m_localPort;
    uint8_t m_deviceId[ID_BYTES];
    uint8_t m_peerId[ID_BYTES];

    uint8_t m_buffer[MAX_GCS_PACKET_BYTES];
    uint32_t m_txBytes;
    uint32_t m_rxBytes;

    bool computeTag(
        const uint8_t* data,
        size_t lengthWithoutTag,
        uint8_t tag[HMAC_BYTES]);

    bool sendAndReceive(
        const uint8_t* request,
        size_t requestLength,
        uint8_t expectedOp,
        uint32_t expectedVersion,
        uint32_t expectedQ,
        size_t& responseLength);
};

} // namespace puav
