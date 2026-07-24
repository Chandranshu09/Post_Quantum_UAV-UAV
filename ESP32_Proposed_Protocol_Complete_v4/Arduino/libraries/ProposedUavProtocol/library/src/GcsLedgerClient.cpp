#include "GcsLedgerClient.h"
#include "esp_timer.h"

namespace puav {

GcsLedgerClient::GcsLedgerClient()
    : m_gcsPort(0),
      m_localPort(0),
      m_txBytes(0),
      m_rxBytes(0)
{
    memset(m_deviceId, 0, sizeof(m_deviceId));
    memset(m_peerId, 0, sizeof(m_peerId));
    memset(m_buffer, 0, sizeof(m_buffer));
}

bool GcsLedgerClient::begin(
    const IPAddress& gcsIp,
    uint16_t gcsPort,
    uint16_t localPort,
    const uint8_t deviceId[ID_BYTES],
    const uint8_t peerId[ID_BYTES])
{
    m_gcsIp = gcsIp;
    m_gcsPort = gcsPort;
    m_localPort = localPort;
    memcpy(m_deviceId, deviceId, ID_BYTES);
    memcpy(m_peerId, peerId, ID_BYTES);

    return m_udp.begin(localPort) == 1;
}

bool GcsLedgerClient::computeTag(
    const uint8_t* data,
    size_t lengthWithoutTag,
    uint8_t tag[HMAC_BYTES])
{
    return CryptoHelpers::hmacSha256(
        GCS_LEDGER_HMAC_KEY,
        sizeof(GCS_LEDGER_HMAC_KEY),
        data,
        lengthWithoutTag,
        tag);
}

bool GcsLedgerClient::sendAndReceive(
    const uint8_t* request,
    size_t requestLength,
    uint8_t expectedOp,
    uint32_t expectedVersion,
    uint32_t expectedQ,
    size_t& responseLength)
{
    responseLength = 0;

    while (m_udp.parsePacket() > 0) {
        while (m_udp.available()) {
            m_udp.read();
        }
    }

    for (uint32_t attempt = 0; attempt < GCS_RETRIES; ++attempt) {
        if (!m_udp.beginPacket(m_gcsIp, m_gcsPort)) {
            return false;
        }

        const size_t written = m_udp.write(request, requestLength);

        if (written != requestLength || !m_udp.endPacket()) {
            return false;
        }

        m_txBytes += requestLength;
        const uint32_t startMs = millis();

        while (millis() - startMs < GCS_TIMEOUT_MS) {
            const int packetSize = m_udp.parsePacket();

            if (packetSize <= 0) {
                delay(2);
                continue;
            }

            const IPAddress sourceIp = m_udp.remoteIP();
            const uint16_t sourcePort = m_udp.remotePort();

            if (packetSize > static_cast<int>(sizeof(m_buffer))) {
                while (m_udp.available()) {
                    m_udp.read();
                }
                continue;
            }

            const int readLength = m_udp.read(m_buffer, sizeof(m_buffer));

            if (readLength < 8 + static_cast<int>(HMAC_BYTES)) {
                continue;
            }

            m_rxBytes += static_cast<uint32_t>(readLength);

            if (sourceIp != m_gcsIp || sourcePort != m_gcsPort ||
                memcmp(m_buffer, "GCS2", 4) != 0) {
                continue;
            }

            const uint8_t receivedOp = m_buffer[4];
            const uint8_t* receivedTag =
                m_buffer + readLength - HMAC_BYTES;
            uint8_t expectedTag[HMAC_BYTES];

            /* Authenticate every response, including NOT_FOUND. */
            if (!computeTag(
                    m_buffer,
                    static_cast<size_t>(readLength) - HMAC_BYTES,
                    expectedTag) ||
                !constantTimeEqual(
                    receivedTag,
                    expectedTag,
                    HMAC_BYTES)) {
                Serial.println("Repository response authentication failed.");
                continue;
            }

            if (receivedOp == OP_NOT_FOUND) {
                if (readLength >= static_cast<int>(ACK_BYTES)) {
                    Serial.printf(
                        "Repository record not found, version=%u q=%u.\n",
                        static_cast<unsigned>(getU32(m_buffer + 40)),
                        static_cast<unsigned>(getU32(m_buffer + 44)));
                }
                return false;
            }

            if (receivedOp != expectedOp) {
                continue;
            }

            uint32_t receivedVersion = 0;
            uint32_t receivedQ = 0;

            if (receivedOp == OP_ACK ||
                receivedOp == OP_ROOT_RECORD ||
                receivedOp == OP_PATH_RECORD) {
                receivedVersion = getU32(m_buffer + 40);
            }

            if (receivedOp == OP_ACK || receivedOp == OP_PATH_RECORD) {
                receivedQ = getU32(m_buffer + 44);
            }

            if (receivedVersion != expectedVersion ||
                (expectedQ != UINT32_MAX && receivedQ != expectedQ)) {
                continue;
            }

            responseLength = static_cast<size_t>(readLength);
            return true;
        }

        delay(100);
    }

    return false;
}

bool GcsLedgerClient::enrollOwnRoot(
    const LmotsLms& lms,
    uint32_t version,
    uint32_t suiteId,
    uint8_t status,
    uint64_t expiryUnix)
{
    uint8_t request[ROOT_RECORD_BYTES];
    memset(request, 0, sizeof(request));

    memcpy(request, "GCS2", 4);
    request[4] = OP_ENROLL_ROOT;
    memcpy(request + 8, m_deviceId, ID_BYTES);
    putU32(request + 40, version);
    memcpy(request + 44, lms.identifier(), 16);
    memcpy(request + 60, lms.root(), HASH_BYTES);
    putU32(request + 92, suiteId);
    request[96] = status;
    putU64(request + 100, expiryUnix);

    if (!computeTag(
            request,
            ROOT_RECORD_BYTES - HMAC_BYTES,
            request + ROOT_RECORD_BYTES - HMAC_BYTES)) {
        return false;
    }

    size_t responseLength = 0;

    if (!sendAndReceive(
            request,
            sizeof(request),
            OP_ACK,
            version,
            UINT32_MAX,
            responseLength)) {
        return false;
    }

    return responseLength == ACK_BYTES && m_buffer[48] == 0;
}

bool GcsLedgerClient::enrollOwnPaths(
    const LmotsLms& lms,
    uint32_t version,
    uint32_t firstQ,
    uint32_t count)
{
    if (count == 0 || firstQ + count > LMS_LEAVES) {
        return false;
    }

    Serial.printf(
        "Enrolling %u public LMS paths for repository mode...\n",
        static_cast<unsigned>(count));

    uint8_t path[LMS_PATH_BYTES];

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t q = firstQ + i;

        if (!lms.extractPath(q, path)) {
            return false;
        }

        uint8_t request[PATH_RECORD_BYTES];
        memset(request, 0, sizeof(request));
        memcpy(request, "GCS2", 4);
        request[4] = OP_ENROLL_PATH;
        memcpy(request + 8, m_deviceId, ID_BYTES);
        putU32(request + 40, version);
        putU32(request + 44, q);
        memcpy(request + 48, path, LMS_PATH_BYTES);

        if (!computeTag(
                request,
                PATH_RECORD_BYTES - HMAC_BYTES,
                request + PATH_RECORD_BYTES - HMAC_BYTES)) {
            return false;
        }

        size_t responseLength = 0;

        if (!sendAndReceive(
                request,
                sizeof(request),
                OP_ACK,
                version,
                q,
                responseLength) ||
            responseLength != ACK_BYTES || m_buffer[48] != 0) {
            Serial.printf(
                "Path enrollment failed for q=%u.\n",
                static_cast<unsigned>(q));
            return false;
        }

        if ((i + 1) % 25 == 0 || i + 1 == count) {
            Serial.printf(
                "Enrolled %u / %u paths.\n",
                static_cast<unsigned>(i + 1),
                static_cast<unsigned>(count));
        }
    }

    CryptoHelpers::secureZero(path, sizeof(path));
    return true;
}

bool GcsLedgerClient::fetchPeerRoot(
    uint32_t version,
    PeerPublicRecord& record)
{
    uint8_t request[GET_ROOT_BYTES];
    memset(request, 0, sizeof(request));
    memcpy(request, "GCS2", 4);
    request[4] = OP_GET_ROOT;
    memcpy(request + 8, m_deviceId, ID_BYTES);
    memcpy(request + 40, m_peerId, ID_BYTES);
    putU32(request + 72, version);

    if (!computeTag(
            request,
            GET_ROOT_BYTES - HMAC_BYTES,
            request + GET_ROOT_BYTES - HMAC_BYTES)) {
        return false;
    }

    for (uint32_t waitRound = 0; waitRound < 120; ++waitRound) {
        size_t responseLength = 0;

        if (sendAndReceive(
                request,
                sizeof(request),
                OP_ROOT_RECORD,
                version,
                UINT32_MAX,
                responseLength)) {
            if (responseLength != ROOT_RECORD_BYTES ||
                !constantTimeEqual(m_buffer + 8, m_peerId, ID_BYTES)) {
                return false;
            }

            memset(&record, 0, sizeof(record));
            record.version = getU32(m_buffer + 40);
            memcpy(record.identifier, m_buffer + 44, 16);
            memcpy(record.root, m_buffer + 60, HASH_BYTES);
            record.suiteId = getU32(m_buffer + 92);
            record.status = m_buffer[96];
            record.expiryUnix = getU64(m_buffer + 100);
            record.ready = true;
            return true;
        }

        delay(1000);
    }

    return false;
}

bool GcsLedgerClient::fetchPeerPath(
    uint32_t version,
    uint32_t q,
    uint8_t path[LMS_PATH_BYTES],
    RepositoryOperationMetrics* operationMetrics)
{
    if (q >= LMS_LEAVES || path == nullptr) {
        return false;
    }

    uint8_t request[GET_PATH_BYTES];
    memset(request, 0, sizeof(request));
    memcpy(request, "GCS2", 4);
    request[4] = OP_GET_PATH;
    memcpy(request + 8, m_deviceId, ID_BYTES);
    memcpy(request + 40, m_peerId, ID_BYTES);
    putU32(request + 72, version);
    putU32(request + 76, q);

    if (!computeTag(
            request,
            GET_PATH_BYTES - HMAC_BYTES,
            request + GET_PATH_BYTES - HMAC_BYTES)) {
        return false;
    }

    const uint32_t txBefore = m_txBytes;
    const uint32_t rxBefore = m_rxBytes;
    const int64_t startUs = esp_timer_get_time();
    size_t responseLength = 0;

    const bool received = sendAndReceive(
        request,
        sizeof(request),
        OP_PATH_RECORD,
        version,
        q,
        responseLength);

    if (operationMetrics != nullptr) {
        operationMetrics->elapsedUs = static_cast<uint64_t>(
            esp_timer_get_time() - startUs);
        operationMetrics->txBytes = m_txBytes - txBefore;
        operationMetrics->rxBytes = m_rxBytes - rxBefore;
    }

    if (!received || responseLength != PATH_RECORD_BYTES ||
        !constantTimeEqual(m_buffer + 8, m_peerId, ID_BYTES)) {
        return false;
    }

    memcpy(path, m_buffer + 48, LMS_PATH_BYTES);
    return true;
}

uint32_t GcsLedgerClient::txBytes() const
{
    return m_txBytes;
}

uint32_t GcsLedgerClient::rxBytes() const
{
    return m_rxBytes;
}

} // namespace puav
