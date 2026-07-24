#include "FabricUdpClient.h"

#include "CryptoHelpers.h"

namespace apqe {

FabricUdpClient::FabricUdpClient()
    : m_gatewayPort(0),
      m_nextRequestId(1),
      m_lastStatus(GW_BAD_REQUEST)
{
    memset(m_tx, 0, sizeof(m_tx));
    memset(m_rx, 0, sizeof(m_rx));
    memset(m_recordScratch, 0, sizeof(m_recordScratch));
}

bool FabricUdpClient::begin(
    const IPAddress& gatewayIp,
    uint16_t gatewayPort,
    uint16_t localPort)
{
    m_gatewayIp = gatewayIp;
    m_gatewayPort = gatewayPort;
    return m_udp.begin(localPort) == 1;
}

void FabricUdpClient::serializeCredential(
    const FabricCredential& credential,
    uint8_t out[FABRIC_RECORD_BYTES])
{
    size_t offset = 0;
    memcpy(out + offset, credential.identityHash, ID_BYTES); offset += ID_BYTES;
    memcpy(out + offset, credential.tid, TID_BYTES); offset += TID_BYTES;
    memcpy(out + offset, credential.publicKey, KYBER_PUBLIC_KEY_BYTES); offset += KYBER_PUBLIC_KEY_BYTES;
    memcpy(out + offset, credential.w, PUF_BYTES); offset += PUF_BYTES;
    memcpy(out + offset, credential.verifyHash, HASH_BYTES);
}

bool FabricUdpClient::parseCredential(
    const uint8_t in[FABRIC_RECORD_BYTES],
    FabricCredential& credential)
{
    if (in == nullptr) return false;
    size_t offset = 0;
    memcpy(credential.identityHash, in + offset, ID_BYTES); offset += ID_BYTES;
    memcpy(credential.tid, in + offset, TID_BYTES); offset += TID_BYTES;
    memcpy(credential.publicKey, in + offset, KYBER_PUBLIC_KEY_BYTES); offset += KYBER_PUBLIC_KEY_BYTES;
    memcpy(credential.w, in + offset, PUF_BYTES); offset += PUF_BYTES;
    memcpy(credential.verifyHash, in + offset, HASH_BYTES);
    return true;
}

bool FabricUdpClient::transact(
    uint8_t op,
    uint16_t slot,
    const uint8_t* payload,
    uint16_t payloadLength,
    uint8_t* responsePayload,
    uint16_t responseCapacity,
    uint16_t& responseLength,
    uint64_t& fabricUs,
    uint64_t& wallUs,
    uint32_t& appTx,
    uint32_t& appRx)
{
    if ((payloadLength != 0 && payload == nullptr) ||
        GATEWAY_REQUEST_HEADER_BYTES + payloadLength + GATEWAY_TAG_BYTES > sizeof(m_tx)) {
        return false;
    }

    const uint32_t requestId = m_nextRequestId++;
    putU16(m_tx + 0, GATEWAY_MAGIC);
    m_tx[2] = GATEWAY_VERSION;
    m_tx[3] = op;
    putU32(m_tx + 4, requestId);
    putU16(m_tx + 8, slot);
    putU16(m_tx + 10, payloadLength);
    if (payloadLength != 0) {
        memcpy(m_tx + GATEWAY_REQUEST_HEADER_BYTES, payload, payloadLength);
    }
    const size_t authenticatedLength = GATEWAY_REQUEST_HEADER_BYTES + payloadLength;
    if (!CryptoHelpers::hmacSha256(
            GATEWAY_HMAC_KEY,
            sizeof(GATEWAY_HMAC_KEY),
            m_tx,
            authenticatedLength,
            m_tx + authenticatedLength)) {
        return false;
    }
    const size_t requestLength = authenticatedLength + GATEWAY_TAG_BYTES;

    for (uint32_t attempt = 0; attempt < GATEWAY_RETRIES; ++attempt) {
        while (m_udp.parsePacket() > 0) {
            while (m_udp.available()) m_udp.read();
        }

        const uint64_t beginUs = micros();
        if (!m_udp.beginPacket(m_gatewayIp, m_gatewayPort)) return false;
        if (m_udp.write(m_tx, requestLength) != requestLength) {
            m_udp.endPacket();
            return false;
        }
        if (!m_udp.endPacket()) return false;
        appTx += static_cast<uint32_t>(requestLength);

        const uint32_t startMs = millis();
        while (millis() - startMs < GATEWAY_TIMEOUT_MS) {
            const int packetSize = m_udp.parsePacket();
            if (packetSize <= 0) {
                delay(1);
                continue;
            }
            if (packetSize > static_cast<int>(sizeof(m_rx))) {
                while (m_udp.available()) m_udp.read();
                continue;
            }
            const int got = m_udp.read(m_rx, sizeof(m_rx));
            if (got < static_cast<int>(GATEWAY_RESPONSE_HEADER_BYTES + GATEWAY_TAG_BYTES)) continue;
            if (m_udp.remoteIP() != m_gatewayIp || m_udp.remotePort() != m_gatewayPort) continue;
            if (getU16(m_rx + 0) != GATEWAY_MAGIC || m_rx[2] != GATEWAY_VERSION) continue;
            if (m_rx[3] != static_cast<uint8_t>(op | 0x80)) continue;
            if (getU32(m_rx + 4) != requestId) continue;

            const uint16_t receivedPayloadLength = getU16(m_rx + 17);
            const size_t expectedLength = GATEWAY_RESPONSE_HEADER_BYTES +
                receivedPayloadLength + GATEWAY_TAG_BYTES;
            if (expectedLength != static_cast<size_t>(got)) continue;

            uint8_t expectedTag[HASH_BYTES];
            if (!CryptoHelpers::hmacSha256(
                    GATEWAY_HMAC_KEY,
                    sizeof(GATEWAY_HMAC_KEY),
                    m_rx,
                    GATEWAY_RESPONSE_HEADER_BYTES + receivedPayloadLength,
                    expectedTag)) {
                return false;
            }
            if (!constantTimeEqual(
                    expectedTag,
                    m_rx + GATEWAY_RESPONSE_HEADER_BYTES + receivedPayloadLength,
                    GATEWAY_TAG_BYTES)) {
                continue;
            }

            wallUs += micros() - beginUs;
            appRx += static_cast<uint32_t>(got);
            m_lastStatus = m_rx[8];
            fabricUs += getU64(m_rx + 9);
            responseLength = receivedPayloadLength;

            if (m_lastStatus != GW_OK) return false;
            if (receivedPayloadLength > responseCapacity) return false;
            if (receivedPayloadLength != 0 && responsePayload != nullptr) {
                memcpy(responsePayload, m_rx + GATEWAY_RESPONSE_HEADER_BYTES, receivedPayloadLength);
            }
            return true;
        }
    }
    return false;
}

bool FabricUdpClient::ping(uint64_t& gatewayUs)
{
    uint16_t responseLength = 0;
    uint64_t wall = 0;
    uint32_t tx = 0;
    uint32_t rx = 0;
    return transact(GW_PING, 0, nullptr, 0, nullptr, 0,
                    responseLength, gatewayUs, wall, tx, rx);
}

bool FabricUdpClient::putCredential(
    uint16_t slot,
    const FabricCredential& credential,
    uint64_t& fabricUs)
{
    serializeCredential(credential, m_recordScratch);
    uint16_t responseLength = 0;
    uint64_t wall = 0;
    uint32_t tx = 0;
    uint32_t rx = 0;
    return transact(GW_PUT_CREDENTIAL, slot, m_recordScratch, sizeof(m_recordScratch),
                    nullptr, 0, responseLength, fabricUs, wall, tx, rx);
}

bool FabricUdpClient::queryByIdentitySlot(
    const uint8_t identityHash[ID_BYTES],
    uint16_t slot,
    FabricCredential& credential,
    uint64_t& fabricUs,
    uint64_t& wallUs,
    uint32_t& appTx,
    uint32_t& appRx)
{
    uint16_t responseLength = 0;
    if (!transact(GW_QUERY_ID_SLOT, slot, identityHash, ID_BYTES,
                  m_recordScratch, sizeof(m_recordScratch), responseLength,
                  fabricUs, wallUs, appTx, appRx)) {
        return false;
    }
    return responseLength == FABRIC_RECORD_BYTES && parseCredential(m_recordScratch, credential);
}

bool FabricUdpClient::queryByTid(
    const uint8_t tid[TID_BYTES],
    FabricCredential& credential,
    uint64_t& fabricUs,
    uint64_t& wallUs,
    uint32_t& appTx,
    uint32_t& appRx)
{
    uint16_t responseLength = 0;
    if (!transact(GW_QUERY_TID, 0, tid, TID_BYTES,
                  m_recordScratch, sizeof(m_recordScratch), responseLength,
                  fabricUs, wallUs, appTx, appRx)) {
        return false;
    }
    return responseLength == FABRIC_RECORD_BYTES && parseCredential(m_recordScratch, credential);
}

uint8_t FabricUdpClient::lastStatus() const
{
    return m_lastStatus;
}

} // namespace apqe
