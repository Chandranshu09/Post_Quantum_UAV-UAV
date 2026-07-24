#include "FragmentedUdp.h"

namespace apqe {

bool FragmentedUdp::begin(uint16_t localPort)
{
    return m_udp.begin(localPort) == 1;
}

bool FragmentedUdp::sendMessage(
    const IPAddress& destination,
    uint16_t destinationPort,
    uint8_t type,
    uint32_t session,
    const uint8_t* data,
    uint16_t length,
    uint32_t& framedBytes)
{
    if (data == nullptr || length == 0 || length > MAX_PROTOCOL_MESSAGE_BYTES) {
        return false;
    }
    const uint8_t fragmentCount = static_cast<uint8_t>(
        (length + FRAGMENT_PAYLOAD_BYTES - 1) / FRAGMENT_PAYLOAD_BYTES);
    if (fragmentCount == 0 || fragmentCount > MAX_FRAGMENTS) {
        return false;
    }

    framedBytes = 0;
    for (uint8_t index = 0; index < fragmentCount; ++index) {
        const size_t offset = static_cast<size_t>(index) * FRAGMENT_PAYLOAD_BYTES;
        const uint16_t payloadLength = static_cast<uint16_t>(
            min(static_cast<size_t>(FRAGMENT_PAYLOAD_BYTES),
                static_cast<size_t>(length) - offset));

        putU16(m_buffer + 0, FRAGMENT_MAGIC);
        m_buffer[2] = PROTOCOL_VERSION;
        m_buffer[3] = type;
        putU32(m_buffer + 4, session);
        putU16(m_buffer + 8, length);
        m_buffer[10] = index;
        m_buffer[11] = fragmentCount;
        putU16(m_buffer + 12, payloadLength);
        memcpy(m_buffer + FRAGMENT_HEADER_BYTES, data + offset, payloadLength);

        const size_t datagramLength = FRAGMENT_HEADER_BYTES + payloadLength;
        if (!m_udp.beginPacket(destination, destinationPort)) {
            return false;
        }
        if (m_udp.write(m_buffer, datagramLength) != datagramLength) {
            m_udp.endPacket();
            return false;
        }
        if (!m_udp.endPacket()) {
            return false;
        }
        framedBytes += static_cast<uint32_t>(datagramLength);
        delay(2);
    }
    return true;
}

bool FragmentedUdp::receiveMessage(
    uint8_t expectedType,
    uint32_t expectedSession,
    uint8_t* output,
    uint16_t outputCapacity,
    uint32_t timeoutMs,
    ReceivedMessage& received)
{
    bool seen[MAX_FRAGMENTS] = {false};
    bool active = false;
    uint8_t activeType = 0;
    uint32_t activeSession = 0;
    uint16_t activeLength = 0;
    uint8_t activeCount = 0;
    uint8_t complete = 0;
    uint32_t framed = 0;
    IPAddress activeIp;
    uint16_t activePort = 0;

    const uint32_t start = millis();
    while (millis() - start < timeoutMs) {
        const int packetSize = m_udp.parsePacket();
        if (packetSize <= 0) {
            delay(1);
            continue;
        }
        if (packetSize > static_cast<int>(sizeof(m_buffer))) {
            while (m_udp.available()) m_udp.read();
            continue;
        }
        const int got = m_udp.read(m_buffer, sizeof(m_buffer));
        if (got < static_cast<int>(FRAGMENT_HEADER_BYTES)) continue;
        if (getU16(m_buffer) != FRAGMENT_MAGIC || m_buffer[2] != PROTOCOL_VERSION) continue;

        const uint8_t type = m_buffer[3];
        const uint32_t session = getU32(m_buffer + 4);
        const uint16_t totalLength = getU16(m_buffer + 8);
        const uint8_t index = m_buffer[10];
        const uint8_t count = m_buffer[11];
        const uint16_t payloadLength = getU16(m_buffer + 12);
        const IPAddress sourceIp = m_udp.remoteIP();
        const uint16_t sourcePort = m_udp.remotePort();

        if (expectedType != 0xff && type != expectedType) continue;
        if (expectedSession != 0 && session != expectedSession) continue;
        if (count == 0 || count > MAX_FRAGMENTS || index >= count ||
            payloadLength > FRAGMENT_PAYLOAD_BYTES ||
            FRAGMENT_HEADER_BYTES + payloadLength != static_cast<size_t>(got) ||
            totalLength > outputCapacity) continue;

        if (!active) {
            active = true;
            activeType = type;
            activeSession = session;
            activeLength = totalLength;
            activeCount = count;
            activeIp = sourceIp;
            activePort = sourcePort;
        }
        if (type != activeType || session != activeSession ||
            totalLength != activeLength || count != activeCount ||
            sourceIp != activeIp || sourcePort != activePort) continue;

        const size_t offset = static_cast<size_t>(index) * FRAGMENT_PAYLOAD_BYTES;
        if (offset + payloadLength > activeLength) continue;
        if (!seen[index]) {
            memcpy(output + offset, m_buffer + FRAGMENT_HEADER_BYTES, payloadLength);
            seen[index] = true;
            ++complete;
            framed += static_cast<uint32_t>(got);
        }
        if (complete == activeCount) {
            received.type = activeType;
            received.session = activeSession;
            received.length = activeLength;
            received.sourceIp = activeIp;
            received.sourcePort = activePort;
            received.framedBytes = framed;
            return true;
        }
    }
    return false;
}

void FragmentedUdp::discardPending()
{
    while (m_udp.parsePacket() > 0) {
        while (m_udp.available()) m_udp.read();
    }
}

} // namespace apqe
