#include "FragmentedUdp.h"

namespace puav {

FragmentedUdp::FragmentedUdp()
    : m_localPort(0)
{
    memset(m_fragmentBuffer, 0, sizeof(m_fragmentBuffer));
}

bool FragmentedUdp::begin(uint16_t localPort)
{
    m_localPort = localPort;
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
    if (data == nullptr || length == 0 ||
        length > MAX_PROTOCOL_MESSAGE_BYTES) {
        return false;
    }

    const uint8_t fragmentCount =
        static_cast<uint8_t>(
            (length + FRAGMENT_PAYLOAD_BYTES - 1) /
            FRAGMENT_PAYLOAD_BYTES);

    if (fragmentCount == 0 || fragmentCount > MAX_FRAGMENTS) {
        return false;
    }

    framedBytes = 0;

    for (uint8_t fragmentIndex = 0;
         fragmentIndex < fragmentCount;
         ++fragmentIndex) {
        const size_t sourceOffset =
            static_cast<size_t>(fragmentIndex) *
            FRAGMENT_PAYLOAD_BYTES;

        const uint16_t payloadLength =
            static_cast<uint16_t>(
                min(
                    static_cast<size_t>(
                        FRAGMENT_PAYLOAD_BYTES),
                    static_cast<size_t>(length) -
                        sourceOffset));

        uint8_t* header = m_fragmentBuffer;

        putU16(header + 0, FRAGMENT_MAGIC);
        header[2] = PROTOCOL_VERSION;
        header[3] = type;
        putU32(header + 4, session);
        putU16(header + 8, length);
        header[10] = fragmentIndex;
        header[11] = fragmentCount;
        putU16(header + 12, payloadLength);

        memcpy(
            m_fragmentBuffer + FRAGMENT_HEADER_BYTES,
            data + sourceOffset,
            payloadLength);

        if (!m_udp.beginPacket(destination, destinationPort)) {
            return false;
        }

        const size_t datagramLength =
            FRAGMENT_HEADER_BYTES + payloadLength;

        const size_t written = m_udp.write(
            m_fragmentBuffer,
            datagramLength);

        if (written != datagramLength) {
            m_udp.endPacket();
            return false;
        }

        if (!m_udp.endPacket()) {
            return false;
        }

        framedBytes += static_cast<uint32_t>(datagramLength);
        delay(1);
    }

    return true;
}

bool FragmentedUdp::readOneDatagram(
    uint8_t& type,
    uint32_t& session,
    uint16_t& totalLength,
    uint8_t& fragmentIndex,
    uint8_t& fragmentCount,
    uint16_t& payloadLength,
    IPAddress& sourceIp,
    uint16_t& sourcePort,
    uint32_t& datagramBytes)
{
    const int packetSize = m_udp.parsePacket();

    if (packetSize <= 0) {
        return false;
    }

    if (packetSize >
        static_cast<int>(sizeof(m_fragmentBuffer))) {
        while (m_udp.available()) {
            m_udp.read();
        }
        return false;
    }

    const int readLength = m_udp.read(
        m_fragmentBuffer,
        sizeof(m_fragmentBuffer));

    if (readLength < static_cast<int>(FRAGMENT_HEADER_BYTES)) {
        return false;
    }

    if (getU16(m_fragmentBuffer + 0) != FRAGMENT_MAGIC ||
        m_fragmentBuffer[2] != PROTOCOL_VERSION) {
        return false;
    }

    type = m_fragmentBuffer[3];
    session = getU32(m_fragmentBuffer + 4);
    totalLength = getU16(m_fragmentBuffer + 8);
    fragmentIndex = m_fragmentBuffer[10];
    fragmentCount = m_fragmentBuffer[11];
    payloadLength = getU16(m_fragmentBuffer + 12);

    if (fragmentCount == 0 ||
        fragmentCount > MAX_FRAGMENTS ||
        fragmentIndex >= fragmentCount ||
        payloadLength > FRAGMENT_PAYLOAD_BYTES ||
        FRAGMENT_HEADER_BYTES + payloadLength !=
            static_cast<size_t>(readLength) ||
        totalLength > MAX_PROTOCOL_MESSAGE_BYTES) {
        return false;
    }

    sourceIp = m_udp.remoteIP();
    sourcePort = m_udp.remotePort();
    datagramBytes = static_cast<uint32_t>(readLength);
    return true;
}

bool FragmentedUdp::receiveMessage(
    uint8_t expectedType,
    uint32_t expectedSession,
    uint8_t* output,
    uint16_t outputCapacity,
    uint32_t timeoutMs,
    ReceivedPacket& received)
{
    if (output == nullptr) {
        return false;
    }

    bool receivedFragments[MAX_FRAGMENTS] = {false};
    uint8_t activeType = 0;
    uint32_t activeSession = 0;
    uint16_t activeLength = 0;
    uint8_t activeCount = 0;
    uint8_t completed = 0;
    bool active = false;
    uint32_t framedBytes = 0;
    IPAddress activeIp;
    uint16_t activePort = 0;

    const uint32_t startMs = millis();

    while (millis() - startMs < timeoutMs) {
        uint8_t type = 0;
        uint32_t session = 0;
        uint16_t totalLength = 0;
        uint8_t fragmentIndex = 0;
        uint8_t fragmentCount = 0;
        uint16_t payloadLength = 0;
        IPAddress sourceIp;
        uint16_t sourcePort = 0;
        uint32_t datagramBytes = 0;

        if (!readOneDatagram(
                type,
                session,
                totalLength,
                fragmentIndex,
                fragmentCount,
                payloadLength,
                sourceIp,
                sourcePort,
                datagramBytes)) {
            delay(1);
            continue;
        }

        if (expectedType != 0xff && type != expectedType) {
            continue;
        }

        if (expectedSession != 0 &&
            session != expectedSession) {
            continue;
        }

        if (!active) {
            if (totalLength > outputCapacity) {
                continue;
            }

            active = true;
            activeType = type;
            activeSession = session;
            activeLength = totalLength;
            activeCount = fragmentCount;
            activeIp = sourceIp;
            activePort = sourcePort;
            framedBytes = 0;
        }

        if (type != activeType ||
            session != activeSession ||
            totalLength != activeLength ||
            fragmentCount != activeCount ||
            sourceIp != activeIp ||
            sourcePort != activePort) {
            continue;
        }

        const size_t outputOffset =
            static_cast<size_t>(fragmentIndex) *
            FRAGMENT_PAYLOAD_BYTES;

        if (outputOffset + payloadLength > activeLength) {
            continue;
        }

        if (!receivedFragments[fragmentIndex]) {
            memcpy(
                output + outputOffset,
                m_fragmentBuffer + FRAGMENT_HEADER_BYTES,
                payloadLength);

            receivedFragments[fragmentIndex] = true;
            ++completed;
            framedBytes += datagramBytes;
        }

        if (completed == activeCount) {
            received.type = activeType;
            received.session = activeSession;
            received.length = activeLength;
            received.sourceIp = activeIp;
            received.sourcePort = activePort;
            received.framedBytes = framedBytes;
            return true;
        }
    }

    return false;
}

void FragmentedUdp::discardPending()
{
    while (m_udp.parsePacket() > 0) {
        while (m_udp.available()) {
            m_udp.read();
        }
    }
}

} // namespace puav
