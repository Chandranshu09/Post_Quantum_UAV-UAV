#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>

#include "ApqeConstants.h"

namespace apqe {

struct ReceivedMessage {
    uint8_t type = 0;
    uint32_t session = 0;
    uint16_t length = 0;
    IPAddress sourceIp;
    uint16_t sourcePort = 0;
    uint32_t framedBytes = 0;
};

class FragmentedUdp {
public:
    bool begin(uint16_t localPort);
    bool sendMessage(
        const IPAddress& destination,
        uint16_t destinationPort,
        uint8_t type,
        uint32_t session,
        const uint8_t* data,
        uint16_t length,
        uint32_t& framedBytes);
    bool receiveMessage(
        uint8_t expectedType,
        uint32_t expectedSession,
        uint8_t* output,
        uint16_t outputCapacity,
        uint32_t timeoutMs,
        ReceivedMessage& received);
    void discardPending();

private:
    WiFiUDP m_udp;
    uint8_t m_buffer[FRAGMENT_HEADER_BYTES + FRAGMENT_PAYLOAD_BYTES];
};

} // namespace apqe
