#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>

#include "ApqeConstants.h"

namespace apqe {

class FabricUdpClient {
public:
    FabricUdpClient();

    bool begin(const IPAddress& gatewayIp, uint16_t gatewayPort, uint16_t localPort);
    bool ping(uint64_t& gatewayUs);
    bool putCredential(uint16_t slot, const FabricCredential& credential, uint64_t& fabricUs);
    bool queryByIdentitySlot(
        const uint8_t identityHash[ID_BYTES],
        uint16_t slot,
        FabricCredential& credential,
        uint64_t& fabricUs,
        uint64_t& wallUs,
        uint32_t& appTx,
        uint32_t& appRx);
    bool queryByTid(
        const uint8_t tid[TID_BYTES],
        FabricCredential& credential,
        uint64_t& fabricUs,
        uint64_t& wallUs,
        uint32_t& appTx,
        uint32_t& appRx);
    uint8_t lastStatus() const;

private:
    WiFiUDP m_udp;
    IPAddress m_gatewayIp;
    uint16_t m_gatewayPort;
    uint32_t m_nextRequestId;
    uint8_t m_lastStatus;
    uint8_t m_tx[GATEWAY_MAX_REQUEST_BYTES];
    uint8_t m_rx[GATEWAY_MAX_RESPONSE_BYTES];
    uint8_t m_recordScratch[FABRIC_RECORD_BYTES];

    bool transact(
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
        uint32_t& appRx);
    static void serializeCredential(const FabricCredential& credential, uint8_t out[FABRIC_RECORD_BYTES]);
    static bool parseCredential(const uint8_t in[FABRIC_RECORD_BYTES], FabricCredential& credential);
};

} // namespace apqe
