#pragma once

#include <Arduino.h>

#include "ApqeConstants.h"
#include "FabricUdpClient.h"
#include "FragmentedUdp.h"
#include "SoftwarePuf.h"

namespace apqe {

class ApqeProtocol {
public:
    explicit ApqeProtocol(const NodeConfig& config);
    bool begin();
    void loop();

private:
    NodeConfig m_config;
    SoftwarePuf m_puf;
    FabricUdpClient m_fabric;
    FragmentedUdp m_direct;
    uint8_t m_identityHash[ID_BYTES];
    uint8_t m_peerIdentityHash[ID_BYTES];
    uint8_t m_publicKey[KYBER_PUBLIC_KEY_BYTES];
    uint8_t m_secretKey[KYBER_SECRET_KEY_BYTES];
    uint8_t m_m1[M1_BYTES];
    uint8_t m_m2[M2_BYTES];
    uint8_t m_m3[M3_BYTES];
    uint8_t m_result[RESULT_BYTES];
    FabricCredential m_runtimeOwnCredential;
    FabricCredential m_runtimePeerCredential;
    bool m_initialized;
    bool m_completed;

    bool connectWifi();
    bool enrollCredentials();
    bool deriveChallenge(uint16_t slot, uint8_t challenge[CHALLENGE_BYTES]);
    bool buildCredential(uint16_t slot, FabricCredential& credential);
    bool verifyCredential(const FabricCredential& credential, SessionMetrics* metrics = nullptr);
    bool timedShaParts(
        SessionMetrics& metrics,
        const uint8_t* const* parts,
        const size_t* lengths,
        size_t count,
        uint8_t out[HASH_BYTES]);
    bool timedReconstruct(SessionMetrics& metrics, uint8_t seed[HASH_BYTES]);
    bool timedKeygen(SessionMetrics& metrics, const uint8_t seed[HASH_BYTES]);
    void timedPufMap(SessionMetrics& metrics, const uint8_t input[PUF_BYTES], uint8_t output[PUF_BYTES]);
    bool timedPufInverse(SessionMetrics& metrics, const uint8_t tid[TID_BYTES], uint8_t challenge[CHALLENGE_BYTES]);
    bool runInitiatorSession(uint32_t session, uint16_t slot);
    bool runResponderSession(uint32_t session, const ReceivedMessage& incoming);
    void responderLoop();
    void printMemory(const char* label) const;
    void printSessionResult(
        uint32_t session,
        uint16_t slot,
        const SessionMetrics& a,
        const SessionMetrics& b,
        uint64_t bProtocolUs) const;
    static void xorBytes(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t length);
    static void maskPair(
        const uint8_t key[HASH_BYTES],
        const uint8_t first[HASH_BYTES],
        const uint8_t second[HASH_BYTES],
        uint8_t output[PJ_BYTES]);
    static void unmaskPair(
        const uint8_t key[HASH_BYTES],
        const uint8_t input[PJ_BYTES],
        uint8_t first[HASH_BYTES],
        uint8_t second[HASH_BYTES]);
    static void encodeResult(
        uint32_t session,
        uint64_t protocolUs,
        const SessionMetrics& metrics,
        const uint8_t sessionKeyHash[HASH_BYTES],
        uint8_t output[RESULT_BYTES]);
    static bool decodeResult(
        const uint8_t input[RESULT_BYTES],
        uint32_t expectedSession,
        uint64_t& protocolUs,
        SessionMetrics& metrics,
        uint8_t sessionKeyHash[HASH_BYTES]);
};

} // namespace apqe
