#pragma once

#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>

#include <wolfssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "ProtocolConstants.h"
#include "CryptoHelpers.h"
#include "PufFeProvider.h"
#include "LmotsLms.h"
#include "FragmentedUdp.h"
#include "GcsLedgerClient.h"

namespace puav {

class ProposedUavProtocol {
public:
    explicit ProposedUavProtocol(const NodeConfig& config);

    bool begin();
    void loop();

private:
    NodeConfig m_config;
    LmotsLms m_lms;
    PeerPublicRecord m_peerRecord;
    GcsLedgerClient m_gcs;
    FragmentedUdp m_transport;
    Preferences m_preferences;

    WC_RNG m_rng;
    MlKemKey m_kemKey;
    bool m_rngInitialized;
    bool m_kemInitialized;
    bool m_ready;
    bool m_initiatorCompleted;

    uint8_t m_bootSeed[HASH_BYTES];
    uint8_t m_m0[M0_BYTES];
    uint8_t m_m1[M1_BYTES];
    uint8_t m_m2[M2_MAX_BYTES];
    uint8_t m_m3[M3_MAX_BYTES];
    uint8_t m_m4[M4_BYTES];
    uint8_t m_mu[MU_A_BYTES];
    uint8_t m_signInput[LMOTS_SIGNED_OBJECT_BYTES];
    uint8_t m_result[128];

    bool connectWiFi();
    bool prepareLmsAndLedger();
    bool initializePersistentCounter();
    bool reserveQ(uint32_t& q);
    bool validatePeerRecord(uint32_t version) const;
    void printMemory(const char* label);
    void printId(const char* label, const uint8_t id[ID_BYTES]);

    void runInitiatorExperiments();
    bool runInitiatorSession(uint32_t runNumber);
    void runResponderOnce();

    bool sendProtocolMessage(
        const IPAddress& destination,
        uint16_t destinationPort,
        uint8_t type,
        uint32_t session,
        const uint8_t* data,
        uint16_t length,
        LocalMetrics& metrics,
        bool countAsProtocol);

    bool receiveProtocolMessage(
        uint8_t expectedType,
        uint32_t expectedSession,
        uint8_t* data,
        uint16_t capacity,
        uint16_t expectedLength,
        ReceivedPacket& packet,
        LocalMetrics& metrics,
        bool countAsProtocol);

    bool buildM0(uint8_t nonceA[NONCE_BYTES]);
    bool validateM0(const uint8_t nonceA[NONCE_BYTES]) const;

    bool buildM1(
        const uint8_t nonceA[NONCE_BYTES],
        uint8_t nonceB[NONCE_BYTES]);

    bool validateM1(
        const uint8_t nonceA[NONCE_BYTES],
        uint8_t nonceB[NONCE_BYTES]) const;

    bool computeSid0(
        uint8_t sid[HASH_BYTES],
        LocalMetrics& metrics);

    void buildM2SignedInput(
        const uint8_t sid[HASH_BYTES],
        uint32_t version,
        uint32_t q,
        const uint8_t publicKey[MLKEM_PUBLIC_KEY_BYTES]);

    void buildM3SignedInput(
        const uint8_t sid[HASH_BYTES],
        const uint8_t hashM2[HASH_BYTES],
        uint32_t version,
        uint32_t q,
        const uint8_t ciphertext[MLKEM_CIPHERTEXT_BYTES]);

    bool timedSha(
        const uint8_t* data,
        size_t length,
        uint8_t output[HASH_BYTES],
        LocalMetrics& metrics);

    bool timedTranscriptHash(
        const uint8_t sid[HASH_BYTES],
        size_t m2Length,
        const uint8_t* m3Inner,
        size_t m3InnerLength,
        uint8_t output[HASH_BYTES],
        LocalMetrics& metrics);

    bool timedHmac(
        const uint8_t* key,
        size_t keyLength,
        const uint8_t* data,
        size_t dataLength,
        uint8_t output[HMAC_BYTES],
        LocalMetrics& metrics);

    bool timedHkdf(
        const uint8_t* ikm,
        size_t ikmLength,
        const uint8_t* salt,
        size_t saltLength,
        const uint8_t* info,
        size_t infoLength,
        uint8_t* output,
        size_t outputLength,
        LocalMetrics& metrics);

    bool timedRuntimeSeed(
        uint8_t output[HASH_BYTES],
        LocalMetrics& metrics);

    bool deriveSessionKeys(
        const uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES],
        const uint8_t transcriptHash[HASH_BYTES],
        uint8_t sessionKey[HASH_BYTES],
        uint8_t confirmA[HASH_BYTES],
        uint8_t confirmB[HASH_BYTES],
        LocalMetrics& metrics);

    bool computeConfirmationTag(
        uint8_t domain,
        const uint8_t confirmationKey[HASH_BYTES],
        const uint8_t transcriptHash[HASH_BYTES],
        uint8_t output[HMAC_BYTES],
        LocalMetrics& metrics);

    bool obtainPeerPath(
        uint32_t version,
        uint32_t q,
        const uint8_t* carriedPath,
        uint8_t outputPath[LMS_PATH_BYTES],
        LocalMetrics& metrics);

    bool initializeKem();
    void freeKem();

    void wipeSessionSecrets(
        uint8_t runtimeSeed[HASH_BYTES],
        uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES],
        uint8_t sessionKey[HASH_BYTES],
        uint8_t confirmA[HASH_BYTES],
        uint8_t confirmB[HASH_BYTES]);

    void finalizeMetrics(LocalMetrics& metrics);
    void printInitiatorResult(
        uint32_t runNumber,
        uint32_t qA,
        uint32_t qB,
        uint64_t confirmedE2eUs,
        const LocalMetrics& initiator,
        const uint8_t* responderResult,
        size_t responderResultLength);
};

} // namespace puav
