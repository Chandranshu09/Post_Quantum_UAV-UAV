#include "ApqeProtocol.h"

#include <WiFi.h>
#include <esp_heap_caps.h>

#include "CryptoHelpers.h"
#include "KyberCpaWrapper.h"

namespace apqe {

ApqeProtocol::ApqeProtocol(const NodeConfig& config)
    : m_config(config), m_initialized(false), m_completed(false)
{
    memset(m_identityHash, 0, sizeof(m_identityHash));
    memset(m_peerIdentityHash, 0, sizeof(m_peerIdentityHash));
    memset(m_publicKey, 0, sizeof(m_publicKey));
    memset(m_secretKey, 0, sizeof(m_secretKey));
    memset(m_m1, 0, sizeof(m_m1));
    memset(m_m2, 0, sizeof(m_m2));
    memset(m_m3, 0, sizeof(m_m3));
    memset(m_result, 0, sizeof(m_result));
    memset(&m_runtimeOwnCredential, 0, sizeof(m_runtimeOwnCredential));
    memset(&m_runtimePeerCredential, 0, sizeof(m_runtimePeerCredential));
}

bool ApqeProtocol::connectWifi()
{
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(m_config.wifiSsid, m_config.wifiPassword);
    Serial.print("Connecting to Wi-Fi");
    const uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 30000) {
        Serial.print('.');
        delay(500);
    }
    Serial.println();
    if (WiFi.status() != WL_CONNECTED) return false;
    Serial.print("Connected, IP: ");
    Serial.println(WiFi.localIP());
    Serial.print("RSSI: ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
    return true;
}

void ApqeProtocol::printMemory(const char* label) const
{
    Serial.println();
    Serial.print("----- "); Serial.print(label); Serial.println(" -----");
    Serial.printf("ESP free heap:          %u bytes\n", ESP.getFreeHeap());
    Serial.printf("ESP minimum free heap:  %u bytes\n", ESP.getMinFreeHeap());
    Serial.printf("Free 8-bit heap:        %u bytes\n", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    Serial.printf("Minimum 8-bit heap:     %u bytes\n", heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT));
    Serial.printf("Largest 8-bit block:    %u bytes\n", heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    Serial.printf("Loop-task stack reserve:%u bytes\n", uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t));
}

bool ApqeProtocol::deriveChallenge(uint16_t slot, uint8_t challenge[CHALLENGE_BYTES])
{
    static const uint8_t label[] = {'A','P','Q','E','-','C','H','A','L'};
    uint8_t slotBytes[2];
    putU16(slotBytes, slot);
    const uint8_t* parts[] = {label, m_config.deviceId, slotBytes};
    const size_t lengths[] = {sizeof(label), ID_BYTES, sizeof(slotBytes)};
    return CryptoHelpers::sha256Parts(parts, lengths, 3, challenge);
}

bool ApqeProtocol::buildCredential(uint16_t slot, FabricCredential& credential)
{
    uint8_t challenge[CHALLENGE_BYTES];
    uint8_t response[PUF_BYTES];
    uint8_t challengeHash[HASH_BYTES];
    if (!deriveChallenge(slot, challenge)) return false;
    if (!m_puf.reversibleMap(m_secretKey, challenge, credential.tid)) return false;
    m_puf.commutativeMap(challenge, response);
    if (!CryptoHelpers::sha256(challenge, sizeof(challenge), challengeHash)) return false;
    xorBytes(response, challengeHash, credential.w, PUF_BYTES);
    memcpy(credential.identityHash, m_identityHash, ID_BYTES);
    memcpy(credential.publicKey, m_publicKey, KYBER_PUBLIC_KEY_BYTES);

    const uint8_t* parts[] = {
        credential.identityHash,
        credential.w,
        credential.publicKey
    };
    const size_t lengths[] = {ID_BYTES, PUF_BYTES, KYBER_PUBLIC_KEY_BYTES};
    return CryptoHelpers::sha256Parts(parts, lengths, 3, credential.verifyHash);
}

bool ApqeProtocol::verifyCredential(
    const FabricCredential& credential,
    SessionMetrics* metrics)
{
    uint8_t expected[HASH_BYTES];
    const uint8_t* parts[] = {
        credential.identityHash,
        credential.w,
        credential.publicKey
    };
    const size_t lengths[] = {ID_BYTES, PUF_BYTES, KYBER_PUBLIC_KEY_BYTES};
    bool ok = false;
    if (metrics != nullptr) {
        ok = timedShaParts(*metrics, parts, lengths, 3, expected);
    } else {
        ok = CryptoHelpers::sha256Parts(parts, lengths, 3, expected);
    }
    return ok && constantTimeEqual(expected, credential.verifyHash, HASH_BYTES);
}

bool ApqeProtocol::enrollCredentials()
{
    uint8_t seed[HASH_BYTES];
    if (!m_puf.reconstructKyberSeed(seed)) return false;
    if (!KyberCpaWrapper::keypairDeterministic(seed, m_publicKey, m_secretKey)) return false;

    Serial.print("Enrolling ");
    Serial.print(m_config.numberOfSessions);
    Serial.println(" APQE credential records with Fabric...");
    for (uint16_t slot = 0; slot < m_config.numberOfSessions; ++slot) {
        FabricCredential credential;
        if (!buildCredential(slot, credential)) return false;
        uint64_t fabricUs = 0;
        if (!m_fabric.putCredential(slot, credential, fabricUs)) {
            Serial.printf("Fabric enrollment failed at slot=%u, status=%u\n",
                          slot, m_fabric.lastStatus());
            return false;
        }
        Serial.printf("  slot %u enrolled/confirmed, Fabric %.3f ms\n",
                      slot, fabricUs / 1000.0);
    }
    return true;
}

bool ApqeProtocol::begin()
{
    Serial.println();
    Serial.println("Complete APQE-CDA runnable literal-256 implementation");
    Serial.print("Role: ");
    Serial.println(m_config.role == Role::Initiator ? "UAV_A / initiator" : "UAV_B / responder");
    Serial.printf("CPU: %u MHz, flash: %u bytes, PSRAM: %u bytes\n",
                  ESP.getCpuFreqMHz(), ESP.getFlashChipSize(), ESP.getPsramSize());
    Serial.printf("Direct application bytes/session: %u\n", DIRECT_APPLICATION_BYTES);
    Serial.println("PUF and fuzzy reconstruction are software emulations, not physical PUF measurements.");
    printMemory("At protocol startup");

    if (!m_puf.begin(
            m_config.emulatedSramRaw,
            m_config.emulatedSramHelper,
            m_config.emulatedBsPufSecret)) {
        return false;
    }
    if (!CryptoHelpers::sha256(m_config.deviceId, ID_BYTES, m_identityHash) ||
        !CryptoHelpers::sha256(m_config.peerId, ID_BYTES, m_peerIdentityHash)) {
        return false;
    }
    if (!connectWifi()) return false;
    if (!m_fabric.begin(m_config.gatewayIp, m_config.gatewayPort, m_config.gatewayLocalPort)) return false;
    if (!m_direct.begin(m_config.protocolPort)) return false;

    uint64_t pingUs = 0;
    if (!m_fabric.ping(pingUs)) {
        Serial.println("Fabric gateway ping failed.");
        return false;
    }
    Serial.printf("Fabric gateway ping accepted, backend time %.3f ms\n", pingUs / 1000.0);

    if (!enrollCredentials()) return false;
    printMemory("After APQE enrollment");
    m_initialized = true;

    if (m_config.role == Role::Responder) {
        Serial.println("Responder is ready and waiting for M1.");
    } else {
        Serial.println("Initiator will start sessions in two seconds.");
        delay(2000);
    }
    return true;
}

bool ApqeProtocol::timedShaParts(
    SessionMetrics& metrics,
    const uint8_t* const* parts,
    const size_t* lengths,
    size_t count,
    uint8_t out[HASH_BYTES])
{
    const uint64_t start = micros();
    const bool ok = CryptoHelpers::sha256Parts(parts, lengths, count, out);
    metrics.shaUs += micros() - start;
    return ok;
}

bool ApqeProtocol::timedReconstruct(SessionMetrics& metrics, uint8_t seed[HASH_BYTES])
{
    const uint64_t start = micros();
    const bool ok = m_puf.reconstructKyberSeed(seed);
    metrics.fuzzyReconstructionUs += micros() - start;
    return ok;
}

bool ApqeProtocol::timedKeygen(SessionMetrics& metrics, const uint8_t seed[HASH_BYTES])
{
    const uint64_t start = micros();
    const bool ok = KyberCpaWrapper::keypairDeterministic(seed, m_publicKey, m_secretKey);
    metrics.kyberKeygenUs += micros() - start;
    return ok;
}

void ApqeProtocol::timedPufMap(
    SessionMetrics& metrics,
    const uint8_t input[PUF_BYTES],
    uint8_t output[PUF_BYTES])
{
    const uint64_t start = micros();
    m_puf.commutativeMap(input, output);
    metrics.pufUs += micros() - start;
}

bool ApqeProtocol::timedPufInverse(
    SessionMetrics& metrics,
    const uint8_t tid[TID_BYTES],
    uint8_t challenge[CHALLENGE_BYTES])
{
    const uint64_t start = micros();
    const bool ok = m_puf.reversibleInverse(m_secretKey, tid, challenge);
    metrics.pufUs += micros() - start;
    return ok;
}

void ApqeProtocol::xorBytes(
    const uint8_t* a,
    const uint8_t* b,
    uint8_t* out,
    size_t length)
{
    for (size_t i = 0; i < length; ++i) out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
}

void ApqeProtocol::maskPair(
    const uint8_t key[HASH_BYTES],
    const uint8_t first[HASH_BYTES],
    const uint8_t second[HASH_BYTES],
    uint8_t output[PJ_BYTES])
{
    xorBytes(first, key, output, HASH_BYTES);
    xorBytes(second, key, output + HASH_BYTES, HASH_BYTES);
}

void ApqeProtocol::unmaskPair(
    const uint8_t key[HASH_BYTES],
    const uint8_t input[PJ_BYTES],
    uint8_t first[HASH_BYTES],
    uint8_t second[HASH_BYTES])
{
    xorBytes(input, key, first, HASH_BYTES);
    xorBytes(input + HASH_BYTES, key, second, HASH_BYTES);
}

bool ApqeProtocol::runInitiatorSession(uint32_t session, uint16_t slot)
{
    SessionMetrics a;
    const uint64_t protocolStart = micros();

    uint8_t seed[HASH_BYTES];
    if (!timedReconstruct(a, seed) || !timedKeygen(a, seed)) return false;

    if (!m_fabric.queryByIdentitySlot(
            m_identityHash, slot, m_runtimeOwnCredential,
            a.fabricPeerUs, a.fabricWallUs,
            a.gatewayAppTx, a.gatewayAppRx)) {
        Serial.printf("Own Fabric query failed, slot=%u status=%u\n", slot, m_fabric.lastStatus());
        return false;
    }
    if (!m_fabric.queryByIdentitySlot(
            m_peerIdentityHash, slot, m_runtimePeerCredential,
            a.fabricPeerUs, a.fabricWallUs,
            a.gatewayAppTx, a.gatewayAppRx)) {
        Serial.printf("Peer Fabric query failed, slot=%u status=%u\n", slot, m_fabric.lastStatus());
        return false;
    }
    if (!constantTimeEqual(m_runtimeOwnCredential.identityHash, m_identityHash, ID_BYTES) ||
        !constantTimeEqual(m_runtimePeerCredential.identityHash, m_peerIdentityHash, ID_BYTES) ||
        !verifyCredential(m_runtimeOwnCredential, &a) || !verifyCredential(m_runtimePeerCredential, &a) ||
        !constantTimeEqual(m_runtimeOwnCredential.publicKey, m_publicKey, KYBER_PUBLIC_KEY_BYTES)) {
        Serial.println("Fabric credential verification failed.");
        return false;
    }

    uint8_t ci[CHALLENGE_BYTES];
    uint8_t ni[NONCE_BYTES];
    if (!timedPufInverse(a, m_runtimeOwnCredential.tid, ci)) return false;
    CryptoHelpers::randomBytes(ni, sizeof(ni));

    uint8_t ei[EI_BYTES];
    memcpy(ei + 0, m_runtimeOwnCredential.tid, TID_BYTES);
    memcpy(ei + 32, ci, CHALLENGE_BYTES);
    memcpy(ei + 64, ni, NONCE_BYTES);
    memcpy(ei + 96, m_runtimePeerCredential.tid, TID_BYTES);

    for (size_t block = 0; block < EI_BLOCKS; ++block) {
        uint8_t coins[KYBER_COINS_BYTES];
        CryptoHelpers::randomBytes(coins, sizeof(coins));
        const uint64_t start = micros();
        const bool ok = KyberCpaWrapper::encrypt(
            ei + block * KYBER_MESSAGE_BYTES,
            m_runtimePeerCredential.publicKey,
            coins,
            m_m1 + block * KYBER_CIPHERTEXT_BYTES);
        a.kyberEncryptUs += micros() - start;
        if (!ok) return false;
    }
    const uint8_t* h1Parts[] = {ei};
    const size_t h1Lengths[] = {sizeof(ei)};
    if (!timedShaParts(a, h1Parts, h1Lengths, 1,
                       m_m1 + EI_BLOCKS * KYBER_CIPHERTEXT_BYTES)) return false;

    uint32_t framed = 0;
    if (!m_direct.sendMessage(
            m_config.responderIp, m_config.protocolPort,
            MSG_M1, session, m_m1, M1_BYTES, framed)) return false;
    a.directAppTx += M1_BYTES;
    a.directFramedTx += framed;

    ReceivedMessage received;
    if (!m_direct.receiveMessage(
            MSG_M2, session, m_m2, sizeof(m_m2),
            DIRECT_RECEIVE_TIMEOUT_MS, received) || received.length != M2_BYTES) {
        Serial.println("M2 receive failed.");
        return false;
    }
    a.directAppRx += M2_BYTES;
    a.directFramedRx += received.framedBytes;

    uint8_t tkJ[HASH_BYTES];
    uint8_t tkJi[HASH_BYTES];
    uint8_t cj[CHALLENGE_BYTES];
    uint8_t nj[NONCE_BYTES];
    xorBytes(m_m2, ni, tkJ, HASH_BYTES);
    timedPufMap(a, tkJ, tkJi);
    unmaskPair(tkJi, m_m2 + HASH_BYTES, cj, nj);

    uint8_t expectedH2[HASH_BYTES];
    const uint8_t* h2Parts[] = {tkJi, tkJ, cj, nj};
    const size_t h2Lengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(a, h2Parts, h2Lengths, 4, expectedH2) ||
        !constantTimeEqual(expectedH2, m_m2 + HASH_BYTES + PJ_BYTES, HASH_BYTES)) {
        Serial.println("H2 verification failed.");
        return false;
    }

    uint8_t cjHash[HASH_BYTES];
    const uint8_t* cjParts[] = {cj};
    const size_t cjLengths[] = {HASH_BYTES};
    if (!timedShaParts(a, cjParts, cjLengths, 1, cjHash)) return false;
    uint8_t rj[HASH_BYTES];
    xorBytes(m_runtimePeerCredential.w, cjHash, rj, HASH_BYTES);

    uint8_t tkI[HASH_BYTES];
    uint8_t tkIj[HASH_BYTES];
    timedPufMap(a, cj, tkI);
    timedPufMap(a, rj, tkIj);
    xorBytes(tkI, nj, m_m3, HASH_BYTES); // TNi

    uint8_t sessionKey[HASH_BYTES];
    const uint8_t* skParts[] = {tkJi, tkIj, ni, nj};
    const size_t skLengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(a, skParts, skLengths, 4, sessionKey)) return false;

    const uint8_t* h3Parts[] = {tkIj, tkI, sessionKey};
    const size_t h3Lengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(a, h3Parts, h3Lengths, 3, m_m3 + HASH_BYTES)) return false;

    if (!m_direct.sendMessage(
            m_config.responderIp, m_config.protocolPort,
            MSG_M3, session, m_m3, M3_BYTES, framed)) return false;
    a.directAppTx += M3_BYTES;
    a.directFramedTx += framed;
    a.protocolUs = micros() - protocolStart;

    if (!m_direct.receiveMessage(
            MSG_RESULT, session, m_result, sizeof(m_result),
            DIRECT_RECEIVE_TIMEOUT_MS, received) || received.length != RESULT_BYTES) {
        Serial.println("Measurement RESULT receive failed.");
        return false;
    }
    a.confirmedUs = micros() - protocolStart;

    SessionMetrics b;
    uint64_t bProtocolUs = 0;
    uint8_t bKeyHash[HASH_BYTES];
    if (!decodeResult(m_result, session, bProtocolUs, b, bKeyHash)) return false;
    uint8_t aKeyHash[HASH_BYTES];
    if (!CryptoHelpers::sha256(sessionKey, sizeof(sessionKey), aKeyHash) ||
        !constantTimeEqual(aKeyHash, bKeyHash, HASH_BYTES)) {
        Serial.println("Session-key equality check failed.");
        return false;
    }

    printSessionResult(session, slot, a, b, bProtocolUs);
    return true;
}

bool ApqeProtocol::runResponderSession(uint32_t session, const ReceivedMessage& incoming)
{
    SessionMetrics b;
    b.directAppRx = M1_BYTES;
    b.directFramedRx = incoming.framedBytes;
    const uint64_t protocolStart = micros();

    uint8_t seed[HASH_BYTES];
    if (!timedReconstruct(b, seed) || !timedKeygen(b, seed)) return false;

    uint8_t ei[EI_BYTES];
    for (size_t block = 0; block < EI_BLOCKS; ++block) {
        const uint64_t start = micros();
        const bool ok = KyberCpaWrapper::decrypt(
            m_m1 + block * KYBER_CIPHERTEXT_BYTES,
            m_secretKey,
            ei + block * KYBER_MESSAGE_BYTES);
        b.kyberDecryptUs += micros() - start;
        if (!ok) return false;
    }

    uint8_t expectedH1[HASH_BYTES];
    const uint8_t* h1Parts[] = {ei};
    const size_t h1Lengths[] = {sizeof(ei)};
    if (!timedShaParts(b, h1Parts, h1Lengths, 1, expectedH1) ||
        !constantTimeEqual(expectedH1,
                           m_m1 + EI_BLOCKS * KYBER_CIPHERTEXT_BYTES,
                           HASH_BYTES)) {
        Serial.println("H1 verification failed.");
        return false;
    }

    const uint8_t* tidI = ei + 0;
    const uint8_t* ci = ei + 32;
    const uint8_t* ni = ei + 64;
    const uint8_t* tidJ = ei + 96;

    if (!m_fabric.queryByTid(
            tidI, m_runtimePeerCredential,
            b.fabricPeerUs, b.fabricWallUs,
            b.gatewayAppTx, b.gatewayAppRx)) {
        Serial.printf("TID Fabric query failed, status=%u\n", m_fabric.lastStatus());
        return false;
    }
    if (!constantTimeEqual(m_runtimePeerCredential.identityHash, m_peerIdentityHash, ID_BYTES) ||
        !verifyCredential(m_runtimePeerCredential, &b)) {
        Serial.println("Initiator Fabric credential verification failed.");
        return false;
    }

    uint8_t cj[CHALLENGE_BYTES];
    if (!timedPufInverse(b, tidJ, cj)) return false;

    uint8_t ciHash[HASH_BYTES];
    const uint8_t* ciParts[] = {ci};
    const size_t ciLengths[] = {HASH_BYTES};
    if (!timedShaParts(b, ciParts, ciLengths, 1, ciHash)) return false;
    uint8_t ri[HASH_BYTES];
    xorBytes(m_runtimePeerCredential.w, ciHash, ri, HASH_BYTES);

    uint8_t tkJi[HASH_BYTES];
    uint8_t tkJ[HASH_BYTES];
    timedPufMap(b, ri, tkJi);
    timedPufMap(b, ci, tkJ);
    xorBytes(tkJ, ni, m_m2, HASH_BYTES); // TNj

    uint8_t nj[NONCE_BYTES];
    CryptoHelpers::randomBytes(nj, sizeof(nj));
    maskPair(tkJi, cj, nj, m_m2 + HASH_BYTES);
    const uint8_t* h2Parts[] = {tkJi, tkJ, cj, nj};
    const size_t h2Lengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(b, h2Parts, h2Lengths, 4,
                       m_m2 + HASH_BYTES + PJ_BYTES)) return false;

    uint32_t framed = 0;
    if (!m_direct.sendMessage(
            incoming.sourceIp, incoming.sourcePort,
            MSG_M2, session, m_m2, M2_BYTES, framed)) return false;
    b.directAppTx += M2_BYTES;
    b.directFramedTx += framed;

    ReceivedMessage received;
    if (!m_direct.receiveMessage(
            MSG_M3, session, m_m3, sizeof(m_m3),
            DIRECT_RECEIVE_TIMEOUT_MS, received) || received.length != M3_BYTES) {
        Serial.println("M3 receive failed.");
        return false;
    }
    b.directAppRx += M3_BYTES;
    b.directFramedRx += received.framedBytes;

    uint8_t tkI[HASH_BYTES];
    uint8_t tkIj[HASH_BYTES];
    xorBytes(m_m3, nj, tkI, HASH_BYTES);
    timedPufMap(b, tkI, tkIj);

    /* Canonicalized order. The paper prints the responder order reversed. */
    uint8_t sessionKey[HASH_BYTES];
    const uint8_t* skParts[] = {tkJi, tkIj, ni, nj};
    const size_t skLengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(b, skParts, skLengths, 4, sessionKey)) return false;

    uint8_t expectedH3[HASH_BYTES];
    const uint8_t* h3Parts[] = {tkIj, tkI, sessionKey};
    const size_t h3Lengths[] = {HASH_BYTES, HASH_BYTES, HASH_BYTES};
    if (!timedShaParts(b, h3Parts, h3Lengths, 3, expectedH3) ||
        !constantTimeEqual(expectedH3, m_m3 + HASH_BYTES, HASH_BYTES)) {
        Serial.println("H3 verification failed.");
        return false;
    }

    b.protocolUs = micros() - protocolStart;
    uint8_t keyHash[HASH_BYTES];
    if (!CryptoHelpers::sha256(sessionKey, sizeof(sessionKey), keyHash)) return false;
    encodeResult(session, b.protocolUs, b, keyHash, m_result);
    if (!m_direct.sendMessage(
            incoming.sourceIp, incoming.sourcePort,
            MSG_RESULT, session, m_result, RESULT_BYTES, framed)) return false;
    return true;
}

void ApqeProtocol::encodeResult(
    uint32_t session,
    uint64_t protocolUs,
    const SessionMetrics& metrics,
    const uint8_t sessionKeyHash[HASH_BYTES],
    uint8_t output[RESULT_BYTES])
{
    memset(output, 0, RESULT_BYTES);
    output[0] = 0;
    putU32(output + 1, session);
    putU64(output + 5, protocolUs);
    putU64(output + 13, metrics.shaUs);
    putU64(output + 21, metrics.pufUs);
    putU64(output + 29, metrics.fuzzyReconstructionUs);
    putU64(output + 37, metrics.kyberKeygenUs);
    putU64(output + 45, metrics.kyberEncryptUs);
    putU64(output + 53, metrics.kyberDecryptUs);
    putU64(output + 61, metrics.fabricWallUs);
    putU64(output + 69, metrics.fabricPeerUs);
    putU32(output + 77, metrics.directAppTx);
    putU32(output + 81, metrics.directAppRx);
    putU32(output + 85, metrics.directFramedTx);
    putU32(output + 89, metrics.directFramedRx);
    putU32(output + 93, metrics.gatewayAppTx);
    putU32(output + 97, metrics.gatewayAppRx);
    memcpy(output + 101, sessionKeyHash, HASH_BYTES);
}

bool ApqeProtocol::decodeResult(
    const uint8_t input[RESULT_BYTES],
    uint32_t expectedSession,
    uint64_t& protocolUs,
    SessionMetrics& metrics,
    uint8_t sessionKeyHash[HASH_BYTES])
{
    if (input[0] != 0 || getU32(input + 1) != expectedSession) return false;
    protocolUs = getU64(input + 5);
    metrics.protocolUs = protocolUs;
    metrics.shaUs = getU64(input + 13);
    metrics.pufUs = getU64(input + 21);
    metrics.fuzzyReconstructionUs = getU64(input + 29);
    metrics.kyberKeygenUs = getU64(input + 37);
    metrics.kyberEncryptUs = getU64(input + 45);
    metrics.kyberDecryptUs = getU64(input + 53);
    metrics.fabricWallUs = getU64(input + 61);
    metrics.fabricPeerUs = getU64(input + 69);
    metrics.directAppTx = getU32(input + 77);
    metrics.directAppRx = getU32(input + 81);
    metrics.directFramedTx = getU32(input + 85);
    metrics.directFramedRx = getU32(input + 89);
    metrics.gatewayAppTx = getU32(input + 93);
    metrics.gatewayAppRx = getU32(input + 97);
    memcpy(sessionKeyHash, input + 101, HASH_BYTES);
    return true;
}

void ApqeProtocol::printSessionResult(
    uint32_t session,
    uint16_t slot,
    const SessionMetrics& a,
    const SessionMetrics& b,
    uint64_t bProtocolUs) const
{
    const uint64_t aCrypto = a.shaUs + a.pufUs + a.fuzzyReconstructionUs +
        a.kyberKeygenUs + a.kyberEncryptUs + a.kyberDecryptUs;
    const uint64_t bCrypto = b.shaUs + b.pufUs + b.fuzzyReconstructionUs +
        b.kyberKeygenUs + b.kyberEncryptUs + b.kyberDecryptUs;
    const uint32_t totalFramed = a.directFramedTx + a.directFramedRx;

    Serial.println();
    Serial.println("==============================================");
    Serial.printf("SESSION %u SUCCESS, credential slot=%u\n", session, slot);
    Serial.printf("A protocol time through M3 send: %.3f ms\n", a.protocolUs / 1000.0);
    Serial.printf("Confirmed E2E including measurement RESULT: %.3f ms\n", a.confirmedUs / 1000.0);
    Serial.printf("B time from full M1 receipt to M3 acceptance: %.3f ms\n", bProtocolUs / 1000.0);

    Serial.println("\nInitiator measured operations:");
    Serial.printf("  SHA-256:                %.3f ms\n", a.shaUs / 1000.0);
    Serial.printf("  PUF emulation:           %.3f ms\n", a.pufUs / 1000.0);
    Serial.printf("  SRAM/FE emulation:       %.3f ms\n", a.fuzzyReconstructionUs / 1000.0);
    Serial.printf("  Kyber CPA key generation:%.3f ms\n", a.kyberKeygenUs / 1000.0);
    Serial.printf("  Kyber CPA encryption:    %.3f ms\n", a.kyberEncryptUs / 1000.0);
    Serial.printf("  Local crypto total:      %.3f ms\n", aCrypto / 1000.0);
    Serial.printf("  Fabric query wall time:  %.3f ms\n", a.fabricWallUs / 1000.0);
    Serial.printf("  Fabric evaluate time:    %.3f ms\n", a.fabricPeerUs / 1000.0);

    Serial.println("\nResponder measured operations:");
    Serial.printf("  SHA-256:                %.3f ms\n", b.shaUs / 1000.0);
    Serial.printf("  PUF emulation:           %.3f ms\n", b.pufUs / 1000.0);
    Serial.printf("  SRAM/FE emulation:       %.3f ms\n", b.fuzzyReconstructionUs / 1000.0);
    Serial.printf("  Kyber CPA key generation:%.3f ms\n", b.kyberKeygenUs / 1000.0);
    Serial.printf("  Kyber CPA decryption:    %.3f ms\n", b.kyberDecryptUs / 1000.0);
    Serial.printf("  Local crypto total:      %.3f ms\n", bCrypto / 1000.0);
    Serial.printf("  Fabric query wall time:  %.3f ms\n", b.fabricWallUs / 1000.0);
    Serial.printf("  Fabric evaluate time:    %.3f ms\n", b.fabricPeerUs / 1000.0);

    Serial.printf("\nDirect UAV application bytes: %u (M1=%u, M2=%u, M3=%u)\n",
                  DIRECT_APPLICATION_BYTES, M1_BYTES, M2_BYTES, M3_BYTES);
    Serial.printf("Direct fragment-framed UDP payload bytes observed: %u\n", totalFramed);
    Serial.printf("A direct TX/RX: %u / %u bytes\n", a.directAppTx, a.directAppRx);
    Serial.printf("B direct TX/RX: %u / %u bytes\n", b.directAppTx, b.directAppRx);
    Serial.printf("Runtime gateway application bytes A/B: %u / %u bytes\n",
                  a.gatewayAppTx + a.gatewayAppRx,
                  b.gatewayAppTx + b.gatewayAppRx);
    Serial.println("RESULT is measurement-only and excluded from all APQE protocol byte counts.");
    Serial.printf(
        "CSV,%u,%u,%llu,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%d,%u,%u\n",
        session,
        slot,
        static_cast<unsigned long long>(a.protocolUs),
        static_cast<unsigned long long>(a.confirmedUs),
        static_cast<unsigned long long>(bProtocolUs),
        static_cast<unsigned long long>(aCrypto),
        static_cast<unsigned long long>(bCrypto),
        DIRECT_APPLICATION_BYTES,
        totalFramed,
        a.gatewayAppTx + a.gatewayAppRx,
        b.gatewayAppTx + b.gatewayAppRx,
        WiFi.RSSI(),
        ESP.getFreeHeap(),
        ESP.getMinFreeHeap());
}

void ApqeProtocol::responderLoop()
{
    ReceivedMessage received;
    if (!m_direct.receiveMessage(
            MSG_M1, 0, m_m1, sizeof(m_m1), 1000, received)) {
        return;
    }
    if (received.length != M1_BYTES) {
        Serial.println("Unexpected M1 length.");
        return;
    }
    Serial.printf("Received M1 for session %u\n", received.session);
    if (!runResponderSession(received.session, received)) {
        Serial.printf("Responder session %u failed.\n", received.session);
    }
}

void ApqeProtocol::loop()
{
    if (!m_initialized || m_completed) {
        delay(100);
        return;
    }
    if (m_config.role == Role::Responder) {
        responderLoop();
        return;
    }

    uint32_t successes = 0;
    for (uint32_t index = 0; index < m_config.numberOfSessions; ++index) {
        const uint32_t session = index + 1;
        const uint16_t slot = static_cast<uint16_t>(index);
        Serial.printf("\nStarting APQE session %u / %u\n",
                      session, m_config.numberOfSessions);
        if (runInitiatorSession(session, slot)) {
            ++successes;
        } else {
            Serial.printf("Session %u failed. Stopping experiment.\n", session);
            break;
        }
        delay(500);
    }
    Serial.printf("\nInitiator experiment complete: %u / %u sessions succeeded.\n",
                  successes, m_config.numberOfSessions);
    printMemory("After complete APQE initiator experiment");
    m_completed = true;
}

} // namespace apqe
