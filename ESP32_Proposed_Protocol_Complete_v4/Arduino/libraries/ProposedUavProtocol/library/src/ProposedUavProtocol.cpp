#include "ProposedUavProtocol.h"

#include <time.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"

namespace puav {

static constexpr size_t RESULT_BYTES = 116;

ProposedUavProtocol::ProposedUavProtocol(const NodeConfig& config)
    : m_config(config),
      m_rngInitialized(false),
      m_kemInitialized(false),
      m_ready(false),
      m_initiatorCompleted(false)
{
    memset(&m_rng, 0, sizeof(m_rng));
    memset(&m_kemKey, 0, sizeof(m_kemKey));
    memset(m_bootSeed, 0, sizeof(m_bootSeed));
    memset(m_m0, 0, sizeof(m_m0));
    memset(m_m1, 0, sizeof(m_m1));
    memset(m_m2, 0, sizeof(m_m2));
    memset(m_m3, 0, sizeof(m_m3));
    memset(m_m4, 0, sizeof(m_m4));
    memset(m_mu, 0, sizeof(m_mu));
    memset(m_signInput, 0, sizeof(m_signInput));
    memset(m_result, 0, sizeof(m_result));
}

void ProposedUavProtocol::printId(
    const char* label,
    const uint8_t id[ID_BYTES])
{
    Serial.print(label);
    Serial.print(": ");

    for (size_t i = 0; i < 8; ++i) {
        if (id[i] < 0x10) {
            Serial.print('0');
        }
        Serial.print(id[i], HEX);
    }

    Serial.println("...");
}

void ProposedUavProtocol::printMemory(const char* label)
{
    const size_t free8 = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    const size_t min8 = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    const size_t largest8 = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    const UBaseType_t stackWords = uxTaskGetStackHighWaterMark(nullptr);

    Serial.println();
    Serial.printf("----- %s -----\n", label);
    Serial.printf("ESP free heap:          %u bytes\n", static_cast<unsigned>(ESP.getFreeHeap()));
    Serial.printf("ESP minimum free heap:  %u bytes\n", static_cast<unsigned>(ESP.getMinFreeHeap()));
    Serial.printf("Free 8-bit heap:        %u bytes\n", static_cast<unsigned>(free8));
    Serial.printf("Minimum 8-bit heap:     %u bytes\n", static_cast<unsigned>(min8));
    Serial.printf("Largest 8-bit block:    %u bytes\n", static_cast<unsigned>(largest8));
    Serial.printf(
        "Loop-task stack reserve:%u bytes\n",
        static_cast<unsigned>(stackWords * sizeof(StackType_t)));
}

bool ProposedUavProtocol::connectWiFi()
{
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(m_config.wifiSsid, m_config.wifiPassword);

    Serial.print("Connecting to Wi-Fi");
    const uint32_t startMs = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - startMs < 30000) {
        delay(500);
        Serial.print('.');
    }

    Serial.println();

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Wi-Fi connection failed.");
        return false;
    }

    Serial.printf("Connected, IP: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("RSSI: %d dBm\n", WiFi.RSSI());

    if (WiFi.RSSI() < -75) {
        Serial.println("WARNING: weak RSSI; do not use this run for final latency statistics.");
    }

    return true;
}

bool ProposedUavProtocol::validatePeerRecord(uint32_t version) const
{
    if (!m_peerRecord.ready || m_peerRecord.version != version ||
        m_peerRecord.version != m_config.peerCredentialVersion ||
        m_peerRecord.suiteId != suiteIdForMode(m_config.pathMode) ||
        m_peerRecord.status != CREDENTIAL_STATUS_ACTIVE) {
        return false;
    }

    if (m_peerRecord.expiryUnix != 0) {
        const time_t now = time(nullptr);

        /* A nonzero expiry requires a synchronized wall clock. */
        if (now < 1700000000 ||
            static_cast<uint64_t>(now) > m_peerRecord.expiryUnix) {
            return false;
        }
    }

    return true;
}

bool ProposedUavProtocol::prepareLmsAndLedger()
{
    Serial.println();
    Serial.println("Preparing laboratory PUF-rooted LMS state...");
    Serial.println(
        "NOTE: the hardcoded root is a placeholder for the external APUF + Python FE output.");

    uint8_t helperDigest[HASH_BYTES];
    uint8_t pufRoot[HASH_BYTES];

    if (!CryptoHelpers::helperDataDigest(
            m_config.hardcodedHelperData,
            helperDigest) ||
        !PufFeProvider::reconstruct(m_config, pufRoot)) {
        return false;
    }

    Serial.print("Local helper-data placeholder digest: ");
    for (size_t i = 0; i < 8; ++i) {
        if (helperDigest[i] < 0x10) {
            Serial.print('0');
        }
        Serial.print(helperDigest[i], HEX);
    }
    Serial.println("...");
    CryptoHelpers::secureZero(helperDigest, sizeof(helperDigest));

    if (!CryptoHelpers::deriveLmsSeed(
            pufRoot,
            m_config.deviceId,
            m_config.credentialVersion,
            m_config.lmsIdentifier,
            m_bootSeed)) {
        CryptoHelpers::secureZero(pufRoot, sizeof(pufRoot));
        Serial.printf("LMS seed derivation failed, error %d\n", CryptoHelpers::lastError());
        return false;
    }
    CryptoHelpers::secureZero(pufRoot, sizeof(pufRoot));

    if (!m_lms.initialize(m_config.lmsIdentifier, m_bootSeed)) {
        return false;
    }

    Serial.println("Building the local h=10 LMS tree outside runtime timing...");
    const int64_t startUs = esp_timer_get_time();

    if (!m_lms.buildTree(true)) {
        Serial.printf("LMS tree construction failed, error %d\n", CryptoHelpers::lastError());
        return false;
    }

    Serial.printf("LMS tree built in %.3f ms\n", (esp_timer_get_time() - startUs) / 1000.0);
    CryptoHelpers::secureZero(m_bootSeed, sizeof(m_bootSeed));
    printMemory("After local LMS tree construction");

    if (!connectWiFi()) {
        return false;
    }

    if (!m_transport.begin(m_config.protocolPort)) {
        Serial.println("Could not start protocol UDP socket.");
        return false;
    }

    if (!m_gcs.begin(
            m_config.gcsIp,
            m_config.gcsPort,
            m_config.gcsLocalPort,
            m_config.deviceId,
            m_config.peerId)) {
        Serial.println("Could not start GCS/repository UDP client.");
        return false;
    }

    const uint32_t suiteId = suiteIdForMode(m_config.pathMode);

    if (!m_gcs.enrollOwnRoot(
            m_lms,
            m_config.credentialVersion,
            suiteId,
            CREDENTIAL_STATUS_ACTIVE,
            m_config.credentialExpiryUnix)) {
        Serial.println("Could not enroll own public LMS root.");
        return false;
    }

    if (m_config.pathMode == PathDeliveryMode::RepositoryAssisted) {
        if (!m_gcs.enrollOwnPaths(
                m_lms,
                m_config.credentialVersion,
                m_config.firstQ,
                m_config.numberOfSessions)) {
            return false;
        }
    }

    if (!m_gcs.fetchPeerRoot(
            m_config.peerCredentialVersion,
            m_peerRecord)) {
        Serial.println("Could not fetch peer public credential record.");
        return false;
    }

    if (!validatePeerRecord(m_peerRecord.version)) {
        Serial.println("Peer root record is not active, fresh, or suite-compatible.");
        return false;
    }

    Serial.printf(
        "Provisioning complete. Mode=%s, GCS TX/RX=%u/%u bytes.\n",
        m_config.pathMode == PathDeliveryMode::RepositoryAssisted
            ? "repository-assisted"
            : "signer-carried",
        static_cast<unsigned>(m_gcs.txBytes()),
        static_cast<unsigned>(m_gcs.rxBytes()));

    printMemory("After Wi-Fi and public-record provisioning");
    return true;
}

bool ProposedUavProtocol::initializePersistentCounter()
{
    if (!m_preferences.begin(m_config.nvsNamespace, false)) {
        Serial.println("Preferences/NVS initialization failed.");
        return false;
    }

    if (m_config.resetQCounter) {
        Serial.println("WARNING: resetting q for a new laboratory LMS version.");
        m_preferences.putUInt("nextq", m_config.firstQ);
    }

    const uint32_t nextQ = m_preferences.getUInt("nextq", m_config.firstQ);
    const uint32_t endQ = m_config.firstQ + m_config.numberOfSessions;

    if (nextQ < m_config.firstQ || nextQ >= endQ || nextQ >= LMS_LEAVES) {
        Serial.println("Stored q is outside this experiment's unused range.");
        return false;
    }

    Serial.printf("Next reserved LM-OTS q: %u\n", static_cast<unsigned>(nextQ));
    return true;
}

bool ProposedUavProtocol::reserveQ(uint32_t& q)
{
    const uint32_t nextQ = m_preferences.getUInt("nextq", m_config.firstQ);
    const uint32_t endQ = m_config.firstQ + m_config.numberOfSessions;

    if (nextQ < m_config.firstQ || nextQ >= endQ || nextQ >= LMS_LEAVES) {
        Serial.println("No unused q remains in this experiment range.");
        return false;
    }

    /* Crash-safe reservation: a crash may skip q, but does not reuse q. */
    if (m_preferences.putUInt("nextq", nextQ + 1) == 0) {
        Serial.println("Could not persist the next q value.");
        return false;
    }

    q = nextQ;
    return true;
}

bool ProposedUavProtocol::initializeKem()
{
    freeKem();

    const int ret = wc_MlKemKey_Init(
        &m_kemKey,
        WC_ML_KEM_512,
        nullptr,
        INVALID_DEVID);

    if (ret != 0) {
        Serial.printf("wc_MlKemKey_Init failed: %d\n", ret);
        return false;
    }

    m_kemInitialized = true;
    return true;
}

void ProposedUavProtocol::freeKem()
{
    if (m_kemInitialized) {
        wc_MlKemKey_Free(&m_kemKey);
        memset(&m_kemKey, 0, sizeof(m_kemKey));
        m_kemInitialized = false;
    }
}

bool ProposedUavProtocol::begin()
{
    Serial.println();
    Serial.println("Revised ESP32 UAV-UAV post-quantum protocol");
    Serial.printf(
        "Role: %s\n",
        m_config.role == Role::Initiator ? "UAV_A / initiator" : "UAV_B / responder");
    Serial.printf(
        "Path mode: %s\n",
        m_config.pathMode == PathDeliveryMode::RepositoryAssisted
            ? "A: repository-assisted"
            : "C: signer-carried");
    Serial.printf(
        "CPU: %u MHz, flash: %u bytes, PSRAM: %u bytes\n",
        ESP.getCpuFreqMHz(),
        ESP.getFlashChipSize(),
        ESP.getPsramSize());

    printId("Device ID", m_config.deviceId);
    printId("Peer ID", m_config.peerId);

    if (m_config.numberOfSessions == 0 ||
        m_config.firstQ + m_config.numberOfSessions > LMS_LEAVES) {
        Serial.println("Invalid q/session range.");
        return false;
    }

    printMemory("At protocol startup");

    if (!prepareLmsAndLedger()) {
        return false;
    }

    const int rngRet = wc_InitRng(&m_rng);

    if (rngRet != 0) {
        Serial.printf("wc_InitRng failed: %d\n", rngRet);
        return false;
    }

    m_rngInitialized = true;

    if (!initializePersistentCounter()) {
        return false;
    }

    m_ready = true;

    if (m_config.role == Role::Initiator) {
        Serial.println("Initiator ready; experiment starts in 5 seconds.");
    }
    else {
        Serial.println("Responder ready and waiting for M0.");
    }

    return true;
}

bool ProposedUavProtocol::sendProtocolMessage(
    const IPAddress& destination,
    uint16_t destinationPort,
    uint8_t type,
    uint32_t session,
    const uint8_t* data,
    uint16_t length,
    LocalMetrics& metrics,
    bool countAsProtocol)
{
    uint32_t framedBytes = 0;

    if (!m_transport.sendMessage(
            destination,
            destinationPort,
            type,
            session,
            data,
            length,
            framedBytes)) {
        return false;
    }

    if (countAsProtocol) {
        metrics.appTxBytes += length;
        metrics.framedTxBytes += framedBytes;
    }

    return true;
}

bool ProposedUavProtocol::receiveProtocolMessage(
    uint8_t expectedType,
    uint32_t expectedSession,
    uint8_t* data,
    uint16_t capacity,
    uint16_t expectedLength,
    ReceivedPacket& packet,
    LocalMetrics& metrics,
    bool countAsProtocol)
{
    if (!m_transport.receiveMessage(
            expectedType,
            expectedSession,
            data,
            capacity,
            RECEIVE_TIMEOUT_MS,
            packet)) {
        return false;
    }

    if (expectedLength != 0 && packet.length != expectedLength) {
        Serial.printf(
            "Unexpected message size: got %u, expected %u\n",
            static_cast<unsigned>(packet.length),
            static_cast<unsigned>(expectedLength));
        return false;
    }

    if (countAsProtocol) {
        metrics.appRxBytes += packet.length;
        metrics.framedRxBytes += packet.framedBytes;
    }

    return true;
}

bool ProposedUavProtocol::buildM0(uint8_t nonceA[NONCE_BYTES])
{
    memset(m_m0, 0, sizeof(m_m0));
    m_m0[0] = PROTOCOL_VERSION;
    m_m0[1] = MSG_M0_REQ;
    memcpy(m_m0 + 2, m_config.deviceId, ID_BYTES);
    memcpy(m_m0 + 34, m_config.peerId, ID_BYTES);
    esp_fill_random(nonceA, NONCE_BYTES);
    memcpy(m_m0 + 66, nonceA, NONCE_BYTES);
    putU32(m_m0 + 82, suiteIdForMode(m_config.pathMode));
    return true;
}

bool ProposedUavProtocol::validateM0(const uint8_t nonceA[NONCE_BYTES]) const
{
    return m_m0[0] == PROTOCOL_VERSION &&
        m_m0[1] == MSG_M0_REQ &&
        constantTimeEqual(m_m0 + 2, m_config.peerId, ID_BYTES) &&
        constantTimeEqual(m_m0 + 34, m_config.deviceId, ID_BYTES) &&
        constantTimeEqual(m_m0 + 66, nonceA, NONCE_BYTES) &&
        getU32(m_m0 + 82) == suiteIdForMode(m_config.pathMode);
}

bool ProposedUavProtocol::buildM1(
    const uint8_t nonceA[NONCE_BYTES],
    uint8_t nonceB[NONCE_BYTES])
{
    memset(m_m1, 0, sizeof(m_m1));
    m_m1[0] = PROTOCOL_VERSION;
    m_m1[1] = MSG_M1_CHAL;

    /* CHAL carries ID_B followed by ID_A. */
    memcpy(m_m1 + 2, m_config.deviceId, ID_BYTES);
    memcpy(m_m1 + 34, m_config.peerId, ID_BYTES);
    memcpy(m_m1 + 66, nonceA, NONCE_BYTES);
    esp_fill_random(nonceB, NONCE_BYTES);
    memcpy(m_m1 + 82, nonceB, NONCE_BYTES);
    putU32(m_m1 + 98, suiteIdForMode(m_config.pathMode));
    return true;
}

bool ProposedUavProtocol::validateM1(
    const uint8_t nonceA[NONCE_BYTES],
    uint8_t nonceB[NONCE_BYTES]) const
{
    const bool valid = m_m1[0] == PROTOCOL_VERSION &&
        m_m1[1] == MSG_M1_CHAL &&
        constantTimeEqual(m_m1 + 2, m_config.peerId, ID_BYTES) &&
        constantTimeEqual(m_m1 + 34, m_config.deviceId, ID_BYTES) &&
        constantTimeEqual(m_m1 + 66, nonceA, NONCE_BYTES) &&
        getU32(m_m1 + 98) == suiteIdForMode(m_config.pathMode);

    if (valid) {
        memcpy(nonceB, m_m1 + 82, NONCE_BYTES);
    }

    return valid;
}

bool ProposedUavProtocol::computeSid0(
    uint8_t sid[HASH_BYTES],
    LocalMetrics& metrics)
{
    uint8_t input[SID0_INPUT_BYTES];
    size_t offset = 0;
    input[offset++] = PROTOCOL_VERSION;
    input[offset++] = DOMAIN_SID0;
    putU16(input + offset, M0_BYTES);
    offset += 2;
    memcpy(input + offset, m_m0, M0_BYTES);
    offset += M0_BYTES;
    putU16(input + offset, M1_BYTES);
    offset += 2;
    memcpy(input + offset, m_m1, M1_BYTES);
    offset += M1_BYTES;

    const bool ok = timedSha(input, offset, sid, metrics);
    CryptoHelpers::secureZero(input, sizeof(input));
    return ok;
}

void ProposedUavProtocol::buildM2SignedInput(
    const uint8_t sid[HASH_BYTES],
    uint32_t version,
    uint32_t q,
    const uint8_t publicKey[MLKEM_PUBLIC_KEY_BYTES])
{
    memset(m_mu, 0, sizeof(m_mu));
    m_mu[0] = PROTOCOL_VERSION;
    m_mu[1] = DOMAIN_INIT;

    const uint8_t* idA = m_config.role == Role::Initiator
        ? m_config.deviceId
        : m_config.peerId;
    const uint8_t* idB = m_config.role == Role::Initiator
        ? m_config.peerId
        : m_config.deviceId;

    memcpy(m_mu + 2, sid, HASH_BYTES);
    memcpy(m_mu + 34, idA, ID_BYTES);
    memcpy(m_mu + 66, idB, ID_BYTES);
    putU32(m_mu + 98, version);
    memcpy(m_mu + 102, publicKey, MLKEM_PUBLIC_KEY_BYTES);

    memset(m_signInput, 0, sizeof(m_signInput));
    m_signInput[0] = PROTOCOL_VERSION;
    m_signInput[1] = DOMAIN_LMOTS_SIGN;
    putU16(m_signInput + 2, MU_A_BYTES);
    memcpy(m_signInput + 4, m_mu, MU_A_BYTES);
    putU32(m_signInput + 4 + MU_A_BYTES, q);
}

void ProposedUavProtocol::buildM3SignedInput(
    const uint8_t sid[HASH_BYTES],
    const uint8_t hashM2[HASH_BYTES],
    uint32_t version,
    uint32_t q,
    const uint8_t ciphertext[MLKEM_CIPHERTEXT_BYTES])
{
    memset(m_mu, 0, sizeof(m_mu));
    m_mu[0] = PROTOCOL_VERSION;
    m_mu[1] = DOMAIN_RESP;

    const uint8_t* idA = m_config.role == Role::Initiator
        ? m_config.deviceId
        : m_config.peerId;
    const uint8_t* idB = m_config.role == Role::Initiator
        ? m_config.peerId
        : m_config.deviceId;

    memcpy(m_mu + 2, sid, HASH_BYTES);
    memcpy(m_mu + 34, hashM2, HASH_BYTES);
    memcpy(m_mu + 66, idA, ID_BYTES);
    memcpy(m_mu + 98, idB, ID_BYTES);
    putU32(m_mu + 130, version);
    memcpy(m_mu + 134, ciphertext, MLKEM_CIPHERTEXT_BYTES);

    memset(m_signInput, 0, sizeof(m_signInput));
    m_signInput[0] = PROTOCOL_VERSION;
    m_signInput[1] = DOMAIN_LMOTS_SIGN;
    putU16(m_signInput + 2, MU_B_BYTES);
    memcpy(m_signInput + 4, m_mu, MU_B_BYTES);
    putU32(m_signInput + 4 + MU_B_BYTES, q);
}

bool ProposedUavProtocol::timedSha(
    const uint8_t* data,
    size_t length,
    uint8_t output[HASH_BYTES],
    LocalMetrics& metrics)
{
    const int64_t startUs = esp_timer_get_time();
    const bool ok = CryptoHelpers::sha256(data, length, output);
    metrics.shaUs += static_cast<uint64_t>(esp_timer_get_time() - startUs);
    return ok;
}

bool ProposedUavProtocol::timedTranscriptHash(
    const uint8_t sid[HASH_BYTES],
    size_t m2Length,
    const uint8_t* m3Inner,
    size_t m3InnerLength,
    uint8_t output[HASH_BYTES],
    LocalMetrics& metrics)
{
    const int64_t startUs = esp_timer_get_time();
    wc_Sha256 sha;
    int ret = wc_InitSha256(&sha);
    uint8_t header[4];

    if (ret == 0) {
        const uint8_t domain[2] = {PROTOCOL_VERSION, DOMAIN_TRANSCRIPT};
        ret = wc_Sha256Update(&sha, domain, sizeof(domain));
    }
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, sid, HASH_BYTES);
    }

    const struct {
        const uint8_t* data;
        size_t length;
    } fields[] = {
        {m_m0, M0_BYTES},
        {m_m1, M1_BYTES},
        {m_m2, m2Length},
        {m3Inner, m3InnerLength},
    };

    for (const auto& field : fields) {
        if (ret != 0 || field.length > UINT16_MAX) {
            ret = -1;
            break;
        }
        putU16(header, static_cast<uint16_t>(field.length));
        ret = wc_Sha256Update(&sha, header, 2);
        if (ret == 0) {
            ret = wc_Sha256Update(
                &sha,
                field.data,
                static_cast<word32>(field.length));
        }
    }

    if (ret == 0) {
        ret = wc_Sha256Final(&sha, output);
    }

    metrics.shaUs += static_cast<uint64_t>(esp_timer_get_time() - startUs);

    if (ret != 0) {
        Serial.printf("Transcript SHA-256 failed: %d\n", ret);
        return false;
    }

    return true;
}

bool ProposedUavProtocol::timedHmac(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t output[HMAC_BYTES],
    LocalMetrics& metrics)
{
    const int64_t startUs = esp_timer_get_time();
    const bool ok = CryptoHelpers::hmacSha256(
        key, keyLength, data, dataLength, output);
    metrics.hmacUs += static_cast<uint64_t>(esp_timer_get_time() - startUs);
    return ok;
}

bool ProposedUavProtocol::timedHkdf(
    const uint8_t* ikm,
    size_t ikmLength,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* info,
    size_t infoLength,
    uint8_t* output,
    size_t outputLength,
    LocalMetrics& metrics)
{
    const int64_t startUs = esp_timer_get_time();
    const bool ok = CryptoHelpers::hkdfSha256(
        ikm,
        ikmLength,
        salt,
        saltLength,
        info,
        infoLength,
        output,
        outputLength);
    metrics.hmacUs += static_cast<uint64_t>(esp_timer_get_time() - startUs);
    return ok;
}

bool ProposedUavProtocol::timedRuntimeSeed(
    uint8_t output[HASH_BYTES],
    LocalMetrics& metrics)
{
    uint8_t pufRoot[HASH_BYTES];

    const int64_t pufStartUs = esp_timer_get_time();
    const bool reconstructed = PufFeProvider::reconstruct(m_config, pufRoot);
    metrics.pufFeUs += static_cast<uint64_t>(
        esp_timer_get_time() - pufStartUs);

    if (!reconstructed) {
        CryptoHelpers::secureZero(pufRoot, sizeof(pufRoot));
        return false;
    }

    const int64_t kdfStartUs = esp_timer_get_time();
    const bool derived = CryptoHelpers::deriveLmsSeed(
        pufRoot,
        m_config.deviceId,
        m_config.credentialVersion,
        m_config.lmsIdentifier,
        output);
    metrics.hmacUs += static_cast<uint64_t>(
        esp_timer_get_time() - kdfStartUs);

    CryptoHelpers::secureZero(pufRoot, sizeof(pufRoot));
    return derived;
}

bool ProposedUavProtocol::deriveSessionKeys(
    const uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t transcriptHash[HASH_BYTES],
    uint8_t sessionKey[HASH_BYTES],
    uint8_t confirmA[HASH_BYTES],
    uint8_t confirmB[HASH_BYTES],
    LocalMetrics& metrics)
{
    uint8_t info[1 + 1 + 2 + HASH_BYTES];
    info[0] = PROTOCOL_VERSION;
    info[1] = DOMAIN_UAV_AKE;
    putU16(info + 2, HASH_BYTES);
    memcpy(info + 4, transcriptHash, HASH_BYTES);

    uint8_t material[SESSION_KEY_MATERIAL_BYTES];

    if (!timedHkdf(
            sharedSecret,
            MLKEM_SHARED_SECRET_BYTES,
            transcriptHash,
            HASH_BYTES,
            info,
            sizeof(info),
            material,
            sizeof(material),
            metrics)) {
        return false;
    }

    memcpy(sessionKey, material, HASH_BYTES);
    memcpy(confirmA, material + HASH_BYTES, HASH_BYTES);
    memcpy(confirmB, material + 2 * HASH_BYTES, HASH_BYTES);
    CryptoHelpers::secureZero(material, sizeof(material));
    return true;
}

bool ProposedUavProtocol::computeConfirmationTag(
    uint8_t domain,
    const uint8_t confirmationKey[HASH_BYTES],
    const uint8_t transcriptHash[HASH_BYTES],
    uint8_t output[HMAC_BYTES],
    LocalMetrics& metrics)
{
    uint8_t input[1 + 1 + 2 + HASH_BYTES];
    input[0] = PROTOCOL_VERSION;
    input[1] = domain;
    putU16(input + 2, HASH_BYTES);
    memcpy(input + 4, transcriptHash, HASH_BYTES);

    return timedHmac(
        confirmationKey,
        HASH_BYTES,
        input,
        sizeof(input),
        output,
        metrics);
}

bool ProposedUavProtocol::obtainPeerPath(
    uint32_t version,
    uint32_t q,
    const uint8_t* carriedPath,
    uint8_t outputPath[LMS_PATH_BYTES],
    LocalMetrics& metrics)
{
    if (m_config.pathMode == PathDeliveryMode::SignerCarried) {
        if (carriedPath == nullptr) {
            return false;
        }
        memcpy(outputPath, carriedPath, LMS_PATH_BYTES);
        return true;
    }

    RepositoryOperationMetrics operation;

    if (!m_gcs.fetchPeerPath(version, q, outputPath, &operation)) {
        return false;
    }

    metrics.repositoryUs += operation.elapsedUs;
    metrics.repositoryTxBytes += operation.txBytes;
    metrics.repositoryRxBytes += operation.rxBytes;
    return true;
}

void ProposedUavProtocol::wipeSessionSecrets(
    uint8_t runtimeSeed[HASH_BYTES],
    uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES],
    uint8_t sessionKey[HASH_BYTES],
    uint8_t confirmA[HASH_BYTES],
    uint8_t confirmB[HASH_BYTES])
{
    CryptoHelpers::secureZero(runtimeSeed, HASH_BYTES);
    CryptoHelpers::secureZero(sharedSecret, MLKEM_SHARED_SECRET_BYTES);
    CryptoHelpers::secureZero(sessionKey, HASH_BYTES);
    CryptoHelpers::secureZero(confirmA, HASH_BYTES);
    CryptoHelpers::secureZero(confirmB, HASH_BYTES);
    CryptoHelpers::secureZero(m_mu, sizeof(m_mu));
    CryptoHelpers::secureZero(m_signInput, sizeof(m_signInput));
}

void ProposedUavProtocol::finalizeMetrics(LocalMetrics& metrics)
{
    metrics.totalCryptoUs = metrics.shaUs + metrics.hmacUs +
        metrics.lmotsSignUs + metrics.lmotsVerifyUs + metrics.kemUs +
        metrics.pufFeUs;
}

bool ProposedUavProtocol::runInitiatorSession(uint32_t runNumber)
{
    LocalMetrics metrics;
    ReceivedPacket packet;
    uint8_t nonceA[NONCE_BYTES] = {0};
    uint8_t nonceB[NONCE_BYTES] = {0};
    uint8_t sid[HASH_BYTES] = {0};
    uint8_t hashM2[HASH_BYTES] = {0};
    uint8_t transcriptHash[HASH_BYTES] = {0};
    uint8_t runtimeSeed[HASH_BYTES] = {0};
    uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES] = {0};
    uint8_t sessionKey[HASH_BYTES] = {0};
    uint8_t confirmA[HASH_BYTES] = {0};
    uint8_t confirmB[HASH_BYTES] = {0};
    uint8_t expectedTauB[HMAC_BYTES] = {0};
    uint8_t tauA[HMAC_BYTES] = {0};
    uint8_t peerPath[LMS_PATH_BYTES] = {0};
    uint32_t qA = 0;
    uint32_t qB = 0;
    uint64_t confirmedE2eUs = 0;
    bool success = false;

    const size_t m2Length = m2BytesForMode(m_config.pathMode);
    const size_t m3InnerLength = m3InnerBytesForMode(m_config.pathMode);
    const size_t m3Length = m3BytesForMode(m_config.pathMode);
    const uint32_t session = esp_random() | 1u;

    memset(m_m0, 0, sizeof(m_m0));
    memset(m_m1, 0, sizeof(m_m1));
    memset(m_m2, 0, sizeof(m_m2));
    memset(m_m3, 0, sizeof(m_m3));
    memset(m_m4, 0, sizeof(m_m4));

    buildM0(nonceA);
    const uint64_t e2eStartUs = esp_timer_get_time();
    const uint64_t protocolStartUs = e2eStartUs;

    if (!sendProtocolMessage(
            m_config.responderIp,
            m_config.protocolPort,
            MSG_M0_REQ,
            session,
            m_m0,
            M0_BYTES,
            metrics,
            true)) {
        Serial.println("Could not send M0.");
        goto cleanup;
    }

    if (!receiveProtocolMessage(
            MSG_M1_CHAL,
            session,
            m_m1,
            sizeof(m_m1),
            M1_BYTES,
            packet,
            metrics,
            true) ||
        !validateM1(nonceA, nonceB)) {
        Serial.println("M1 reception or validation failed.");
        goto cleanup;
    }

    if (!computeSid0(sid, metrics) || !initializeKem()) {
        goto cleanup;
    }

    {
        const int64_t kemStartUs = esp_timer_get_time();
        int ret = wc_MlKemKey_MakeKey(&m_kemKey, &m_rng);

        if (ret == 0) {
            ret = wc_MlKemKey_EncodePublicKey(
                &m_kemKey,
                m_m2 + 42,
                MLKEM_PUBLIC_KEY_BYTES);
        }

        metrics.kemUs += static_cast<uint64_t>(esp_timer_get_time() - kemStartUs);

        if (ret != 0) {
            Serial.printf("Initiator ML-KEM key generation/export failed: %d\n", ret);
            goto cleanup;
        }
    }

    if (!reserveQ(qA) || !timedRuntimeSeed(runtimeSeed, metrics)) {
        goto cleanup;
    }

    m_m2[0] = PROTOCOL_VERSION;
    m_m2[1] = MSG_M2_INIT;
    memcpy(m_m2 + 2, sid, HASH_BYTES);
    putU32(m_m2 + 34, m_config.credentialVersion);
    putU32(m_m2 + 38, qA);

    buildM2SignedInput(
        sid,
        m_config.credentialVersion,
        qA,
        m_m2 + 42);

    {
        const int64_t signStartUs = esp_timer_get_time();
        const bool signOk = m_lms.sign(
            qA,
            m_signInput,
            LMOTS_SIGNED_OBJECT_BYTES,
            runtimeSeed,
            m_m2 + 842);
        metrics.lmotsSignUs += static_cast<uint64_t>(esp_timer_get_time() - signStartUs);

        if (!signOk) {
            Serial.println("M2 LM-OTS signing failed.");
            goto cleanup;
        }
    }

    if (m_config.pathMode == PathDeliveryMode::SignerCarried &&
        !m_lms.extractPath(qA, m_m2 + M2_BASE_BYTES)) {
        Serial.println("Could not attach A's LMS path.");
        goto cleanup;
    }

    if (!timedSha(m_m2, m2Length, hashM2, metrics) ||
        !sendProtocolMessage(
            packet.sourceIp,
            packet.sourcePort,
            MSG_M2_INIT,
            session,
            m_m2,
            static_cast<uint16_t>(m2Length),
            metrics,
            true)) {
        Serial.println("Could not hash or send M2.");
        goto cleanup;
    }

    if (!receiveProtocolMessage(
            MSG_M3_RESP_FIN,
            session,
            m_m3,
            sizeof(m_m3),
            static_cast<uint16_t>(m3Length),
            packet,
            metrics,
            true)) {
        Serial.println("Timed out waiting for M3.");
        goto cleanup;
    }

    if (m_m3[0] != PROTOCOL_VERSION ||
        m_m3[1] != MSG_M3_RESP_FIN ||
        !constantTimeEqual(m_m3 + 2, sid, HASH_BYTES) ||
        getU16(m_m3 + 34) != m3InnerLength) {
        Serial.println("M3 outer parsing failed.");
        goto cleanup;
    }

    {
        const uint8_t* inner = m_m3 + 36;
        const uint8_t* tauB = m_m3 + 36 + m3InnerLength;

        if (inner[0] != PROTOCOL_VERSION ||
            inner[1] != MSG_M3_INNER ||
            !constantTimeEqual(inner + 2, sid, HASH_BYTES)) {
            Serial.println("M3 inner parsing failed.");
            goto cleanup;
        }

        const uint32_t versionB = getU32(inner + 34);
        qB = getU32(inner + 38);

        if (qB >= LMS_LEAVES || !validatePeerRecord(versionB)) {
            Serial.println("B credential record, version, or q is invalid.");
            goto cleanup;
        }

        const uint8_t* carriedPath =
            m_config.pathMode == PathDeliveryMode::SignerCarried
                ? inner + M3_INNER_BASE_BYTES
                : nullptr;

        if (!obtainPeerPath(versionB, qB, carriedPath, peerPath, metrics)) {
            Serial.println("Could not obtain B's LMS path.");
            goto cleanup;
        }

        buildM3SignedInput(
            sid,
            hashM2,
            versionB,
            qB,
            inner + 42);

        const int64_t verifyStartUs = esp_timer_get_time();
        const bool verified = LmotsLms::verify(
            qB,
            m_signInput,
            LMOTS_SIGNED_OBJECT_BYTES,
            inner + 810,
            m_peerRecord.identifier,
            peerPath,
            m_peerRecord.root);
        metrics.lmotsVerifyUs += static_cast<uint64_t>(esp_timer_get_time() - verifyStartUs);

        if (!verified) {
            Serial.println("M3 LM-OTS/LMS verification failed.");
            goto cleanup;
        }

        const int64_t kemStartUs = esp_timer_get_time();
        const int ret = wc_MlKemKey_Decapsulate(
            &m_kemKey,
            sharedSecret,
            inner + 42,
            MLKEM_CIPHERTEXT_BYTES);
        metrics.kemUs += static_cast<uint64_t>(esp_timer_get_time() - kemStartUs);

        if (ret != 0) {
            Serial.printf("ML-KEM decapsulation failed: %d\n", ret);
            goto cleanup;
        }

        if (!timedTranscriptHash(
                sid,
                m2Length,
                inner,
                m3InnerLength,
                transcriptHash,
                metrics) ||
            !deriveSessionKeys(
                sharedSecret,
                transcriptHash,
                sessionKey,
                confirmA,
                confirmB,
                metrics) ||
            !computeConfirmationTag(
                DOMAIN_B_CONFIRM,
                confirmB,
                transcriptHash,
                expectedTauB,
                metrics) ||
            !constantTimeEqual(expectedTauB, tauB, HMAC_BYTES)) {
            Serial.println("B key-confirmation verification failed.");
            goto cleanup;
        }
    }

    if (!computeConfirmationTag(
            DOMAIN_A_CONFIRM,
            confirmA,
            transcriptHash,
            tauA,
            metrics)) {
        goto cleanup;
    }

    m_m4[0] = PROTOCOL_VERSION;
    m_m4[1] = MSG_M4_INIT_FIN;
    memcpy(m_m4 + 2, sid, HASH_BYTES);
    memcpy(m_m4 + 34, tauA, HMAC_BYTES);

    if (!sendProtocolMessage(
            packet.sourceIp,
            packet.sourcePort,
            MSG_M4_INIT_FIN,
            session,
            m_m4,
            M4_BYTES,
            metrics,
            true)) {
        Serial.println("Could not send M4.");
        goto cleanup;
    }

    metrics.protocolUs = static_cast<uint64_t>(esp_timer_get_time() - protocolStartUs);

    {
        ReceivedPacket resultPacket;
        if (!receiveProtocolMessage(
                MSG_RESULT,
                session,
                m_result,
                sizeof(m_result),
                RESULT_BYTES,
                resultPacket,
                metrics,
                false)) {
            Serial.println("M4 sent, but measurement RESULT was not received.");
            goto cleanup;
        }
    }

    confirmedE2eUs = static_cast<uint64_t>(esp_timer_get_time() - e2eStartUs);
    finalizeMetrics(metrics);

    if (m_result[0] != RESULT_OK) {
        Serial.printf("Responder returned failure status %u\n", static_cast<unsigned>(m_result[0]));
        goto cleanup;
    }

    printInitiatorResult(
        runNumber,
        qA,
        qB,
        confirmedE2eUs,
        metrics,
        m_result,
        RESULT_BYTES);
    success = true;

cleanup:
    freeKem();
    wipeSessionSecrets(runtimeSeed, sharedSecret, sessionKey, confirmA, confirmB);
    CryptoHelpers::secureZero(expectedTauB, sizeof(expectedTauB));
    CryptoHelpers::secureZero(tauA, sizeof(tauA));
    CryptoHelpers::secureZero(peerPath, sizeof(peerPath));
    return success;
}

void ProposedUavProtocol::printInitiatorResult(
    uint32_t runNumber,
    uint32_t qA,
    uint32_t qB,
    uint64_t confirmedE2eUs,
    const LocalMetrics& initiator,
    const uint8_t* responderResult,
    size_t responderResultLength)
{
    if (responderResultLength < RESULT_BYTES) {
        return;
    }

    const uint32_t resultQa = getU32(responderResult + 4);
    const uint32_t resultQb = getU32(responderResult + 8);
    const uint64_t responderProtocolUs = getU64(responderResult + 12);
    const uint64_t responderCryptoUs = getU64(responderResult + 20);
    const uint64_t responderShaUs = getU64(responderResult + 28);
    const uint64_t responderHmacUs = getU64(responderResult + 36);
    const uint64_t responderSignUs = getU64(responderResult + 44);
    const uint64_t responderVerifyUs = getU64(responderResult + 52);
    const uint64_t responderKemUs = getU64(responderResult + 60);
    const uint64_t responderPufFeUs = getU64(responderResult + 68);
    const uint64_t responderRepositoryUs = getU64(responderResult + 76);
    const uint32_t responderAppTx = getU32(responderResult + 84);
    const uint32_t responderAppRx = getU32(responderResult + 88);
    const uint32_t responderFramedTx = getU32(responderResult + 92);
    const uint32_t responderFramedRx = getU32(responderResult + 96);
    const uint32_t responderRepoTx = getU32(responderResult + 100);
    const uint32_t responderRepoRx = getU32(responderResult + 104);

    const uint32_t applicationTotal = initiator.appTxBytes + initiator.appRxBytes;
    const uint32_t framedTotal = initiator.framedTxBytes + initiator.framedRxBytes;
    const uint32_t repositoryTotal = initiator.repositoryTxBytes +
        initiator.repositoryRxBytes + responderRepoTx + responderRepoRx;

    Serial.println();
    Serial.println("==============================================");
    Serial.printf(
        "SESSION %u SUCCESS, qA=%u, qB=%u\n",
        static_cast<unsigned>(runNumber),
        static_cast<unsigned>(qA),
        static_cast<unsigned>(qB));

    if (qA != resultQa || qB != resultQb) {
        Serial.println("WARNING: result q values do not match.");
    }

    Serial.printf("A protocol time through M4 send: %.3f ms\n", initiator.protocolUs / 1000.0);
    Serial.printf("Confirmed E2E including measurement ACK: %.3f ms\n", confirmedE2eUs / 1000.0);
    Serial.printf("B time from M0 receipt to M4 acceptance: %.3f ms\n", responderProtocolUs / 1000.0);

    Serial.println("Initiator local cryptographic time:");
    Serial.printf("  SHA-256:      %.3f ms\n", initiator.shaUs / 1000.0);
    Serial.printf("  HMAC/HKDF:    %.3f ms\n", initiator.hmacUs / 1000.0);
    Serial.printf("  LM-OTS sign:  %.3f ms\n", initiator.lmotsSignUs / 1000.0);
    Serial.printf("  LMS verify:   %.3f ms\n", initiator.lmotsVerifyUs / 1000.0);
    Serial.printf("  ML-KEM:       %.3f ms\n", initiator.kemUs / 1000.0);
    Serial.printf("  PUF/FE hook:  %.3f ms\n", initiator.pufFeUs / 1000.0);
    Serial.printf("  Total crypto: %.3f ms\n", initiator.totalCryptoUs / 1000.0);

    Serial.println("Responder local cryptographic time:");
    Serial.printf("  SHA-256:      %.3f ms\n", responderShaUs / 1000.0);
    Serial.printf("  HMAC/HKDF:    %.3f ms\n", responderHmacUs / 1000.0);
    Serial.printf("  LM-OTS sign:  %.3f ms\n", responderSignUs / 1000.0);
    Serial.printf("  LMS verify:   %.3f ms\n", responderVerifyUs / 1000.0);
    Serial.printf("  ML-KEM:       %.3f ms\n", responderKemUs / 1000.0);
    Serial.printf("  PUF/FE hook:  %.3f ms\n", responderPufFeUs / 1000.0);
    Serial.printf("  Total crypto: %.3f ms\n", responderCryptoUs / 1000.0);

    Serial.printf(
        "Repository wait A/B: %.3f / %.3f ms\n",
        initiator.repositoryUs / 1000.0,
        responderRepositoryUs / 1000.0);
    Serial.printf(
        "Direct application bytes: %u (expected %u)\n",
        static_cast<unsigned>(applicationTotal),
        static_cast<unsigned>(expectedDirectApplicationBytes(m_config.pathMode)));
    Serial.printf("Fragment-framed direct bytes: %u\n", static_cast<unsigned>(framedTotal));
    Serial.printf("Repository application bytes: %u\n", static_cast<unsigned>(repositoryTotal));
    Serial.printf("A direct TX/RX: %u/%u\n", static_cast<unsigned>(initiator.appTxBytes), static_cast<unsigned>(initiator.appRxBytes));
    Serial.printf("B direct TX/RX: %u/%u\n", static_cast<unsigned>(responderAppTx), static_cast<unsigned>(responderAppRx));
    Serial.printf("A repository TX/RX: %u/%u\n", static_cast<unsigned>(initiator.repositoryTxBytes), static_cast<unsigned>(initiator.repositoryRxBytes));
    Serial.printf("B repository TX/RX: %u/%u\n", static_cast<unsigned>(responderRepoTx), static_cast<unsigned>(responderRepoRx));

    /*
      CSV fields:
      run,qA,qB,path_mode,A_protocol_us,confirmed_e2e_us,B_protocol_us,
      A_crypto_us,B_crypto_us,A_puf_fe_us,B_puf_fe_us,A_repo_us,B_repo_us,
      direct_app_bytes,direct_framed_bytes,repository_app_bytes,RSSI,
      free_heap,min_free_heap
    */
    Serial.printf(
        "CSV,%u,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u,%u,%u,%d,%u,%u\n",
        static_cast<unsigned>(runNumber),
        static_cast<unsigned>(qA),
        static_cast<unsigned>(qB),
        static_cast<unsigned>(m_config.pathMode),
        static_cast<unsigned long long>(initiator.protocolUs),
        static_cast<unsigned long long>(confirmedE2eUs),
        static_cast<unsigned long long>(responderProtocolUs),
        static_cast<unsigned long long>(initiator.totalCryptoUs),
        static_cast<unsigned long long>(responderCryptoUs),
        static_cast<unsigned long long>(initiator.pufFeUs),
        static_cast<unsigned long long>(responderPufFeUs),
        static_cast<unsigned long long>(initiator.repositoryUs),
        static_cast<unsigned long long>(responderRepositoryUs),
        static_cast<unsigned>(applicationTotal),
        static_cast<unsigned>(framedTotal),
        static_cast<unsigned>(repositoryTotal),
        WiFi.RSSI(),
        static_cast<unsigned>(ESP.getFreeHeap()),
        static_cast<unsigned>(ESP.getMinFreeHeap()));

    Serial.println("The RESULT message is measurement-only and excluded from all protocol byte counts.");
    Serial.println("==============================================");
}

void ProposedUavProtocol::runInitiatorExperiments()
{
    delay(5000);
    uint32_t successful = 0;

    for (uint32_t run = 1; run <= m_config.numberOfSessions; ++run) {
        Serial.printf(
            "\nStarting session %u / %u\n",
            static_cast<unsigned>(run),
            static_cast<unsigned>(m_config.numberOfSessions));

        if (runInitiatorSession(run)) {
            ++successful;
        }
        else {
            Serial.printf("Session %u FAILED.\n", static_cast<unsigned>(run));
        }

        delay(750);
    }

    Serial.printf(
        "\nExperiment complete: %u / %u sessions succeeded.\n",
        static_cast<unsigned>(successful),
        static_cast<unsigned>(m_config.numberOfSessions));
    printMemory("After complete initiator experiment");
    m_initiatorCompleted = true;
}

void ProposedUavProtocol::runResponderOnce()
{
    LocalMetrics metrics;
    ReceivedPacket packet;
    uint8_t nonceA[NONCE_BYTES] = {0};
    uint8_t nonceB[NONCE_BYTES] = {0};
    uint8_t sid[HASH_BYTES] = {0};
    uint8_t hashM2[HASH_BYTES] = {0};
    uint8_t transcriptHash[HASH_BYTES] = {0};
    uint8_t runtimeSeed[HASH_BYTES] = {0};
    uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES] = {0};
    uint8_t sessionKey[HASH_BYTES] = {0};
    uint8_t confirmA[HASH_BYTES] = {0};
    uint8_t confirmB[HASH_BYTES] = {0};
    uint8_t tauB[HMAC_BYTES] = {0};
    uint8_t expectedTauA[HMAC_BYTES] = {0};
    uint8_t peerPath[LMS_PATH_BYTES] = {0};
    uint32_t qA = 0;
    uint32_t qB = 0;
    bool accepted = false;

    const size_t m2Length = m2BytesForMode(m_config.pathMode);
    const size_t m3InnerLength = m3InnerBytesForMode(m_config.pathMode);
    const size_t m3Length = m3BytesForMode(m_config.pathMode);

    memset(m_m0, 0, sizeof(m_m0));
    memset(m_m1, 0, sizeof(m_m1));
    memset(m_m2, 0, sizeof(m_m2));
    memset(m_m3, 0, sizeof(m_m3));
    memset(m_m4, 0, sizeof(m_m4));
    memset(m_result, 0, sizeof(m_result));

    if (!receiveProtocolMessage(
            MSG_M0_REQ,
            0,
            m_m0,
            sizeof(m_m0),
            M0_BYTES,
            packet,
            metrics,
            true)) {
        return;
    }

    const uint64_t responderStartUs = esp_timer_get_time();
    const uint32_t session = packet.session;
    const IPAddress initiatorIp = packet.sourceIp;
    const uint16_t initiatorPort = packet.sourcePort;
    memcpy(nonceA, m_m0 + 66, NONCE_BYTES);

    if (!validateM0(nonceA) || !buildM1(nonceA, nonceB) ||
        !computeSid0(sid, metrics)) {
        Serial.println("Responder rejected M0 or could not build M1/SID0.");
        goto cleanup;
    }

    if (!sendProtocolMessage(
            initiatorIp,
            initiatorPort,
            MSG_M1_CHAL,
            session,
            m_m1,
            M1_BYTES,
            metrics,
            true)) {
        goto cleanup;
    }

    if (!receiveProtocolMessage(
            MSG_M2_INIT,
            session,
            m_m2,
            sizeof(m_m2),
            static_cast<uint16_t>(m2Length),
            packet,
            metrics,
            true)) {
        Serial.println("Responder timed out waiting for M2.");
        goto cleanup;
    }

    if (m_m2[0] != PROTOCOL_VERSION ||
        m_m2[1] != MSG_M2_INIT ||
        !constantTimeEqual(m_m2 + 2, sid, HASH_BYTES)) {
        Serial.println("Responder M2 parsing failed.");
        goto cleanup;
    }

    {
        const uint32_t versionA = getU32(m_m2 + 34);
        qA = getU32(m_m2 + 38);

        if (qA >= LMS_LEAVES || !validatePeerRecord(versionA)) {
            Serial.println("A credential record, version, or q is invalid.");
            goto cleanup;
        }

        if (!timedSha(m_m2, m2Length, hashM2, metrics)) {
            goto cleanup;
        }

        const uint8_t* carriedPath =
            m_config.pathMode == PathDeliveryMode::SignerCarried
                ? m_m2 + M2_BASE_BYTES
                : nullptr;

        if (!obtainPeerPath(versionA, qA, carriedPath, peerPath, metrics)) {
            Serial.println("Could not obtain A's LMS path.");
            goto cleanup;
        }

        buildM2SignedInput(sid, versionA, qA, m_m2 + 42);
        const int64_t verifyStartUs = esp_timer_get_time();
        const bool signatureAOk = LmotsLms::verify(
            qA,
            m_signInput,
            LMOTS_SIGNED_OBJECT_BYTES,
            m_m2 + 842,
            m_peerRecord.identifier,
            peerPath,
            m_peerRecord.root);
        metrics.lmotsVerifyUs += static_cast<uint64_t>(esp_timer_get_time() - verifyStartUs);

        if (!signatureAOk) {
            Serial.println("Responder rejected A's LM-OTS signature.");
            goto cleanup;
        }
    }

    if (!initializeKem()) {
        goto cleanup;
    }

    {
        const int64_t kemStartUs = esp_timer_get_time();
        int ret = wc_MlKemKey_DecodePublicKey(
            &m_kemKey,
            m_m2 + 42,
            MLKEM_PUBLIC_KEY_BYTES);

        uint8_t* inner = m_m3 + 36;

        if (ret == 0) {
            ret = wc_MlKemKey_Encapsulate(
                &m_kemKey,
                inner + 42,
                sharedSecret,
                &m_rng);
        }

        metrics.kemUs += static_cast<uint64_t>(esp_timer_get_time() - kemStartUs);

        if (ret != 0) {
            Serial.printf("Responder ML-KEM import/encapsulation failed: %d\n", ret);
            goto cleanup;
        }
    }

    if (!reserveQ(qB) || !timedRuntimeSeed(runtimeSeed, metrics)) {
        goto cleanup;
    }

    {
        uint8_t* inner = m_m3 + 36;
        inner[0] = PROTOCOL_VERSION;
        inner[1] = MSG_M3_INNER;
        memcpy(inner + 2, sid, HASH_BYTES);
        putU32(inner + 34, m_config.credentialVersion);
        putU32(inner + 38, qB);

        buildM3SignedInput(
            sid,
            hashM2,
            m_config.credentialVersion,
            qB,
            inner + 42);

        const int64_t signStartUs = esp_timer_get_time();
        const bool signatureBOk = m_lms.sign(
            qB,
            m_signInput,
            LMOTS_SIGNED_OBJECT_BYTES,
            runtimeSeed,
            inner + 810);
        metrics.lmotsSignUs += static_cast<uint64_t>(esp_timer_get_time() - signStartUs);

        if (!signatureBOk) {
            Serial.println("Responder M3 LM-OTS signing failed.");
            goto cleanup;
        }

        if (m_config.pathMode == PathDeliveryMode::SignerCarried &&
            !m_lms.extractPath(qB, inner + M3_INNER_BASE_BYTES)) {
            Serial.println("Could not attach B's LMS path.");
            goto cleanup;
        }

        if (!timedTranscriptHash(
                sid,
                m2Length,
                inner,
                m3InnerLength,
                transcriptHash,
                metrics) ||
            !deriveSessionKeys(
                sharedSecret,
                transcriptHash,
                sessionKey,
                confirmA,
                confirmB,
                metrics) ||
            !computeConfirmationTag(
                DOMAIN_B_CONFIRM,
                confirmB,
                transcriptHash,
                tauB,
                metrics)) {
            goto cleanup;
        }

        m_m3[0] = PROTOCOL_VERSION;
        m_m3[1] = MSG_M3_RESP_FIN;
        memcpy(m_m3 + 2, sid, HASH_BYTES);
        putU16(m_m3 + 34, static_cast<uint16_t>(m3InnerLength));
        memcpy(m_m3 + 36 + m3InnerLength, tauB, HMAC_BYTES);
    }

    if (!sendProtocolMessage(
            initiatorIp,
            initiatorPort,
            MSG_M3_RESP_FIN,
            session,
            m_m3,
            static_cast<uint16_t>(m3Length),
            metrics,
            true)) {
        goto cleanup;
    }

    if (!receiveProtocolMessage(
            MSG_M4_INIT_FIN,
            session,
            m_m4,
            sizeof(m_m4),
            M4_BYTES,
            packet,
            metrics,
            true)) {
        Serial.println("Responder timed out waiting for M4.");
        goto cleanup;
    }

    if (m_m4[0] != PROTOCOL_VERSION ||
        m_m4[1] != MSG_M4_INIT_FIN ||
        !constantTimeEqual(m_m4 + 2, sid, HASH_BYTES) ||
        !computeConfirmationTag(
            DOMAIN_A_CONFIRM,
            confirmA,
            transcriptHash,
            expectedTauA,
            metrics) ||
        !constantTimeEqual(expectedTauA, m_m4 + 34, HMAC_BYTES)) {
        Serial.println("Responder rejected M4/tauA.");
        goto cleanup;
    }

    metrics.protocolUs = static_cast<uint64_t>(esp_timer_get_time() - responderStartUs);
    finalizeMetrics(metrics);
    accepted = true;

    memset(m_result, 0, RESULT_BYTES);
    m_result[0] = RESULT_OK;
    putU32(m_result + 4, qA);
    putU32(m_result + 8, qB);
    putU64(m_result + 12, metrics.protocolUs);
    putU64(m_result + 20, metrics.totalCryptoUs);
    putU64(m_result + 28, metrics.shaUs);
    putU64(m_result + 36, metrics.hmacUs);
    putU64(m_result + 44, metrics.lmotsSignUs);
    putU64(m_result + 52, metrics.lmotsVerifyUs);
    putU64(m_result + 60, metrics.kemUs);
    putU64(m_result + 68, metrics.pufFeUs);
    putU64(m_result + 76, metrics.repositoryUs);
    putU32(m_result + 84, metrics.appTxBytes);
    putU32(m_result + 88, metrics.appRxBytes);
    putU32(m_result + 92, metrics.framedTxBytes);
    putU32(m_result + 96, metrics.framedRxBytes);
    putU32(m_result + 100, metrics.repositoryTxBytes);
    putU32(m_result + 104, metrics.repositoryRxBytes);
    putU32(m_result + 108, ESP.getFreeHeap());
    putU32(m_result + 112, ESP.getMinFreeHeap());

    {
        LocalMetrics ignored;
        if (!sendProtocolMessage(
                initiatorIp,
                initiatorPort,
                MSG_RESULT,
                session,
                m_result,
                RESULT_BYTES,
                ignored,
                false)) {
            Serial.println("Responder could not send RESULT.");
        }
    }

cleanup:
    freeKem();
    wipeSessionSecrets(runtimeSeed, sharedSecret, sessionKey, confirmA, confirmB);
    CryptoHelpers::secureZero(tauB, sizeof(tauB));
    CryptoHelpers::secureZero(expectedTauA, sizeof(expectedTauA));
    CryptoHelpers::secureZero(peerPath, sizeof(peerPath));

    if (accepted) {
        Serial.printf(
            "Accepted session qA=%u qB=%u, B protocol %.3f ms, B crypto %.3f ms, repository %.3f ms\n",
            static_cast<unsigned>(qA),
            static_cast<unsigned>(qB),
            metrics.protocolUs / 1000.0,
            metrics.totalCryptoUs / 1000.0,
            metrics.repositoryUs / 1000.0);
    }
}

void ProposedUavProtocol::loop()
{
    if (!m_ready) {
        delay(1000);
        return;
    }

    if (m_config.role == Role::Initiator) {
        if (!m_initiatorCompleted) {
            runInitiatorExperiments();
        }
        else {
            delay(1000);
        }
    }
    else {
        runResponderOnce();
        delay(1);
    }
}

} // namespace puav
