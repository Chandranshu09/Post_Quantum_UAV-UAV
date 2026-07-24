#pragma once

#include <Arduino.h>

#include "ProtocolConstants.h"
#include "CryptoHelpers.h"

namespace puav {

class LmotsLms {
public:
    LmotsLms();
    ~LmotsLms();

    LmotsLms(const LmotsLms&) = delete;
    LmotsLms& operator=(const LmotsLms&) = delete;

    bool initialize(
        const uint8_t identifier[16],
        const uint8_t seed[HASH_BYTES]);

    bool buildTree(bool printProgress);

    const uint8_t* root() const;
    const uint8_t* identifier() const;

    bool extractPath(
        uint32_t q,
        uint8_t path[LMS_PATH_BYTES]) const;

    bool sign(
        uint32_t q,
        const uint8_t* message,
        size_t messageLength,
        const uint8_t runtimeSeed[HASH_BYTES],
        uint8_t signature[LMOTS_SIGNATURE_BYTES]);

    static bool verify(
        uint32_t q,
        const uint8_t* message,
        size_t messageLength,
        const uint8_t signature[LMOTS_SIGNATURE_BYTES],
        const uint8_t peerIdentifier[16],
        const uint8_t peerPath[LMS_PATH_BYTES],
        const uint8_t peerRoot[HASH_BYTES]);

private:
    static constexpr uint32_t LMOTS_TYPE = 3;
    static constexpr uint32_t LMS_TYPE = 6;
    static constexpr size_t N = 32;
    static constexpr size_t P = 67;
    static constexpr uint8_t W = 4;
    static constexpr uint8_t LS = 4;
    static constexpr uint8_t MAX_CHAIN = 15;

    static constexpr uint16_t D_PBLC = 0x8080;
    static constexpr uint16_t D_MESG = 0x8181;
    static constexpr uint16_t D_LEAF = 0x8282;
    static constexpr uint16_t D_INTR = 0x8383;

    uint8_t m_identifier[16];
    uint8_t m_seed[HASH_BYTES];

    /*
      The full h=10 tree is 65,536 bytes. Keeping it as a direct class
      member places it in .dram0.bss and can overflow the ESP32 static DRAM
      linker region. It is therefore allocated from the runtime heap before
      Wi-Fi starts.
    */
    uint8_t (*m_tree)[HASH_BYTES];

    uint8_t m_smallHashInput[1024];
    uint8_t m_publicHashInput[16 + 4 + 2 + P * N];

    static uint8_t coefficientW4(
        const uint8_t* data,
        size_t index);

    static bool hashMessageWithChecksum(
        const uint8_t identifier[16],
        uint32_t q,
        const uint8_t C[HASH_BYTES],
        const uint8_t* message,
        size_t messageLength,
        uint8_t output[HASH_BYTES + 2],
        uint8_t* scratch,
        size_t scratchLength);

    static bool derivePrivateElement(
        const uint8_t identifier[16],
        const uint8_t seed[HASH_BYTES],
        uint32_t q,
        uint16_t chainIndex,
        uint8_t output[HASH_BYTES],
        uint8_t* scratch);

    static bool chainHash(
        const uint8_t identifier[16],
        uint32_t q,
        uint16_t chainIndex,
        uint8_t startStep,
        uint8_t endStep,
        const uint8_t input[HASH_BYTES],
        uint8_t output[HASH_BYTES],
        uint8_t* scratch);

    static bool lmotsPublicHash(
        const uint8_t identifier[16],
        const uint8_t seed[HASH_BYTES],
        uint32_t q,
        uint8_t output[HASH_BYTES],
        uint8_t* smallScratch,
        uint8_t* publicScratch);

    static bool lmotsCandidatePublicHash(
        const uint8_t identifier[16],
        uint32_t q,
        const uint8_t* message,
        size_t messageLength,
        const uint8_t signature[LMOTS_SIGNATURE_BYTES],
        uint8_t output[HASH_BYTES],
        uint8_t* smallScratch,
        uint8_t* publicScratch);

    static bool hashLeaf(
        const uint8_t identifier[16],
        uint32_t nodeNumber,
        const uint8_t lmotsPublicHashValue[HASH_BYTES],
        uint8_t output[HASH_BYTES],
        uint8_t* scratch);

    static bool hashInternal(
        const uint8_t identifier[16],
        uint32_t nodeNumber,
        const uint8_t left[HASH_BYTES],
        const uint8_t right[HASH_BYTES],
        uint8_t output[HASH_BYTES],
        uint8_t* scratch);
};

} // namespace puav
