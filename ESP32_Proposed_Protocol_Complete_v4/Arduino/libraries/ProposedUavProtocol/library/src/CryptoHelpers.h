#pragma once

#include <Arduino.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "ProtocolConstants.h"

namespace puav {

class CryptoHelpers {
public:
    static bool sha256(
        const uint8_t* data,
        size_t length,
        uint8_t output[HASH_BYTES]);

    static bool hmacSha256(
        const uint8_t* key,
        size_t keyLength,
        const uint8_t* data,
        size_t dataLength,
        uint8_t output[HMAC_BYTES]);

    static bool hkdfSha256(
        const uint8_t* ikm,
        size_t ikmLength,
        const uint8_t* salt,
        size_t saltLength,
        const uint8_t* info,
        size_t infoLength,
        uint8_t* output,
        size_t outputLength);

    static bool deriveLmsSeed(
        const uint8_t pufRoot[HASH_BYTES],
        const uint8_t deviceId[ID_BYTES],
        uint32_t credentialVersion,
        const uint8_t identifier[16],
        uint8_t seed[HASH_BYTES]);

    static bool helperDataDigest(
        const uint8_t helperData[FE_HELPER_PLACEHOLDER_BYTES],
        uint8_t digest[HASH_BYTES]);

    static void secureZero(void* memory, size_t length);

    static int lastError();

private:
    static int s_lastError;
};

} // namespace puav
