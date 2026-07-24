#pragma once

#include <Arduino.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "ApqeConstants.h"

namespace apqe {

class CryptoHelpers {
public:
    static bool sha256(const uint8_t* data, size_t length, uint8_t out[HASH_BYTES]);
    static bool sha256Parts(
        const uint8_t* const* parts,
        const size_t* lengths,
        size_t count,
        uint8_t out[HASH_BYTES]);
    static bool hmacSha256(
        const uint8_t* key,
        size_t keyLength,
        const uint8_t* data,
        size_t dataLength,
        uint8_t out[HASH_BYTES]);
    static void randomBytes(uint8_t* output, size_t length);
    static int lastError();

private:
    static int s_lastError;
};

} // namespace apqe
