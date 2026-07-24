#pragma once

#include <Arduino.h>

#include "ApqeConstants.h"

namespace apqe {

class SoftwarePuf {
public:
    SoftwarePuf();

    bool begin(
        const uint8_t rawSram[HASH_BYTES],
        const uint8_t helper[HASH_BYTES],
        const uint8_t bsPufSecret[HASH_BYTES]);

    bool reconstructKyberSeed(uint8_t seed[HASH_BYTES]) const;
    void commutativeMap(const uint8_t input[PUF_BYTES], uint8_t output[PUF_BYTES]) const;
    bool reversibleMap(
        const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
        const uint8_t challenge[CHALLENGE_BYTES],
        uint8_t tid[TID_BYTES]) const;
    bool reversibleInverse(
        const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
        const uint8_t tid[TID_BYTES],
        uint8_t challenge[CHALLENGE_BYTES]) const;

private:
    uint8_t m_rawSram[HASH_BYTES];
    uint8_t m_helper[HASH_BYTES];
    uint8_t m_commutativeMask[HASH_BYTES];
    uint8_t m_reversibleSecret[HASH_BYTES];

    bool reversibleMask(
        const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
        uint8_t mask[HASH_BYTES]) const;
};

} // namespace apqe
