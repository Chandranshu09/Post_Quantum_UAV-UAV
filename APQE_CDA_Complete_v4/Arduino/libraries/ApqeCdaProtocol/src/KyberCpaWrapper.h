#pragma once

#include <Arduino.h>

#include "ApqeConstants.h"

namespace apqe {

class KyberCpaWrapper {
public:
    static bool keypairDeterministic(
        const uint8_t seed[KYBER_COINS_BYTES],
        uint8_t publicKey[KYBER_PUBLIC_KEY_BYTES],
        uint8_t secretKey[KYBER_SECRET_KEY_BYTES]);

    static bool encrypt(
        const uint8_t message[KYBER_MESSAGE_BYTES],
        const uint8_t publicKey[KYBER_PUBLIC_KEY_BYTES],
        const uint8_t coins[KYBER_COINS_BYTES],
        uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES]);

    static bool decrypt(
        const uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES],
        const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
        uint8_t message[KYBER_MESSAGE_BYTES]);
};

} // namespace apqe
