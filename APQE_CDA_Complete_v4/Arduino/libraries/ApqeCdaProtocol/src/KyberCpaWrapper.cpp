#include "KyberCpaWrapper.h"

extern "C" {
#include "vendor/kyber_ref/params.h"
#include "vendor/kyber_ref/indcpa.h"
#include "vendor/kyber_ref/randombytes.h"
}

namespace apqe {

static_assert(KYBER_INDCPA_PUBLICKEYBYTES == KYBER_PUBLIC_KEY_BYTES,
              "Kyber public-key size mismatch");
static_assert(KYBER_INDCPA_SECRETKEYBYTES == KYBER_SECRET_KEY_BYTES,
              "Kyber secret-key size mismatch");
static_assert(KYBER_INDCPA_BYTES == KYBER_CIPHERTEXT_BYTES,
              "Kyber ciphertext size mismatch");
static_assert(KYBER_INDCPA_MSGBYTES == KYBER_MESSAGE_BYTES,
              "Kyber message size mismatch");
static_assert(KYBER_SYMBYTES == KYBER_COINS_BYTES,
              "Kyber coins size mismatch");

bool KyberCpaWrapper::keypairDeterministic(
    const uint8_t seed[KYBER_COINS_BYTES],
    uint8_t publicKey[KYBER_PUBLIC_KEY_BYTES],
    uint8_t secretKey[KYBER_SECRET_KEY_BYTES])
{
    if (seed == nullptr || publicKey == nullptr || secretKey == nullptr) {
        return false;
    }
    apqe_randombytes_set_seed(seed);
    indcpa_keypair(publicKey, secretKey);
    return true;
}

bool KyberCpaWrapper::encrypt(
    const uint8_t message[KYBER_MESSAGE_BYTES],
    const uint8_t publicKey[KYBER_PUBLIC_KEY_BYTES],
    const uint8_t coins[KYBER_COINS_BYTES],
    uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES])
{
    if (message == nullptr || publicKey == nullptr ||
        coins == nullptr || ciphertext == nullptr) {
        return false;
    }
    indcpa_enc(ciphertext, message, publicKey, coins);
    return true;
}

bool KyberCpaWrapper::decrypt(
    const uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES],
    const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
    uint8_t message[KYBER_MESSAGE_BYTES])
{
    if (ciphertext == nullptr || secretKey == nullptr || message == nullptr) {
        return false;
    }
    indcpa_dec(message, ciphertext, secretKey);
    return true;
}

} // namespace apqe
