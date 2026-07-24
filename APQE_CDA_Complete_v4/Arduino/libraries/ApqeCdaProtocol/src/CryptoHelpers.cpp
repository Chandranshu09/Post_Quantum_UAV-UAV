#include "CryptoHelpers.h"

#include <esp_system.h>

namespace apqe {

int CryptoHelpers::s_lastError = 0;

bool CryptoHelpers::sha256(const uint8_t* data, size_t length, uint8_t out[HASH_BYTES])
{
    const uint8_t* parts[1] = {data};
    const size_t lengths[1] = {length};
    return sha256Parts(parts, lengths, 1, out);
}

bool CryptoHelpers::sha256Parts(
    const uint8_t* const* parts,
    const size_t* lengths,
    size_t count,
    uint8_t out[HASH_BYTES])
{
    if (parts == nullptr || lengths == nullptr || out == nullptr) {
        s_lastError = -1;
        return false;
    }

    wc_Sha256 sha;
    int ret = wc_InitSha256(&sha);
    if (ret != 0) {
        s_lastError = ret;
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        if (parts[i] == nullptr || lengths[i] > UINT32_MAX) {
            s_lastError = -2;
            return false;
        }
        ret = wc_Sha256Update(
            &sha,
            reinterpret_cast<const byte*>(parts[i]),
            static_cast<word32>(lengths[i]));
        if (ret != 0) {
            s_lastError = ret;
            return false;
        }
    }

    ret = wc_Sha256Final(&sha, reinterpret_cast<byte*>(out));
    if (ret != 0) {
        s_lastError = ret;
        return false;
    }
    return true;
}

bool CryptoHelpers::hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t out[HASH_BYTES])
{
    if (key == nullptr || data == nullptr || out == nullptr ||
        keyLength > UINT32_MAX || dataLength > UINT32_MAX) {
        s_lastError = -3;
        return false;
    }

    Hmac hmac;
    memset(&hmac, 0, sizeof(hmac));
    int ret = wc_HmacSetKey(
        &hmac,
        WC_SHA256,
        reinterpret_cast<const byte*>(key),
        static_cast<word32>(keyLength));
    if (ret != 0) {
        s_lastError = ret;
        return false;
    }
    ret = wc_HmacUpdate(
        &hmac,
        reinterpret_cast<const byte*>(data),
        static_cast<word32>(dataLength));
    if (ret != 0) {
        s_lastError = ret;
        return false;
    }
    ret = wc_HmacFinal(&hmac, reinterpret_cast<byte*>(out));
    if (ret != 0) {
        s_lastError = ret;
        return false;
    }
    return true;
}

void CryptoHelpers::randomBytes(uint8_t* output, size_t length)
{
    if (output != nullptr && length != 0) {
        esp_fill_random(output, length);
    }
}

int CryptoHelpers::lastError()
{
    return s_lastError;
}

} // namespace apqe
