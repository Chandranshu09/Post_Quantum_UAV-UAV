#include "CryptoHelpers.h"

namespace puav {

int CryptoHelpers::s_lastError = 0;

bool CryptoHelpers::sha256(
    const uint8_t* data,
    size_t length,
    uint8_t output[HASH_BYTES])
{
    if ((data == nullptr && length != 0) || output == nullptr ||
        length > UINT32_MAX) {
        s_lastError = -1;
        return false;
    }

    wc_Sha256 sha;
    int ret = wc_InitSha256(&sha);

    if (ret == 0 && length != 0) {
        ret = wc_Sha256Update(
            &sha,
            reinterpret_cast<const byte*>(data),
            static_cast<word32>(length));
    }

    if (ret == 0) {
        ret = wc_Sha256Final(
            &sha,
            reinterpret_cast<byte*>(output));
    }

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
    uint8_t output[HMAC_BYTES])
{
    if ((key == nullptr && keyLength != 0) ||
        (data == nullptr && dataLength != 0) || output == nullptr ||
        keyLength > UINT32_MAX || dataLength > UINT32_MAX) {
        s_lastError = -2;
        return false;
    }

    Hmac hmac;
    memset(&hmac, 0, sizeof(hmac));

    int ret = wc_HmacSetKey(
        &hmac,
        WC_SHA256,
        reinterpret_cast<const byte*>(key),
        static_cast<word32>(keyLength));

    if (ret == 0 && dataLength != 0) {
        ret = wc_HmacUpdate(
            &hmac,
            reinterpret_cast<const byte*>(data),
            static_cast<word32>(dataLength));
    }

    if (ret == 0) {
        ret = wc_HmacFinal(
            &hmac,
            reinterpret_cast<byte*>(output));
    }

    if (ret != 0) {
        s_lastError = ret;
        return false;
    }

    return true;
}

bool CryptoHelpers::hkdfSha256(
    const uint8_t* ikm,
    size_t ikmLength,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* info,
    size_t infoLength,
    uint8_t* output,
    size_t outputLength)
{
    if ((ikm == nullptr && ikmLength != 0) ||
        (salt == nullptr && saltLength != 0) ||
        (info == nullptr && infoLength != 0) || output == nullptr ||
        ikmLength > UINT32_MAX || saltLength > UINT32_MAX ||
        infoLength > UINT32_MAX || outputLength == 0 ||
        outputLength > 255u * HASH_BYTES) {
        s_lastError = -3;
        return false;
    }

    static const uint8_t ZERO_SALT[HASH_BYTES] = {0};
    const uint8_t* effectiveSalt = saltLength == 0 ? ZERO_SALT : salt;
    const size_t effectiveSaltLength = saltLength == 0
        ? sizeof(ZERO_SALT)
        : saltLength;

    uint8_t prk[HASH_BYTES];

    if (!hmacSha256(
            effectiveSalt,
            effectiveSaltLength,
            ikm,
            ikmLength,
            prk)) {
        return false;
    }

    uint8_t previous[HASH_BYTES];
    uint8_t block[HASH_BYTES];
    size_t previousLength = 0;
    size_t outputOffset = 0;
    uint8_t counter = 1;

    /* Largest use in this package is 32 + 34 + 1 bytes. */
    uint8_t expandInput[HASH_BYTES + 128 + 1];

    if (infoLength > 128) {
        secureZero(prk, sizeof(prk));
        s_lastError = -4;
        return false;
    }

    while (outputOffset < outputLength) {
        size_t offset = 0;

        if (previousLength != 0) {
            memcpy(expandInput + offset, previous, previousLength);
            offset += previousLength;
        }

        if (infoLength != 0) {
            memcpy(expandInput + offset, info, infoLength);
            offset += infoLength;
        }

        expandInput[offset++] = counter;

        if (!hmacSha256(
                prk,
                sizeof(prk),
                expandInput,
                offset,
                block)) {
            secureZero(prk, sizeof(prk));
            secureZero(previous, sizeof(previous));
            secureZero(block, sizeof(block));
            secureZero(expandInput, sizeof(expandInput));
            return false;
        }

        const size_t remaining = outputLength - outputOffset;
        const size_t copyLength = remaining < HASH_BYTES
            ? remaining
            : HASH_BYTES;

        memcpy(output + outputOffset, block, copyLength);
        memcpy(previous, block, HASH_BYTES);
        previousLength = HASH_BYTES;
        outputOffset += copyLength;
        ++counter;
    }

    secureZero(prk, sizeof(prk));
    secureZero(previous, sizeof(previous));
    secureZero(block, sizeof(block));
    secureZero(expandInput, sizeof(expandInput));
    return true;
}

bool CryptoHelpers::deriveLmsSeed(
    const uint8_t pufRoot[HASH_BYTES],
    const uint8_t deviceId[ID_BYTES],
    uint32_t credentialVersion,
    const uint8_t identifier[16],
    uint8_t seed[HASH_BYTES])
{
    if (pufRoot == nullptr || deviceId == nullptr ||
        identifier == nullptr || seed == nullptr) {
        s_lastError = -5;
        return false;
    }

    static constexpr uint8_t LABEL[] = {
        'L','M','S','-','S','E','E','D'
    };

    uint8_t info[
        sizeof(LABEL) + ID_BYTES + 4 + 16];
    size_t offset = 0;

    memcpy(info + offset, LABEL, sizeof(LABEL));
    offset += sizeof(LABEL);
    memcpy(info + offset, deviceId, ID_BYTES);
    offset += ID_BYTES;
    putU32(info + offset, credentialVersion);
    offset += 4;
    memcpy(info + offset, identifier, 16);
    offset += 16;

    return hkdfSha256(
        pufRoot,
        HASH_BYTES,
        nullptr,
        0,
        info,
        offset,
        seed,
        HASH_BYTES);
}

bool CryptoHelpers::helperDataDigest(
    const uint8_t helperData[FE_HELPER_PLACEHOLDER_BYTES],
    uint8_t digest[HASH_BYTES])
{
    return sha256(
        helperData,
        FE_HELPER_PLACEHOLDER_BYTES,
        digest);
}

void CryptoHelpers::secureZero(void* memory, size_t length)
{
    volatile uint8_t* cursor =
        reinterpret_cast<volatile uint8_t*>(memory);

    while (length-- != 0) {
        *cursor++ = 0;
    }
}

int CryptoHelpers::lastError()
{
    return s_lastError;
}

} // namespace puav
