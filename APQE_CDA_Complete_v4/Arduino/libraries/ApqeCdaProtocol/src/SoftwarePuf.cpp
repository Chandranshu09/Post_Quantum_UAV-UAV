#include "SoftwarePuf.h"

#include "CryptoHelpers.h"

namespace apqe {

SoftwarePuf::SoftwarePuf()
{
    memset(m_rawSram, 0, sizeof(m_rawSram));
    memset(m_helper, 0, sizeof(m_helper));
    memset(m_commutativeMask, 0, sizeof(m_commutativeMask));
    memset(m_reversibleSecret, 0, sizeof(m_reversibleSecret));
}

bool SoftwarePuf::begin(
    const uint8_t rawSram[HASH_BYTES],
    const uint8_t helper[HASH_BYTES],
    const uint8_t bsPufSecret[HASH_BYTES])
{
    if (rawSram == nullptr || helper == nullptr || bsPufSecret == nullptr) {
        return false;
    }
    memcpy(m_rawSram, rawSram, HASH_BYTES);
    memcpy(m_helper, helper, HASH_BYTES);

    static const uint8_t commLabel[] = {'A','P','Q','E','-','C','O','M','M'};
    static const uint8_t revLabel[] = {'A','P','Q','E','-','R','E','V'};
    const uint8_t* commParts[] = {commLabel, bsPufSecret};
    const size_t commLengths[] = {sizeof(commLabel), HASH_BYTES};
    const uint8_t* revParts[] = {revLabel, bsPufSecret};
    const size_t revLengths[] = {sizeof(revLabel), HASH_BYTES};

    return CryptoHelpers::sha256Parts(
               commParts, commLengths, 2, m_commutativeMask) &&
           CryptoHelpers::sha256Parts(
               revParts, revLengths, 2, m_reversibleSecret);
}

bool SoftwarePuf::reconstructKyberSeed(uint8_t seed[HASH_BYTES]) const
{
    static const uint8_t label[] = {
        'S','R','A','M','-','F','E','-','E','M','U'
    };
    const uint8_t* parts[] = {label, m_rawSram, m_helper};
    const size_t lengths[] = {sizeof(label), HASH_BYTES, HASH_BYTES};
    return CryptoHelpers::sha256Parts(parts, lengths, 3, seed);
}

void SoftwarePuf::commutativeMap(
    const uint8_t input[PUF_BYTES],
    uint8_t output[PUF_BYTES]) const
{
    for (size_t i = 0; i < PUF_BYTES; ++i) {
        output[i] = static_cast<uint8_t>(input[i] ^ m_commutativeMask[i]);
    }
}

bool SoftwarePuf::reversibleMask(
    const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
    uint8_t mask[HASH_BYTES]) const
{
    uint8_t skHash[HASH_BYTES];
    if (!CryptoHelpers::sha256(secretKey, KYBER_SECRET_KEY_BYTES, skHash)) {
        return false;
    }
    static const uint8_t label[] = {'R','E','V','-','M','A','S','K'};
    const uint8_t* parts[] = {label, skHash, m_reversibleSecret};
    const size_t lengths[] = {sizeof(label), HASH_BYTES, HASH_BYTES};
    return CryptoHelpers::sha256Parts(parts, lengths, 3, mask);
}

bool SoftwarePuf::reversibleMap(
    const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
    const uint8_t challenge[CHALLENGE_BYTES],
    uint8_t tid[TID_BYTES]) const
{
    uint8_t mask[HASH_BYTES];
    if (!reversibleMask(secretKey, mask)) {
        return false;
    }
    for (size_t i = 0; i < TID_BYTES; ++i) {
        tid[i] = static_cast<uint8_t>(challenge[i] ^ mask[i]);
    }
    return true;
}

bool SoftwarePuf::reversibleInverse(
    const uint8_t secretKey[KYBER_SECRET_KEY_BYTES],
    const uint8_t tid[TID_BYTES],
    uint8_t challenge[CHALLENGE_BYTES]) const
{
    return reversibleMap(secretKey, tid, challenge);
}

} // namespace apqe
