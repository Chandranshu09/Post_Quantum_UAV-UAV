#include "LmotsLms.h"
#include "esp_heap_caps.h"

namespace puav {

LmotsLms::LmotsLms()
    : m_tree(nullptr)
{
    memset(m_identifier, 0, sizeof(m_identifier));
    memset(m_seed, 0, sizeof(m_seed));
    memset(m_smallHashInput, 0, sizeof(m_smallHashInput));
    memset(m_publicHashInput, 0, sizeof(m_publicHashInput));
}

LmotsLms::~LmotsLms()
{
    if (m_tree != nullptr) {
        heap_caps_free(m_tree);
        m_tree = nullptr;
    }
}

bool LmotsLms::initialize(
    const uint8_t identifierValue[16],
    const uint8_t seedValue[HASH_BYTES])
{
    if (identifierValue == nullptr || seedValue == nullptr) {
        return false;
    }

    memcpy(m_identifier, identifierValue, sizeof(m_identifier));
    memcpy(m_seed, seedValue, sizeof(m_seed));

    if (m_tree == nullptr) {
        const size_t treeBytes =
            LMS_TREE_NODES * HASH_BYTES;

        m_tree = reinterpret_cast<uint8_t (*)[HASH_BYTES]>(
            heap_caps_malloc(treeBytes, MALLOC_CAP_8BIT));

        if (m_tree == nullptr) {
            Serial.printf(
                "Could not allocate LMS tree: %u bytes\n",
                static_cast<unsigned>(treeBytes));
            return false;
        }
    }

    memset(
        m_tree,
        0,
        LMS_TREE_NODES * HASH_BYTES);

    return true;
}

uint8_t LmotsLms::coefficientW4(
    const uint8_t* data,
    size_t index)
{
    const uint8_t value = data[index / 2];

    if ((index & 1u) == 0) {
        return static_cast<uint8_t>((value >> 4) & 0x0f);
    }

    return static_cast<uint8_t>(value & 0x0f);
}

bool LmotsLms::derivePrivateElement(
    const uint8_t identifierValue[16],
    const uint8_t seedValue[HASH_BYTES],
    uint32_t q,
    uint16_t chainIndex,
    uint8_t output[HASH_BYTES],
    uint8_t* scratch)
{
    size_t offset = 0;

    memcpy(scratch + offset, identifierValue, 16);
    offset += 16;

    putU32(scratch + offset, q);
    offset += 4;

    putU16(scratch + offset, chainIndex);
    offset += 2;

    scratch[offset++] = 0xff;

    memcpy(scratch + offset, seedValue, HASH_BYTES);
    offset += HASH_BYTES;

    return CryptoHelpers::sha256(scratch, offset, output);
}

bool LmotsLms::chainHash(
    const uint8_t identifierValue[16],
    uint32_t q,
    uint16_t chainIndex,
    uint8_t startStep,
    uint8_t endStep,
    const uint8_t input[HASH_BYTES],
    uint8_t output[HASH_BYTES],
    uint8_t* scratch)
{
    uint8_t current[HASH_BYTES];
    uint8_t next[HASH_BYTES];

    memcpy(current, input, HASH_BYTES);

    for (uint8_t j = startStep; j < endStep; ++j) {
        size_t offset = 0;

        memcpy(scratch + offset, identifierValue, 16);
        offset += 16;

        putU32(scratch + offset, q);
        offset += 4;

        putU16(scratch + offset, chainIndex);
        offset += 2;

        scratch[offset++] = j;

        memcpy(scratch + offset, current, HASH_BYTES);
        offset += HASH_BYTES;

        if (!CryptoHelpers::sha256(
                scratch,
                offset,
                next)) {
            return false;
        }

        memcpy(current, next, HASH_BYTES);
    }

    memcpy(output, current, HASH_BYTES);
    return true;
}

bool LmotsLms::hashMessageWithChecksum(
    const uint8_t identifierValue[16],
    uint32_t q,
    const uint8_t C[HASH_BYTES],
    const uint8_t* message,
    size_t messageLength,
    uint8_t output[HASH_BYTES + 2],
    uint8_t* scratch,
    size_t scratchLength)
{
    const size_t required =
        16 + 4 + 2 + HASH_BYTES + messageLength;

    if (required > scratchLength) {
        return false;
    }

    size_t offset = 0;

    memcpy(scratch + offset, identifierValue, 16);
    offset += 16;

    putU32(scratch + offset, q);
    offset += 4;

    putU16(scratch + offset, D_MESG);
    offset += 2;

    memcpy(scratch + offset, C, HASH_BYTES);
    offset += HASH_BYTES;

    memcpy(scratch + offset, message, messageLength);
    offset += messageLength;

    if (!CryptoHelpers::sha256(
            scratch,
            offset,
            output)) {
        return false;
    }

    uint16_t checksum = 0;

    for (size_t i = 0; i < 64; ++i) {
        checksum = static_cast<uint16_t>(
            checksum + MAX_CHAIN - coefficientW4(output, i));
    }

    checksum = static_cast<uint16_t>(checksum << LS);
    putU16(output + HASH_BYTES, checksum);

    return true;
}

bool LmotsLms::lmotsPublicHash(
    const uint8_t identifierValue[16],
    const uint8_t seedValue[HASH_BYTES],
    uint32_t q,
    uint8_t output[HASH_BYTES],
    uint8_t* smallScratch,
    uint8_t* publicScratch)
{
    size_t prefix = 0;

    memcpy(publicScratch + prefix, identifierValue, 16);
    prefix += 16;

    putU32(publicScratch + prefix, q);
    prefix += 4;

    putU16(publicScratch + prefix, D_PBLC);
    prefix += 2;

    uint8_t x[HASH_BYTES];
    uint8_t chainEnd[HASH_BYTES];

    for (uint16_t i = 0; i < P; ++i) {
        if (!derivePrivateElement(
                identifierValue,
                seedValue,
                q,
                i,
                x,
                smallScratch)) {
            return false;
        }

        if (!chainHash(
                identifierValue,
                q,
                i,
                0,
                MAX_CHAIN,
                x,
                chainEnd,
                smallScratch)) {
            return false;
        }

        memcpy(
            publicScratch + prefix + i * HASH_BYTES,
            chainEnd,
            HASH_BYTES);
    }

    return CryptoHelpers::sha256(
        publicScratch,
        16 + 4 + 2 + P * HASH_BYTES,
        output);
}

bool LmotsLms::hashLeaf(
    const uint8_t identifierValue[16],
    uint32_t nodeNumber,
    const uint8_t lmotsPublicHashValue[HASH_BYTES],
    uint8_t output[HASH_BYTES],
    uint8_t* scratch)
{
    size_t offset = 0;

    memcpy(scratch + offset, identifierValue, 16);
    offset += 16;

    putU32(scratch + offset, nodeNumber);
    offset += 4;

    putU16(scratch + offset, D_LEAF);
    offset += 2;

    memcpy(
        scratch + offset,
        lmotsPublicHashValue,
        HASH_BYTES);
    offset += HASH_BYTES;

    return CryptoHelpers::sha256(scratch, offset, output);
}

bool LmotsLms::hashInternal(
    const uint8_t identifierValue[16],
    uint32_t nodeNumber,
    const uint8_t left[HASH_BYTES],
    const uint8_t right[HASH_BYTES],
    uint8_t output[HASH_BYTES],
    uint8_t* scratch)
{
    size_t offset = 0;

    memcpy(scratch + offset, identifierValue, 16);
    offset += 16;

    putU32(scratch + offset, nodeNumber);
    offset += 4;

    putU16(scratch + offset, D_INTR);
    offset += 2;

    memcpy(scratch + offset, left, HASH_BYTES);
    offset += HASH_BYTES;

    memcpy(scratch + offset, right, HASH_BYTES);
    offset += HASH_BYTES;

    return CryptoHelpers::sha256(scratch, offset, output);
}

bool LmotsLms::buildTree(bool printProgress)
{
    if (m_tree == nullptr) {
        Serial.println("LMS tree memory is not allocated.");
        return false;
    }

    uint8_t lmotsHash[HASH_BYTES];

    for (uint32_t q = 0; q < LMS_LEAVES; ++q) {
        if (!lmotsPublicHash(
                m_identifier,
                m_seed,
                q,
                lmotsHash,
                m_smallHashInput,
                m_publicHashInput)) {
            return false;
        }

        const uint32_t node = LMS_LEAVES + q;

        if (!hashLeaf(
                m_identifier,
                node,
                lmotsHash,
                m_tree[node],
                m_smallHashInput)) {
            return false;
        }

        if ((q & 3u) == 3u) {
            yield();
        }

        if (printProgress && (q & 63u) == 63u) {
            Serial.printf(
                "LMS leaves completed: %u / %u\n",
                static_cast<unsigned>(q + 1),
                static_cast<unsigned>(LMS_LEAVES));
        }
    }

    for (int32_t node = static_cast<int32_t>(LMS_LEAVES) - 1;
         node >= 1;
         --node) {
        if (!hashInternal(
                m_identifier,
                static_cast<uint32_t>(node),
                m_tree[2 * node],
                m_tree[2 * node + 1],
                m_tree[node],
                m_smallHashInput)) {
            CryptoHelpers::secureZero(m_seed, sizeof(m_seed));
            return false;
        }

        if ((node & 127) == 0) {
            yield();
        }
    }

    /* The retained tree and paths are public. Signing reconstructs the seed
       through the PUF/FE hook, so the temporary build seed is no longer needed. */
    CryptoHelpers::secureZero(m_seed, sizeof(m_seed));
    return true;
}

const uint8_t* LmotsLms::root() const
{
    return m_tree == nullptr ? nullptr : m_tree[1];
}

const uint8_t* LmotsLms::identifier() const
{
    return m_identifier;
}

bool LmotsLms::extractPath(
    uint32_t q,
    uint8_t path[LMS_PATH_BYTES]) const
{
    if (m_tree == nullptr ||
        q >= LMS_LEAVES ||
        path == nullptr) {
        return false;
    }

    uint32_t node = LMS_LEAVES + q;

    for (size_t level = 0; level < LMS_HEIGHT; ++level) {
        memcpy(
            path + level * HASH_BYTES,
            m_tree[node ^ 1u],
            HASH_BYTES);
        node >>= 1;
    }

    return true;
}

bool LmotsLms::sign(
    uint32_t q,
    const uint8_t* message,
    size_t messageLength,
    const uint8_t runtimeSeed[HASH_BYTES],
    uint8_t signature[LMOTS_SIGNATURE_BYTES])
{
    if (q >= LMS_LEAVES || message == nullptr ||
        runtimeSeed == nullptr || signature == nullptr) {
        return false;
    }

    putU32(signature, LMOTS_TYPE);

    uint8_t C[HASH_BYTES];
    esp_fill_random(C, sizeof(C));
    memcpy(signature + 4, C, HASH_BYTES);

    uint8_t digestAndChecksum[HASH_BYTES + 2];

    if (!hashMessageWithChecksum(
            m_identifier,
            q,
            C,
            message,
            messageLength,
            digestAndChecksum,
            m_smallHashInput,
            sizeof(m_smallHashInput))) {
        return false;
    }

    uint8_t x[HASH_BYTES];
    uint8_t y[HASH_BYTES];

    for (uint16_t i = 0; i < P; ++i) {
        const uint8_t a =
            coefficientW4(digestAndChecksum, i);

        if (!derivePrivateElement(
                m_identifier,
                runtimeSeed,
                q,
                i,
                x,
                m_smallHashInput)) {
            return false;
        }

        if (!chainHash(
                m_identifier,
                q,
                i,
                0,
                a,
                x,
                y,
                m_smallHashInput)) {
            return false;
        }

        memcpy(
            signature + 4 + HASH_BYTES + i * HASH_BYTES,
            y,
            HASH_BYTES);
    }

    return true;
}

bool LmotsLms::lmotsCandidatePublicHash(
    const uint8_t identifierValue[16],
    uint32_t q,
    const uint8_t* message,
    size_t messageLength,
    const uint8_t signature[LMOTS_SIGNATURE_BYTES],
    uint8_t output[HASH_BYTES],
    uint8_t* smallScratch,
    uint8_t* publicScratch)
{
    if (getU32(signature) != LMOTS_TYPE) {
        return false;
    }

    const uint8_t* C = signature + 4;
    const uint8_t* yArray = signature + 4 + HASH_BYTES;

    uint8_t digestAndChecksum[HASH_BYTES + 2];

    if (!hashMessageWithChecksum(
            identifierValue,
            q,
            C,
            message,
            messageLength,
            digestAndChecksum,
            smallScratch,
            1024)) {
        return false;
    }

    size_t prefix = 0;

    memcpy(publicScratch + prefix, identifierValue, 16);
    prefix += 16;

    putU32(publicScratch + prefix, q);
    prefix += 4;

    putU16(publicScratch + prefix, D_PBLC);
    prefix += 2;

    uint8_t chainEnd[HASH_BYTES];

    for (uint16_t i = 0; i < P; ++i) {
        const uint8_t a =
            coefficientW4(digestAndChecksum, i);

        if (!chainHash(
                identifierValue,
                q,
                i,
                a,
                MAX_CHAIN,
                yArray + i * HASH_BYTES,
                chainEnd,
                smallScratch)) {
            return false;
        }

        memcpy(
            publicScratch + prefix + i * HASH_BYTES,
            chainEnd,
            HASH_BYTES);
    }

    return CryptoHelpers::sha256(
        publicScratch,
        16 + 4 + 2 + P * HASH_BYTES,
        output);
}

bool LmotsLms::verify(
    uint32_t q,
    const uint8_t* message,
    size_t messageLength,
    const uint8_t signature[LMOTS_SIGNATURE_BYTES],
    const uint8_t peerIdentifier[16],
    const uint8_t peerPath[LMS_PATH_BYTES],
    const uint8_t peerRoot[HASH_BYTES])
{
    if (q >= LMS_LEAVES || message == nullptr ||
        signature == nullptr || peerIdentifier == nullptr ||
        peerPath == nullptr || peerRoot == nullptr) {
        return false;
    }

    /*
      Static scratch keeps the roughly 3.2 KB verifier workspace off the
      Arduino loop-task stack. Verification is single-threaded in this test.
    */
    static uint8_t smallScratch[1024];
    static uint8_t publicScratch[16 + 4 + 2 + P * HASH_BYTES];
    uint8_t lmotsHash[HASH_BYTES];

    if (!lmotsCandidatePublicHash(
            peerIdentifier,
            q,
            message,
            messageLength,
            signature,
            lmotsHash,
            smallScratch,
            publicScratch)) {
        return false;
    }

    uint32_t node = LMS_LEAVES + q;
    uint8_t current[HASH_BYTES];

    if (!hashLeaf(
            peerIdentifier,
            node,
            lmotsHash,
            current,
            smallScratch)) {
        return false;
    }

    for (size_t level = 0; level < LMS_HEIGHT; ++level) {
        uint8_t parent[HASH_BYTES];
        const uint8_t* sibling =
            peerPath + level * HASH_BYTES;
        const uint32_t parentNode = node >> 1;

        bool ok;

        if ((node & 1u) == 0) {
            ok = hashInternal(
                peerIdentifier,
                parentNode,
                current,
                sibling,
                parent,
                smallScratch);
        }
        else {
            ok = hashInternal(
                peerIdentifier,
                parentNode,
                sibling,
                current,
                parent,
                smallScratch);
        }

        if (!ok) {
            return false;
        }

        memcpy(current, parent, HASH_BYTES);
        node = parentNode;
    }

    return constantTimeEqual(current, peerRoot, HASH_BYTES);
}

} // namespace puav
