#include "PufFeProvider.h"

#include "CryptoHelpers.h"

namespace puav {

bool PufFeProvider::reconstruct(
    const NodeConfig& config,
    uint8_t output[HASH_BYTES])
{
    if (output == nullptr) {
        return false;
    }

    /*
      Laboratory placeholder. hardcodedPufRoot represents the already stable
      output of FE.Rep(APUF_response, helper_data). Hashing the local helper
      exercises the configured input and makes accidental all-zero/unset helper
      values visible during debugging, but the digest is not used as secret
      entropy and is not transmitted.
    */
    uint8_t helperOr = 0;
    for (size_t i = 0; i < FE_HELPER_PLACEHOLDER_BYTES; ++i) {
        helperOr |= config.hardcodedHelperData[i];
    }
    if (helperOr == 0) {
        return false;
    }

    uint8_t helperDigest[HASH_BYTES];
    if (!CryptoHelpers::helperDataDigest(
            config.hardcodedHelperData,
            helperDigest)) {
        return false;
    }
    CryptoHelpers::secureZero(helperDigest, sizeof(helperDigest));

    uint8_t rootOr = 0;
    for (size_t i = 0; i < HASH_BYTES; ++i) {
        rootOr |= config.hardcodedPufRoot[i];
    }
    if (rootOr == 0) {
        return false;
    }

    memcpy(output, config.hardcodedPufRoot, HASH_BYTES);
    return true;
}

} // namespace puav
