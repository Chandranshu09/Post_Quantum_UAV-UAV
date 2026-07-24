#pragma once

#include <Arduino.h>

#include "ProtocolConstants.h"

namespace puav {

/*
  Replace only this provider when integrating the external Pynq-Z2 APUF and
  Python fuzzy extractor. The protocol consumes one stable 32-byte device-root
  value. The helper data remain local and are never required by a verifier.
*/
class PufFeProvider {
public:
    static bool reconstruct(
        const NodeConfig& config,
        uint8_t output[HASH_BYTES]);
};

} // namespace puav
