#ifndef MIFARE_EMISSION_ACCESS_ENGINE_H
#define MIFARE_EMISSION_ACCESS_ENGINE_H

#include <chrono>
#include <memory>

#include "mifare_emission/types.h"
#include "mifare_emission/crypto.h"
#include "mifare_emission/json_state.h"
#include "mifare_emission/logger.h"
#include "mifare_emission/rfid_reader.h"
#include "mifare_emission/time_policy.h"

namespace mifare_emission {

struct AccessEngineConfig {
    uint8_t counter_block = kCounterBlock;
    uint8_t counter_sector = kCounterSector;
    uint8_t trailer_block = kSectorTrailerBlock;
    bool rotate_key_on_allow = true;
    bool write_counter_on_allow = true;
    MifareKeyType auth_key_type = MifareKeyType::KEY_A;

    // How many prior key generations to try when authenticating a card whose
    // stored.counter is N. We walk N, N-1, ..., max(0, N - max_auth_lookback)
    // so that clones lagging behind by a bounded number of transactions are
    // detected (and marked COMPROMISED) instead of just failing auth.
    uint32_t max_auth_lookback = 64;
};

class AccessEngine {
public:
    AccessEngine(IRfidReader* reader,
                 JsonStateStore* state,
                 BeltKdf* kdf,
                 TimePolicy time_policy,
                 Logger* logger,
                 AccessEngineConfig config = {});

    TransactionResult decide(const Uid& uid,
                             Counter counter_from_card,
                             std::chrono::system_clock::time_point now);

    TransactionResult runOnce(std::chrono::system_clock::time_point now);

    const TimePolicy& timePolicy() const { return time_policy_; }
    const AccessEngineConfig& config() const { return config_; }

private:
    IRfidReader* reader_;
    JsonStateStore* state_;
    BeltKdf* kdf_;
    TimePolicy time_policy_;
    Logger* logger_;
    AccessEngineConfig config_;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_ACCESS_ENGINE_H
