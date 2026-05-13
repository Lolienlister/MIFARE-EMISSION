#include "mifare_emission/access_engine.h"

#include <sstream>
#include <stdexcept>
#include <utility>

namespace mifare_emission {

namespace {

std::string format_decision_log(const TransactionResult& r) {
    std::ostringstream oss;
    oss << "uid=" << uid_to_hex(r.uid)
        << " decision=" << (r.decision == Decision::ALLOW ? "ALLOW" : "DENY")
        << " reason=" << to_string(r.reason)
        << " old_counter=" << r.old_counter
        << " new_counter=" << r.new_counter
        << " state_mutated=" << (r.state_mutated ? "true" : "false");
    return oss.str();
}

}  // namespace

AccessEngine::AccessEngine(IRfidReader* reader,
                           JsonStateStore* state,
                           BeltKdf* kdf,
                           TimePolicy time_policy,
                           Logger* logger,
                           AccessEngineConfig config)
    : reader_(reader),
      state_(state),
      kdf_(kdf),
      time_policy_(time_policy),
      logger_(logger),
      config_(config) {}

TransactionResult AccessEngine::decide(const Uid& uid,
                                       Counter counter_from_card,
                                       std::chrono::system_clock::time_point now) {
    TransactionResult result;
    result.uid = uid;
    result.old_counter = counter_from_card;
    result.new_counter = counter_from_card;

    if (!time_policy_.isAccessAllowed(now)) {
        result.decision = Decision::DENY;
        result.reason = DenyReason::OUT_OF_TIME_WINDOW;
        if (logger_) logger_->warn("deny " + format_decision_log(result));
        return result;
    }

    const auto stored = state_ ? state_->find(uid) : std::nullopt;

    if (stored) {
        if (stored->status == CardStatus::COMPROMISED) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::COMPROMISED;
            result.old_counter = stored->counter;
            result.new_counter = stored->counter;
            if (logger_) logger_->warn("deny " + format_decision_log(result));
            return result;
        }
        if (stored->status == CardStatus::BLOCKED) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::BLOCKED;
            result.old_counter = stored->counter;
            result.new_counter = stored->counter;
            if (logger_) logger_->warn("deny " + format_decision_log(result));
            return result;
        }

        if (counter_from_card == stored->counter) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::REPLAY;
            result.old_counter = stored->counter;
            result.new_counter = stored->counter;
            if (state_) state_->markCompromised(uid);
            result.state_mutated = true;
            if (logger_) logger_->error("compromised(replay) " + format_decision_log(result));
            return result;
        }
        if (counter_from_card < stored->counter) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::COUNTER_REGRESSION;
            result.old_counter = stored->counter;
            result.new_counter = stored->counter;
            if (state_) state_->markCompromised(uid);
            result.state_mutated = true;
            if (logger_) logger_->error("compromised(regression) " + format_decision_log(result));
            return result;
        }
        if (counter_from_card > kMaxCounter - 1) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::COUNTER_OVERFLOW;
            result.old_counter = stored->counter;
            result.new_counter = stored->counter;
            if (logger_) logger_->error("deny " + format_decision_log(result));
            return result;
        }
    } else {
        if (counter_from_card > kMaxCounter - 1) {
            result.decision = Decision::DENY;
            result.reason = DenyReason::COUNTER_OVERFLOW;
            if (logger_) logger_->error("deny " + format_decision_log(result));
            return result;
        }
    }

    CardState new_state{};
    new_state.counter = counter_from_card + 1;
    new_state.status = CardStatus::OK;
    new_state.last_seen = now;

    if (state_) state_->upsert(uid, new_state);

    result.decision = Decision::ALLOW;
    result.reason = DenyReason::NONE;
    result.old_counter = counter_from_card;
    result.new_counter = new_state.counter;
    result.state_mutated = true;
    if (logger_) logger_->info("allow " + format_decision_log(result));
    return result;
}

TransactionResult AccessEngine::runOnce(std::chrono::system_clock::time_point now) {
    TransactionResult result;
    if (!reader_ || !kdf_) {
        result.reason = DenyReason::INTERNAL_ERROR;
        return result;
    }

    Uid uid;
    try {
        uid = reader_->readUid();
    } catch (const std::exception& e) {
        if (logger_) logger_->error(std::string("reader.readUid: ") + e.what());
        result.reason = DenyReason::READER_ERROR;
        return result;
    }
    result.uid = uid;

    auto stored = state_ ? state_->find(uid) : std::nullopt;
    const Counter top = stored ? stored->counter : 0;
    const Counter lookback = static_cast<Counter>(config_.max_auth_lookback);
    const Counter floor = (top > lookback) ? (top - lookback) : 0;

    bool authenticated = false;
    Counter probe_counter = top;
    while (!authenticated) {
        const SectorKey key = kdf_->deriveSectorKey(uid, probe_counter);
        try {
            if (reader_->authenticateSector(config_.counter_sector, key, config_.auth_key_type)) {
                authenticated = true;
                break;
            }
        } catch (const std::exception& e) {
            if (logger_) logger_->warn(std::string("auth attempt failed: ") + e.what());
        }
        if (probe_counter == floor) break;
        --probe_counter;
    }

    if (!authenticated) {
        result.reason = DenyReason::CRYPTO_ERROR;
        if (logger_) logger_->error("authentication failed for uid=" + uid_to_hex(uid));
        return result;
    }

    Counter on_card_counter = 0;

    try {
        const auto block = reader_->readBlock(config_.counter_block);
        on_card_counter = decodeCounter(block);
    } catch (const std::exception& e) {
        if (logger_) logger_->error(std::string("reader.readBlock: ") + e.what());
        result.reason = DenyReason::READER_ERROR;
        return result;
    }

    TransactionResult decision = decide(uid, on_card_counter, now);
    if (decision.decision != Decision::ALLOW) {
        return decision;
    }

    if (config_.write_counter_on_allow) {
        try {
            const auto encoded = encodeCounter(decision.new_counter);
            reader_->writeBlock(config_.counter_block, encoded);
        } catch (const std::exception& e) {
            if (logger_) logger_->error(std::string("writeBlock(counter): ") + e.what());
            decision.decision = Decision::DENY;
            decision.reason = DenyReason::READER_ERROR;
            return decision;
        }
    }

    if (config_.rotate_key_on_allow) {
        try {
            const SectorKey new_key = kdf_->deriveSectorKey(uid, decision.new_counter);
            const auto trailer = buildSectorTrailer(new_key, kDefaultAccessBits, new_key);
            reader_->writeBlock(config_.trailer_block, trailer);
        } catch (const std::exception& e) {
            if (logger_) logger_->error(std::string("writeBlock(trailer): ") + e.what());
            decision.decision = Decision::DENY;
            decision.reason = DenyReason::READER_ERROR;
            return decision;
        }
    }

    return decision;
}

}  // namespace mifare_emission
