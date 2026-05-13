#ifndef MIFARE_EMISSION_TYPES_H
#define MIFARE_EMISSION_TYPES_H

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mifare_emission {

using Uid = std::vector<uint8_t>;
using Counter = uint32_t;

using SectorKey = std::array<uint8_t, 6>;
using MasterKey = std::array<uint8_t, 32>;

inline constexpr std::size_t kBeltBlockSize = 16;
inline constexpr std::size_t kBeltMacSize = 16;
inline constexpr std::size_t kBeltKeySize = 32;
inline constexpr std::size_t kSectorKeySize = 6;

inline constexpr Counter kMaxCounter = 0xFFFFFFFEu;

enum class CardStatus {
    OK,
    COMPROMISED,
    BLOCKED
};

std::string to_string(CardStatus status);
std::optional<CardStatus> card_status_from_string(const std::string& s);

struct CardState {
    Counter counter = 0;
    CardStatus status = CardStatus::OK;
    std::chrono::system_clock::time_point last_seen{};
};

enum class Decision {
    ALLOW,
    DENY
};

enum class DenyReason {
    NONE,
    OUT_OF_TIME_WINDOW,
    COMPROMISED,
    BLOCKED,
    REPLAY,
    COUNTER_REGRESSION,
    COUNTER_OVERFLOW,
    READER_ERROR,
    CRYPTO_ERROR,
    INTERNAL_ERROR
};

std::string to_string(DenyReason reason);

struct TransactionResult {
    Decision decision = Decision::DENY;
    DenyReason reason = DenyReason::INTERNAL_ERROR;
    Counter old_counter = 0;
    Counter new_counter = 0;
    Uid uid;
    bool state_mutated = false;
};

std::string uid_to_hex(const Uid& uid);
std::optional<Uid> uid_from_hex(const std::string& hex);

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_TYPES_H
