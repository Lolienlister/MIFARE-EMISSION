#include "mifare_emission/types.h"

#include <cctype>
#include <sstream>

namespace mifare_emission {

std::string to_string(CardStatus status) {
    switch (status) {
        case CardStatus::OK:           return "OK";
        case CardStatus::COMPROMISED:  return "COMPROMISED";
        case CardStatus::BLOCKED:      return "BLOCKED";
    }
    return "OK";
}

std::optional<CardStatus> card_status_from_string(const std::string& s) {
    if (s == "OK")           return CardStatus::OK;
    if (s == "COMPROMISED")  return CardStatus::COMPROMISED;
    if (s == "BLOCKED")      return CardStatus::BLOCKED;
    return std::nullopt;
}

std::string to_string(DenyReason reason) {
    switch (reason) {
        case DenyReason::NONE:                return "NONE";
        case DenyReason::OUT_OF_TIME_WINDOW:  return "OUT_OF_TIME_WINDOW";
        case DenyReason::COMPROMISED:         return "COMPROMISED";
        case DenyReason::BLOCKED:             return "BLOCKED";
        case DenyReason::REPLAY:              return "REPLAY";
        case DenyReason::COUNTER_REGRESSION:  return "COUNTER_REGRESSION";
        case DenyReason::COUNTER_OVERFLOW:    return "COUNTER_OVERFLOW";
        case DenyReason::READER_ERROR:        return "READER_ERROR";
        case DenyReason::CRYPTO_ERROR:        return "CRYPTO_ERROR";
        case DenyReason::INTERNAL_ERROR:      return "INTERNAL_ERROR";
    }
    return "INTERNAL_ERROR";
}

std::string uid_to_hex(const Uid& uid) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(uid.size() * 2);
    for (uint8_t b : uid) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

namespace {
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
}  // namespace

std::optional<Uid> uid_from_hex(const std::string& hex) {
    if (hex.empty() || (hex.size() % 2) != 0) return std::nullopt;
    Uid out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace mifare_emission
