#include "mifare_emission/json_state.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include <nlohmann/json.hpp>

namespace mifare_emission {

namespace fs = std::filesystem;

namespace {

std::string format_iso8601(std::chrono::system_clock::time_point tp) {
    if (tp.time_since_epoch().count() == 0) {
        return std::string{};
    }
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

std::chrono::system_clock::time_point parse_iso8601(const std::string& s) {
    if (s.empty()) return {};
    std::tm tmv{};
    int year, month, day, hour, minute, second;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ",
                    &year, &month, &day, &hour, &minute, &second) != 6) {
        return {};
    }
    tmv.tm_year = year - 1900;
    tmv.tm_mon = month - 1;
    tmv.tm_mday = day;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = second;
#if defined(_WIN32)
    const std::time_t t = _mkgmtime(&tmv);
#else
    const std::time_t t = timegm(&tmv);
#endif
    if (t == -1) return {};
    return std::chrono::system_clock::from_time_t(t);
}

std::string random_suffix() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << gen();
    return oss.str();
}

}  // namespace

JsonStateStore::JsonStateStore(fs::path path) : path_(std::move(path)) {}

void JsonStateStore::load() {
    std::lock_guard<std::mutex> guard(mutex_);
    records_.clear();
    schema_version_ = kCurrentSchemaVersion;

    std::error_code ec;
    if (!fs::exists(path_, ec) || ec) {
        return;
    }

    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open state file for reading: " + path_.string());
    }

    nlohmann::json doc;
    try {
        in >> doc;
    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error(std::string("Corrupt state file: ") + e.what());
    }

    if (doc.is_null()) {
        return;
    }
    if (!doc.is_object()) {
        throw std::runtime_error("State file must be a JSON object");
    }

    nlohmann::json cards = doc;
    if (doc.contains("schema_version") || doc.contains("cards")) {
        schema_version_ = doc.value("schema_version", kCurrentSchemaVersion);
        cards = doc.value("cards", nlohmann::json::object());
        if (!cards.is_object()) {
            throw std::runtime_error("'cards' must be a JSON object");
        }
    }

    for (auto it = cards.begin(); it != cards.end(); ++it) {
        const std::string uid_hex = it.key();
        const auto& entry = it.value();
        if (!entry.is_object()) continue;

        CardState st{};
        st.counter = entry.value("counter", static_cast<Counter>(0));
        const std::string status = entry.value("status", std::string{"OK"});
        const auto parsed = card_status_from_string(status);
        st.status = parsed.value_or(CardStatus::OK);
        st.last_seen = parse_iso8601(entry.value("last_seen", std::string{}));
        records_.emplace(uid_hex, st);
    }
}

void JsonStateStore::save() const {
    std::lock_guard<std::mutex> guard(mutex_);
    saveLocked();
}

void JsonStateStore::saveLocked() const {
    nlohmann::json cards = nlohmann::json::object();
    for (const auto& [uid_hex, state] : records_) {
        cards[uid_hex] = {
            {"counter", state.counter},
            {"status", to_string(state.status)},
            {"last_seen", format_iso8601(state.last_seen)},
        };
    }

    nlohmann::json doc = {
        {"schema_version", schema_version_},
        {"cards", cards},
    };

    const fs::path parent = path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        fs::create_directories(parent, ec);
    }

    const fs::path tmp = path_.parent_path() / (path_.filename().string() + ".tmp." + random_suffix());
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("Cannot open temp state file for writing: " + tmp.string());
        }
        out << doc.dump(2);
        out.flush();
        if (!out) {
            throw std::runtime_error("Failed to write state file: " + tmp.string());
        }
    }

    std::error_code ec;
    fs::rename(tmp, path_, ec);
    if (ec) {
        fs::remove(path_, ec);
        fs::rename(tmp, path_, ec);
        if (ec) {
            throw std::runtime_error("Atomic rename failed: " + ec.message());
        }
    }
}

std::optional<CardState> JsonStateStore::find(const Uid& uid) const {
    std::lock_guard<std::mutex> guard(mutex_);
    const auto it = records_.find(uid_to_hex(uid));
    if (it == records_.end()) return std::nullopt;
    return it->second;
}

void JsonStateStore::upsert(const Uid& uid, const CardState& state) {
    std::lock_guard<std::mutex> guard(mutex_);
    records_[uid_to_hex(uid)] = state;
    saveLocked();
}

bool JsonStateStore::erase(const Uid& uid) {
    std::lock_guard<std::mutex> guard(mutex_);
    const auto it = records_.find(uid_to_hex(uid));
    if (it == records_.end()) return false;
    records_.erase(it);
    saveLocked();
    return true;
}

bool JsonStateStore::markCompromised(const Uid& uid) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto& entry = records_[uid_to_hex(uid)];
    entry.status = CardStatus::COMPROMISED;
    entry.last_seen = std::chrono::system_clock::now();
    saveLocked();
    return true;
}

bool JsonStateStore::markBlocked(const Uid& uid) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto& entry = records_[uid_to_hex(uid)];
    entry.status = CardStatus::BLOCKED;
    entry.last_seen = std::chrono::system_clock::now();
    saveLocked();
    return true;
}

std::size_t JsonStateStore::size() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return records_.size();
}

}  // namespace mifare_emission
