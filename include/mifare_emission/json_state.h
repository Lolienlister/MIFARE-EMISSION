#ifndef MIFARE_EMISSION_JSON_STATE_H
#define MIFARE_EMISSION_JSON_STATE_H

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "mifare_emission/types.h"

namespace mifare_emission {

class JsonStateStore {
public:
    explicit JsonStateStore(std::filesystem::path path);

    void load();
    void save() const;

    std::optional<CardState> find(const Uid& uid) const;
    void upsert(const Uid& uid, const CardState& state);
    bool erase(const Uid& uid);
    bool markCompromised(const Uid& uid);
    bool markBlocked(const Uid& uid);

    std::size_t size() const;
    const std::filesystem::path& path() const { return path_; }

    int schemaVersion() const { return schema_version_; }
    const std::string& fileFingerprint() const { return file_fingerprint_; }

    static constexpr int kCurrentSchemaVersion = 1;

private:
    void saveLocked() const;

    std::filesystem::path path_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CardState> records_;
    int schema_version_ = kCurrentSchemaVersion;
    std::string file_fingerprint_;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_JSON_STATE_H
