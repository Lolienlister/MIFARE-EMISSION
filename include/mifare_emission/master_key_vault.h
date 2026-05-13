#ifndef MIFARE_EMISSION_MASTER_KEY_VAULT_H
#define MIFARE_EMISSION_MASTER_KEY_VAULT_H

#include <filesystem>
#include <optional>
#include <string>

#include "mifare_emission/types.h"

namespace mifare_emission {

class IMasterKeyVault {
public:
    virtual ~IMasterKeyVault() = default;

    virtual std::optional<MasterKey> load() = 0;

    virtual bool store(const MasterKey& key) = 0;
};

class FilesystemMasterKeyVault : public IMasterKeyVault {
public:
    explicit FilesystemMasterKeyVault(std::filesystem::path path);

    std::optional<MasterKey> load() override;
    bool store(const MasterKey& key) override;

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

#if defined(_WIN32)
class DpapiMasterKeyVault : public IMasterKeyVault {
public:
    explicit DpapiMasterKeyVault(std::filesystem::path path);

    std::optional<MasterKey> load() override;
    bool store(const MasterKey& key) override;

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};
#endif

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_MASTER_KEY_VAULT_H
