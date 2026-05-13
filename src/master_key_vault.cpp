#include "mifare_emission/master_key_vault.h"

#include <fstream>
#include <sstream>
#include <system_error>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wincrypt.h>
#  include <dpapi.h>
#  pragma comment(lib, "crypt32.lib")
#endif

namespace mifare_emission {

namespace fs = std::filesystem;

FilesystemMasterKeyVault::FilesystemMasterKeyVault(fs::path path)
    : path_(std::move(path)) {}

std::optional<MasterKey> FilesystemMasterKeyVault::load() {
    std::ifstream in(path_, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream oss;
    oss << in.rdbuf();
    std::string contents = oss.str();
    while (!contents.empty() && (contents.back() == '\n' || contents.back() == '\r' ||
                                 contents.back() == ' ' || contents.back() == '\t')) {
        contents.pop_back();
    }
    if (contents.size() == kBeltKeySize) {
        MasterKey k{};
        for (std::size_t i = 0; i < kBeltKeySize; ++i) k[i] = static_cast<uint8_t>(contents[i]);
        return k;
    }
    if (contents.size() == kBeltKeySize * 2) {
        const auto bytes = uid_from_hex(contents);
        if (!bytes || bytes->size() != kBeltKeySize) return std::nullopt;
        MasterKey k{};
        for (std::size_t i = 0; i < kBeltKeySize; ++i) k[i] = (*bytes)[i];
        return k;
    }
    return std::nullopt;
}

bool FilesystemMasterKeyVault::store(const MasterKey& key) {
    const fs::path parent = path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        fs::create_directories(parent, ec);
    }
    std::ofstream out(path_, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(key.data()),
              static_cast<std::streamsize>(key.size()));
    return static_cast<bool>(out);
}

#if defined(_WIN32)

DpapiMasterKeyVault::DpapiMasterKeyVault(fs::path path) : path_(std::move(path)) {}

std::optional<MasterKey> DpapiMasterKeyVault::load() {
    std::ifstream in(path_, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream oss;
    oss << in.rdbuf();
    const std::string blob = oss.str();
    if (blob.empty()) return std::nullopt;

    DATA_BLOB in_blob{};
    in_blob.cbData = static_cast<DWORD>(blob.size());
    in_blob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(blob.data()));

    DATA_BLOB out_blob{};
    if (!CryptUnprotectData(&in_blob,
                            nullptr,
                            nullptr,
                            nullptr,
                            nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN,
                            &out_blob)) {
        return std::nullopt;
    }
    std::optional<MasterKey> result;
    if (out_blob.cbData == kBeltKeySize) {
        MasterKey k{};
        for (std::size_t i = 0; i < kBeltKeySize; ++i) k[i] = out_blob.pbData[i];
        result = k;
    }
    SecureZeroMemory(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return result;
}

bool DpapiMasterKeyVault::store(const MasterKey& key) {
    DATA_BLOB in_blob{};
    in_blob.cbData = static_cast<DWORD>(key.size());
    in_blob.pbData = const_cast<BYTE*>(key.data());

    DATA_BLOB out_blob{};
    if (!CryptProtectData(&in_blob,
                          L"MIFARE-EMISSION MASTER_KEY",
                          nullptr,
                          nullptr,
                          nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN,
                          &out_blob)) {
        return false;
    }
    const fs::path parent = path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        fs::create_directories(parent, ec);
    }
    bool ok = false;
    {
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        if (out) {
            out.write(reinterpret_cast<const char*>(out_blob.pbData), out_blob.cbData);
            ok = static_cast<bool>(out);
        }
    }
    SecureZeroMemory(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return ok;
}

#endif  // _WIN32

}  // namespace mifare_emission
