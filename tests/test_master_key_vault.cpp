#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "mifare_emission/master_key_vault.h"
#include "mifare_emission/types.h"

using namespace mifare_emission;
namespace fs = std::filesystem;

namespace {

class VaultTempDir {
public:
    VaultTempDir() {
        path_ = fs::temp_directory_path() /
                ("mifare_vault_test_" + std::to_string(::getpid()) + "_" +
                 std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(path_);
    }
    ~VaultTempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    fs::path path() const { return path_; }
private:
    fs::path path_;
};

MasterKey sample_key() {
    MasterKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    }
    return k;
}

void write_text_file(const fs::path& p, const std::string& contents) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(static_cast<bool>(f));
    f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

}  // namespace

TEST(FilesystemMasterKeyVault, StoreThenLoadRoundtripRaw) {
    VaultTempDir tmp;
    const auto p = tmp.path() / "master.key";
    FilesystemMasterKeyVault vault(p);
    const auto original = sample_key();
    ASSERT_TRUE(vault.store(original));
    ASSERT_EQ(fs::file_size(p), kBeltKeySize);

    const auto loaded = vault.load();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, original);
}

TEST(FilesystemMasterKeyVault, LoadsHexEncodedKey) {
    VaultTempDir tmp;
    const auto p = tmp.path() / "master.key.hex";

    // 64-char lowercase hex; matches `sample_key()` byte-for-byte so we can
    // assert exact equality on load.
    const auto original = sample_key();
    static const char hexd[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(kBeltKeySize * 2);
    for (uint8_t b : original) {
        hex.push_back(hexd[(b >> 4) & 0x0F]);
        hex.push_back(hexd[b & 0x0F]);
    }
    write_text_file(p, hex + "\n");

    FilesystemMasterKeyVault vault(p);
    const auto loaded = vault.load();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, original);
}

TEST(FilesystemMasterKeyVault, LoadRejectsWrongLength) {
    VaultTempDir tmp;
    const auto p = tmp.path() / "master.key.short";
    write_text_file(p, std::string(7, 'A'));  // neither 32 raw nor 64 hex
    FilesystemMasterKeyVault vault(p);
    EXPECT_FALSE(vault.load().has_value());
}

TEST(FilesystemMasterKeyVault, LoadReturnsNulloptIfFileMissing) {
    VaultTempDir tmp;
    FilesystemMasterKeyVault vault(tmp.path() / "does_not_exist");
    EXPECT_FALSE(vault.load().has_value());
}
