#ifndef MIFARE_EMISSION_TESTS_MOCK_RFID_READER_H
#define MIFARE_EMISSION_TESTS_MOCK_RFID_READER_H

#include <map>
#include <stdexcept>
#include <vector>

#include "mifare_emission/rfid_reader.h"

namespace mifare_emission_tests {

class MockRfidReader : public mifare_emission::IRfidReader {
public:
    MockRfidReader() = default;

    void setUid(const mifare_emission::Uid& uid) { uid_ = uid; }
    void setBlock(uint8_t block, const std::array<uint8_t, mifare_emission::kMifareBlockSize>& v) {
        blocks_[block] = v;
    }
    void setAuthorizedKey(uint8_t sector, const mifare_emission::SectorKey& key) {
        authorized_keys_[sector] = key;
    }
    void clearAuthorizedKey(uint8_t sector) { authorized_keys_.erase(sector); }
    const std::vector<std::pair<uint8_t, std::array<uint8_t, mifare_emission::kMifareBlockSize>>>&
    writes() const { return writes_; }

    void failNextRead(bool fail) { fail_next_read_ = fail; }
    void failNextWrite(bool fail) { fail_next_write_ = fail; }

    bool waitForCard(int) override { return true; }
    mifare_emission::Uid readUid() override { return uid_; }
    bool authenticateSector(uint8_t sector,
                            const mifare_emission::SectorKey& key,
                            mifare_emission::MifareKeyType) override {
        const auto it = authorized_keys_.find(sector);
        if (it == authorized_keys_.end()) return true;
        return it->second == key;
    }
    std::array<uint8_t, mifare_emission::kMifareBlockSize> readBlock(uint8_t block) override {
        if (fail_next_read_) {
            fail_next_read_ = false;
            throw std::runtime_error("mock read failure");
        }
        const auto it = blocks_.find(block);
        if (it == blocks_.end()) {
            return {};
        }
        return it->second;
    }
    void writeBlock(uint8_t block,
                    const std::array<uint8_t, mifare_emission::kMifareBlockSize>& data) override {
        if (fail_next_write_) {
            fail_next_write_ = false;
            throw std::runtime_error("mock write failure");
        }
        blocks_[block] = data;
        writes_.emplace_back(block, data);
    }
    void disconnect() override {}
    std::string lastError() const override { return last_error_; }

private:
    mifare_emission::Uid uid_;
    std::map<uint8_t, std::array<uint8_t, mifare_emission::kMifareBlockSize>> blocks_;
    std::map<uint8_t, mifare_emission::SectorKey> authorized_keys_;
    std::vector<std::pair<uint8_t, std::array<uint8_t, mifare_emission::kMifareBlockSize>>> writes_;
    bool fail_next_read_ = false;
    bool fail_next_write_ = false;
    std::string last_error_;
};

}  // namespace mifare_emission_tests

#endif  // MIFARE_EMISSION_TESTS_MOCK_RFID_READER_H
