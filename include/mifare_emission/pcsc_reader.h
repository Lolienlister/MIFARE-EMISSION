#ifndef MIFARE_EMISSION_PCSC_READER_H
#define MIFARE_EMISSION_PCSC_READER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "mifare_emission/rfid_reader.h"

namespace mifare_emission {

class PcscReader : public IRfidReader {
public:
    PcscReader();
    ~PcscReader() override;

    PcscReader(const PcscReader&) = delete;
    PcscReader& operator=(const PcscReader&) = delete;

    std::vector<std::string> listReaders();
    bool connect(const std::string& reader_name);

    bool waitForCard(int timeout_ms) override;
    Uid readUid() override;
    bool authenticateSector(uint8_t sector,
                            const SectorKey& key,
                            MifareKeyType type) override;
    std::array<uint8_t, kMifareBlockSize> readBlock(uint8_t block) override;
    void writeBlock(uint8_t block,
                    const std::array<uint8_t, kMifareBlockSize>& data) override;
    void disconnect() override;
    std::string lastError() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_PCSC_READER_H
