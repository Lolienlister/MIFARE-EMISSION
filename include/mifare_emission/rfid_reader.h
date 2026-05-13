#ifndef MIFARE_EMISSION_RFID_READER_H
#define MIFARE_EMISSION_RFID_READER_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "mifare_emission/types.h"

namespace mifare_emission {

enum class MifareKeyType {
    KEY_A,
    KEY_B
};

inline constexpr std::size_t kMifareBlockSize = 16;
inline constexpr uint8_t kCounterBlock = 4;
inline constexpr uint8_t kCounterSector = 1;
inline constexpr uint8_t kSectorTrailerBlock = 7;
inline constexpr std::array<uint8_t, 4> kDefaultAccessBits = {0xFF, 0x07, 0x80, 0x69};

class IRfidReader {
public:
    virtual ~IRfidReader() = default;

    virtual bool waitForCard(int timeout_ms) = 0;

    virtual Uid readUid() = 0;

    virtual bool authenticateSector(uint8_t sector, const SectorKey& key, MifareKeyType type) = 0;

    virtual std::array<uint8_t, kMifareBlockSize> readBlock(uint8_t block) = 0;

    virtual void writeBlock(uint8_t block, const std::array<uint8_t, kMifareBlockSize>& data) = 0;

    virtual void disconnect() = 0;

    virtual std::string lastError() const = 0;
};

Counter decodeCounter(const std::array<uint8_t, kMifareBlockSize>& block);
std::array<uint8_t, kMifareBlockSize> encodeCounter(Counter counter);

std::array<uint8_t, kMifareBlockSize> buildSectorTrailer(
    const SectorKey& key_a,
    const std::array<uint8_t, 4>& access_bits,
    const SectorKey& key_b);

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_RFID_READER_H
