#include "mifare_emission/rfid_reader.h"

namespace mifare_emission {

Counter decodeCounter(const std::array<uint8_t, kMifareBlockSize>& block) {
    const uint32_t value =
        (static_cast<uint32_t>(block[0]) << 0) |
        (static_cast<uint32_t>(block[1]) << 8) |
        (static_cast<uint32_t>(block[2]) << 16) |
        (static_cast<uint32_t>(block[3]) << 24);
    const uint32_t inverted =
        (static_cast<uint32_t>(block[4]) << 0) |
        (static_cast<uint32_t>(block[5]) << 8) |
        (static_cast<uint32_t>(block[6]) << 16) |
        (static_cast<uint32_t>(block[7]) << 24);
    if ((value ^ inverted) != 0xFFFFFFFFu) {
        return 0;
    }
    const uint32_t value2 =
        (static_cast<uint32_t>(block[8]) << 0) |
        (static_cast<uint32_t>(block[9]) << 8) |
        (static_cast<uint32_t>(block[10]) << 16) |
        (static_cast<uint32_t>(block[11]) << 24);
    if (value != value2) {
        return 0;
    }
    return static_cast<Counter>(value);
}

std::array<uint8_t, kMifareBlockSize> encodeCounter(Counter counter) {
    std::array<uint8_t, kMifareBlockSize> block{};
    const uint32_t v = counter;
    const uint32_t inv = ~v;
    block[0] = static_cast<uint8_t>((v >> 0) & 0xFF);
    block[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    block[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    block[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    block[4] = static_cast<uint8_t>((inv >> 0) & 0xFF);
    block[5] = static_cast<uint8_t>((inv >> 8) & 0xFF);
    block[6] = static_cast<uint8_t>((inv >> 16) & 0xFF);
    block[7] = static_cast<uint8_t>((inv >> 24) & 0xFF);
    block[8] = block[0];
    block[9] = block[1];
    block[10] = block[2];
    block[11] = block[3];
    block[12] = 0x00;
    block[13] = 0xFF;
    block[14] = 0x00;
    block[15] = 0xFF;
    return block;
}

std::array<uint8_t, kMifareBlockSize> buildSectorTrailer(
    const SectorKey& key_a,
    const std::array<uint8_t, 4>& access_bits,
    const SectorKey& key_b) {
    std::array<uint8_t, kMifareBlockSize> trailer{};
    for (std::size_t i = 0; i < kSectorKeySize; ++i) trailer[i] = key_a[i];
    for (std::size_t i = 0; i < 4; ++i) trailer[6 + i] = access_bits[i];
    for (std::size_t i = 0; i < kSectorKeySize; ++i) trailer[10 + i] = key_b[i];
    return trailer;
}

}  // namespace mifare_emission
