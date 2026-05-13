#include <gtest/gtest.h>

#include "mifare_emission/rfid_reader.h"

using namespace mifare_emission;

TEST(RfidReader, CounterEncodeDecodeRoundTrip) {
    for (Counter c : {Counter{0}, Counter{1}, Counter{42}, Counter{0xDEADBEEF}, kMaxCounter - 1}) {
        const auto block = encodeCounter(c);
        EXPECT_EQ(decodeCounter(block), c) << "counter=" << c;
    }
}

TEST(RfidReader, CounterRejectsCorruptedMirror) {
    auto block = encodeCounter(0x11223344);
    block[4] ^= 0xFF;
    EXPECT_EQ(decodeCounter(block), 0u);
}

TEST(RfidReader, CounterRejectsCorruptedReplica) {
    auto block = encodeCounter(0x11223344);
    block[8] ^= 0x01;
    EXPECT_EQ(decodeCounter(block), 0u);
}

TEST(RfidReader, BuildSectorTrailer) {
    SectorKey key_a = {1, 2, 3, 4, 5, 6};
    SectorKey key_b = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::array<uint8_t, 4> access = {0xFF, 0x07, 0x80, 0x69};
    const auto t = buildSectorTrailer(key_a, access, key_b);
    EXPECT_EQ(t[0], 1);
    EXPECT_EQ(t[5], 6);
    EXPECT_EQ(t[6], 0xFF);
    EXPECT_EQ(t[9], 0x69);
    EXPECT_EQ(t[10], 0xAA);
    EXPECT_EQ(t[15], 0xFF);
}
