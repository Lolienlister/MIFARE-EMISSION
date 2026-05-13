#include <gtest/gtest.h>

#include <algorithm>

#include "mifare_emission/crypto.h"

using namespace mifare_emission;

namespace {

MasterKey make_master_key(uint8_t seed = 0) {
    MasterKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<uint8_t>((i * 31u) ^ seed);
    }
    return k;
}

}  // namespace

TEST(Crypto, BuildKdfInputLayout) {
    const Uid uid = {0xAA, 0xBB, 0xCC, 0xDD};
    const auto input = BeltKdf::buildKdfInput(uid, 0x01020304);
    ASSERT_EQ(input.size(), uid.size() + 4);
    EXPECT_EQ(input[0], 0xAA);
    EXPECT_EQ(input[3], 0xDD);
    EXPECT_EQ(input[4], 0x04);
    EXPECT_EQ(input[5], 0x03);
    EXPECT_EQ(input[6], 0x02);
    EXPECT_EQ(input[7], 0x01);
}

TEST(Crypto, KeyIsDeterministic) {
    BeltKdf kdf(make_master_key());
    const Uid uid = {1, 2, 3, 4};
    const auto k1 = kdf.deriveSectorKey(uid, 42);
    const auto k2 = kdf.deriveSectorKey(uid, 42);
    EXPECT_EQ(k1, k2);
}

TEST(Crypto, KeyChangesWithCounter) {
    BeltKdf kdf(make_master_key());
    const Uid uid = {1, 2, 3, 4};
    const auto k1 = kdf.deriveSectorKey(uid, 1);
    const auto k2 = kdf.deriveSectorKey(uid, 2);
    EXPECT_NE(k1, k2);
}

TEST(Crypto, KeyChangesWithUid) {
    BeltKdf kdf(make_master_key());
    const auto k1 = kdf.deriveSectorKey({1, 2, 3, 4}, 7);
    const auto k2 = kdf.deriveSectorKey({1, 2, 3, 5}, 7);
    EXPECT_NE(k1, k2);
}

TEST(Crypto, KeyChangesWithMasterKey) {
    BeltKdf kdf1(make_master_key(0x00));
    BeltKdf kdf2(make_master_key(0xA5));
    const Uid uid = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_NE(kdf1.deriveSectorKey(uid, 7), kdf2.deriveSectorKey(uid, 7));
}

TEST(Crypto, MacIs16Bytes) {
    BeltKdf kdf(make_master_key());
    const auto mac = kdf.deriveMac({1, 2, 3, 4}, 1);
    EXPECT_EQ(mac.size(), kBeltMacSize);
}

TEST(Crypto, SectorKeyMatchesMacPrefix) {
    BeltKdf kdf(make_master_key());
    const auto mac = kdf.deriveMac({9, 8, 7, 6}, 100);
    const auto key = kdf.deriveSectorKey({9, 8, 7, 6}, 100);
    for (std::size_t i = 0; i < kSectorKeySize; ++i) {
        EXPECT_EQ(mac[i], key[i]);
    }
}
