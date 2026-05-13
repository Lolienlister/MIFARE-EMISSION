#include <gtest/gtest.h>

#include "mifare_emission/types.h"

using namespace mifare_emission;

TEST(Types, UidHexRoundTrip) {
    Uid uid = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto hex = uid_to_hex(uid);
    EXPECT_EQ(hex, "DEADBEEF");
    const auto parsed = uid_from_hex(hex);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, uid);
}

TEST(Types, UidFromHexLowercase) {
    const auto parsed = uid_from_hex("0123abcd");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->size(), 4u);
    EXPECT_EQ((*parsed)[3], 0xCD);
}

TEST(Types, UidFromHexRejectsOddLength) {
    EXPECT_FALSE(uid_from_hex("ABC").has_value());
    EXPECT_FALSE(uid_from_hex("XY").has_value());
    EXPECT_FALSE(uid_from_hex("").has_value());
}

TEST(Types, CardStatusRoundTrip) {
    for (auto s : {CardStatus::OK, CardStatus::COMPROMISED, CardStatus::BLOCKED}) {
        const auto str = to_string(s);
        const auto parsed = card_status_from_string(str);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(*parsed, s);
    }
    EXPECT_FALSE(card_status_from_string("garbage").has_value());
}

TEST(Types, DenyReasonNames) {
    EXPECT_EQ(to_string(DenyReason::OUT_OF_TIME_WINDOW), "OUT_OF_TIME_WINDOW");
    EXPECT_EQ(to_string(DenyReason::REPLAY), "REPLAY");
    EXPECT_EQ(to_string(DenyReason::COUNTER_REGRESSION), "COUNTER_REGRESSION");
}
