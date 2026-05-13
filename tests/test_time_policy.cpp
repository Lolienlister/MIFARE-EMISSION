#include <gtest/gtest.h>

#include <chrono>
#include <ctime>

#include "mifare_emission/time_policy.h"

using namespace mifare_emission;

namespace {

std::chrono::system_clock::time_point local_time(int hour, int minute) {
    std::tm tmv{};
    tmv.tm_year = 124;
    tmv.tm_mon = 0;
    tmv.tm_mday = 1;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = 0;
    tmv.tm_isdst = -1;
    return std::chrono::system_clock::from_time_t(std::mktime(&tmv));
}

}  // namespace

TEST(TimePolicy, DefaultIs8To18) {
    TimePolicy policy;
    EXPECT_EQ(policy.start().hour, 8);
    EXPECT_EQ(policy.end().hour, 18);
}

TEST(TimePolicy, OpenAtBoundaryStart) {
    TimePolicy policy({8, 0}, {18, 0});
    EXPECT_TRUE(policy.isAccessAllowed(local_time(8, 0)));
    EXPECT_TRUE(policy.isAccessAllowed(local_time(8, 1)));
    EXPECT_TRUE(policy.isAccessAllowed(local_time(12, 0)));
}

TEST(TimePolicy, ClosedAtBoundaryEnd) {
    TimePolicy policy({8, 0}, {18, 0});
    EXPECT_FALSE(policy.isAccessAllowed(local_time(18, 0)));
    EXPECT_TRUE(policy.isAccessAllowed(local_time(17, 59)));
}

TEST(TimePolicy, DeniesBeforeWindow) {
    TimePolicy policy({8, 0}, {18, 0});
    EXPECT_FALSE(policy.isAccessAllowed(local_time(0, 0)));
    EXPECT_FALSE(policy.isAccessAllowed(local_time(7, 59)));
}

TEST(TimePolicy, DeniesAfterWindow) {
    TimePolicy policy({8, 0}, {18, 0});
    EXPECT_FALSE(policy.isAccessAllowed(local_time(20, 0)));
    EXPECT_FALSE(policy.isAccessAllowed(local_time(23, 59)));
}

TEST(TimePolicy, WrapAroundMidnight) {
    TimePolicy policy({22, 0}, {6, 0});
    EXPECT_TRUE(policy.isAccessAllowed(local_time(23, 30)));
    EXPECT_TRUE(policy.isAccessAllowed(local_time(0, 30)));
    EXPECT_FALSE(policy.isAccessAllowed(local_time(12, 0)));
}

TEST(TimePolicy, AlwaysClosedWhenStartEqualsEnd) {
    TimePolicy policy({9, 0}, {9, 0});
    EXPECT_FALSE(policy.isAccessAllowed(local_time(9, 0)));
    EXPECT_FALSE(policy.isAccessAllowed(local_time(12, 0)));
}
