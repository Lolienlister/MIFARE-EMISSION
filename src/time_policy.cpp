#include "mifare_emission/time_policy.h"

#include <ctime>

namespace mifare_emission {

namespace {

std::tm to_local_tm(std::chrono::system_clock::time_point tp) {
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    return tmv;
}

}  // namespace

TimePolicy::TimePolicy(LocalTimeOfDay start, LocalTimeOfDay end)
    : start_(start), end_(end) {}

bool TimePolicy::isAccessAllowed(std::chrono::system_clock::time_point now) const {
    const std::tm lt = to_local_tm(now);
    const int cur = lt.tm_hour * 60 + lt.tm_min;
    const int s = start_.minutes_since_midnight();
    const int e = end_.minutes_since_midnight();
    if (s == e) {
        return false;
    }
    if (s < e) {
        return cur >= s && cur < e;
    }
    return cur >= s || cur < e;
}

}  // namespace mifare_emission
