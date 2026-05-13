#ifndef MIFARE_EMISSION_TIME_POLICY_H
#define MIFARE_EMISSION_TIME_POLICY_H

#include <chrono>
#include <cstdint>

namespace mifare_emission {

struct LocalTimeOfDay {
    uint8_t hour = 0;
    uint8_t minute = 0;

    constexpr int minutes_since_midnight() const {
        return static_cast<int>(hour) * 60 + static_cast<int>(minute);
    }
};

class TimePolicy {
public:
    static constexpr LocalTimeOfDay kDefaultStart{8, 0};
    static constexpr LocalTimeOfDay kDefaultEnd{18, 0};

    TimePolicy() : TimePolicy(kDefaultStart, kDefaultEnd) {}
    TimePolicy(LocalTimeOfDay start, LocalTimeOfDay end);

    bool isAccessAllowed(std::chrono::system_clock::time_point now) const;

    LocalTimeOfDay start() const { return start_; }
    LocalTimeOfDay end() const { return end_; }

private:
    LocalTimeOfDay start_;
    LocalTimeOfDay end_;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_TIME_POLICY_H
