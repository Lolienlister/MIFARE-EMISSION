#include "mifare_emission/logger.h"

#include <chrono>
#include <ctime>
#include <iostream>
#include <sstream>

namespace mifare_emission {

namespace {

const char* level_name(LogLevel l) {
    switch (l) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "INFO";
}

std::string now_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

}  // namespace

Logger::Logger() = default;

Logger::Logger(std::filesystem::path log_path) {
    if (!log_path.empty()) {
        const auto parent = log_path.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parent, ec);
        }
        file_.open(log_path, std::ios::app | std::ios::binary);
    }
}

void Logger::setMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> guard(mutex_);
    min_level_ = level;
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (static_cast<int>(level) < static_cast<int>(min_level_)) return;

    std::ostringstream oss;
    oss << now_iso8601() << " [" << level_name(level) << "] " << message;
    const std::string line = oss.str();

    if (level == LogLevel::Error || level == LogLevel::Warn) {
        std::cerr << line << '\n';
    } else {
        std::cout << line << '\n';
    }
    if (file_.is_open()) {
        file_ << line << '\n';
        file_.flush();
    }
}

}  // namespace mifare_emission
