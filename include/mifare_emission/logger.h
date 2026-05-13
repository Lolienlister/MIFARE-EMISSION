#ifndef MIFARE_EMISSION_LOGGER_H
#define MIFARE_EMISSION_LOGGER_H

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace mifare_emission {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    Logger();
    explicit Logger(std::filesystem::path log_path);

    void setMinLevel(LogLevel level);
    void log(LogLevel level, const std::string& message);

    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message)  { log(LogLevel::INFO,  message); }
    void warn(const std::string& message)  { log(LogLevel::WARN,  message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }

private:
    std::mutex mutex_;
    std::ofstream file_;
    LogLevel min_level_ = LogLevel::INFO;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_LOGGER_H
