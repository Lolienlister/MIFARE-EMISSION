#ifndef MIFARE_EMISSION_LOGGER_H
#define MIFARE_EMISSION_LOGGER_H

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace mifare_emission {

// Names are PascalCase so they don't collide with Windows preprocessor macros
// like `ERROR` (wingdi.h) when this header is included after <windows.h>.
enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error
};

class Logger {
public:
    Logger();
    explicit Logger(std::filesystem::path log_path);

    void setMinLevel(LogLevel level);
    void log(LogLevel level, const std::string& message);

    void debug(const std::string& message) { log(LogLevel::Debug, message); }
    void info(const std::string& message)  { log(LogLevel::Info,  message); }
    void warn(const std::string& message)  { log(LogLevel::Warn,  message); }
    void error(const std::string& message) { log(LogLevel::Error, message); }

private:
    std::mutex mutex_;
    std::ofstream file_;
    LogLevel min_level_ = LogLevel::Info;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_LOGGER_H
