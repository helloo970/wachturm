#pragma once
// Thread-sicherer Logger: schreibt in eine Datei und (ab einem Level) auf stderr.

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace wt {

enum class LogLevel { Debug, Info, Warn, Error };

class Logger {
public:
    static Logger& instance();

    void openFile(const std::filesystem::path& file);
    void setConsoleLevel(LogLevel level);
    void write(LogLevel level, std::string_view message);

private:
    Logger() = default;
    std::mutex mutex_;
    std::ofstream file_;
    LogLevel consoleLevel_ = LogLevel::Info;
};

// "2026-11-09 14:03:12" - wird auch in Quarantaene-Eintraegen benutzt.
std::string currentTimestamp();

// "DEBUG", "INFO", "WARN", "ERROR"
std::string_view levelName(LogLevel level);

inline void logDebug(std::string_view m) { Logger::instance().write(LogLevel::Debug, m); }
inline void logInfo(std::string_view m)  { Logger::instance().write(LogLevel::Info, m); }
inline void logWarn(std::string_view m)  { Logger::instance().write(LogLevel::Warn, m); }
inline void logError(std::string_view m) { Logger::instance().write(LogLevel::Error, m); }

}  // namespace wt
