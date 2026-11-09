#include "core/Logger.hpp"

#include "core/Console.hpp"

#include <ctime>
#include <iostream>

namespace wt {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::openFile(const std::filesystem::path& file) {
    std::lock_guard lock(mutex_);
    file_.open(file, std::ios::app | std::ios::binary);
    if (!file_) std::cerr << "Warnung: Logdatei kann nicht geoeffnet werden\n";
}

void Logger::setConsoleLevel(LogLevel level) {
    std::lock_guard lock(mutex_);
    consoleLevel_ = level;
}

void Logger::write(LogLevel level, std::string_view message) {
    const std::string line =
        "[" + currentTimestamp() + "] [" + std::string(levelName(level)) + "] " + std::string(message);

    std::lock_guard lock(mutex_);
    if (file_.is_open()) {
        file_ << line << '\n';
        file_.flush();
    }
    if (level < consoleLevel_) return;

    std::string_view color = console::kGray;
    if (level == LogLevel::Info)  color = console::kCyan;
    if (level == LogLevel::Warn)  color = console::kYellow;
    if (level == LogLevel::Error) color = console::kRed;
    std::cerr << color << line << console::kReset << '\n';
}

std::string currentTimestamp() {
    // localtime_s / localtime_r sind thread-sicher (std::localtime nicht).
    const std::time_t now = std::time(nullptr);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
    return buf;
}

std::string_view levelName(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "?";
}

}  // namespace wt
