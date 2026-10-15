#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace Inkwell {

enum class LogLevel : uint8_t {
    Debug = 0,
    Info,
    Success,
    Warning,
    Error,
    Kernel,
    Telemetry,
    Memory
};

struct LogEntry {
    std::string timestamp;
    LogLevel level;
    std::string message;
};

class Logger {
public:
    static Logger& Get();

    void Init(const std::wstring& logFilePath = L"");
    void Shutdown();

    void Log(LogLevel level, const char* fmt, ...);
    void Clear();

    std::vector<LogEntry> GetEntries();
    size_t GetEntryCount();
    bool ExportToFile(const std::wstring& exportPath);

    static const char* LevelToString(LogLevel level);

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string CurrentTimestamp();

    std::mutex m_mutex;
    std::vector<LogEntry> m_entries;
    std::wstring m_logFile;
    bool m_initialized = false;
    const size_t m_maxEntries = 2000;
};

} // namespace Inkwell
