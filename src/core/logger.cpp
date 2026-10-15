#include "logger.h"
#include <windows.h>
#include <cstdarg>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace Inkwell {

Logger& Logger::Get() {
    static Logger instance;
    return instance;
}

void Logger::Init(const std::wstring& logFilePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (logFilePath.empty()) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring pathStr = exePath;
        size_t pos = pathStr.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            m_logFile = pathStr.substr(0, pos + 1) + L"analyzer_diagnostics.log";
        } else {
            m_logFile = L"analyzer_diagnostics.log";
        }
    } else {
        m_logFile = logFilePath;
    }

    m_initialized = true;
    m_entries.reserve(m_maxEntries);
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_initialized = false;
}

std::string Logger::CurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    struct tm timeinfo;
    localtime_s(&timeinfo, &now_c);

    char buf[64];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, static_cast<int>(ms.count()));
    return std::string(buf);
}

const char* Logger::LevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::Debug:     return "[DEBUG]";
    case LogLevel::Info:      return "[INFO]";
    case LogLevel::Success:   return "[SUCCESS]";
    case LogLevel::Warning:   return "[WARN]";
    case LogLevel::Error:     return "[ERROR]";
    case LogLevel::Kernel:    return "[KERNEL]";
    case LogLevel::Telemetry: return "[TELEM]";
    case LogLevel::Memory:    return "[MEM]";
    default:                  return "[LOG]";
    }
}

void Logger::Log(LogLevel level, const char* fmt, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    std::string timestamp = CurrentTimestamp();
    std::string message(buffer);

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_entries.size() >= m_maxEntries) {
            m_entries.erase(m_entries.begin(), m_entries.begin() + 100);
        }
        m_entries.push_back({ timestamp, level, message });

        if (m_initialized && !m_logFile.empty()) {
            std::ofstream out(m_logFile, std::ios::app);
            if (out.is_open()) {
                out << "[" << timestamp << "] " << LevelToString(level) << " " << message << "\n";
                out.close();
            }
        }
    }

    OutputDebugStringA((std::string("[ANALYZER] ") + LevelToString(level) + " " + message + "\n").c_str());
}

void Logger::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.clear();
}

std::vector<LogEntry> Logger::GetEntries() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries;
}

size_t Logger::GetEntryCount() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

bool Logger::ExportToFile(const std::wstring& exportPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream out(exportPath, std::ios::out | std::ios::trunc);
    if (!out.is_open()) return false;

    out << "=================================================================\n";
    out << "   INKWELL UNIVERSAL ANALYZER & KERNEL SANDBOX EXPORT LOG       \n";
    out << "=================================================================\n\n";

    for (const auto& entry : m_entries) {
        out << "[" << entry.timestamp << "] " << LevelToString(entry.level) << " " << entry.message << "\n";
    }

    out.close();
    return true;
}

} // namespace Inkwell
