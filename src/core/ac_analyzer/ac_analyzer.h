#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace Inkwell {

struct DriverSnapshotEntry {
    uint64_t baseAddress;
    std::wstring baseName;
    std::wstring fullPath;
    bool isSigned;
};

struct ServiceSnapshotEntry {
    std::wstring serviceName;
    std::wstring displayName;
    DWORD serviceType;
    DWORD currentState;
    std::wstring binaryPath;
};

struct FileIntegrityEntry {
    std::wstring filePath;
    uint64_t fileSize;
    std::string sha256;
    bool isSigned;
    std::string signerSubject;
    bool isModified;
    bool isStubSuspect;
};

struct UnbackedMemoryRegion {
    uint64_t baseAddress;
    uint64_t regionSize;
    DWORD protect;
    DWORD state;
    DWORD type;
    bool hasFloatingPE;
    std::string threatDescription;
};

struct DifferentialAuditReport {
    std::vector<DriverSnapshotEntry> newDrivers;
    std::vector<ServiceSnapshotEntry> newServices;
    std::vector<FileIntegrityEntry> tamperedFiles;
    std::vector<UnbackedMemoryRegion> injectedRegions;
    std::vector<std::string> hostsRedirects;

    bool baselineCaptured = false;
    bool auditCompleted = false;
    uint32_t baselineDriverCount = 0;
    uint32_t baselineServiceCount = 0;
};

class AntiCheatAnalyzer {
public:
    static AntiCheatAnalyzer& Get();

    // Baseline Operations
    bool CaptureBaseline();
    bool HasBaseline() const { return m_report.baselineCaptured; }

    // Live Audit Operations
    bool RunDifferentialAudit(const std::wstring& targetGameDir = L"", const std::wstring& targetProcessName = L"");

    // Specific Vector Scanners
    std::vector<UnbackedMemoryRegion> ScanProcessUnbackedMemory(DWORD pid);
    std::vector<FileIntegrityEntry> AuditDirectoryIntegrity(const std::wstring& directoryPath);
    std::vector<std::string> AuditHostsFile();

    DifferentialAuditReport GetReport();
    void ClearReport();

    // Utility: Process resolver
    DWORD FindProcessIdByName(const std::wstring& processName);
    std::vector<std::pair<DWORD, std::wstring>> EnumerateRunningProcesses();

private:
    AntiCheatAnalyzer();
    ~AntiCheatAnalyzer() = default;
    AntiCheatAnalyzer(const AntiCheatAnalyzer&) = delete;
    AntiCheatAnalyzer& operator=(const AntiCheatAnalyzer&) = delete;

    std::vector<DriverSnapshotEntry> SnapshotLoadedDrivers();
    std::vector<ServiceSnapshotEntry> SnapshotWindowsServices();
    bool VerifyFileSignature(const std::wstring& filePath, std::string& outSigner);
    std::string ComputeFileSHA256(const std::wstring& filePath);

    std::mutex m_mutex;
    DifferentialAuditReport m_report;

    std::vector<DriverSnapshotEntry> m_baselineDrivers;
    std::vector<ServiceSnapshotEntry> m_baselineServices;
    std::vector<std::string> m_baselineHostsLines;
    std::map<std::wstring, FileIntegrityEntry> m_baselineFiles;
};

} // namespace Inkwell
