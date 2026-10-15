#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdint>

namespace Inkwell {

struct DumpedArtifact {
    std::wstring sourcePath;
    std::wstring savedPath;
    uint64_t fileSize;
    std::string artifactType; // "TEMP_WATCHER_DRIVER", "PROCESS_HEAP_PE", etc.
    uint64_t remoteBaseAddress;
    std::string timestamp;
};

class DriverDumper {
public:
    static DriverDumper& Get();

    // 1. Filesystem Ephemeral Driver Watcher
    bool StartTempWatcher(const std::wstring& watchDir = L"", const std::wstring& outDir = L"");
    void StopTempWatcher();
    bool IsWatcherRunning() const { return m_watcherRunning.load(); }

    // 2. Process VAD / Heap PE Dumper
    int DumpProcessMemoryPE(DWORD pid, const std::wstring& outDir = L"");

    std::vector<DumpedArtifact> GetCapturedArtifacts();
    void ClearArtifacts();

private:
    DriverDumper();
    ~DriverDumper();
    DriverDumper(const DriverDumper&) = delete;
    DriverDumper& operator=(const DriverDumper&) = delete;

    void WatcherWorker(std::wstring watchDir, std::wstring outDir);
    bool FastCopyLockedFile(const std::wstring& srcPath, const std::wstring& dstPath);
    void EnableDebugPrivilege();

    std::atomic<bool> m_watcherRunning{ false };
    std::thread m_watcherThread;
    std::mutex m_mutex;
    std::vector<DumpedArtifact> m_artifacts;
    std::set<std::wstring> m_processedPaths;
};

} // namespace Inkwell
