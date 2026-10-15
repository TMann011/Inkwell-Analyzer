#include "driver_dumper.h"
#include "../logger.h"
#include "../config.h"
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

namespace Inkwell {

typedef NTSTATUS(NTAPI* pfnRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

DriverDumper& DriverDumper::Get() {
    static DriverDumper instance;
    return instance;
}

DriverDumper::DriverDumper() {
    EnableDebugPrivilege();
}

DriverDumper::~DriverDumper() {
    StopTempWatcher();
}

void DriverDumper::EnableDebugPrivilege() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto RtlAdjustPrivilege = reinterpret_cast<pfnRtlAdjustPrivilege>(GetProcAddress(hNtdll, "RtlAdjustPrivilege"));
        if (RtlAdjustPrivilege) {
            BOOLEAN enabled = FALSE;
            RtlAdjustPrivilege(20, TRUE, FALSE, &enabled); // SeDebugPrivilege = 20
        }
    }
}

bool DriverDumper::FastCopyLockedFile(const std::wstring& srcPath, const std::wstring& dstPath) {
    HANDLE hFile = CreateFileW(
        srcPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < 64 || fileSize > 150 * 1024 * 1024) { // Filter empty or >150MB files
        CloseHandle(hFile);
        return false;
    }

    std::vector<uint8_t> buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr) || bytesRead == 0) {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);

    // Verify DOS / PE magic
    if (buffer.size() >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
        std::ofstream out(dstPath, std::ios::binary);
        if (out.is_open()) {
            out.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
            out.close();
            return true;
        }
    }
    return false;
}

bool DriverDumper::StartTempWatcher(const std::wstring& watchDir, const std::wstring& outDir) {
    if (m_watcherRunning.load()) {
        Logger::Get().Log(LogLevel::Warning, "Filesystem watcher is already running.");
        return false;
    }

    std::wstring targetWatch = watchDir.empty() ? ConfigManager::Get().GetDefaultWatchDirectory() : watchDir;
    std::wstring targetOut = outDir.empty() ? ConfigManager::Get().GetDefaultDumpDirectory() : outDir;

    fs::create_directories(targetOut);

    m_watcherRunning.store(true);
    if (m_watcherThread.joinable()) m_watcherThread.join();

    m_watcherThread = std::thread(&DriverDumper::WatcherWorker, this, targetWatch, targetOut);
    return true;
}

void DriverDumper::StopTempWatcher() {
    if (m_watcherRunning.load()) {
        m_watcherRunning.store(false);
        Logger::Get().Log(LogLevel::Info, "Halting filesystem driver watcher...");
        if (m_watcherThread.joinable()) {
            m_watcherThread.join();
        }
        Logger::Get().Log(LogLevel::Success, "Filesystem watcher stopped.");
    }
}

void DriverDumper::WatcherWorker(std::wstring watchDir, std::wstring outDir) {
    Logger::Get().Log(LogLevel::Telemetry, "Ephemeral Driver Watcher armed on: %ls", watchDir.c_str());

    HANDLE hDir = CreateFileW(
        watchDir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        Logger::Get().Log(LogLevel::Error, "Failed to open directory handle for watcher (Error 0x%08X)", GetLastError());
        m_watcherRunning.store(false);
        return;
    }

    std::vector<uint8_t> buffer(64 * 1024);
    DWORD bytesReturned = 0;

    while (m_watcherRunning.load()) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            nullptr,
            nullptr
        ) && bytesReturned > 0) {
            auto notify = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer.data());
            do {
                std::wstring fileName(notify->FileName, notify->FileNameLength / sizeof(wchar_t));
                std::wstring fullPath = watchDir + (watchDir.back() == L'\\' ? L"" : L"\\") + fileName;

                std::wstring ext = fs::path(fullPath).extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                if (ext == L".sys" || ext == L".dll" || ext == L".tmp") {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_processedPaths.find(fullPath) == m_processedPaths.end()) {
                        m_processedPaths.insert(fullPath);

                        auto now = std::chrono::system_clock::now();
                        auto time_t_now = std::chrono::system_clock::to_time_t(now);
                        struct tm tmNow;
                        localtime_s(&tmNow, &time_t_now);

                        wchar_t timeBuf[64];
                        wcsftime(timeBuf, 64, L"%Y%m%d_%H%M%S", &tmNow);

                        std::wstring dstPath = outDir + L"intercepted_" + timeBuf + L"_" + fs::path(fullPath).filename().wstring();
                        if (ext == L".tmp") dstPath += L".sys";

                        if (FastCopyLockedFile(fullPath, dstPath)) {
                            DumpedArtifact art{};
                            art.sourcePath = fullPath;
                            art.savedPath = dstPath;
                            art.fileSize = fs::file_size(dstPath);
                            art.artifactType = "TEMP_WATCHER_DRIVER";
                            art.remoteBaseAddress = 0;

                            char timeStr[64];
                            strftime(timeStr, 64, "%H:%M:%S", &tmNow);
                            art.timestamp = timeStr;

                            m_artifacts.push_back(art);
                            Logger::Get().Log(LogLevel::Success, "CAPTURED EPHEMERAL DRIVER: %ls -> %ls (%llu bytes)",
                                              fullPath.c_str(), dstPath.c_str(), art.fileSize);
                        }
                    }
                }

                if (notify->NextEntryOffset == 0) break;
                notify = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<const uint8_t*>(notify) + notify->NextEntryOffset
                );
            } while (true);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    CloseHandle(hDir);
}

int DriverDumper::DumpProcessMemoryPE(DWORD pid, const std::wstring& outDir) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        Logger::Get().Log(LogLevel::Error, "Cannot open process PID %u for memory payload dumping (Error 0x%08X)",
                          pid, GetLastError());
        return 0;
    }

    std::wstring targetOut = outDir.empty() ? ConfigManager::Get().GetDefaultDumpDirectory() : outDir;
    fs::create_directories(targetOut);

    Logger::Get().Log(LogLevel::Memory, "Executing full VAD memory dump scan against PID %u...", pid);

    uint8_t* pAddr = reinterpret_cast<uint8_t*>(0x10000);
    uint8_t* pMaxAddr = reinterpret_cast<uint8_t*>(0x7FFFFFFF0000);
    MEMORY_BASIC_INFORMATION mbi{};
    int capturedCount = 0;

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tmNow;
    localtime_s(&tmNow, &time_t_now);

    wchar_t timeBuf[64];
    wcsftime(timeBuf, 64, L"%Y%m%d_%H%M%S", &tmNow);

    while (pAddr < pMaxAddr) {
        if (VirtualQueryEx(hProcess, pAddr, &mbi, sizeof(mbi)) == 0) {
            pAddr += 0x10000;
            continue;
        }

        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 4096 && mbi.RegionSize <= 64 * 1024 * 1024) {
            std::vector<uint8_t> pageBuffer(4096);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, pageBuffer.data(), pageBuffer.size(), &bytesRead) && bytesRead >= sizeof(IMAGE_DOS_HEADER)) {
                auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pageBuffer.data());
                if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 1024) {
                    // Possible PE image
                    std::vector<uint8_t> fullBuffer(mbi.RegionSize);
                    SIZE_T totalRead = 0;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, fullBuffer.data(), mbi.RegionSize, &totalRead) && totalRead > 0) {
                        wchar_t hexBase[32];
                        swprintf_s(hexBase, L"0x%016llX", reinterpret_cast<uint64_t>(mbi.BaseAddress));

                        std::wstring dstPath = targetOut + L"payload_dump_" + timeBuf + L"_" + hexBase + L".sys";
                        std::ofstream out(dstPath, std::ios::binary);
                        if (out.is_open()) {
                            out.write(reinterpret_cast<const char*>(fullBuffer.data()), totalRead);
                            out.close();

                            DumpedArtifact art{};
                            art.sourcePath = L"PID_" + std::to_wstring(pid) + L"_" + hexBase;
                            art.savedPath = dstPath;
                            art.fileSize = totalRead;
                            art.artifactType = "PROCESS_HEAP_PE";
                            art.remoteBaseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);

                            char timeStr[64];
                            strftime(timeStr, 64, "%H:%M:%S", &tmNow);
                            art.timestamp = timeStr;

                            {
                                std::lock_guard<std::mutex> lock(m_mutex);
                                m_artifacts.push_back(art);
                            }

                            capturedCount++;
                            Logger::Get().Log(LogLevel::Success, "DUMPED PROCESS PE IMAGE: Base %ls (%zu bytes) -> %ls",
                                              hexBase, totalRead, dstPath.c_str());
                        }
                    }
                }
            }
        }

        pAddr = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    CloseHandle(hProcess);
    Logger::Get().Log(LogLevel::Success, "Memory dump scan completed: %d PE images captured.", capturedCount);
    return capturedCount;
}

std::vector<DumpedArtifact> DriverDumper::GetCapturedArtifacts() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_artifacts;
}

void DriverDumper::ClearArtifacts() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_artifacts.clear();
    m_processedPaths.clear();
}

} // namespace Inkwell
