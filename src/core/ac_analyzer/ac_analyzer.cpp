#include "ac_analyzer.h"
#include "../logger.h"
#include "../config.h"

#include <psapi.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

namespace Inkwell {

AntiCheatAnalyzer& AntiCheatAnalyzer::Get() {
    static AntiCheatAnalyzer instance;
    return instance;
}

AntiCheatAnalyzer::AntiCheatAnalyzer() {
}

std::vector<DriverSnapshotEntry> AntiCheatAnalyzer::SnapshotLoadedDrivers() {
    std::vector<DriverSnapshotEntry> drivers;
    LPVOID driversList[1024];
    DWORD cbNeeded = 0;

    if (EnumDeviceDrivers(driversList, sizeof(driversList), &cbNeeded) && cbNeeded < sizeof(driversList)) {
        int count = cbNeeded / sizeof(LPVOID);
        drivers.reserve(count);

        wchar_t baseName[MAX_PATH];
        wchar_t fullPath[MAX_PATH];

        for (int i = 0; i < count; ++i) {
            DriverSnapshotEntry entry{};
            entry.baseAddress = reinterpret_cast<uint64_t>(driversList[i]);

            if (GetDeviceDriverBaseNameW(driversList[i], baseName, MAX_PATH)) {
                entry.baseName = baseName;
            } else {
                entry.baseName = L"Unknown";
            }

            if (GetDeviceDriverFileNameW(driversList[i], fullPath, MAX_PATH)) {
                entry.fullPath = fullPath;
            } else {
                entry.fullPath = entry.baseName;
            }

            std::string signer;
            entry.isSigned = VerifyFileSignature(entry.fullPath, signer);
            drivers.push_back(entry);
        }
    }
    return drivers;
}

std::vector<ServiceSnapshotEntry> AntiCheatAnalyzer::SnapshotWindowsServices() {
    std::vector<ServiceSnapshotEntry> services;
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return services;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                          NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (bytesNeeded > 0) {
        std::vector<uint8_t> buffer(bytesNeeded);
        if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                                  buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
            auto pServices = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
            services.reserve(servicesReturned);

            for (DWORD i = 0; i < servicesReturned; ++i) {
                ServiceSnapshotEntry entry{};
                entry.serviceName = pServices[i].lpServiceName ? pServices[i].lpServiceName : L"";
                entry.displayName = pServices[i].lpDisplayName ? pServices[i].lpDisplayName : L"";
                entry.serviceType = pServices[i].ServiceStatusProcess.dwServiceType;
                entry.currentState = pServices[i].ServiceStatusProcess.dwCurrentState;
                services.push_back(entry);
            }
        }
    }

    CloseServiceHandle(hSCM);
    return services;
}

bool AntiCheatAnalyzer::VerifyFileSignature(const std::wstring& filePath, std::string& outSigner) {
    if (!fs::exists(filePath)) return false;

    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &winTrustData);
    bool isValid = (status == ERROR_SUCCESS);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &winTrustData);

    outSigner = isValid ? "Valid Microsoft/Vendor Authenticode" : "Unsigned or Invalid Signature";
    return isValid;
}

std::string AntiCheatAnalyzer::ComputeFileSHA256(const std::wstring& filePath) {
    if (!fs::exists(filePath)) return "";

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return "";

    DWORD hashObjSize = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&hashObjSize), sizeof(DWORD), &cbData, 0);
    std::vector<uint8_t> hashObject(hashObjSize);

    DWORD hashSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&hashSize), sizeof(DWORD), &cbData, 0);
    std::vector<uint8_t> hashBuf(hashSize);

    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjSize, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    char buffer[16384];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        BCryptHashData(hHash, reinterpret_cast<PBYTE>(buffer), static_cast<ULONG>(file.gcount()), 0);
    }
    file.close();

    BCryptFinishHash(hHash, hashBuf.data(), hashSize, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::stringstream ss;
    for (uint8_t b : hashBuf) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

bool AntiCheatAnalyzer::CaptureBaseline() {
    std::lock_guard<std::mutex> lock(m_mutex);
    Logger::Get().Log(LogLevel::Telemetry, "Capturing system telemetry baseline...");

    m_baselineDrivers = SnapshotLoadedDrivers();
    m_baselineServices = SnapshotWindowsServices();
    m_baselineHostsLines = AuditHostsFile();

    m_report.baselineDriverCount = static_cast<uint32_t>(m_baselineDrivers.size());
    m_report.baselineServiceCount = static_cast<uint32_t>(m_baselineServices.size());
    m_report.baselineCaptured = true;

    Logger::Get().Log(LogLevel::Success, "Baseline locked: %u Active Drivers, %u Windows Services recorded.",
                      m_report.baselineDriverCount, m_report.baselineServiceCount);
    return true;
}

bool AntiCheatAnalyzer::RunDifferentialAudit(const std::wstring& targetGameDir, const std::wstring& targetProcessName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Logger::Get().Log(LogLevel::Telemetry, "Executing differential telemetry audit against baseline...");

    m_report.newDrivers.clear();
    m_report.newServices.clear();
    m_report.tamperedFiles.clear();
    m_report.injectedRegions.clear();
    m_report.hostsRedirects.clear();

    // 1. Diff Drivers
    auto liveDrivers = SnapshotLoadedDrivers();
    std::set<std::wstring> baseDriverSet;
    for (const auto& d : m_baselineDrivers) baseDriverSet.insert(d.baseName);

    for (const auto& d : liveDrivers) {
        if (baseDriverSet.find(d.baseName) == baseDriverSet.end()) {
            m_report.newDrivers.push_back(d);
            Logger::Get().Log(LogLevel::Warning, "NEW DRIVER DETECTED: %ls (Base: 0x%016llX, Signed: %s)",
                              d.baseName.c_str(), d.baseAddress, d.isSigned ? "YES" : "NO - SUSPICIOUS");
        }
    }

    // 2. Diff Services
    auto liveServices = SnapshotWindowsServices();
    std::set<std::wstring> baseServiceSet;
    for (const auto& s : m_baselineServices) baseServiceSet.insert(s.serviceName);

    for (const auto& s : liveServices) {
        if (baseServiceSet.find(s.serviceName) == baseServiceSet.end()) {
            m_report.newServices.push_back(s);
            Logger::Get().Log(LogLevel::Warning, "NEW SERVICE DETECTED: %ls (%ls)",
                              s.serviceName.c_str(), s.displayName.c_str());
        }
    }

    // 3. Hosts file audit
    auto liveHosts = AuditHostsFile();
    m_report.hostsRedirects = liveHosts;

    // 4. Game Directory Integrity Audit (if specified)
    if (!targetGameDir.empty() && fs::exists(targetGameDir)) {
        m_report.tamperedFiles = AuditDirectoryIntegrity(targetGameDir);
    }

    // 5. Target Process Memory Scan (if specified)
    if (!targetProcessName.empty()) {
        DWORD pid = FindProcessIdByName(targetProcessName);
        if (pid != 0) {
            m_report.injectedRegions = ScanProcessUnbackedMemory(pid);
        } else {
            Logger::Get().Log(LogLevel::Warning, "Target process '%ls' is not currently running.", targetProcessName.c_str());
        }
    }

    m_report.auditCompleted = true;
    Logger::Get().Log(LogLevel::Success, "Audit completed: %zu New Drivers, %zu New Services, %zu Tampered Files, %zu Injected Memory Regions.",
                      m_report.newDrivers.size(), m_report.newServices.size(), m_report.tamperedFiles.size(), m_report.injectedRegions.size());

    return true;
}

std::vector<UnbackedMemoryRegion> AntiCheatAnalyzer::ScanProcessUnbackedMemory(DWORD pid) {
    std::vector<UnbackedMemoryRegion> regions;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        Logger::Get().Log(LogLevel::Error, "Failed to open target process PID %u for memory audit (Error 0x%08X). Run as Administrator.",
                          pid, GetLastError());
        return regions;
    }

    Logger::Get().Log(LogLevel::Memory, "Auditing VAD virtual memory of PID %u for unbacked executable code...", pid);

    uint8_t* pAddr = reinterpret_cast<uint8_t*>(0x10000);
    uint8_t* pMaxAddr = reinterpret_cast<uint8_t*>(0x7FFFFFFF0000);
    MEMORY_BASIC_INFORMATION mbi{};

    while (pAddr < pMaxAddr) {
        if (VirtualQueryEx(hProcess, pAddr, &mbi, sizeof(mbi)) == 0) {
            pAddr += 0x10000;
            continue;
        }

        bool isExecutable = (mbi.Protect == PAGE_EXECUTE ||
                             mbi.Protect == PAGE_EXECUTE_READ ||
                             mbi.Protect == PAGE_EXECUTE_READWRITE ||
                             mbi.Protect == PAGE_EXECUTE_WRITECOPY);

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && isExecutable) {
            UnbackedMemoryRegion reg{};
            reg.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            reg.regionSize = mbi.RegionSize;
            reg.protect = mbi.Protect;
            reg.state = mbi.State;
            reg.type = mbi.Type;

            // Check for floating MZ / PE header
            uint8_t peekBuffer[64] = { 0 };
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, peekBuffer, sizeof(peekBuffer), &bytesRead) && bytesRead >= 2) {
                if (peekBuffer[0] == 'M' && peekBuffer[1] == 'Z') {
                    reg.hasFloatingPE = true;
                    reg.threatDescription = "FLOATING PE / MZ HEADER IN UNBACKED PRIVATE MEMORY (Manual Map / Decrypted Payload)";
                    Logger::Get().Log(LogLevel::Memory, "CRITICAL: Floating PE header discovered at 0x%016llX (Size: 0x%llX)",
                                      reg.baseAddress, reg.regionSize);
                } else {
                    reg.hasFloatingPE = false;
                    reg.threatDescription = "Unbacked Private Executable Memory (Shellcode / Hook Trampoline)";
                    Logger::Get().Log(LogLevel::Memory, "SUSPICIOUS: Unbacked Executable Memory at 0x%016llX (Size: 0x%llX)",
                                      reg.baseAddress, reg.regionSize);
                }
            }
            regions.push_back(reg);
        }

        pAddr = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return regions;
}

std::vector<FileIntegrityEntry> AntiCheatAnalyzer::AuditDirectoryIntegrity(const std::wstring& directoryPath) {
    std::vector<FileIntegrityEntry> entries;
    if (!fs::exists(directoryPath)) return entries;

    for (const auto& item : fs::recursive_directory_iterator(directoryPath, fs::directory_options::skip_permission_denied)) {
        if (!item.is_regular_file()) continue;
        std::wstring ext = item.path().extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == L".exe" || ext == L".dll" || ext == L".sys") {
            FileIntegrityEntry entry{};
            entry.filePath = item.path().wstring();
            entry.fileSize = fs::file_size(item.path());
            entry.sha256 = ComputeFileSHA256(entry.filePath);
            entry.isSigned = VerifyFileSignature(entry.filePath, entry.signerSubject);

            // Anti-cheat stub detection: size drops under 64KB for major binaries
            std::wstring filename = item.path().filename().wstring();
            std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

            if ((filename.find(L"easyanticheat") != std::wstring::npos ||
                 filename.find(L"beservice") != std::wstring::npos ||
                 filename.find(L"vanguard") != std::wstring::npos) &&
                entry.fileSize < 65536) {
                entry.isStubSuspect = true;
                Logger::Get().Log(LogLevel::Error, "SUSPECT AC STUB DETECTED: %ls (Unusually small size: %llu bytes)",
                                  item.path().filename().c_str(), entry.fileSize);
            }

            if (!entry.isSigned) {
                Logger::Get().Log(LogLevel::Warning, "UNSIGNED BINARY IN GAME TREE: %ls", item.path().filename().c_str());
            }

            entries.push_back(entry);
        }
    }
    return entries;
}

std::vector<std::string> AntiCheatAnalyzer::AuditHostsFile() {
    std::vector<std::string> suspiciousLines;
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring hostsPath = std::wstring(sysDir) + L"\\drivers\\etc\\hosts";

    if (!fs::exists(hostsPath)) return suspiciousLines;

    std::ifstream file(hostsPath);
    if (!file.is_open()) return suspiciousLines;

    std::string line;
    while (std::getline(file, line)) {
        // Strip whitespace
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] == '#') continue;

        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find("easyanticheat") != std::string::npos ||
            lower.find("battleye") != std::string::npos ||
            lower.find("riotgames") != std::string::npos ||
            lower.find("epicgames") != std::string::npos ||
            lower.find("127.0.0.1") != std::string::npos) {
            suspiciousLines.push_back(line);
            Logger::Get().Log(LogLevel::Warning, "HOSTS REDIRECTION DETECTED: %s", line.c_str());
        }
    }
    return suspiciousLines;
}

DWORD AntiCheatAnalyzer::FindProcessIdByName(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

std::vector<std::pair<DWORD, std::wstring>> AntiCheatAnalyzer::EnumerateRunningProcesses() {
    std::vector<std::pair<DWORD, std::wstring>> procs;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID != 0) {
                procs.push_back({ pe.th32ProcessID, pe.szExeFile });
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return procs;
}

DifferentialAuditReport AntiCheatAnalyzer::GetReport() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_report;
}

void AntiCheatAnalyzer::ClearReport() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_report = DifferentialAuditReport{};
}

} // namespace Inkwell
