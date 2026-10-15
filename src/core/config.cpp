#include "config.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace Inkwell {

ConfigManager& ConfigManager::Get() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() {
    // Defaults resolved dynamically per-system without hardcoded paths
    std::wstring exeDir = GetExecutableDirectory();
    m_config.dumpOutputDirectory = GetDefaultDumpDirectory();
    m_config.watchDirectory = GetDefaultWatchDirectory();
    m_config.targetProcessName = L"";
    m_config.guestDriverPath = L"";
    m_config.targetGameDirectory = L"";
    m_config.unityAssembliesPath = L"";

    // Auto-discover sibling paths if available in parent or workspace tree
    std::wstring parentDir = exeDir;
    size_t lastSlash = parentDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        parentDir = parentDir.substr(0, lastSlash);
    }

    // Check sibling driver prepared
    std::wstring candidateSys = parentDir + L"\\driver prepared\\stage1_staging_driver\\iqvw64e.sys";
    if (fs::exists(candidateSys)) {
        m_config.guestDriverPath = candidateSys;
    }

    // Check sibling anti/analyse for KEVLAR and kernemul
    std::wstring candidateKev = parentDir + L"\\anti\\analyse\\KEVLAR\\x64\\Release\\KEVLAR.exe";
    if (fs::exists(candidateKev)) {
        m_config.externalKevlarPath = candidateKev;
    }
    std::wstring candidateEmu = parentDir + L"\\anti\\analyse\\kernemul\\kernemul\\build\\kernemul.exe";
    if (fs::exists(candidateEmu)) {
        m_config.externalKernemulPath = candidateEmu;
    }
}

std::wstring ConfigManager::GetExecutableDirectory() const {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring pathStr = exePath;
    size_t pos = pathStr.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return pathStr.substr(0, pos + 1);
    }
    return L".\\";
}

std::wstring ConfigManager::GetDefaultDumpDirectory() const {
    std::wstring dir = GetExecutableDirectory() + L"dumps\\";
    fs::create_directories(dir);
    return dir;
}

std::wstring ConfigManager::GetDefaultWatchDirectory() const {
    wchar_t tempPath[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, tempPath);
    if (len > 0 && len < MAX_PATH) {
        return std::wstring(tempPath);
    }
    wchar_t expanded[MAX_PATH];
    if (ExpandEnvironmentStringsW(L"%TEMP%\\", expanded, MAX_PATH) > 0) {
        return std::wstring(expanded);
    }
    return GetExecutableDirectory() + L"temp\\";
}

std::wstring ConfigManager::GetSystemDriversDirectory() const {
    wchar_t sysDir[MAX_PATH];
    UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::wstring(sysDir) + L"\\drivers\\";
    }
    wchar_t expanded[MAX_PATH];
    if (ExpandEnvironmentStringsW(L"%SYSTEMROOT%\\System32\\drivers\\", expanded, MAX_PATH) > 0) {
        return std::wstring(expanded);
    }
    return L".\\drivers\\";
}

static std::wstring ReadIniString(const std::wstring& file, const wchar_t* section, const wchar_t* key, const wchar_t* defVal) {
    wchar_t buf[1024];
    GetPrivateProfileStringW(section, key, defVal, buf, 1024, file.c_str());
    return std::wstring(buf);
}

static int ReadIniInt(const std::wstring& file, const wchar_t* section, const wchar_t* key, int defVal) {
    return GetPrivateProfileIntW(section, key, defVal, file.c_str());
}

static bool ReadIniBool(const std::wstring& file, const wchar_t* section, const wchar_t* key, bool defVal) {
    int val = GetPrivateProfileIntW(section, key, defVal ? 1 : 0, file.c_str());
    return val != 0;
}

static void WriteIniString(const std::wstring& file, const wchar_t* section, const wchar_t* key, const std::wstring& value) {
    WritePrivateProfileStringW(section, key, value.c_str(), file.c_str());
}

static void WriteIniInt(const std::wstring& file, const wchar_t* section, const wchar_t* key, int value) {
    WritePrivateProfileStringW(section, key, std::to_wstring(value).c_str(), file.c_str());
}

static void WriteIniBool(const std::wstring& file, const wchar_t* section, const wchar_t* key, bool value) {
    WritePrivateProfileStringW(section, key, value ? L"1" : L"0", file.c_str());
}

bool ConfigManager::LoadFromFile(const std::wstring& filename) {
    std::wstring fullPath;
    if (fs::path(filename).is_absolute()) {
        fullPath = filename;
    } else {
        fullPath = GetExecutableDirectory() + filename;
    }
    m_currentConfigPath = fullPath;

    if (!fs::exists(fullPath)) {
        return SaveToFile(filename);
    }

    m_config.selectedTheme           = ReadIniInt(fullPath, L"UI", L"SelectedTheme", m_config.selectedTheme);
    m_config.autoElevate             = ReadIniBool(fullPath, L"UI", L"AutoElevate", m_config.autoElevate);
    m_config.alwaysOnTop             = ReadIniBool(fullPath, L"UI", L"AlwaysOnTop", m_config.alwaysOnTop);

    m_config.guestDriverPath         = ReadIniString(fullPath, L"HybridEmul", L"GuestDriverPath", m_config.guestDriverPath.c_str());
    m_config.emulationMode           = ReadIniInt(fullPath, L"HybridEmul", L"EmulationMode", m_config.emulationMode);
    m_config.trackMemoryAllocations  = ReadIniBool(fullPath, L"HybridEmul", L"TrackMemoryAllocations", m_config.trackMemoryAllocations);
    m_config.trapIoctlDispatch       = ReadIniBool(fullPath, L"HybridEmul", L"TrapIoctlDispatch", m_config.trapIoctlDispatch);
    m_config.emulSyscalls            = ReadIniBool(fullPath, L"HybridEmul", L"EmulSyscalls", m_config.emulSyscalls);
    m_config.emulTimeoutMs           = ReadIniInt(fullPath, L"HybridEmul", L"EmulTimeoutMs", m_config.emulTimeoutMs);
    m_config.externalKevlarPath      = ReadIniString(fullPath, L"HybridEmul", L"ExternalKevlarPath", m_config.externalKevlarPath.c_str());
    m_config.externalKernemulPath    = ReadIniString(fullPath, L"HybridEmul", L"ExternalKernemulPath", m_config.externalKernemulPath.c_str());

    m_config.targetGameDirectory     = ReadIniString(fullPath, L"AntiCheat", L"TargetGameDirectory", m_config.targetGameDirectory.c_str());
    m_config.targetProcessName       = ReadIniString(fullPath, L"AntiCheat", L"TargetProcessName", m_config.targetProcessName.c_str());
    m_config.monitorServices         = ReadIniBool(fullPath, L"AntiCheat", L"MonitorServices", m_config.monitorServices);
    m_config.monitorDrivers          = ReadIniBool(fullPath, L"AntiCheat", L"MonitorDrivers", m_config.monitorDrivers);
    m_config.verifyCertificates      = ReadIniBool(fullPath, L"AntiCheat", L"VerifyCertificates", m_config.verifyCertificates);
    m_config.auditHostsFile          = ReadIniBool(fullPath, L"AntiCheat", L"AuditHostsFile", m_config.auditHostsFile);

    m_config.unityAssembliesPath     = ReadIniString(fullPath, L"Unity", L"AssembliesPath", m_config.unityAssembliesPath.c_str());
    m_config.metadataTimeoutSeconds  = ReadIniInt(fullPath, L"Unity", L"TimeoutSeconds", m_config.metadataTimeoutSeconds);
    m_config.dumpExportedMethods     = ReadIniBool(fullPath, L"Unity", L"DumpExportedMethods", m_config.dumpExportedMethods);

    m_config.dumpOutputDirectory     = ReadIniString(fullPath, L"Dumper", L"DumpOutputDirectory", m_config.dumpOutputDirectory.c_str());
    m_config.watchDirectory          = ReadIniString(fullPath, L"Dumper", L"WatchDirectory", m_config.watchDirectory.c_str());
    m_config.autoDumpFloatingPE      = ReadIniBool(fullPath, L"Dumper", L"AutoDumpFloatingPE", m_config.autoDumpFloatingPE);
    m_config.pollingIntervalMs       = ReadIniInt(fullPath, L"Dumper", L"PollingIntervalMs", m_config.pollingIntervalMs);

    return true;
}

bool ConfigManager::SaveToFile(const std::wstring& filename) {
    std::wstring fullPath;
    if (fs::path(filename).is_absolute()) {
        fullPath = filename;
    } else {
        fullPath = GetExecutableDirectory() + filename;
    }
    m_currentConfigPath = fullPath;

    WriteIniInt(fullPath, L"UI", L"SelectedTheme", m_config.selectedTheme);
    WriteIniBool(fullPath, L"UI", L"AutoElevate", m_config.autoElevate);
    WriteIniBool(fullPath, L"UI", L"AlwaysOnTop", m_config.alwaysOnTop);

    WriteIniString(fullPath, L"HybridEmul", L"GuestDriverPath", m_config.guestDriverPath);
    WriteIniInt(fullPath, L"HybridEmul", L"EmulationMode", m_config.emulationMode);
    WriteIniBool(fullPath, L"HybridEmul", L"TrackMemoryAllocations", m_config.trackMemoryAllocations);
    WriteIniBool(fullPath, L"HybridEmul", L"TrapIoctlDispatch", m_config.trapIoctlDispatch);
    WriteIniBool(fullPath, L"HybridEmul", L"EmulSyscalls", m_config.emulSyscalls);
    WriteIniInt(fullPath, L"HybridEmul", L"EmulTimeoutMs", m_config.emulTimeoutMs);
    WriteIniString(fullPath, L"HybridEmul", L"ExternalKevlarPath", m_config.externalKevlarPath);
    WriteIniString(fullPath, L"HybridEmul", L"ExternalKernemulPath", m_config.externalKernemulPath);

    WriteIniString(fullPath, L"AntiCheat", L"TargetGameDirectory", m_config.targetGameDirectory);
    WriteIniString(fullPath, L"AntiCheat", L"TargetProcessName", m_config.targetProcessName);
    WriteIniBool(fullPath, L"AntiCheat", L"MonitorServices", m_config.monitorServices);
    WriteIniBool(fullPath, L"AntiCheat", L"MonitorDrivers", m_config.monitorDrivers);
    WriteIniBool(fullPath, L"AntiCheat", L"VerifyCertificates", m_config.verifyCertificates);
    WriteIniBool(fullPath, L"AntiCheat", L"AuditHostsFile", m_config.auditHostsFile);

    WriteIniString(fullPath, L"Unity", L"AssembliesPath", m_config.unityAssembliesPath);
    WriteIniInt(fullPath, L"Unity", L"TimeoutSeconds", m_config.metadataTimeoutSeconds);
    WriteIniBool(fullPath, L"Unity", L"DumpExportedMethods", m_config.dumpExportedMethods);

    WriteIniString(fullPath, L"Dumper", L"DumpOutputDirectory", m_config.dumpOutputDirectory);
    WriteIniString(fullPath, L"Dumper", L"WatchDirectory", m_config.watchDirectory);
    WriteIniBool(fullPath, L"Dumper", L"AutoDumpFloatingPE", m_config.autoDumpFloatingPE);
    WriteIniInt(fullPath, L"Dumper", L"PollingIntervalMs", m_config.pollingIntervalMs);

    return true;
}

} // namespace Inkwell
