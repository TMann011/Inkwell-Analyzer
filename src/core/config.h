#pragma once

#include <string>
#include <cstdint>

namespace Inkwell {

struct AnalyzerConfig {
    // General Settings
    int selectedTheme = 0;              // 0: PurpleBlack, 1: ElectricIndigo, 2: CyberEmerald, 3: CrimsonBlood, 4: Slate
    bool autoElevate = true;            // Prompt for elevation on startup
    bool alwaysOnTop = false;           // Window Z-order
    float uiScale = 1.0f;               // DPI / Font Scale

    // Engine 1: Emul + Kevlar Hybrid
    std::wstring guestDriverPath;       // Target .sys to emulate / map
    int emulationMode = 0;              // 0: Hybrid Co-Emul, 1: Kevlar PE Mapper, 2: Kernemul Mock
    bool trackMemoryAllocations = true; // Log pool allocations and physical mappings
    bool trapIoctlDispatch = true;      // Intercept and decode DeviceIoControl
    bool emulSyscalls = true;           // Hook guest Nt/Zw syscall routines
    int emulTimeoutMs = 15000;          // Guard timeout for guest execution
    std::wstring externalKevlarPath;    // Optional path to external KEVLAR.exe if present
    std::wstring externalKernemulPath;  // Optional path to external kernemul.exe if present

    // Engine 2: Black-Box Anti-Cheat Differential Audit
    std::wstring targetGameDirectory;   // Path to game root for file/cert diff
    std::wstring targetProcessName;     // Target process to scan for unbacked code
    bool monitorServices = true;        // Track service creation
    bool monitorDrivers = true;         // Track BYOVD loading
    bool verifyCertificates = true;     // Check Authenticode stubs
    bool auditHostsFile = true;         // Check %SYSTEMROOT%\System32\drivers\etc\hosts

    // Engine 3: Unity / IL2CPP Forensic Analyzer
    std::wstring unityAssembliesPath;   // Path to Il2CppAssemblies or Managed folder
    int metadataTimeoutSeconds = 30;    // Hard timeout for PE traversal
    bool dumpExportedMethods = true;    // Parse il2cpp runtime exports

    // Engine 4: Driver & Payload Dumper
    std::wstring dumpOutputDirectory;   // Where to save captured .sys/.dll dumps
    std::wstring watchDirectory;        // Defaults to %TEMP%
    bool autoDumpFloatingPE = true;     // Dump unbacked MZ headers from target PID
    int pollingIntervalMs = 25;         // VAD scan frequency
};

class ConfigManager {
public:
    static ConfigManager& Get();

    bool LoadFromFile(const std::wstring& filename = L"analyzer_config.ini");
    bool SaveToFile(const std::wstring& filename = L"analyzer_config.ini");

    AnalyzerConfig& Data() { return m_config; }
    const AnalyzerConfig& Data() const { return m_config; }

    std::wstring GetExecutableDirectory() const;
    std::wstring GetDefaultDumpDirectory() const;
    std::wstring GetDefaultWatchDirectory() const;
    std::wstring GetSystemDriversDirectory() const;

private:
    ConfigManager();
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    AnalyzerConfig m_config;
    std::wstring m_currentConfigPath;
};

} // namespace Inkwell
