#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace Inkwell {

enum class CoEmulMode : int {
    HybridCoEmulation = 0, // KEVLAR Memory & Symbol Tracker + Kernemul NT Dispatcher
    KevlarHostEngine,      // KEVLAR Native Provider & PE Mapper
    KernemulSandbox        // Kernemul System Call & Hypervisor Sandbox
};

struct DriverSectionInfo {
    std::string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawDataSize;
    uint32_t characteristics;
    bool isExecutable;
    bool isWritable;
};

struct KernelImportInfo {
    std::string moduleName;
    std::string functionName;
    uint32_t ordinal;
    uint64_t thunkRva;
    bool isIntercepted;
};

struct EmulationTelemetry {
    std::string driverName;
    uint64_t imageBase;
    uint32_t imageSize;
    uint64_t entryPointRva;
    uint32_t sectionCount;
    std::vector<DriverSectionInfo> sections;
    std::vector<KernelImportInfo> imports;

    // Tracked Behaviors
    std::vector<std::string> createdDevices;
    std::vector<std::string> symbolicLinks;
    std::vector<std::string> registeredCallbacks;
    std::vector<std::string> memoryPoolAllocations;
    std::vector<std::string> interceptedIoctls;
    std::vector<std::string> detectedThreats;

    bool isByovdExploitDriver = false; // E.g. iqvw64e.sys / gdrv.sys
    bool isAntiCheatDriver = false;    // E.g. EasyAntiCheat / BattlEye / Vanguard
    bool executionSucceeded = false;
    std::string executionStatus;
};

class HybridEngine {
public:
    static HybridEngine& Get();

    bool StartEmulation(const std::wstring& driverPath, CoEmulMode mode = CoEmulMode::HybridCoEmulation);
    void StopEmulation();

    bool IsRunning() const { return m_isRunning.load(); }
    EmulationTelemetry GetTelemetry();

    // Direct Analysis Helpers
    bool ParseDriverPE(const std::wstring& driverPath, EmulationTelemetry& outTelem);
    bool DumpEmulatedPayload(const std::wstring& outputPath);

    // External binary integrations (auto-detected or configured)
    bool IsKevlarBinaryAvailable() const;
    bool IsKernemulBinaryAvailable() const;
    std::wstring GetDiscoveredKevlarPath() const;
    std::wstring GetDiscoveredKernemulPath() const;

private:
    HybridEngine();
    ~HybridEngine();
    HybridEngine(const HybridEngine&) = delete;
    HybridEngine& operator=(const HybridEngine&) = delete;

    void EmulationWorker(std::wstring driverPath, CoEmulMode mode);
    bool ExecuteHybridCoEmulation(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem);
    bool LaunchExternalEmulator(const std::wstring& exePath, const std::wstring& driverPath, const std::string& label);

    // Mock NT Kernel Dispatcher & Intercept Primitives
    void DispatchKernelImport(const std::string& mod, const std::string& func, EmulationTelemetry& telem);
    void CheckAntiCheatSignatures(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem);
    void CheckByovdSignatures(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem);

    std::atomic<bool> m_isRunning{ false };
    std::thread m_workerThread;
    std::mutex m_telemetryMutex;
    EmulationTelemetry m_telemetry;

    std::vector<uint8_t> m_mappedVirtualImage;
    uint64_t m_virtualBase = 0xFFFFD00000000000ULL;
};

} // namespace Inkwell
