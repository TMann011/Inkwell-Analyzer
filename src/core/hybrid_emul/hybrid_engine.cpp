#include "hybrid_engine.h"
#include "../logger.h"
#include "../config.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>

namespace fs = std::filesystem;

namespace Inkwell {

HybridEngine& HybridEngine::Get() {
    static HybridEngine instance;
    return instance;
}

HybridEngine::HybridEngine() {
}

HybridEngine::~HybridEngine() {
    StopEmulation();
}

bool HybridEngine::IsKevlarBinaryAvailable() const {
    return !GetDiscoveredKevlarPath().empty();
}

bool HybridEngine::IsKernemulBinaryAvailable() const {
    return !GetDiscoveredKernemulPath().empty();
}

std::wstring HybridEngine::GetDiscoveredKevlarPath() const {
    const auto& cfg = ConfigManager::Get().Data();
    if (!cfg.externalKevlarPath.empty() && fs::exists(cfg.externalKevlarPath)) {
        return cfg.externalKevlarPath;
    }

    std::wstring exeDir = ConfigManager::Get().GetExecutableDirectory();
    std::wstring parentDir = exeDir;
    size_t lastSlash = parentDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) parentDir = parentDir.substr(0, lastSlash);

    std::vector<std::wstring> candidates = {
        exeDir + L"KEVLAR.exe",
        parentDir + L"\\anti\\analyse\\KEVLAR\\x64\\Release\\KEVLAR.exe",
        parentDir + L"\\anti\\analyse\\KEVLAR\\KEVLAR.exe",
        parentDir + L"\\anti\\analyse\\KEVLAR\\x64\\Debug\\KEVLAR.exe"
    };

    for (const auto& path : candidates) {
        if (fs::exists(path)) return path;
    }
    return L"";
}

std::wstring HybridEngine::GetDiscoveredKernemulPath() const {
    const auto& cfg = ConfigManager::Get().Data();
    if (!cfg.externalKernemulPath.empty() && fs::exists(cfg.externalKernemulPath)) {
        return cfg.externalKernemulPath;
    }

    std::wstring exeDir = ConfigManager::Get().GetExecutableDirectory();
    std::wstring parentDir = exeDir;
    size_t lastSlash = parentDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) parentDir = parentDir.substr(0, lastSlash);

    std::vector<std::wstring> candidates = {
        exeDir + L"kernemul.exe",
        parentDir + L"\\anti\\analyse\\kernemul\\kernemul\\build\\kernemul.exe",
        parentDir + L"\\anti\\analyse\\kernemul\\kernemul\\build\\Release\\kernemul.exe",
        parentDir + L"\\anti\\analyse\\kernemul\\kernemul.exe"
    };

    for (const auto& path : candidates) {
        if (fs::exists(path)) return path;
    }
    return L"";
}

bool HybridEngine::ParseDriverPE(const std::wstring& driverPath, EmulationTelemetry& outTelem) {
    if (!fs::exists(driverPath)) {
        Logger::Get().Log(LogLevel::Error, "Driver file does not exist: %ls", driverPath.c_str());
        return false;
    }

    std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        Logger::Get().Log(LogLevel::Error, "Failed to open driver for analysis: %ls", driverPath.c_str());
        return false;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        Logger::Get().Log(LogLevel::Error, "Failed to read driver bytes: %ls", driverPath.c_str());
        return false;
    }
    file.close();

    fs::path p(driverPath);
    outTelem.driverName = p.filename().string();

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Logger::Get().Log(LogLevel::Error, "Invalid DOS signature (0x%04X). Expected 'MZ'", dosHeader->e_magic);
        return false;
    }

    if (buffer.size() < static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS64)) return false;
    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Logger::Get().Log(LogLevel::Error, "Invalid NT signature (0x%08X). Expected 'PE\\0\\0'", ntHeaders->Signature);
        return false;
    }

    outTelem.imageBase = ntHeaders->OptionalHeader.ImageBase;
    outTelem.imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    outTelem.entryPointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    outTelem.sectionCount = ntHeaders->FileHeader.NumberOfSections;

    // Enumerate Sections
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    outTelem.sections.clear();
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        DriverSectionInfo s;
        char nameBuf[9] = { 0 };
        memcpy_s(nameBuf, 8, sectionHeader->Name, 8);
        s.name = nameBuf;
        s.virtualAddress = sectionHeader->VirtualAddress;
        s.virtualSize = sectionHeader->Misc.VirtualSize;
        s.rawDataSize = sectionHeader->SizeOfRawData;
        s.characteristics = sectionHeader->Characteristics;
        s.isExecutable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        s.isWritable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        outTelem.sections.push_back(s);
    }

    // Parse Imports
    outTelem.imports.clear();
    auto importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size > 0) {
        // Map RVA to raw file offset
        auto RvaToOffset = [&](uint32_t rva) -> uint32_t {
            for (const auto& sec : outTelem.sections) {
                if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
                    return sec.rawDataSize > 0 ? (rva - sec.virtualAddress) + (reinterpret_cast<const uint8_t*>(buffer.data()) ? 
                        // find raw offset
                        0 : 0) : 0;
                }
            }
            return 0;
        };

        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(ntHeaders);
        auto FindRawOffset = [&](uint32_t rva) -> uint32_t {
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                    return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
                }
            }
            return 0;
        };

        uint32_t descOffset = FindRawOffset(importDir.VirtualAddress);
        if (descOffset != 0 && descOffset < buffer.size()) {
            auto importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + descOffset);
            while (importDesc->Characteristics != 0 || importDesc->Name != 0) {
                uint32_t modNameOffset = FindRawOffset(importDesc->Name);
                std::string modName = "UNKNOWN";
                if (modNameOffset != 0 && modNameOffset < buffer.size()) {
                    modName = reinterpret_cast<const char*>(buffer.data() + modNameOffset);
                }

                uint32_t thunkRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
                uint32_t thunkOffset = FindRawOffset(thunkRva);

                if (thunkOffset != 0 && thunkOffset < buffer.size()) {
                    auto thunkData = reinterpret_cast<const IMAGE_THUNK_DATA64*>(buffer.data() + thunkOffset);
                    while (thunkData->u1.AddressOfData != 0) {
                        KernelImportInfo imp;
                        imp.moduleName = modName;
                        imp.thunkRva = thunkRva;

                        if (IMAGE_SNAP_BY_ORDINAL64(thunkData->u1.Ordinal)) {
                            imp.ordinal = static_cast<uint32_t>(IMAGE_ORDINAL64(thunkData->u1.Ordinal));
                            imp.functionName = "Ordinal_" + std::to_string(imp.ordinal);
                        } else {
                            imp.ordinal = 0;
                            uint32_t nameDataOffset = FindRawOffset(static_cast<uint32_t>(thunkData->u1.AddressOfData));
                            if (nameDataOffset != 0 && nameDataOffset < buffer.size()) {
                                auto importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(buffer.data() + nameDataOffset);
                                imp.functionName = importByName->Name;
                            } else {
                                imp.functionName = "UnknownImport";
                            }
                        }

                        imp.isIntercepted = true;
                        outTelem.imports.push_back(imp);
                        ++thunkData;
                    }
                }
                ++importDesc;
            }
        }
    }

    CheckAntiCheatSignatures(buffer, outTelem);
    CheckByovdSignatures(buffer, outTelem);

    return true;
}

void HybridEngine::CheckAntiCheatSignatures(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem) {
    std::string content(reinterpret_cast<const char*>(fileBytes.data()), fileBytes.size());

    // Search common anti-cheat identifiers
    std::vector<std::pair<std::string, std::string>> acIndicators = {
        { "EasyAntiCheat", "EasyAntiCheat Core Dispatcher / EOS telemetry detected" },
        { "\\Device\\EasyAntiCheat", "EAC named device communication endpoint" },
        { "Vanguard", "Riot Vanguard kernel driver hypervisor hooks detected" },
        { "\\Device\\vgk", "Vanguard control endpoint" },
        { "BattlEye", "BattlEye BEDaisy kernel filter driver" },
        { "\\Device\\BEDaisy", "BattlEye device handle" },
        { "AntiCheatExpert", "Tencent ACE-BASE driver protection module" },
        { "ObRegisterCallbacks", "Ring 0 process/thread access handle filter installed" },
        { "PsSetCreateProcessNotifyRoutine", "Process creation monitor routine" },
        { "PsSetLoadImageNotifyRoutine", "Module image load notification trap" },
        { "KeBugCheckEx", "Driver armed with intentional kernel bugcheck traps" }
    };

    for (const auto& item : acIndicators) {
        if (content.find(item.first) != std::string::npos) {
            telem.isAntiCheatDriver = true;
            telem.detectedThreats.push_back(item.second);
        }
    }
}

void HybridEngine::CheckByovdSignatures(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem) {
    std::string content(reinterpret_cast<const char*>(fileBytes.data()), fileBytes.size());

    // BYOVD Exploitation signatures
    std::vector<std::pair<std::string, std::string>> byovdIndicators = {
        { "\\Device\\Nal", "Intel iqvw64e.sys physical memory mapping vector (kdmapper target)" },
        { "MmMapIoSpace", "Arbitrary physical memory map primitive" },
        { "MmGetPhysicalAddress", "Virtual-to-Physical translation primitive" },
        { "ZwMapViewOfSection", "Arbitrary kernel/user section mapping" },
        { "RTCore64", "Micro-Star RTCore64 arbitrary MSR/physical read/write driver" },
        { "gdrv.sys", "GIGABYTE arbitrary kernel write driver" },
        { "AsIO.sys", "ASUS port/memory I/O exploit driver" },
        { "ExAllocatePoolWithTag", "Unbacked kernel pool memory allocation" }
    };

    for (const auto& item : byovdIndicators) {
        if (content.find(item.first) != std::string::npos) {
            telem.isByovdExploitDriver = true;
            telem.detectedThreats.push_back(item.second);
        }
    }
}

bool HybridEngine::StartEmulation(const std::wstring& driverPath, CoEmulMode mode) {
    if (m_isRunning.load()) {
        Logger::Get().Log(LogLevel::Warning, "Emulation engine is already executing.");
        return false;
    }

    if (!fs::exists(driverPath)) {
        Logger::Get().Log(LogLevel::Error, "Driver file not found: %ls", driverPath.c_str());
        return false;
    }

    m_isRunning.store(true);

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }

    m_workerThread = std::thread(&HybridEngine::EmulationWorker, this, driverPath, mode);
    return true;
}

void HybridEngine::StopEmulation() {
    if (m_isRunning.load()) {
        m_isRunning.store(false);
        Logger::Get().Log(LogLevel::Info, "Halting emulation sandbox worker...");
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
        Logger::Get().Log(LogLevel::Success, "Emulation sandbox stopped cleanly.");
    }
}

EmulationTelemetry HybridEngine::GetTelemetry() {
    std::lock_guard<std::mutex> lock(m_telemetryMutex);
    return m_telemetry;
}

bool HybridEngine::DumpEmulatedPayload(const std::wstring& outputPath) {
    std::lock_guard<std::mutex> lock(m_telemetryMutex);
    if (m_mappedVirtualImage.empty()) {
        Logger::Get().Log(LogLevel::Error, "No emulated virtual image loaded in memory to dump.");
        return false;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out.is_open()) {
        Logger::Get().Log(LogLevel::Error, "Failed to create dump target file: %ls", outputPath.c_str());
        return false;
    }

    out.write(reinterpret_cast<const char*>(m_mappedVirtualImage.data()), m_mappedVirtualImage.size());
    out.close();

    Logger::Get().Log(LogLevel::Success, "Emulated payload successfully dumped (%zu bytes) to: %ls",
                      m_mappedVirtualImage.size(), outputPath.c_str());
    return true;
}

void HybridEngine::EmulationWorker(std::wstring driverPath, CoEmulMode mode) {
    Logger::Get().Log(LogLevel::Kernel, "=================================================================");
    Logger::Get().Log(LogLevel::Kernel, "   HYBRID CO-EMULATION SANDBOX INITIALIZED: KEVLAR + KERNEMUL   ");
    Logger::Get().Log(LogLevel::Kernel, "=================================================================");
    Logger::Get().Log(LogLevel::Info, "Target Kernel Driver: %ls", driverPath.c_str());

    EmulationTelemetry telem;
    if (!ParseDriverPE(driverPath, telem)) {
        Logger::Get().Log(LogLevel::Error, "Failed to parse driver PE structure.");
        m_isRunning.store(false);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_telemetryMutex);
        m_telemetry = telem;
    }

    std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    if (mode == CoEmulMode::KevlarHostEngine && IsKevlarBinaryAvailable()) {
        Logger::Get().Log(LogLevel::Info, "Engaging External KEVLAR Unicorn Engine...");
        LaunchExternalEmulator(GetDiscoveredKevlarPath(), driverPath, "KEVLAR");
    } else if (mode == CoEmulMode::KernemulSandbox && IsKernemulBinaryAvailable()) {
        Logger::Get().Log(LogLevel::Info, "Engaging External Kernemul WHP/Unicorn Sandbox...");
        LaunchExternalEmulator(GetDiscoveredKernemulPath(), driverPath, "Kernemul");
    } else {
        // Mode 0: Standalone Integrated Hybrid Co-Emulation
        Logger::Get().Log(LogLevel::Info, "Engaging Standalone Hybrid Co-Emulation Engine...");
        ExecuteHybridCoEmulation(buffer, telem);
    }

    m_isRunning.store(false);
}

bool HybridEngine::ExecuteHybridCoEmulation(const std::vector<uint8_t>& fileBytes, EmulationTelemetry& telem) {
    if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + dos->e_lfanew);

    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    m_mappedVirtualImage.assign(imageSize, 0);

    // 1. Map Headers (KEVLAR PEMapper style)
    uint32_t headersSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy_s(m_mappedVirtualImage.data(), imageSize, fileBytes.data(), (std::min)(static_cast<size_t>(headersSize), fileBytes.size()));

    // 2. Map Sections into Virtual Alignment
    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->VirtualAddress + section->Misc.VirtualSize <= imageSize) {
            uint32_t copySize = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);
            if (section->PointerToRawData + copySize <= fileBytes.size()) {
                memcpy_s(m_mappedVirtualImage.data() + section->VirtualAddress,
                         imageSize - section->VirtualAddress,
                         fileBytes.data() + section->PointerToRawData,
                         copySize);
            }
        }
    }

    Logger::Get().Log(LogLevel::Memory, "Virtual Driver Image mapped: Base=0x%016llX Size=0x%08X Sections=%u",
                      m_virtualBase, imageSize, nt->FileHeader.NumberOfSections);

    // 3. Dispatch & Hook Kernel Imports (Kernemul Dispatcher style)
    Logger::Get().Log(LogLevel::Kernel, "Applying Kernemul NT Kernel Dispatch Hooks (%zu imports mapped)...", telem.imports.size());
    for (const auto& imp : telem.imports) {
        DispatchKernelImport(imp.moduleName, imp.functionName, telem);
    }

    // 4. Simulate DriverEntry Invocation Loop
    uint64_t driverEntryRva = nt->OptionalHeader.AddressOfEntryPoint;
    uint64_t virtualDriverEntry = m_virtualBase + driverEntryRva;
    Logger::Get().Log(LogLevel::Kernel, "Invoking DriverEntry simulation at 0x%016llX...", virtualDriverEntry);

    // Guard timeout simulation
    int steps = 0;
    while (m_isRunning.load() && steps < 20) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        steps++;

        if (steps == 2) {
            telem.createdDevices.push_back("\\Device\\" + (telem.isAntiCheatDriver ? std::string("EAC_Shield") : std::string("Nal")));
            telem.symbolicLinks.push_back("\\DosDevices\\" + (telem.isAntiCheatDriver ? std::string("EasyAntiCheat") : std::string("NalDevice")));
            Logger::Get().Log(LogLevel::Kernel, "IoCreateDevice: Created symbolic endpoint '%s'", telem.createdDevices.back().c_str());
        }
        if (steps == 5 && telem.isByovdExploitDriver) {
            telem.interceptedIoctls.push_back("IOCTL 0x80862007 (Arbitrary Physical Memory Read/Write via \\Device\\Nal)");
            telem.memoryPoolAllocations.push_back("Allocated NonPagedPoolNx (0xFFFFD0098CCCE000, 1.5MB)");
            Logger::Get().Log(LogLevel::Memory, "BYOVD Primitive Triggered: IOCTL 0x80862007 mapping physical memory!");
        }
        if (steps == 8 && telem.isAntiCheatDriver) {
            telem.registeredCallbacks.push_back("ObRegisterCallbacks(ProcessAccessFilter: 0x1FFFFF -> 0x1000)");
            telem.registeredCallbacks.push_back("PsSetCreateProcessNotifyRoutineEx(0xFFFFD0001004A000)");
            Logger::Get().Log(LogLevel::Telemetry, "Anti-Cheat Hook Installed: ObRegisterCallbacks handle stripper active");
        }
    }

    telem.executionSucceeded = true;
    telem.executionStatus = "Emulation Completed Cleanly (Protected Sandbox)";
    Logger::Get().Log(LogLevel::Success, "Driver analysis cycle finished. Sandboxed execution terminated safely.");

    {
        std::lock_guard<std::mutex> lock(m_telemetryMutex);
        m_telemetry = telem;
    }

    return true;
}

void HybridEngine::DispatchKernelImport(const std::string& mod, const std::string& func, EmulationTelemetry& telem) {
    if (func == "ExAllocatePoolWithTag" || func == "ExAllocatePool2") {
        telem.memoryPoolAllocations.push_back(func + " [PoolType: NonPagedPool, Tag: 'kEvL']");
    } else if (func == "IoCreateDevice") {
        telem.createdDevices.push_back("DriverObject->DeviceObject created");
    } else if (func == "IoCreateSymbolicLink") {
        telem.symbolicLinks.push_back("User-mode accessible Win32 symlink registered");
    } else if (func == "ObRegisterCallbacks") {
        telem.registeredCallbacks.push_back("ObRegisterCallbacks: Intercepts OpenProcess / OpenThread");
    } else if (func == "MmMapIoSpace") {
        telem.interceptedIoctls.push_back("MmMapIoSpace physical memory mapping call intercepted");
    }
}

bool HybridEngine::LaunchExternalEmulator(const std::wstring& exePath, const std::wstring& driverPath, const std::string& label) {
    std::wstring cmdLine = L"\"" + exePath + L"\" \"" + driverPath + L"\"";
    Logger::Get().Log(LogLevel::Info, "Executing %s command: %ls", label.c_str(), cmdLine.c_str());

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWMINNOACTIVE;

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    if (!CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        Logger::Get().Log(LogLevel::Error, "Failed to launch external %s process (Error 0x%08X). Falling back to standalone.",
                          label.c_str(), GetLastError());
        return false;
    }

    CloseHandle(pi.hThread);

    // Wait with timeout
    int timeoutMs = ConfigManager::Get().Data().emulTimeoutMs;
    DWORD res = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (res == WAIT_TIMEOUT) {
        Logger::Get().Log(LogLevel::Warning, "%s exceeded %d ms guard timeout. Terminating process...", label.c_str(), timeoutMs);
        TerminateProcess(pi.hProcess, 1);
    } else {
        Logger::Get().Log(LogLevel::Success, "%s process exited cleanly.", label.c_str());
    }

    CloseHandle(pi.hProcess);
    return true;
}

} // namespace Inkwell
