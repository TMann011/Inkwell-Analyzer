#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace Inkwell {

struct CliMetadataSummary {
    std::string assemblyName;
    std::wstring filePath;
    uint64_t fileSize;
    std::string clrVersion;
    uint32_t typeDefCount;
    uint32_t methodDefCount;
    uint32_t fieldCount;
    uint32_t typeRefCount;
    std::vector<std::string> discoveredTypes;
};

struct Il2CppRuntimeSummary {
    bool isIl2CppGame;
    std::wstring gameAssemblyPath;
    uint64_t gameAssemblySize;
    std::vector<std::string> runtimeExports;
    std::vector<std::string> criticalHooks;
};

struct UnityForensicReport {
    std::wstring targetPath;
    bool isIl2Cpp;
    bool isMono;
    uint32_t totalAssemblies;
    std::vector<CliMetadataSummary> assemblies;
    Il2CppRuntimeSummary runtime;
    std::string statusMessage;
    bool completed;
};

class UnityAnalyzer {
public:
    static UnityAnalyzer& Get();

    bool AnalyzeDirectory(const std::wstring& targetPath);
    void CancelAnalysis();

    bool IsAnalyzing() const { return m_isAnalyzing.load(); }
    UnityForensicReport GetReport();

    // Specific Inspector Helpers
    bool ParseCliAssembly(const std::wstring& filePath, CliMetadataSummary& outSummary);
    bool InspectGameAssembly(const std::wstring& dllPath, Il2CppRuntimeSummary& outSummary);

private:
    UnityAnalyzer();
    ~UnityAnalyzer() = default;
    UnityAnalyzer(const UnityAnalyzer&) = delete;
    UnityAnalyzer& operator=(const UnityAnalyzer&) = delete;

    void AnalysisWorker(std::wstring targetPath);

    std::atomic<bool> m_isAnalyzing{ false };
    std::mutex m_mutex;
    UnityForensicReport m_report;
};

} // namespace Inkwell
