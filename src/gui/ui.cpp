#include "ui.h"
#include "theme.h"
#include "../core/config.h"
#include "../core/logger.h"
#include "../core/hybrid_emul/hybrid_engine.h"
#include "../core/ac_analyzer/ac_analyzer.h"
#include "../core/unity_analyzer/unity_analyzer.h"
#include "../core/driver_dumper/driver_dumper.h"
#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"

#include <psapi.h>
#include <commdlg.h>
#include <shlobj.h>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace Inkwell {

static std::string WStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &str[0], sizeNeeded, NULL, NULL);
    return str;
}

static std::wstring Utf8ToWString(const std::string& str) {
    if (str.empty()) return L"";
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &wstr[0], sizeNeeded);
    return wstr;
}

UI& UI::Get() {
    static UI instance;
    return instance;
}

UI::UI() {
    m_isElevated = IsUserAnAdmin();
}

void UI::Init(HWND hWnd) {
    m_hWnd = hWnd;

    // Load Configuration
    ConfigManager::Get().LoadFromFile();
    const auto& cfg = ConfigManager::Get().Data();

    m_selectedThemeIndex = cfg.selectedTheme;
    ApplyThemePreset(static_cast<ThemePreset>(m_selectedThemeIndex));

    strncpy_s(m_guestDriverBuf, WStringToUtf8(cfg.guestDriverPath).c_str(), sizeof(m_guestDriverBuf) - 1);
    strncpy_s(m_gameDirBuf, WStringToUtf8(cfg.targetGameDirectory).c_str(), sizeof(m_gameDirBuf) - 1);
    strncpy_s(m_targetProcessBuf, WStringToUtf8(cfg.targetProcessName).c_str(), sizeof(m_targetProcessBuf) - 1);
    strncpy_s(m_unityPathBuf, WStringToUtf8(cfg.unityAssembliesPath).c_str(), sizeof(m_unityPathBuf) - 1);
    strncpy_s(m_dumpDirBuf, WStringToUtf8(cfg.dumpOutputDirectory).c_str(), sizeof(m_dumpDirBuf) - 1);
    strncpy_s(m_watchDirBuf, WStringToUtf8(cfg.watchDirectory).c_str(), sizeof(m_watchDirBuf) - 1);

    Logger::Get().Init();
    Logger::Get().Log(LogLevel::Info, "Inkwell Universal Analyzer Loader initialized.");
    Logger::Get().Log(LogLevel::Info, "Host Privilege: %s | Standalone Mode: Active", m_isElevated ? "Elevated (Admin)" : "Standard User");

    if (HybridEngine::Get().IsKevlarBinaryAvailable()) {
        Logger::Get().Log(LogLevel::Kernel, "Discovered KEVLAR Engine: %ls", HybridEngine::Get().GetDiscoveredKevlarPath().c_str());
    }
    if (HybridEngine::Get().IsKernemulBinaryAvailable()) {
        Logger::Get().Log(LogLevel::Kernel, "Discovered Kernemul Sandbox: %ls", HybridEngine::Get().GetDiscoveredKernemulPath().c_str());
    }
}

void UI::Shutdown() {
    HybridEngine::Get().StopEmulation();
    DriverDumper::Get().StopTempWatcher();
    Logger::Get().Shutdown();
}

std::wstring UI::OpenFileDialog(const wchar_t* filter, const wchar_t* title) {
    wchar_t szFile[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(szFile);
    }
    return L"";
}

std::wstring UI::OpenFolderDialog(const wchar_t* title) {
    wchar_t szPath[MAX_PATH] = { 0 };
    BROWSEINFOW bi = { 0 };
    bi.hwndOwner = m_hWnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl != 0) {
        SHGetPathFromIDListW(pidl, szPath);
        CoTaskMemFree(pidl);
        return std::wstring(szPath);
    }
    return L"";
}

void UI::Render() {
    m_statusPollTimer += ImGui::GetIO().DeltaTime;
    if (m_statusPollTimer >= 1.0f) {
        m_statusPollTimer = 0.0f;
        LPVOID driversList[1024];
        DWORD cbNeeded = 0;
        if (EnumDeviceDrivers(driversList, sizeof(driversList), &cbNeeded)) {
            m_cachedDriverCount = cbNeeded / sizeof(LPVOID);
        }
    }

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                             ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    if (ImGui::Begin("##InkwellMainCanvas", nullptr, flags)) {
        RenderCustomTitleBar();

        ImGui::SetCursorPos(ImVec2(0, 48));
        ImGui::BeginChild("##MainContentRegion", ImVec2(io.DisplaySize.x, io.DisplaySize.y - 78), false, ImGuiWindowFlags_NoScrollbar);

        RenderNavigationTabs();

        ImGui::SetCursorPos(ImVec2(18, 52));
        ImGui::BeginChild("##ActiveTabArea", ImVec2(io.DisplaySize.x - 36, io.DisplaySize.y - 140), true);

        switch (m_currentTab) {
        case ActiveTab::Dashboard:        RenderDashboardTab(); break;
        case ActiveTab::HybridEmul:       RenderHybridEmulTab(); break;
        case ActiveTab::AntiCheatDiff:    RenderAntiCheatDiffTab(); break;
        case ActiveTab::MemoryInjection:  RenderMemoryInjectionTab(); break;
        case ActiveTab::UnityIl2Cpp:      RenderUnityIl2CppTab(); break;
        case ActiveTab::DriverDumper:     RenderDriverDumperTab(); break;
        case ActiveTab::Diagnostics:      RenderDiagnosticsTab(); break;
        case ActiveTab::Settings:         RenderSettingsTab(); break;
        }

        ImGui::EndChild();
        ImGui::EndChild();

        RenderStatusBar();
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
}

void UI::RenderCustomTitleBar() {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetWindowPos();
    float width = ImGui::GetWindowWidth();

    // Dark bar background with subtle accent glow line
    drawList->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + 46), ImColor(g_Style.PanelBg));
    drawList->AddLine(ImVec2(pos.x, pos.y + 46), ImVec2(pos.x + width, pos.y + 46), ImColor(g_Style.Border));

    // Drag window region
    ImGui::SetCursorPos(ImVec2(18, 12));
    ImGui::TextColored(g_Style.AccentColor, "[ COOK45 / INKWELL ]");
    ImGui::SameLine();
    ImGui::TextColored(g_Style.TextPrimary, "UNIVERSAL ANALYZER & KERNEL SANDBOX");
    ImGui::SameLine();
    ImGui::TextColored(g_Style.TextMuted, "v4.0 Core");

    // Allow dragging by clicking title text
    if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        ReleaseCapture();
        SendMessage(m_hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }

    // Window controls (Right side)
    float btnWidth = 36.0f;
    float startX = width - (btnWidth * 3) - 10.0f;

    ImGui::SetCursorPos(ImVec2(startX, 8));
    if (ImGui::Button("—##Minimize", ImVec2(btnWidth, 28))) {
        ShowWindow(m_hWnd, SW_MINIMIZE);
    }
    ImGui::SameLine();
    if (ImGui::Button("[]##Maximize", ImVec2(btnWidth, 28))) {
        WINDOWPLACEMENT wp = { sizeof(wp) };
        GetWindowPlacement(m_hWnd, &wp);
        ShowWindow(m_hWnd, (wp.showCmd == SW_SHOWMAXIMIZED) ? SW_RESTORE : SW_MAXIMIZE);
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.20f, 0.25f, 0.90f));
    if (ImGui::Button("X##Close", ImVec2(btnWidth, 28))) {
        m_wantQuit = true;
        PostMessage(m_hWnd, WM_CLOSE, 0, 0);
    }
    ImGui::PopStyleColor();
}

void UI::RenderNavigationTabs() {
    const char* tabs[] = {
        "DASHBOARD",
        "HYBRID EMUL (KEV+EMUL)",
        "AC TELEMETRY",
        "MEMORY AUDIT",
        "UNITY & IL2CPP",
        "PAYLOAD DUMPER",
        "DIAGNOSTICS",
        "SETTINGS"
    };

    ImGui::SetCursorPos(ImVec2(18, 10));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6, 0));

    for (int i = 0; i < 8; ++i) {
        bool isCurrent = (m_currentTab == static_cast<ActiveTab>(i));
        if (isCurrent) {
            ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, g_Style.PanelAlt);
            ImGui::PushStyleColor(ImGuiCol_Text, g_Style.TextSecondary);
        }

        if (ImGui::Button(tabs[i], ImVec2(0, 32))) {
            m_currentTab = static_cast<ActiveTab>(i);
        }

        ImGui::PopStyleColor(2);
        if (i < 7) ImGui::SameLine();
    }
    ImGui::PopStyleVar();
}

void UI::RenderStatusBar() {
    ImVec2 pos = ImGui::GetWindowPos();
    float width = ImGui::GetWindowWidth();
    float height = ImGui::GetWindowHeight();

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->AddRectFilled(ImVec2(pos.x, pos.y + height - 28), ImVec2(pos.x + width, pos.y + height), ImColor(g_Style.Background));
    drawList->AddLine(ImVec2(pos.x, pos.y + height - 28), ImVec2(pos.x + width, pos.y + height - 28), ImColor(g_Style.Border));

    ImGui::SetCursorPos(ImVec2(18, height - 22));
    ImGui::TextColored(m_isElevated ? g_Style.SuccessColor : g_Style.WarningColor,
                       m_isElevated ? "[ADMIN] Ring-3 Elevated" : "[USER] Unelevated");

    ImGui::SameLine(180);
    ImGui::TextColored(g_Style.KernelColor, "Kernel Drivers: %u", m_cachedDriverCount);

    ImGui::SameLine(330);
    bool emulRunning = HybridEngine::Get().IsRunning();
    ImGui::TextColored(emulRunning ? g_Style.SuccessColor : g_Style.TextMuted,
                       "Hybrid Co-Emul: %s", emulRunning ? "ACTIVE" : "STANDBY");

    ImGui::SameLine(500);
    bool watcherRunning = DriverDumper::Get().IsWatcherRunning();
    ImGui::TextColored(watcherRunning ? g_Style.WarningColor : g_Style.TextMuted,
                       "Temp Watcher: %s", watcherRunning ? "ARMED" : "OFF");

    ImGui::SameLine(width - 240);
    ImGui::TextColored(g_Style.TextMuted, "Zero Hardcoded Paths | Standalone");
}

void UI::RenderDashboardTab() {
    PushCardStyle();
    ImGui::BeginChild("##DashCard1", ImVec2(0, 150), true);
    ImGui::TextColored(g_Style.AccentColor, "SYSTEM ENVIRONMENT & TELEMETRY POSTURE");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Columns(3, "##DashCols", false);
    ImGui::TextColored(g_Style.TextSecondary, "Host Architecture:");
    ImGui::Text("x64 Native (AMD64)");
    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Operating Mode:");
    ImGui::Text(m_isElevated ? "Elevated Administrator" : "Limited Userland");

    ImGui::NextColumn();
    ImGui::TextColored(g_Style.TextSecondary, "Loaded Ring-0 Drivers:");
    ImGui::Text("%u Modules Active", m_cachedDriverCount);
    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Active Anti-Cheat Baseline:");
    ImGui::Text(AntiCheatAnalyzer::Get().HasBaseline() ? "LOCKED & ARMED" : "NO BASELINE RECORDED");

    ImGui::NextColumn();
    ImGui::TextColored(g_Style.TextSecondary, "Co-Emulation Backends:");
    ImGui::Text("KEVLAR: %s", HybridEngine::Get().IsKevlarBinaryAvailable() ? "Detected" : "Integrated Standalone");
    ImGui::Text("Kernemul: %s", HybridEngine::Get().IsKernemulBinaryAvailable() ? "Detected" : "Integrated Standalone");
    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Dump Target Directory:");
    ImGui::Text("%ls", ConfigManager::Get().GetDefaultDumpDirectory().c_str());

    ImGui::Columns(1);
    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    PushCardStyle();
    ImGui::BeginChild("##DashCard2", ImVec2(0, 0), true);
    ImGui::TextColored(g_Style.AccentColor, "RAPID ACTION MATRIX");
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Lock System Baseline (Drivers + Services + Hosts)", ImVec2(320, 36))) {
        AntiCheatAnalyzer::Get().CaptureBaseline();
    }
    ImGui::SameLine();
    if (ImGui::Button("Arm Real-Time %TEMP% Ephemeral Driver Watcher", ImVec2(320, 36))) {
        DriverDumper::Get().StartTempWatcher();
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Recent Diagnostics Feed:");
    ImGui::BeginChild("##MiniLog", ImVec2(0, 0), true);
    auto entries = Logger::Get().GetEntries();
    size_t start = entries.size() > 12 ? entries.size() - 12 : 0;
    for (size_t i = start; i < entries.size(); ++i) {
        ImVec4 col = g_Style.TextPrimary;
        if (entries[i].level == LogLevel::Error) col = g_Style.ErrorColor;
        else if (entries[i].level == LogLevel::Warning) col = g_Style.WarningColor;
        else if (entries[i].level == LogLevel::Success) col = g_Style.SuccessColor;
        else if (entries[i].level == LogLevel::Kernel) col = g_Style.KernelColor;

        ImGui::TextColored(g_Style.TextMuted, "[%s]", entries[i].timestamp.c_str());
        ImGui::SameLine();
        ImGui::TextColored(col, "%s", entries[i].message.c_str());
    }
    ImGui::EndChild();

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderHybridEmulTab() {
    PushCardStyle();
    ImGui::BeginChild("##EmulControls", ImVec2(0, 130), true);
    ImGui::TextColored(g_Style.AccentColor, "HYBRID CO-EMULATION ORCHESTRATOR: KEVLAR + KERNEMUL");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Target Driver (.sys):");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 280);
    ImGui::InputText("##DriverPathInput", m_guestDriverBuf, sizeof(m_guestDriverBuf));
    ImGui::SameLine();
    if (ImGui::Button("Browse##Sys", ImVec2(80, 24))) {
        std::wstring selected = OpenFileDialog(L"Driver Files (*.sys)\0*.sys\0All Files (*.*)\0*.*\0", L"Select Kernel Driver");
        if (!selected.empty()) {
            strncpy_s(m_guestDriverBuf, WStringToUtf8(selected).c_str(), sizeof(m_guestDriverBuf) - 1);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Staging##Prep", ImVec2(80, 24))) {
        // Quick load staging driver if available
        std::wstring stage = ConfigManager::Get().GetExecutableDirectory() + L"..\\driver prepared\\stage1_staging_driver\\iqvw64e.sys";
        if (fs::exists(stage)) {
            strncpy_s(m_guestDriverBuf, WStringToUtf8(stage).c_str(), sizeof(m_guestDriverBuf) - 1);
        }
    }

    ImGui::Spacing();
    ImGui::Text("Engine Mode:");
    ImGui::SameLine();
    ImGui::RadioButton("Hybrid Co-Emulation (Integrated)", &m_selectedEmulMode, 0);
    ImGui::SameLine();
    ImGui::RadioButton("KEVLAR Native", &m_selectedEmulMode, 1);
    ImGui::SameLine();
    ImGui::RadioButton("Kernemul Hypervisor", &m_selectedEmulMode, 2);

    ImGui::SameLine(ImGui::GetWindowWidth() - 260);
    bool isRunning = HybridEngine::Get().IsRunning();
    if (!isRunning) {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
        if (ImGui::Button("START CO-EMULATION", ImVec2(160, 28))) {
            HybridEngine::Get().StartEmulation(Utf8ToWString(m_guestDriverBuf), static_cast<CoEmulMode>(m_selectedEmulMode));
        }
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.ErrorColor);
        if (ImGui::Button("STOP EMULATION", ImVec2(160, 28))) {
            HybridEngine::Get().StopEmulation();
        }
        ImGui::PopStyleColor();
    }

    ImGui::SameLine();
    if (ImGui::Button("Dump Payload", ImVec2(90, 28))) {
        std::wstring outPath = ConfigManager::Get().GetDefaultDumpDirectory() + L"emulated_payload.sys";
        HybridEngine::Get().DumpEmulatedPayload(outPath);
    }

    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    // Telemetry Display
    auto telem = HybridEngine::Get().GetTelemetry();
    PushCardStyle();
    ImGui::BeginChild("##EmulTelemetry", ImVec2(0, 0), true);

    ImGui::Columns(2, "##TelemCols", true);

    ImGui::TextColored(g_Style.AccentColor, "DRIVER METRICS & HEADERS");
    ImGui::Separator();
    ImGui::Text("Binary Name: %s", telem.driverName.c_str());
    ImGui::Text("Preferred ImageBase: 0x%016llX", telem.imageBase);
    ImGui::Text("Virtual Size: 0x%08X (%u bytes)", telem.imageSize, telem.imageSize);
    ImGui::Text("EntryPoint RVA: 0x%08llX", telem.entryPointRva);
    ImGui::Text("Sections Count: %u", telem.sectionCount);

    if (telem.isByovdExploitDriver) {
        ImGui::TextColored(g_Style.ErrorColor, "CRITICAL: BYOVD Exploitation Vector Identified!");
    }
    if (telem.isAntiCheatDriver) {
        ImGui::TextColored(g_Style.WarningColor, "WARNING: Anti-Cheat Protection Endpoint Identified!");
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Section Allocation Map:");
    ImGui::BeginChild("##SecMap", ImVec2(0, 160), true);
    for (const auto& sec : telem.sections) {
        ImGui::TextColored(sec.isExecutable ? g_Style.SuccessColor : g_Style.TextPrimary,
                           "%-8s | RVA: 0x%08X | Size: 0x%08X | %s%s",
                           sec.name.c_str(), sec.virtualAddress, sec.virtualSize,
                           sec.isExecutable ? "[EXEC] " : "",
                           sec.isWritable ? "[WRITE]" : "");
    }
    ImGui::EndChild();

    ImGui::NextColumn();

    ImGui::TextColored(g_Style.AccentColor, "INTERCEPTED CALLS & THREAT VECTORS");
    ImGui::Separator();

    ImGui::TextColored(g_Style.KernelColor, "Created Device Endpoints (%zu):", telem.createdDevices.size());
    for (const auto& dev : telem.createdDevices) {
        ImGui::BulletText("%s", dev.c_str());
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.MemoryColor, "Tracked Physical/Pool Memory Primitives (%zu):", telem.memoryPoolAllocations.size());
    for (const auto& pool : telem.memoryPoolAllocations) {
        ImGui::BulletText("%s", pool.c_str());
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.WarningColor, "Intercepted IOCTL Requests (%zu):", telem.interceptedIoctls.size());
    for (const auto& ioctl : telem.interceptedIoctls) {
        ImGui::BulletText("%s", ioctl.c_str());
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.ErrorColor, "Threat Identifiers (%zu):", telem.detectedThreats.size());
    for (const auto& threat : telem.detectedThreats) {
        ImGui::BulletText("%s", threat.c_str());
    }

    ImGui::Columns(1);
    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderAntiCheatDiffTab() {
    PushCardStyle();
    ImGui::BeginChild("##ACDiffControls", ImVec2(0, 120), true);
    ImGui::TextColored(g_Style.AccentColor, "BLACK-BOX ANTI-CHEAT DIFFERENTIAL TELEMETRY AUDITOR");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Target Game Directory:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 480);
    ImGui::InputText("##TargetGameDirInput", m_gameDirBuf, sizeof(m_gameDirBuf));
    ImGui::SameLine();
    if (ImGui::Button("Browse##GameDir", ImVec2(80, 24))) {
        std::wstring selected = OpenFolderDialog(L"Select Game Directory");
        if (!selected.empty()) {
            strncpy_s(m_gameDirBuf, WStringToUtf8(selected).c_str(), sizeof(m_gameDirBuf) - 1);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("LOCK BASELINE", ImVec2(140, 24))) {
        AntiCheatAnalyzer::Get().CaptureBaseline();
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
    if (ImGui::Button("RUN DIFFERENTIAL AUDIT", ImVec2(180, 24))) {
        AntiCheatAnalyzer::Get().RunDifferentialAudit(Utf8ToWString(m_gameDirBuf), Utf8ToWString(m_targetProcessBuf));
    }
    ImGui::PopStyleColor();

    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    auto report = AntiCheatAnalyzer::Get().GetReport();
    PushCardStyle();
    ImGui::BeginChild("##ACDiffResults", ImVec2(0, 0), true);

    ImGui::TextColored(g_Style.AccentColor, "DIFFERENTIAL FINDINGS & TAMPERING DETECTIONS");
    ImGui::Separator();

    if (!report.baselineCaptured) {
        ImGui::TextColored(g_Style.WarningColor, "Baseline not captured yet. Click 'LOCK BASELINE' before launching loader/cheat.");
    } else {
        ImGui::TextColored(g_Style.SuccessColor, "Active Baseline: %u Drivers, %u Services.",
                           report.baselineDriverCount, report.baselineServiceCount);
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.ErrorColor, "Newly Loaded Drivers / BYOVD Vectors (%zu):", report.newDrivers.size());
    for (const auto& d : report.newDrivers) {
        ImGui::BulletText("%ls | Base: 0x%016llX | Signed: %s | Path: %ls",
                          d.baseName.c_str(), d.baseAddress, d.isSigned ? "YES" : "NO (SUSPICIOUS)", d.fullPath.c_str());
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.WarningColor, "Newly Created Services (%zu):", report.newServices.size());
    for (const auto& s : report.newServices) {
        ImGui::BulletText("Service: %ls (%ls)", s.serviceName.c_str(), s.displayName.c_str());
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.ErrorColor, "Anti-Cheat Binary Tampering / Fake Stubs (%zu):", report.tamperedFiles.size());
    for (const auto& f : report.tamperedFiles) {
        ImGui::BulletText("%ls | Size: %llu bytes | %s",
                          f.filePath.c_str(), f.fileSize, f.isStubSuspect ? "[FAKE STUB SUSPECT]" : "[UNSIGNED]");
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.WarningColor, "Hosts File DNS Redirects (%zu):", report.hostsRedirects.size());
    for (const auto& h : report.hostsRedirects) {
        ImGui::BulletText("%s", h.c_str());
    }

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderMemoryInjectionTab() {
    PushCardStyle();
    ImGui::BeginChild("##MemAuditControls", ImVec2(0, 110), true);
    ImGui::TextColored(g_Style.AccentColor, "PROCESS MEMORY AUDITOR: UNBACKED CODE & FLOATING PE HUNTER");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Target Process Name / Exe:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(250);
    ImGui::InputText("##TargetProcInput", m_targetProcessBuf, sizeof(m_targetProcessBuf));
    ImGui::SameLine();

    auto procs = AntiCheatAnalyzer::Get().EnumerateRunningProcesses();
    std::string comboPreview = "Select running process...";
    for (const auto& p : procs) {
        if (WStringToUtf8(p.second) == m_targetProcessBuf) {
            comboPreview = WStringToUtf8(p.second) + " (PID: " + std::to_string(p.first) + ")";
            break;
        }
    }

    ImGui::SetNextItemWidth(300);
    if (ImGui::BeginCombo("##ProcCombo", comboPreview.c_str())) {
        for (const auto& p : procs) {
            std::string item = WStringToUtf8(p.second) + " [" + std::to_string(p.first) + "]";
            if (ImGui::Selectable(item.c_str())) {
                strncpy_s(m_targetProcessBuf, WStringToUtf8(p.second).c_str(), sizeof(m_targetProcessBuf) - 1);
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
    if (ImGui::Button("AUDIT MEMORY", ImVec2(140, 24))) {
        DWORD pid = AntiCheatAnalyzer::Get().FindProcessIdByName(Utf8ToWString(m_targetProcessBuf));
        if (pid != 0) {
            AntiCheatAnalyzer::Get().ScanProcessUnbackedMemory(pid);
        } else {
            Logger::Get().Log(LogLevel::Error, "Could not find process: %s", m_targetProcessBuf);
        }
    }
    ImGui::PopStyleColor();

    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    PushCardStyle();
    ImGui::BeginChild("##MemAuditResults", ImVec2(0, 0), true);
    ImGui::TextColored(g_Style.AccentColor, "UNBACKED PRIVATE EXECUTABLE MEMORY ALLOCATIONS");
    ImGui::Separator();

    auto report = AntiCheatAnalyzer::Get().GetReport();
    if (report.injectedRegions.empty()) {
        ImGui::TextColored(g_Style.TextMuted, "No unbacked executable allocations scanned or detected yet.");
    } else {
        for (const auto& reg : report.injectedRegions) {
            ImVec4 col = reg.hasFloatingPE ? g_Style.ErrorColor : g_Style.WarningColor;
            ImGui::TextColored(col, "0x%016llX | Size: 0x%08llX | Protect: 0x%04X | %s",
                               reg.baseAddress, reg.regionSize, reg.protect, reg.threatDescription.c_str());
        }
    }

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderUnityIl2CppTab() {
    PushCardStyle();
    ImGui::BeginChild("##UnityControls", ImVec2(0, 110), true);
    ImGui::TextColored(g_Style.AccentColor, "UNITY & IL2CPP FORENSIC METADATA ANALYZER");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Assemblies / Game Root Path:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 360);
    ImGui::InputText("##UnityPathInput", m_unityPathBuf, sizeof(m_unityPathBuf));
    ImGui::SameLine();
    if (ImGui::Button("Browse##Unity", ImVec2(80, 24))) {
        std::wstring selected = OpenFolderDialog(L"Select Unity / Il2CppAssemblies Folder");
        if (!selected.empty()) {
            strncpy_s(m_unityPathBuf, WStringToUtf8(selected).c_str(), sizeof(m_unityPathBuf) - 1);
        }
    }

    ImGui::SameLine();
    bool isAnalyzing = UnityAnalyzer::Get().IsAnalyzing();
    if (!isAnalyzing) {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
        if (ImGui::Button("ANALYZE ASSEMBLIES", ImVec2(180, 24))) {
            UnityAnalyzer::Get().AnalyzeDirectory(Utf8ToWString(m_unityPathBuf));
        }
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.ErrorColor);
        if (ImGui::Button("CANCEL", ImVec2(180, 24))) {
            UnityAnalyzer::Get().CancelAnalysis();
        }
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    auto report = UnityAnalyzer::Get().GetReport();
    PushCardStyle();
    ImGui::BeginChild("##UnityResults", ImVec2(0, 0), true);

    ImGui::TextColored(g_Style.AccentColor, "METADATA EXTRACTION RESULTS");
    ImGui::Separator();

    if (report.isIl2Cpp) {
        ImGui::TextColored(g_Style.SuccessColor, "Architecture: IL2CPP (GameAssembly.dll present, %zu API endpoints)",
                           report.runtime.runtimeExports.size());
    } else if (report.isMono) {
        ImGui::TextColored(g_Style.KernelColor, "Architecture: Mono / Managed CLR Assemblies");
    }

    ImGui::Spacing();
    ImGui::TextColored(g_Style.TextSecondary, "Parsed Assemblies (%zu):", report.assemblies.size());

    ImGui::BeginChild("##AssemblyTable", ImVec2(0, 0), true);
    ImGui::Columns(5, "##AsmCols", true);
    ImGui::Text("Assembly Name"); ImGui::NextColumn();
    ImGui::Text("File Size"); ImGui::NextColumn();
    ImGui::Text("TypeDefs"); ImGui::NextColumn();
    ImGui::Text("Methods"); ImGui::NextColumn();
    ImGui::Text("Runtime CLR"); ImGui::NextColumn();
    ImGui::Separator();

    for (const auto& asmItem : report.assemblies) {
        ImGui::Text("%s", asmItem.assemblyName.c_str()); ImGui::NextColumn();
        ImGui::Text("%llu KB", asmItem.fileSize / 1024); ImGui::NextColumn();
        ImGui::Text("%u", asmItem.typeDefCount); ImGui::NextColumn();
        ImGui::Text("%u", asmItem.methodDefCount); ImGui::NextColumn();
        ImGui::Text("%s", asmItem.clrVersion.c_str()); ImGui::NextColumn();
    }
    ImGui::Columns(1);
    ImGui::EndChild();

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderDriverDumperTab() {
    PushCardStyle();
    ImGui::BeginChild("##DumperControls", ImVec2(0, 130), true);
    ImGui::TextColored(g_Style.AccentColor, "DYNAMIC PAYLOAD & EPHEMERAL DRIVER CAPTURE ENGINE");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Watch Directory (Temp):");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(350);
    ImGui::InputText("##WatchDirInput", m_watchDirBuf, sizeof(m_watchDirBuf));
    ImGui::SameLine();

    bool watcherRunning = DriverDumper::Get().IsWatcherRunning();
    if (!watcherRunning) {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.AccentColor);
        if (ImGui::Button("START WATCHER", ImVec2(140, 24))) {
            DriverDumper::Get().StartTempWatcher(Utf8ToWString(m_watchDirBuf));
        }
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, g_Style.ErrorColor);
        if (ImGui::Button("STOP WATCHER", ImVec2(140, 24))) {
            DriverDumper::Get().StopTempWatcher();
        }
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Text("Target Process (PID or Name for VAD Dump):");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("##TargetDumpProc", m_targetProcessBuf, sizeof(m_targetProcessBuf));
    ImGui::SameLine();
    if (ImGui::Button("DUMP PROCESS PE IMAGES", ImVec2(200, 24))) {
        DWORD pid = AntiCheatAnalyzer::Get().FindProcessIdByName(Utf8ToWString(m_targetProcessBuf));
        if (pid != 0) {
            DriverDumper::Get().DumpProcessMemoryPE(pid);
        } else {
            Logger::Get().Log(LogLevel::Error, "Target process '%s' not found for dumping.", m_targetProcessBuf);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Open Output Folder", ImVec2(160, 24))) {
        ShellExecuteW(NULL, L"open", ConfigManager::Get().GetDefaultDumpDirectory().c_str(), NULL, NULL, SW_SHOW);
    }

    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    auto artifacts = DriverDumper::Get().GetCapturedArtifacts();
    PushCardStyle();
    ImGui::BeginChild("##DumperArtifacts", ImVec2(0, 0), true);

    ImGui::TextColored(g_Style.AccentColor, "CAPTURED KERNEL DRIVERS & IN-MEMORY PAYLOADS (%zu)", artifacts.size());
    ImGui::Separator();

    ImGui::Columns(5, "##ArtCols", true);
    ImGui::Text("Time"); ImGui::NextColumn();
    ImGui::Text("Type"); ImGui::NextColumn();
    ImGui::Text("Remote Base / Source"); ImGui::NextColumn();
    ImGui::Text("Captured Path"); ImGui::NextColumn();
    ImGui::Text("Size"); ImGui::NextColumn();
    ImGui::Separator();

    for (const auto& art : artifacts) {
        ImGui::Text("%s", art.timestamp.c_str()); ImGui::NextColumn();
        ImGui::TextColored(g_Style.KernelColor, "%s", art.artifactType.c_str()); ImGui::NextColumn();
        ImGui::Text("%ls", art.sourcePath.c_str()); ImGui::NextColumn();
        ImGui::Text("%ls", art.savedPath.c_str()); ImGui::NextColumn();
        ImGui::Text("%llu KB", art.fileSize / 1024); ImGui::NextColumn();
    }
    ImGui::Columns(1);

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderDiagnosticsTab() {
    PushCardStyle();
    ImGui::BeginChild("##DiagHeader", ImVec2(0, 60), true);
    ImGui::TextColored(g_Style.AccentColor, "DIAGNOSTICS & TELEMETRY STREAM");
    ImGui::SameLine(ImGui::GetWindowWidth() - 360);
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##FilterInput", "Filter logs...", m_logFilterBuf, sizeof(m_logFilterBuf));
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(60, 24))) {
        Logger::Get().Clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Export", ImVec2(70, 24))) {
        std::wstring exportPath = ConfigManager::Get().GetExecutableDirectory() + L"analyzer_export.log";
        Logger::Get().ExportToFile(exportPath);
        ShellExecuteW(NULL, L"open", exportPath.c_str(), NULL, NULL, SW_SHOW);
    }
    ImGui::EndChild();
    PopCardStyle();

    ImGui::Spacing();

    PushCardStyle();
    ImGui::BeginChild("##DiagLogsList", ImVec2(0, 0), true);
    auto entries = Logger::Get().GetEntries();
    std::string filter(m_logFilterBuf);
    std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);

    for (const auto& entry : entries) {
        if (!filter.empty()) {
            std::string lowerMsg = entry.message;
            std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);
            if (lowerMsg.find(filter) == std::string::npos) continue;
        }

        ImVec4 col = g_Style.TextPrimary;
        if (entry.level == LogLevel::Error) col = g_Style.ErrorColor;
        else if (entry.level == LogLevel::Warning) col = g_Style.WarningColor;
        else if (entry.level == LogLevel::Success) col = g_Style.SuccessColor;
        else if (entry.level == LogLevel::Kernel) col = g_Style.KernelColor;
        else if (entry.level == LogLevel::Telemetry) col = g_Style.AccentHovered;
        else if (entry.level == LogLevel::Memory) col = g_Style.MemoryColor;

        ImGui::TextColored(g_Style.TextMuted, "[%s] %-8s", entry.timestamp.c_str(), Logger::LevelToString(entry.level));
        ImGui::SameLine();
        ImGui::TextColored(col, "%s", entry.message.c_str());
    }

    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
    PopCardStyle();
}

void UI::RenderSettingsTab() {
    PushCardStyle();
    ImGui::BeginChild("##SettingsCard", ImVec2(0, 0), true);
    ImGui::TextColored(g_Style.AccentColor, "GLOBAL CONFIGURATION & THEME PRESETS");
    ImGui::Separator();
    ImGui::Spacing();

    const char* themes[] = {
        "Signature Purple & Black (Inkwell Violet)",
        "Electric Indigo (Cyan & Blue)",
        "Cyber Emerald (Matrix Green)",
        "Crimson Blood (High-Contrast Red)",
        "Slate Monochrome (Titanium Grey)"
    };

    ImGui::Text("UI Theme Preset:");
    ImGui::SetNextItemWidth(360);
    if (ImGui::Combo("##ThemeCombo", &m_selectedThemeIndex, themes, IM_ARRAYSIZE(themes))) {
        ApplyThemePreset(static_cast<ThemePreset>(m_selectedThemeIndex));
        ConfigManager::Get().Data().selectedTheme = m_selectedThemeIndex;
        ConfigManager::Get().SaveToFile();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(g_Style.AccentColor, "PORTABILITY & ENVIRONMENT PATH OVERRIDES");
    ImGui::TextColored(g_Style.TextMuted, "All paths automatically resolve relative to the executable if left blank.");

    ImGui::Spacing();
    ImGui::Text("Dump Directory:");
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 200);
    ImGui::InputText("##DumpDirConfig", m_dumpDirBuf, sizeof(m_dumpDirBuf));

    ImGui::Spacing();
    ImGui::Text("Temp Watcher Directory:");
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 200);
    ImGui::InputText("##WatchDirConfig", m_watchDirBuf, sizeof(m_watchDirBuf));

    ImGui::Spacing();
    if (ImGui::Button("SAVE CONFIGURATION (analyzer_config.ini)", ImVec2(320, 36))) {
        ConfigManager::Get().Data().dumpOutputDirectory = Utf8ToWString(m_dumpDirBuf);
        ConfigManager::Get().Data().watchDirectory = Utf8ToWString(m_watchDirBuf);
        ConfigManager::Get().Data().selectedTheme = m_selectedThemeIndex;
        ConfigManager::Get().SaveToFile();
        Logger::Get().Log(LogLevel::Success, "Configuration successfully persisted to analyzer_config.ini");
    }

    ImGui::EndChild();
    PopCardStyle();
}

} // namespace Inkwell
