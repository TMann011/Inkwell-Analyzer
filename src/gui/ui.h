#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "../imgui/imgui.h"

namespace Inkwell {

enum class ActiveTab : int {
    Dashboard = 0,
    HybridEmul,
    AntiCheatDiff,
    MemoryInjection,
    UnityIl2Cpp,
    DriverDumper,
    Diagnostics,
    Settings
};

class UI {
public:
    static UI& Get();

    void Init(HWND hWnd);
    void Render();
    void Shutdown();

    bool WantQuit() const { return m_wantQuit; }

private:
    UI();
    ~UI() = default;
    UI(const UI&) = delete;
    UI& operator=(const UI&) = delete;

    // Header & Navigation
    void RenderCustomTitleBar();
    void RenderStatusBar();
    void RenderNavigationTabs();

    // Tab Renderers
    void RenderDashboardTab();
    void RenderHybridEmulTab();
    void RenderAntiCheatDiffTab();
    void RenderMemoryInjectionTab();
    void RenderUnityIl2CppTab();
    void RenderDriverDumperTab();
    void RenderDiagnosticsTab();
    void RenderSettingsTab();

    // Helper Dialogs
    std::wstring OpenFileDialog(const wchar_t* filter, const wchar_t* title);
    std::wstring OpenFolderDialog(const wchar_t* title);

    HWND m_hWnd = nullptr;
    ActiveTab m_currentTab = ActiveTab::Dashboard;
    bool m_wantQuit = false;

    // Buffers for UI inputs
    char m_guestDriverBuf[MAX_PATH] = { 0 };
    char m_gameDirBuf[MAX_PATH] = { 0 };
    char m_targetProcessBuf[64] = { 0 };
    char m_unityPathBuf[MAX_PATH] = { 0 };
    char m_dumpDirBuf[MAX_PATH] = { 0 };
    char m_watchDirBuf[MAX_PATH] = { 0 };
    char m_logFilterBuf[128] = { 0 };

    int m_selectedProcessIndex = -1;
    int m_selectedThemeIndex = 0;
    int m_selectedEmulMode = 0;
    float m_statusPollTimer = 0.0f;
    uint32_t m_cachedDriverCount = 0;
    uint32_t m_cachedProcessCount = 0;
    bool m_isElevated = false;
};

} // namespace Inkwell
