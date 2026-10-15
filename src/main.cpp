#include "main.h"
#include "gui/ui.h"
#include "gui/theme.h"
#include "core/config.h"
#include "core/logger.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"

#include <shellapi.h>
#include <shlobj.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace Inkwell {

HWND g_hMainWnd = nullptr;
LPDIRECT3D9 g_pD3D = nullptr;
LPDIRECT3DDEVICE9 g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS g_d3dpp = {};

bool EnsureElevatedPrivileges() {
    if (IsUserAnAdmin()) {
        return true;
    }

    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteExW(&sei)) {
            return false;
        }
    }
    return false;
}

bool CreateDeviceD3D(HWND hWnd) {
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
        return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE; // VSync enabled

    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
        D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0) {
        return false;
    }

    return true;
}

void CleanupDeviceD3D() {
    if (g_pd3dDevice) {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
    if (g_pD3D) {
        g_pD3D->Release();
        g_pD3D = nullptr;
    }
}

void ResetDevice() {
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (FAILED(hr)) {
        return;
    }
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_NCHITTEST: {
        POINT pt = { LOWORD(lParam), HIWORD(lParam) };
        ScreenToClient(hWnd, &pt);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int border = 8;

        bool top = pt.y < border;
        bool bottom = pt.y >= rc.bottom - border;
        bool left = pt.x < border;
        bool right = pt.x >= rc.right - border;

        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;

        return HTCLIENT;
    }
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

} // namespace Inkwell

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize high DPI awareness
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // Auto-elevation if requested in config and not already admin
    if (Inkwell::ConfigManager::Get().Data().autoElevate && !IsUserAnAdmin()) {
        if (!Inkwell::EnsureElevatedPrivileges()) {
            // Either elevated child process launched or user cancelled
            return 0;
        }
    }

    // Register Window Class
    WNDCLASSEXW wc = {
        sizeof(wc),
        CS_CLASSDC,
        Inkwell::WndProc,
        0L, 0L,
        hInstance,
        NULL, NULL, NULL, NULL,
        L"InkwellAnalyzerWindowClass",
        NULL
    };
    RegisterClassExW(&wc);

    // 1100 x 720 centered on primary monitor
    int windowWidth = 1100;
    int windowHeight = 720;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - windowWidth) / 2;
    int posY = (screenH - windowHeight) / 2;

    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"Inkwell Universal Analyzer & Kernel Sandbox",
        WS_POPUP | WS_THICKFRAME,
        posX, posY, windowWidth, windowHeight,
        NULL, NULL, wc.hInstance, NULL
    );

    if (!hWnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    Inkwell::g_hMainWnd = hWnd;

    // Initialize Direct3D
    if (!Inkwell::CreateDeviceD3D(hWnd)) {
        Inkwell::CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Initialize Dear ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // Stateless layout

    ImGui_ImplWin32_Init(hWnd);
    ImGui_ImplDX9_Init(Inkwell::g_pd3dDevice);

    // Initialize UI subsystem & theme
    Inkwell::UI::Get().Init(hWnd);

    // Message pump & render loop
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        // Begin frame
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render UI
        Inkwell::UI::Get().Render();

        if (Inkwell::UI::Get().WantQuit()) {
            done = true;
        }

        // End frame & D3D clear/present
        ImGui::EndFrame();
        Inkwell::g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        Inkwell::g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        Inkwell::g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

        D3DCOLOR clearColor = D3DCOLOR_RGBA(10, 8, 15, 255);
        Inkwell::g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clearColor, 1.0f, 0);

        if (Inkwell::g_pd3dDevice->BeginScene() >= 0) {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            Inkwell::g_pd3dDevice->EndScene();
        }

        HRESULT result = Inkwell::g_pd3dDevice->Present(NULL, NULL, NULL, NULL);
        if (result == D3DERR_DEVICELOST && Inkwell::g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            Inkwell::ResetDevice();
        }
    }

    // Cleanup
    Inkwell::UI::Get().Shutdown();
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    Inkwell::CleanupDeviceD3D();
    DestroyWindow(hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}
