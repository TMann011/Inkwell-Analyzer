#pragma once

#include <windows.h>
#include <d3d9.h>
#include <string>

#pragma comment(lib, "d3d9.lib")

namespace Inkwell {

extern HWND g_hMainWnd;
extern LPDIRECT3D9 g_pD3D;
extern LPDIRECT3DDEVICE9 g_pd3dDevice;
extern D3DPRESENT_PARAMETERS g_d3dpp;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
bool EnsureElevatedPrivileges();

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

} // namespace Inkwell
