# Inkwell Universal Analyzer & Kernel Sandbox

A standalone, hardware-accelerated Direct3D 9 / ImGui x64 application engineered for differential anti-cheat telemetry, user-mode kernel driver co-emulation, process memory introspection, and Unity/IL2CPP forensic metadata analysis.

---

## Core Capabilities

1. **Hybrid Co-Emulation Engine (`KEVLAR` + `Kernemul`)**:
   - Sandboxed execution of `.sys` kernel drivers (anti-cheat filters, BYOVD exploit drivers, rootkits) in userland without system BSODs or ring-0 hazards.
2. **Black-Box Anti-Cheat Auditor**:
   - Differential snapshot analysis tracking driver installations, service creations, hosts DNS hijacks, fake AC stub replacements, and unbacked executable memory allocations.
3. **Unity & IL2CPP Forensic Metadata Inspector**:
   - Native PE/CLI metadata table traversals and `GameAssembly.dll` runtime hook identification.
4. **Dynamic Driver & Payload Dumper**:
   - Real-time unbuffered filesystem watcher on `%TEMP%` combined with a rapid process VAD scanner for extracting floating `MZ`/`PE` payloads from decrypted loader RAM.

---

## Build Instructions

### Prerequisites
- Windows 10 / 11 (x64)
- Visual Studio 2022 / v18 with "Desktop development with C++" workload
- DirectX 9 runtime headers (included in modern Windows SDK)

### Compilation
Double-click `build.bat` or run:
```cmd
build.bat
```
The compiled executable `AnalyzerInkwell.exe` will be generated in the root directory.
