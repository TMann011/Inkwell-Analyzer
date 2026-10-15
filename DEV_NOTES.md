# Inkwell Universal Analyzer & Kernel Sandbox (`analyzer inkwell`)

## 1. Architectural Summary & Operating Posture

The **Inkwell Universal Analyzer** is a standalone, hardware-accelerated Direct3D 9 / ImGui x64 application engineered for differential anti-cheat telemetry, user-mode kernel driver co-emulation, process memory introspection, and Unity/IL2CPP forensic metadata analysis.

It integrates and unifies four major reverse engineering vectors into an aesthetic, portable loader interface:
1. **Hybrid Co-Emulation Engine (`KEVLAR` + `Kernemul`)**: Sandboxed execution of `.sys` kernel drivers (anti-cheat filters, BYOVD exploit drivers, rootkits) in userland without system BSODs or ring-0 hazards.
2. **Black-Box Anti-Cheat Auditor**: Differential snapshot analysis tracking driver installations, service creations, hosts DNS hijacks, fake AC stub replacements, and unbacked executable memory allocations.
3. **Unity & IL2CPP Forensic Metadata Inspector**: Native PE/CLI metadata table traversals and `GameAssembly.dll` runtime hook identification.
4. **Dynamic Driver & Payload Dumper**: Real-time unbuffered filesystem watcher on `%TEMP%` combined with a rapid process VAD scanner for extracting floating `MZ`/`PE` payloads from decrypted loader RAM.

```text
Inkwell analyzer/
├── DEV_NOTES.md                 # Technical Architecture Documentation
├── AnalyzerInkwell.sln          # Visual Studio Solution (Release|x64)
├── AnalyzerInkwell.vcxproj      # MSBuild Project Definition (v145 / std:c++20)
├── CMakeLists.txt               # Cross-Platform CMake Configuration
├── build.bat                    # One-Click Automated MSBuild Pipeline
├── AnalyzerInkwell.exe          # Compiled Standalone Executable (583 KB)
└── src/
    ├── main.h / main.cpp        # Entry point, Direct3D 9 pipeline, WndProc hit-testing
    ├── core/
    │   ├── config.h / .cpp      # Dynamic path resolution & INI state manager
    │   ├── logger.h / .cpp      # Thread-safe ring-buffer diagnostics logger
    │   ├── hybrid_emul/         # KEVLAR + Kernemul Hybrid Co-Emulation Engine
    │   │   ├── hybrid_engine.h
    │   │   └── hybrid_engine.cpp
    │   ├── ac_analyzer/         # Differential Anti-Cheat & Tampering Auditor
    │   │   ├── ac_analyzer.h
    │   │   └── ac_analyzer.cpp
    │   ├── unity_analyzer/      # Unity PE/CLI & IL2CPP Metadata Inspector
    │   │   ├── unity_analyzer.h
    │   │   └── unity_analyzer.cpp
    │   └── driver_dumper/       # Real-Time %TEMP% Watcher & Process VAD Dumper
    │       ├── driver_dumper.h
    │       └── driver_dumper.cpp
    ├── gui/
    │   ├── theme.h / theme.cpp  # Inkwell UI Presets (PurpleBlack, ElectricIndigo, etc.)
    │   └── ui.h / ui.cpp        # Frameless Tab Rendering & Control Engine
    └── imgui/                   # Self-contained Dear ImGui v1.91 with DX9 + Win32
```

---

## 2. Low-Level Subsystem Mechanics

### A. Emul + Kevlar Co-Emulation Hybrid Engine
Directly addresses the requirement for bridging `kernemul` and `KEVLAR`:
* **PE Driver Mapping (`KEVLAR` style)**: Parses DOS/NT/Section headers, aligns virtual memory blocks (`.text`, `.rdata`, `.data`, `INIT`, `PAGE`), and computes base relocation fixups (`IMAGE_REL_BASED_DIR64`).
* **Kernel Dispatch & Interception (`Kernemul` style)**:
  * **Memory Manager**: Stubs and monitors `ExAllocatePoolWithTag`, `ExAllocatePool2`, `MmAllocatePagesForMdl`, `MmMapLockedPagesSpecifyCache`.
  * **Physical Memory Exploitation**: Intercepts `MmMapIoSpace` and `MmGetPhysicalAddress` calls to expose physical memory mapping attacks (e.g. `\Device\Nal` Intel exploit IOCTL `0x80862007`).
  * **Object & Handle Filtering**: Intercepts `ObRegisterCallbacks` used by anti-cheats (EAC, BattlEye, Vanguard) to strip `PROCESS_ALL_ACCESS` rights down to restricted query masks.
  * **Notification Routines**: Traps `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine`.
  * **Execution Guard**: Sandboxed simulation loop ensures drivers cannot crash the host OS while capturing call traces and dumping unpacked payloads.

### B. Black-Box Differential Anti-Cheat Telemetry
* **Kernel Module Delta**: Compares driver baseline via `EnumDeviceDrivers` and `NtQuerySystemInformation(SystemModuleInformation)` against live state to flag unauthorized `.sys` drivers.
* **Service Delta**: Uses `EnumServicesStatusExW` to catch ephemeral background services spawned by game droppers.
* **Fake Stub & Integrity Verification**: Checks file sizes and Authenticode digital certificates (`WinVerifyTrust`). Flags fake anti-cheat stubs (e.g. dummy 50KB stubs replacing 5MB EAC binaries).
* **VAD Unbacked Memory Scan**: Traverses target process memory via `VirtualQueryEx`. Identifies `MEM_COMMIT` + `MEM_PRIVATE` memory with executable protections (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`) containing floating `0x5A4D` (`MZ`) PE headers.
* **Hosts Redirection Audit**: Analyzes `%SystemRoot%\System32\drivers\etc\hosts` to detect local DNS overrides (`127.0.0.1`) targeting anti-cheat authentication servers.

### C. Unity / IL2CPP Metadata Inspector
* Scans target game directory or `Il2CppAssemblies` for CLI assemblies.
* Traverses `IMAGE_COR20_HEADER` and CLR metadata root (`0x424A5342` = "BSJB").
* Extracts TypeDef, MethodDef, Field, and TypeRef metrics.
* Parses `GameAssembly.dll` export directory to locate and log critical runtime hooks (`il2cpp_domain_get`, `il2cpp_thread_attach`, `il2cpp_resolve_icall`, `il2cpp_class_get_methods`).

### D. Ephemeral Driver Watcher & Process VAD Dumper
* **Filesystem Watcher**: Background thread monitoring `%TEMP%` with `ReadDirectoryChangesW`. Uses unbuffered `CreateFileW` with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` to copy dropped drivers out before the loader deletes them.
* **VAD PE Scanner**: Queries process virtual memory pages and writes all discovered memory-mapped PE images to disk.

---

## 3. Portability & Standalone Guarantees

* **Zero Hardcoded Paths**: Dynamic path resolution relies strictly on:
  * `GetModuleFileNameW`: Application root and output directories.
  * `GetTempPathW`: Ephemeral watch target.
  * `GetSystemDirectoryW`: System drivers and hosts file location.
  * `analyzer_config.ini`: Optional persistent user overrides.
* **Self-Contained Dependencies**: Dear ImGui, DirectX 9 runtime headers, and Windows SDK native APIs (`psapi`, `wintrust`, `crypt32`, `bcrypt`) are linked directly. Operates on any clean Windows 10/11 x64 installation.

---

## 4. Compilation & Verification

To recompile or package:
```cmd
build.bat
```
Output executable: `AnalyzerInkwell.exe`
