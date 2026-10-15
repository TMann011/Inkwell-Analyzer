@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo =================================================================
echo    COOK45 / INKWELL UNIVERSAL ANALYZER AND KERNEL SANDBOX LOADER   
echo =================================================================
echo.

:: Dynamic MSBuild discovery via vswhere or standard search
set "MSBUILD="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set "MSBUILD=%%i"
    )
)

if not defined MSBUILD (
    if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

if not defined MSBUILD (
    echo [ERROR] MSBuild.exe could not be located on this machine.
    echo Please install Visual Studio with "Desktop development with C++".
    pause
    exit /b 1
)

echo [*] Found MSBuild at: "!MSBUILD!"
echo [*] Compiling Release Target (x64)...

:: Attempt build with default project toolset
"!MSBUILD!" AnalyzerInkwell.sln /p:Configuration=Release /p:Platform=x64 /v:minimal /m
if !ERRORLEVEL! NEQ 0 (
    echo [*] Default toolset unavailable, retrying with standard v143 - VS 2022...
    "!MSBUILD!" AnalyzerInkwell.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /v:minimal /m
)

if !ERRORLEVEL! EQU 0 (
    echo.
    echo =================================================================
    echo [SUCCESS] AnalyzerInkwell compiled successfully!
    echo =================================================================
    if exist "%~dp0bin\Release\AnalyzerInkwell.exe" (
        copy /y "%~dp0bin\Release\AnalyzerInkwell.exe" "%~dp0AnalyzerInkwell.exe" >nul
        echo [*] Staged standalone binary: "%~dp0AnalyzerInkwell.exe"
    )
    exit /b 0
) else (
    echo [-] MSBuild failed with error code !ERRORLEVEL!.
    pause
    exit /b !ERRORLEVEL!
)
