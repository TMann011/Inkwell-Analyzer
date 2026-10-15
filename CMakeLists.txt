cmake_minimum_required(VERSION 3.20)
project(AnalyzerInkwell C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS)

include_directories(
    src
    src/imgui
    src/core
    src/gui
)

file(GLOB_RECURSE SRC_FILES
    src/*.cpp
    src/*.h
)

add_executable(AnalyzerInkwell WIN32 ${SRC_FILES})

target_link_libraries(AnalyzerInkwell
    d3d9
    dwmapi
    wintrust
    crypt32
    bcrypt
    psapi
    shlwapi
)

set_target_properties(AnalyzerInkwell PROPERTIES
    WIN32_EXECUTABLE TRUE
    OUTPUT_NAME "AnalyzerInkwell"
)
