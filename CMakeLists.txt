# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

cmake_minimum_required(VERSION 3.20)

project(WinQuicEcho LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT WIN32)
    message(FATAL_ERROR "WinQuicEcho is currently supported on Windows only.")
endif()

# ---------------------------------------------------------------------------
# MsQuic dependency (built from source)
# ---------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
    msquic
    GIT_REPOSITORY https://github.com/microsoft/msquic.git
    GIT_TAG        v2.5.6
    GIT_SHALLOW    TRUE
    GIT_SUBMODULES_RECURSE TRUE
)
# Build msquic as a shared library with Schannel TLS (Windows default).
set(QUIC_BUILD_TOOLS   OFF CACHE BOOL "" FORCE)
set(QUIC_BUILD_TEST    OFF CACHE BOOL "" FORCE)
set(QUIC_BUILD_PERF    OFF CACHE BOOL "" FORCE)
set(QUIC_BUILD_SHARED  ON  CACHE BOOL "" FORCE)
set(QUIC_TLS_LIB       "schannel" CACHE STRING "" FORCE)
FetchContent_MakeAvailable(msquic)

add_library(quic_common
    src/common/quic_factory.cpp
)
target_include_directories(quic_common PUBLIC ${CMAKE_SOURCE_DIR}/src)

add_library(quic_backend_msquic
    src/backends/msquic/msquic_backend.cpp
)
target_include_directories(quic_backend_msquic PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(quic_backend_msquic PRIVATE quic_common ws2_32 msquic inc)

# Kernel-mode backend — user-mode IOCTL client that talks to winquicecho_km.sys.
# The kernel driver itself is built separately with WDK (see scripts/build-km-driver.ps1).
add_library(quic_backend_msquic_km
    src/backends/msquic_km/msquic_km_backend.cpp
)
target_include_directories(quic_backend_msquic_km PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(quic_backend_msquic_km PRIVATE quic_common)

add_executable(echo_server
    src/server/main.cpp
)
target_include_directories(echo_server PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(echo_server PRIVATE quic_common quic_backend_msquic quic_backend_msquic_km ws2_32)

add_executable(echo_client
    src/client/main.cpp
)
target_include_directories(echo_client PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(echo_client PRIVATE quic_common quic_backend_msquic ws2_32)

# Copy msquic.dll next to the executables after build.
add_custom_command(TARGET echo_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:msquic> $<TARGET_FILE_DIR:echo_server>
    COMMENT "Copying msquic.dll to echo_server output directory"
)

add_custom_command(TARGET echo_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:msquic> $<TARGET_FILE_DIR:echo_client>
    COMMENT "Copying msquic.dll to echo_client output directory"
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()

add_test(
    NAME echo_roundtrip
    COMMAND powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
            ${CMAKE_SOURCE_DIR}/tests/integration/echo-roundtrip.ps1
            -BuildDir ${CMAKE_BINARY_DIR}
            -Config $<CONFIG>
)
set_tests_properties(echo_roundtrip PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
