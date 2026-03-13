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

# MSVC runtime selection:
# By default, use static CRT (/MT) so executables don't depend on VC++ redistributable DLLs.
# Set -DWINQUICECHO_STATIC_CRT=OFF to use the dynamic CRT (/MD) instead (e.g., to match vcpkg OpenSSL).
if (MSVC)
    option(WINQUICECHO_STATIC_CRT "Link MSVC runtime statically (/MT) instead of dynamically (/MD)" ON)
    if (WINQUICECHO_STATIC_CRT)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

# ---------------------------------------------------------------------------
# Optional backends (require OpenSSL; default OFF)
# ---------------------------------------------------------------------------
option(WINQUICECHO_BUILD_NGTCP2   "Build ngtcp2 backend (requires OpenSSL/quictls)"  OFF)
option(WINQUICECHO_BUILD_PICOQUIC "Build picoquic backend (requires OpenSSL)"         OFF)

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

# ---------------------------------------------------------------------------
# ngtcp2 backend (optional; requires OpenSSL with QUIC API support)
# ---------------------------------------------------------------------------
if (WINQUICECHO_BUILD_NGTCP2)
    find_package(OpenSSL REQUIRED)

    FetchContent_Declare(
        ngtcp2
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG        v1.9.1
        GIT_SHALLOW    TRUE
    )
    set(ENABLE_LIB_ONLY    ON  CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB  ON  CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB  OFF CACHE BOOL "" FORCE)
    set(ENABLE_OPENSSL     ON  CACHE BOOL "" FORCE)
    set(ENABLE_GNUTLS      OFF CACHE BOOL "" FORCE)
    set(ENABLE_BORINGSSL   OFF CACHE BOOL "" FORCE)
    set(ENABLE_PICOTLS     OFF CACHE BOOL "" FORCE)
    set(ENABLE_WOLFSSL     OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING      OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(ngtcp2)

    add_library(quic_backend_ngtcp2
        src/backends/ngtcp2/ngtcp2_backend.cpp
    )
    target_include_directories(quic_backend_ngtcp2 PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(quic_backend_ngtcp2 PRIVATE
        quic_common ngtcp2_static ngtcp2_crypto_quictls_static
        OpenSSL::SSL OpenSSL::Crypto ws2_32
    )
    target_compile_definitions(quic_backend_ngtcp2 PRIVATE NGTCP2_STATICLIB)
endif()

# ---------------------------------------------------------------------------
# picoquic backend (optional; requires OpenSSL)
# ---------------------------------------------------------------------------
if (WINQUICECHO_BUILD_PICOQUIC)
    if (NOT OpenSSL_FOUND)
        find_package(OpenSSL REQUIRED)
    endif()

    FetchContent_Declare(
        picoquic
        GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
        GIT_TAG        86d8d0035ffff275bf41359c653911561cb79201  # v1.1.47.0
    )
    set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(picoquic)

    add_library(quic_backend_picoquic
        src/backends/picoquic/picoquic_backend.cpp
    )
    target_include_directories(quic_backend_picoquic PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${picoquic_SOURCE_DIR}/picoquic
        ${picoquic_SOURCE_DIR}/picoquicfirst
    )
    target_link_libraries(quic_backend_picoquic PRIVATE
        quic_common picoquic-core
        OpenSSL::SSL OpenSSL::Crypto ws2_32
    )
endif()

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

# Conditionally link optional backends and set compile definitions.
if (WINQUICECHO_BUILD_NGTCP2)
    target_link_libraries(echo_server PRIVATE quic_backend_ngtcp2)
    target_link_libraries(echo_client PRIVATE quic_backend_ngtcp2)
    target_compile_definitions(echo_server PRIVATE WINQUICECHO_HAS_NGTCP2)
    target_compile_definitions(echo_client PRIVATE WINQUICECHO_HAS_NGTCP2)
endif()

if (WINQUICECHO_BUILD_PICOQUIC)
    target_link_libraries(echo_server PRIVATE quic_backend_picoquic)
    target_link_libraries(echo_client PRIVATE quic_backend_picoquic)
    target_compile_definitions(echo_server PRIVATE WINQUICECHO_HAS_PICOQUIC)
    target_compile_definitions(echo_client PRIVATE WINQUICECHO_HAS_PICOQUIC)
endif()

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

if (WINQUICECHO_BUILD_NGTCP2)
    add_test(
        NAME echo_roundtrip_ngtcp2
        COMMAND powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
                ${CMAKE_SOURCE_DIR}/tests/integration/echo-roundtrip.ps1
                -BuildDir ${CMAKE_BINARY_DIR}
                -Config $<CONFIG>
                -Backend ngtcp2
    )
    set_tests_properties(echo_roundtrip_ngtcp2 PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
endif()

if (WINQUICECHO_BUILD_PICOQUIC)
    add_test(
        NAME echo_roundtrip_picoquic
        COMMAND powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
                ${CMAKE_SOURCE_DIR}/tests/integration/echo-roundtrip.ps1
                -BuildDir ${CMAKE_BINARY_DIR}
                -Config $<CONFIG>
                -Backend picoquic
    )
    set_tests_properties(echo_roundtrip_picoquic PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
endif()
