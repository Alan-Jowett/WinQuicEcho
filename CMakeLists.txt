# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

cmake_minimum_required(VERSION 3.20)

project(WinQuicEcho LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT WIN32)
    message(FATAL_ERROR "WinQuicEcho is currently supported on Windows only.")
endif()

add_library(quic_common
    src/common/quic_factory.cpp
)
target_include_directories(quic_common PUBLIC ${CMAKE_SOURCE_DIR}/src)

add_library(quic_backend_msquic
    src/backends/msquic/msquic_backend.cpp
)
target_include_directories(quic_backend_msquic PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(quic_backend_msquic PRIVATE quic_common ws2_32)

add_executable(echo_server
    src/server/main.cpp
)
target_include_directories(echo_server PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(echo_server PRIVATE quic_common quic_backend_msquic ws2_32)

add_executable(echo_client
    src/client/main.cpp
)
target_include_directories(echo_client PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(echo_client PRIVATE quic_common quic_backend_msquic ws2_32)
