// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

// User-mode backend that communicates with the WinQuicEcho kernel driver
// (winquicecho_km.sys) via IOCTLs.  The kernel driver uses msquic.sys —
// the same kernel-mode QUIC API surface used by http.sys and SMB server.

#include "backends/msquic_km/msquic_km_backend.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>

#include "backends/msquic_km/ioctl.h"
#include "common/quic_backend.hpp"
#include "common/quic_factory.hpp"

namespace winquicecho {
namespace {

using steady_clock = std::chrono::steady_clock;

// RAII wrapper for a handle to the kernel driver device.
class km_device {
  public:
    km_device() {
        handle_ = CreateFileW(
            WINQUICECHO_USERMODE_PATHW,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            const DWORD err = GetLastError();
            throw std::runtime_error(
                "Failed to open " WINQUICECHO_USERMODE_PATH " (error=" +
                std::to_string(err) +
                "). Is the winquicecho_km.sys driver loaded?");
        }
    }

    ~km_device() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    km_device(const km_device&) = delete;
    km_device& operator=(const km_device&) = delete;

    void start_server(const WINQUICECHO_SERVER_CONFIG& config) const {
        DWORD bytes_returned = 0;
        BOOL ok = DeviceIoControl(
            handle_,
            IOCTL_WINQUICECHO_START_SERVER,
            const_cast<WINQUICECHO_SERVER_CONFIG*>(&config),
            sizeof(config),
            nullptr, 0,
            &bytes_returned,
            nullptr);
        if (!ok) {
            const DWORD err = GetLastError();
            throw std::runtime_error(
                "IOCTL_WINQUICECHO_START_SERVER failed (error=" +
                std::to_string(err) + ")");
        }
    }

    void stop_server() const {
        DWORD bytes_returned = 0;
        BOOL ok = DeviceIoControl(
            handle_,
            IOCTL_WINQUICECHO_STOP_SERVER,
            nullptr, 0,
            nullptr, 0,
            &bytes_returned,
            nullptr);
        if (!ok) {
            const DWORD err = GetLastError();
            std::cerr << "IOCTL_WINQUICECHO_STOP_SERVER failed (error="
                      << err << ")\n";
        }
    }

    WINQUICECHO_SERVER_STATS get_stats() const {
        WINQUICECHO_SERVER_STATS stats{};
        DWORD bytes_returned = 0;
        BOOL ok = DeviceIoControl(
            handle_,
            IOCTL_WINQUICECHO_GET_STATS,
            nullptr, 0,
            &stats, sizeof(stats),
            &bytes_returned,
            nullptr);
        if (!ok) {
            const DWORD err = GetLastError();
            throw std::runtime_error(
                "IOCTL_WINQUICECHO_GET_STATS failed (error=" +
                std::to_string(err) + ")");
        }
        if (bytes_returned != sizeof(stats)) {
            throw std::runtime_error(
                "IOCTL_WINQUICECHO_GET_STATS returned " +
                std::to_string(bytes_returned) + " bytes, expected " +
                std::to_string(sizeof(stats)));
        }
        return stats;
    }

  private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

bool parse_sha1_hex_km(const std::string& text, UINT8 hash[20]) {
    std::string clean;
    clean.reserve(text.size());
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c)) && c != ':') {
            clean.push_back(c);
        }
    }
    if (clean.size() != 40) {
        return false;
    }
    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (size_t i = 0; i < 20; ++i) {
        const int high = hex_value(clean[2 * i]);
        const int low  = hex_value(clean[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        hash[i] = static_cast<UINT8>((high << 4) | low);
    }
    return true;
}

class msquic_km_backend final : public quic_backend {
  public:
    std::string_view name() const override { return "msquic-km"; }

    int run_server(const server_options& options,
                   const std::atomic<bool>& shutdown_requested) override {
        km_device device;
        bool server_started = false;

        try {
            WINQUICECHO_SERVER_CONFIG config{};
            config.Port = options.port;
            config.Verbose = options.verbose ? TRUE : FALSE;

            // ALPN.
            std::strncpy(config.Alpn, options.alpn.c_str(), sizeof(config.Alpn) - 1);
            config.Alpn[sizeof(config.Alpn) - 1] = '\0';

            // Certificate — kernel mode only supports Schannel hash path.
            if (options.cert_hash.empty()) {
                throw std::runtime_error(
                    "Kernel-mode backend requires --cert-hash (Schannel "
                    "thumbprint). File-based and PFX credentials are not "
                    "supported in kernel mode.");
            }
            if (!parse_sha1_hex_km(options.cert_hash, config.CertHash)) {
                throw std::runtime_error(
                    "Invalid --cert-hash. Expected 40 hex chars (SHA-1 thumbprint).");
            }

            // Certificate store — kernel driver uses the machine store.
            std::strncpy(config.CertStore, options.cert_store.c_str(),
                         sizeof(config.CertStore) - 1);
            config.CertStore[sizeof(config.CertStore) - 1] = '\0';

            device.start_server(config);
            server_started = true;

            std::cout << "Server backend: msquic-km (kernel mode)\n" << std::flush;
            std::cout << "Listening on UDP port " << options.port
                      << " with ALPN '" << options.alpn << "'\n" << std::flush;

            const auto start = steady_clock::now();
            uint64_t previous_echoed = 0;

            while (!shutdown_requested.load(std::memory_order_relaxed)) {
                if (options.duration_seconds > 0) {
                    const auto elapsed =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            steady_clock::now() - start)
                            .count();
                    if (elapsed >= static_cast<int64_t>(options.duration_seconds)) {
                        break;
                    }
                }

                std::this_thread::sleep_for(std::chrono::seconds(1));

                auto stats = device.get_stats();
                if (!stats.Running) {
                    std::cerr << "Kernel server stopped unexpectedly.\n";
                    break;
                }

                const uint64_t rps = stats.RequestsEchoed - previous_echoed;
                previous_echoed = stats.RequestsEchoed;
                std::cout << "RPS=" << rps
                          << " ActiveConnections=" << stats.ActiveConnections
                          << " TotalEchoed=" << stats.RequestsEchoed
                          << "\n" << std::flush;
            }

            device.stop_server();
            server_started = false;

            auto final_stats = device.get_stats();
            std::cout << "Final echoed requests: " << final_stats.RequestsEchoed << "\n";
            return 0;

        } catch (const std::exception& ex) {
            std::cerr << "msquic-km server error: " << ex.what() << "\n";
            if (server_started) {
                device.stop_server();
            }
            return 1;
        }
    }

    client_run_summary run_client(const client_options&) override {
        std::cerr << "Kernel-mode client is not supported. "
                     "Use the user-mode 'msquic' backend for the client.\n";
        return client_run_summary{1};
    }
};

}  // namespace

void register_msquic_km_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        register_backend(
            "msquic-km",
            "MsQuic kernel-mode backend (msquic.sys — same path as http.sys/SMB)",
            []() { return std::make_unique<msquic_km_backend>(); });
    });
}

}  // namespace winquicecho
