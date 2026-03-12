// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace winquicecho {

struct server_options {
    std::string backend{"msquic"};
    uint16_t port{5001};
    std::string alpn{"echo"};
    uint32_t duration_seconds{0};
    bool verbose{false};

    // Schannel path (recommended on Windows): SHA-1 thumbprint in hex.
    std::string cert_hash;
    std::string cert_store{"MY"};

    // OpenSSL path (optional): PEM key + cert file paths.
    std::string key_file;
    std::string cert_file;

    // OpenSSL path (optional): PKCS#12/PFX file path + password.
    std::string cert_pfx_file;
    std::string cert_pfx_password;
};

struct client_options {
    std::string backend{"msquic"};
    std::string server{"127.0.0.1"};
    uint16_t port{5001};
    std::string alpn{"echo"};
    uint32_t duration_seconds{10};
    uint32_t payload_size{64};
    uint32_t connections{1};
    uint32_t outstanding{1};
    // Certificate validation is enabled by default.  Use --insecure (CLI) to
    // skip validation for development/testing with self-signed certificates.
    bool insecure{false};
    bool verbose{false};
    std::string stats_file;
};

struct client_run_summary {
    int exit_code{1};
    double duration_seconds{0.0};
    uint64_t requests_sent{0};
    uint64_t requests_completed{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    uint64_t errors{0};
    uint64_t latency_min_ns{0};
    uint64_t latency_avg_ns{0};
    uint64_t latency_max_ns{0};
};

class quic_backend {
  public:
    virtual ~quic_backend() = default;
    virtual std::string_view name() const = 0;
    virtual int run_server(const server_options& options,
                           const std::atomic<bool>& shutdown_requested) = 0;
    virtual client_run_summary run_client(const client_options& options) = 0;
};

}  // namespace winquicecho
