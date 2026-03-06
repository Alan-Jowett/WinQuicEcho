// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "backends/msquic/msquic_backend.hpp"
#include "backends/msquic_km/msquic_km_backend.hpp"
#include "common/arg_parser.hpp"
#include "common/quic_backend.hpp"
#include "common/quic_factory.hpp"

namespace {

std::atomic<bool> g_shutdown{false};

void handle_signal(int) { g_shutdown.store(true, std::memory_order_relaxed); }

uint16_t parse_port(const std::string& text) {
    const long value = std::strtol(text.c_str(), nullptr, 10);
    if (value <= 0 || value > 65535) {
        throw std::invalid_argument("Invalid port number.");
    }
    return static_cast<uint16_t>(value);
}

uint32_t parse_u32(const std::string& text, const char* field) {
    const long value = std::strtol(text.c_str(), nullptr, 10);
    if (value < 0) {
        throw std::invalid_argument(std::string("Invalid value for ") + field);
    }
    return static_cast<uint32_t>(value);
}

}  // namespace

int main(int argc, const char* const argv[]) {
    using namespace winquicecho;

    register_msquic_backend();
    register_msquic_km_backend();

    arg_parser parser;
    parser.add_option("backend", 'b', "msquic", true, "Backend name.");
    parser.add_option("port", 'p', "5001", true, "UDP port to listen on.");
    parser.add_option("alpn", 'a', "echo", true, "ALPN protocol name.");
    parser.add_option("duration", 'd', "0", true, "Duration in seconds (0 = until Ctrl+C).");
    parser.add_option("cert-hash", 't', "", true, "Certificate SHA-1 thumbprint for Schannel.");
    parser.add_option("cert-store", '\0', "MY", true, "Certificate store for --cert-hash.");
    parser.add_option("cert-file", '\0', "", true, "Certificate file path (OpenSSL mode).");
    parser.add_option("key-file", '\0', "", true, "Private key file path (OpenSSL mode).");
    parser.add_option("cert-pfx", '\0', "", true, "PKCS#12/PFX certificate file path.");
    parser.add_option("cert-pfx-password", '\0', "", true,
                      "PKCS#12/PFX password (optional).");
    parser.add_option("verbose", 'v', "0", false, "Enable verbose output.");
    parser.add_option("help", 'h', "0", false, "Show help.");
    parser.parse(argc, argv);

    if (parser.is_set("help")) {
        parser.print_help(argv[0]);
        std::cout << "\nAvailable backends:\n";
        for (const auto& backend : list_backends()) {
            std::cout << "  " << backend.name << " - " << backend.description << "\n";
        }
        return 0;
    }

    server_options options;
    try {
        options.backend = parser.get("backend");
        options.port = parse_port(parser.get("port"));
        options.alpn = parser.get("alpn");
        options.duration_seconds = parse_u32(parser.get("duration"), "duration");
        options.cert_hash = parser.get("cert-hash");
        options.cert_store = parser.get("cert-store");
        options.cert_file = parser.get("cert-file");
        options.key_file = parser.get("key-file");
        options.cert_pfx_file = parser.get("cert-pfx");
        options.cert_pfx_password = parser.get("cert-pfx-password");
        options.verbose = parser.is_set("verbose");
    } catch (const std::exception& ex) {
        std::cerr << "Argument error: " << ex.what() << "\n";
        return 1;
    }

    auto backend = create_backend(options.backend);
    if (!backend) {
        std::cerr << "Unknown backend: " << options.backend << "\n";
        std::cerr << "Available backends:\n";
        for (const auto& b : list_backends()) {
            std::cerr << "  " << b.name << "\n";
        }
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    return backend->run_server(options, g_shutdown);
}
