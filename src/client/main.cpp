// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "backends/msquic/msquic_backend.hpp"
#include "common/arg_parser.hpp"
#include "common/quic_backend.hpp"
#include "common/quic_factory.hpp"

namespace {

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

    arg_parser parser;
    parser.add_option("backend", 'b', "msquic", true, "Backend name.");
    parser.add_option("server", 's', "127.0.0.1", true, "Server host or IP.");
    parser.add_option("port", 'p', "5001", true, "Server UDP port.");
    parser.add_option("alpn", 'a', "echo", true, "ALPN protocol name.");
    parser.add_option("duration", 'd', "10", true, "Benchmark duration in seconds.");
    parser.add_option("payload", 'l', "64", true, "Payload bytes per request (minimum 16).");
    parser.add_option("connections", 'c', "1", true, "Number of concurrent client connections.");
    parser.add_option("outstanding", 'n', "1", true, "Outstanding (pipelined) requests per connection.");
    parser.add_option("insecure", 'i', "0", false, "Disable server certificate validation.");
    parser.add_option("stats-file", 'o', "", true, "Write final statistics JSON to file.");
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

    client_options options;
    try {
        options.backend = parser.get("backend");
        options.server = parser.get("server");
        options.port = parse_port(parser.get("port"));
        options.alpn = parser.get("alpn");
        options.duration_seconds = parse_u32(parser.get("duration"), "duration");
        options.payload_size = parse_u32(parser.get("payload"), "payload");
        options.connections = std::max<uint32_t>(1, parse_u32(parser.get("connections"), "connections"));
        options.outstanding = std::max<uint32_t>(1, parse_u32(parser.get("outstanding"), "outstanding"));
        options.insecure = parser.is_set("insecure");
        options.stats_file = parser.get("stats-file");
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

    client_run_summary summary = backend->run_client(options);
    return summary.exit_code;
}
