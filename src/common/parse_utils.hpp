// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace winquicecho {

/// Parse a string as a TCP/UDP port number (1–65535).
/// Throws std::invalid_argument on malformed input or out-of-range values.
inline uint16_t parse_port(const std::string& text) {
    if (text.empty()) {
        throw std::invalid_argument("Port cannot be empty.");
    }
    char* endptr = nullptr;
    errno = 0;
    const long value = std::strtol(text.c_str(), &endptr, 10);
    if (errno != 0 || endptr == text.c_str() || *endptr != '\0') {
        throw std::invalid_argument("Invalid port number: " + text);
    }
    if (value <= 0 || value > 65535) {
        throw std::invalid_argument("Port number out of range: " + text);
    }
    return static_cast<uint16_t>(value);
}

/// Parse a string as a uint32_t.  @p field is used in error messages.
/// Throws std::invalid_argument on malformed input or out-of-range values.
inline uint32_t parse_u32(const std::string& text, const char* field) {
    if (text.empty()) {
        throw std::invalid_argument(std::string("Value for ") + field + " cannot be empty.");
    }
    char* endptr = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(text.c_str(), &endptr, 10);
    if (errno != 0 || endptr == text.c_str() || *endptr != '\0') {
        throw std::invalid_argument(std::string("Invalid value for ") + field + ": " + text);
    }
    // Reject negative inputs: strtoul silently wraps them.
    if (text.front() == '-') {
        throw std::invalid_argument(std::string("Value for ") + field + " must not be negative: " + text);
    }
#if ULONG_MAX > UINT32_MAX
    if (value > UINT32_MAX) {
        throw std::invalid_argument(std::string("Value for ") + field + " out of range: " + text);
    }
#endif
    return static_cast<uint32_t>(value);
}

}  // namespace winquicecho
