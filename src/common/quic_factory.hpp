// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "common/quic_backend.hpp"

namespace winquicecho {

struct backend_descriptor {
    std::string name;
    std::string description;
};

using backend_creator = std::function<std::unique_ptr<quic_backend>()>;

void register_backend(std::string name, std::string description, backend_creator creator);
std::unique_ptr<quic_backend> create_backend(std::string_view name);
std::vector<backend_descriptor> list_backends();

}  // namespace winquicecho
