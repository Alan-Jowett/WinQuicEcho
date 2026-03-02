// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include "common/quic_factory.hpp"

#include <map>
#include <mutex>

namespace winquicecho {

namespace {

struct backend_entry {
    backend_descriptor descriptor;
    backend_creator creator;
};

std::map<std::string, backend_entry>& registry() {
    static std::map<std::string, backend_entry> instance;
    return instance;
}

std::mutex& registry_mutex() {
    static std::mutex instance;
    return instance;
}

}  // namespace

void register_backend(std::string name, std::string description, backend_creator creator) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    registry()[name] = backend_entry{{name, description}, std::move(creator)};
}

std::unique_ptr<quic_backend> create_backend(std::string_view name) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    const auto it = registry().find(std::string(name));
    if (it == registry().end()) {
        return nullptr;
    }
    return it->second.creator();
}

std::vector<backend_descriptor> list_backends() {
    std::lock_guard<std::mutex> lock(registry_mutex());
    std::vector<backend_descriptor> result;
    result.reserve(registry().size());
    for (const auto& [_, entry] : registry()) {
        result.push_back(entry.descriptor);
    }
    return result;
}

}  // namespace winquicecho
