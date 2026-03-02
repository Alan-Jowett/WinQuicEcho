// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#include <atomic>
#include <cstdint>

namespace winquicecho {

inline void update_atomic_min(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t current = target.load(std::memory_order_relaxed);
    while (value < current &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
    }
}

inline void update_atomic_max(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t current = target.load(std::memory_order_relaxed);
    while (value > current &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
    }
}

struct latency_accumulator {
    std::atomic<uint64_t> samples{0};
    std::atomic<uint64_t> total_ns{0};
    std::atomic<uint64_t> min_ns{UINT64_MAX};
    std::atomic<uint64_t> max_ns{0};

    void add_sample(uint64_t ns) {
        samples.fetch_add(1, std::memory_order_relaxed);
        total_ns.fetch_add(ns, std::memory_order_relaxed);
        update_atomic_min(min_ns, ns);
        update_atomic_max(max_ns, ns);
    }
};

}  // namespace winquicecho
