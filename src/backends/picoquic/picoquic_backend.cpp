// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include "backends/picoquic/picoquic_backend.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <picoquic.h>

#include "common/metrics.hpp"
#include "common/quic_factory.hpp"

namespace winquicecho {
namespace {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
constexpr size_t MAX_UDP_PAYLOAD = 1500;
constexpr uint64_t STALE_TIMEOUT_NS = 2'000'000'000ULL;  // 2 seconds

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
using steady_clock = std::chrono::steady_clock;

uint64_t now_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(steady_clock::now().time_since_epoch())
            .count());
}

void fill_payload(std::vector<uint8_t>& payload, uint64_t sequence_number) {
    std::fill(payload.begin(), payload.end(), static_cast<uint8_t>(sequence_number & 0xFF));
    const uint64_t timestamp = now_ns();
    if (payload.size() >= sizeof(uint64_t)) {
        std::memcpy(payload.data(), &sequence_number, sizeof(uint64_t));
    }
    if (payload.size() >= sizeof(uint64_t) * 2) {
        std::memcpy(payload.data() + sizeof(uint64_t), &timestamp, sizeof(uint64_t));
    }
}

// ---------------------------------------------------------------------------
// RAII helpers
// ---------------------------------------------------------------------------

// RAII Winsock initializer.
class winsock_scope {
  public:
    winsock_scope() {
        const int result = WSAStartup(MAKEWORD(2, 2), &data_);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
    }
    ~winsock_scope() { WSACleanup(); }
    winsock_scope(const winsock_scope&) = delete;
    winsock_scope& operator=(const winsock_scope&) = delete;

  private:
    WSADATA data_{};
};

// RAII wrapper for SOCKET.
class udp_socket {
  public:
    udp_socket() = default;
    explicit udp_socket(SOCKET s) : sock_(s) {}
    ~udp_socket() {
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
    }
    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;
    udp_socket(udp_socket&& o) noexcept : sock_(o.sock_) { o.sock_ = INVALID_SOCKET; }
    udp_socket& operator=(udp_socket&& o) noexcept {
        if (this != &o) {
            if (sock_ != INVALID_SOCKET) closesocket(sock_);
            sock_ = o.sock_;
            o.sock_ = INVALID_SOCKET;
        }
        return *this;
    }
    SOCKET get() const { return sock_; }
    bool valid() const { return sock_ != INVALID_SOCKET; }

  private:
    SOCKET sock_{INVALID_SOCKET};
};

// RAII wrapper for picoquic_quic_t.
struct picoquic_deleter {
    void operator()(picoquic_quic_t* q) const {
        if (q) picoquic_free(q);
    }
};
using picoquic_ptr = std::unique_ptr<picoquic_quic_t, picoquic_deleter>;

// ---------------------------------------------------------------------------
// Server state and callback
// ---------------------------------------------------------------------------

struct server_state {
    std::atomic<uint64_t> requests_echoed{0};
    std::atomic<uint64_t> active_connections{0};
    // Connections that reached the ready state and were counted.
    // Only accessed from the picoquic callback thread (single-threaded per quic context).
    std::unordered_set<picoquic_cnx_t*> counted_connections;
    bool verbose{false};
};

int server_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
                    picoquic_call_back_event_t event, void* callback_ctx, void* stream_ctx) {
    (void)stream_id;
    (void)stream_ctx;
    auto* state = static_cast<server_state*>(callback_ctx);

    switch (event) {
        case picoquic_callback_ready:
            state->counted_connections.insert(cnx);
            state->active_connections.fetch_add(1, std::memory_order_relaxed);
            break;

        case picoquic_callback_almost_ready:
            // Ignore — wait for picoquic_callback_ready to count the connection.
            break;

        case picoquic_callback_datagram:
            // Echo the datagram back to the client.
            if (bytes != nullptr && length > 0) {
                picoquic_queue_datagram_frame(cnx, length, bytes);
                state->requests_echoed.fetch_add(1, std::memory_order_relaxed);
            }
            break;

        case picoquic_callback_close:
        case picoquic_callback_application_close:
        case picoquic_callback_stateless_reset:
            if (state->counted_connections.erase(cnx) > 0) {
                state->active_connections.fetch_sub(1, std::memory_order_relaxed);
            }
            break;

        case picoquic_callback_prepare_datagram:
        case picoquic_callback_datagram_acked:
        case picoquic_callback_datagram_lost:
        case picoquic_callback_datagram_spurious:
            // Server doesn't initiate datagrams; nothing to do.
            break;

        default:
            break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Client state and callback
// ---------------------------------------------------------------------------

struct client_state {
    std::atomic<uint64_t> requests_sent{0};
    std::atomic<uint64_t> requests_completed{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> errors{0};
    latency_accumulator latency;
    bool verbose{false};
};

struct client_conn_context {
    client_state* state{nullptr};
    std::atomic<bool> connected{false};
    std::atomic<bool> closed{false};
    std::unordered_map<uint64_t, uint64_t> pending_requests;
    uint32_t max_outstanding{1};
};

int client_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
                    picoquic_call_back_event_t event, void* callback_ctx, void* stream_ctx) {
    (void)cnx;
    (void)stream_id;
    (void)stream_ctx;
    auto* ctx = static_cast<client_conn_context*>(callback_ctx);

    switch (event) {
        case picoquic_callback_ready:
            ctx->connected.store(true, std::memory_order_release);
            break;

        case picoquic_callback_datagram:
            if (bytes != nullptr && length >= sizeof(uint64_t) * 2) {
                ctx->state->bytes_received.fetch_add(length, std::memory_order_relaxed);

                uint64_t seq, send_ts;
                std::memcpy(&seq, bytes, sizeof(uint64_t));
                std::memcpy(&send_ts, bytes + sizeof(uint64_t), sizeof(uint64_t));

                auto it = ctx->pending_requests.find(seq);
                if (it != ctx->pending_requests.end()) {
                    const uint64_t recv_ts = now_ns();
                    if (recv_ts > send_ts) {
                        ctx->state->latency.add_sample(recv_ts - send_ts);
                    }
                    ctx->pending_requests.erase(it);
                    ctx->state->requests_completed.fetch_add(1, std::memory_order_relaxed);
                }
            }
            break;

        case picoquic_callback_close:
        case picoquic_callback_application_close:
        case picoquic_callback_stateless_reset:
            ctx->closed.store(true, std::memory_order_release);
            break;

        case picoquic_callback_prepare_datagram:
        case picoquic_callback_datagram_acked:
        case picoquic_callback_datagram_lost:
        case picoquic_callback_datagram_spurious:
            break;

        default:
            break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Common event loop helpers
// ---------------------------------------------------------------------------

// Drain all pending incoming UDP packets and feed them to picoquic.
void drain_incoming(SOCKET sock, picoquic_quic_t* quic, const sockaddr_in& local_addr) {
    uint8_t recv_buf[MAX_UDP_PAYLOAD];
    for (;;) {
        sockaddr_storage from{};
        int from_len = sizeof(from);
        int bytes = recvfrom(sock, reinterpret_cast<char*>(recv_buf), sizeof(recv_buf), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
        if (bytes <= 0) break;

        picoquic_incoming_packet(
            quic, recv_buf, static_cast<size_t>(bytes),
            reinterpret_cast<sockaddr*>(&from),
            reinterpret_cast<sockaddr*>(const_cast<sockaddr_in*>(&local_addr)),
            0, 0, picoquic_current_time());

        // Check for more data without blocking.
        u_long avail = 0;
        ioctlsocket(sock, FIONREAD, &avail);
        if (avail == 0) break;
    }
}

// Send all pending outgoing packets from picoquic.
void flush_outgoing(SOCKET sock, picoquic_quic_t* quic) {
    uint8_t send_buf[MAX_UDP_PAYLOAD];
    for (;;) {
        size_t send_length = 0;
        sockaddr_storage addr_to{}, addr_from{};
        int if_index = 0;
        picoquic_connection_id_t log_cid{};
        picoquic_cnx_t* last_cnx = nullptr;

        int ret = picoquic_prepare_next_packet(quic, picoquic_current_time(), send_buf,
                                               sizeof(send_buf), &send_length, &addr_to,
                                               &addr_from, &if_index, &log_cid, &last_cnx);
        if (ret != 0 || send_length == 0) break;

        int dest_len = (addr_to.ss_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        sendto(sock, reinterpret_cast<const char*>(send_buf), static_cast<int>(send_length), 0,
               reinterpret_cast<const sockaddr*>(&addr_to), dest_len);
    }
}

// Compute select timeout from picoquic wake delay (microseconds → timeval).
timeval wake_delay_to_timeval(picoquic_quic_t* quic, int64_t max_delay_us) {
    int64_t delay = picoquic_get_next_wake_delay(quic, picoquic_current_time(), max_delay_us);
    if (delay < 0) delay = 0;
    timeval tv{};
    tv.tv_sec = static_cast<long>(delay / 1'000'000);
    tv.tv_usec = static_cast<long>(delay % 1'000'000);
    return tv;
}

// ---------------------------------------------------------------------------
// picoquic_backend implementation
// ---------------------------------------------------------------------------

class picoquic_backend_impl : public quic_backend {
  public:
    std::string_view name() const override { return "picoquic"; }

    int run_server(const server_options& options,
                   const std::atomic<bool>& shutdown_requested) override {
        try {
            winsock_scope winsock;

            if (options.cert_file.empty() || options.key_file.empty()) {
                std::cerr << "picoquic server requires --cert-file and --key-file (PEM)\n";
                return 1;
            }

            server_state state{};
            state.verbose = options.verbose;

            // Create picoquic context with TLS cert/key.
            picoquic_ptr quic(picoquic_create(
                128,                                // max connections
                options.cert_file.c_str(),          // PEM cert file
                options.key_file.c_str(),           // PEM key file
                nullptr,                            // cert root file
                options.alpn.c_str(),               // default ALPN
                server_callback,                    // callback
                &state,                             // callback context
                nullptr,                            // cnx_id callback
                nullptr,                            // cnx_id callback data
                nullptr,                            // reset seed
                picoquic_current_time(),            // current time
                nullptr,                            // simulated time
                nullptr,                            // ticket file
                nullptr,                            // ticket encryption key
                0));                                // ticket key length
            if (!quic) {
                std::cerr << "picoquic_create failed\n";
                return 1;
            }

            // Enable datagram support via transport parameters.
            picoquic_set_default_tp_value(quic.get(), picoquic_tp_max_datagram_frame_size,
                                          MAX_UDP_PAYLOAD);

            // Create and bind UDP socket.
            udp_socket sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
            if (!sock.valid()) {
                std::cerr << "Failed to create UDP socket\n";
                return 1;
            }

            sockaddr_in local_addr{};
            local_addr.sin_family = AF_INET;
            local_addr.sin_addr.s_addr = INADDR_ANY;
            local_addr.sin_port = htons(options.port);

            if (bind(sock.get(), reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) ==
                SOCKET_ERROR) {
                std::cerr << "bind failed: " << WSAGetLastError() << "\n";
                return 1;
            }

            // Set socket to non-blocking for packet draining.
            u_long nonblocking = 1;
            ioctlsocket(sock.get(), FIONBIO, &nonblocking);

            std::cout << "Listening on UDP port " << options.port << " with ALPN '"
                      << options.alpn << "' (picoquic)\n";

            const auto start = steady_clock::now();
            auto last_report = start;
            uint64_t previous = 0;

            while (!shutdown_requested.load(std::memory_order_acquire)) {
                if (options.duration_seconds > 0) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                             steady_clock::now() - start)
                                             .count();
                    if (elapsed >= static_cast<int64_t>(options.duration_seconds)) {
                        break;
                    }
                }
                // Wait for data or timeout.
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(sock.get(), &rfds);
                timeval tv = wake_delay_to_timeval(quic.get(), 100'000);  // 100 ms max
                select(0, &rfds, nullptr, nullptr, &tv);

                // Process incoming packets.
                drain_incoming(sock.get(), quic.get(), local_addr);

                // Send outgoing packets.
                flush_outgoing(sock.get(), quic.get());

                // Periodic stats report.
                auto now_tp = steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now_tp - last_report).count() >=
                    1) {
                    const uint64_t current =
                        state.requests_echoed.load(std::memory_order_relaxed);
                    const uint64_t rps = current - previous;
                    previous = current;
                    last_report = now_tp;
                    std::cout << "RPS=" << rps
                              << " ActiveConnections="
                              << state.active_connections.load(std::memory_order_relaxed)
                              << " TotalEchoed=" << current << "\n"
                              << std::flush;
                }
            }

            std::cout << "Final echoed requests: "
                      << state.requests_echoed.load(std::memory_order_relaxed) << "\n";
            return 0;
        } catch (const std::exception& ex) {
            std::cerr << "picoquic server error: " << ex.what() << "\n";
            return 1;
        }
    }

    client_run_summary run_client(const client_options& options) override {
        client_run_summary summary{};
        try {
            winsock_scope winsock;

            // Resolve server address.
            sockaddr_in server_addr{};
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(options.port);
            if (inet_pton(AF_INET, options.server.c_str(), &server_addr.sin_addr) != 1) {
                throw std::runtime_error("Invalid server address: " + options.server);
            }

            client_state state{};
            state.verbose = options.verbose;

            const uint32_t worker_count = std::max<uint32_t>(1, options.connections);
            std::atomic<uint32_t> connected_workers{0};
            std::atomic<bool> stop_signal{false};

            std::vector<std::thread> workers;
            workers.reserve(worker_count);

            for (uint32_t worker_idx = 0; worker_idx < worker_count; ++worker_idx) {
                workers.emplace_back([&, worker_idx]() {
                    try {
                        auto ctx = std::make_unique<client_conn_context>();
                        ctx->state = &state;
                        ctx->max_outstanding = options.outstanding;

                        // Create picoquic context (one per worker for thread safety).
                        picoquic_ptr quic(picoquic_create(
                            1,                      // max connections (just 1 per worker)
                            nullptr,                // no cert for client
                            nullptr,                // no key for client
                            nullptr,                // cert root file
                            options.alpn.c_str(),   // ALPN
                            client_callback,        // callback
                            ctx.get(),              // callback context
                            nullptr,                // cnx_id callback
                            nullptr,                // cnx_id callback data
                            nullptr,                // reset seed
                            picoquic_current_time(),
                            nullptr,                // simulated time
                            nullptr,                // ticket file
                            nullptr,                // ticket key
                            0));
                        if (!quic) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Enable datagram support.
                        picoquic_set_default_tp_value(quic.get(),
                                                      picoquic_tp_max_datagram_frame_size,
                                                      MAX_UDP_PAYLOAD);

                        // Disable certificate verification for insecure mode.
                        if (options.insecure) {
                            picoquic_set_null_verifier(quic.get());
                        }

                        // Create UDP socket.
                        udp_socket sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
                        if (!sock.valid()) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Bind to ephemeral port.
                        sockaddr_in local_addr{};
                        local_addr.sin_family = AF_INET;
                        local_addr.sin_addr.s_addr = INADDR_ANY;
                        local_addr.sin_port = 0;
                        if (bind(sock.get(), reinterpret_cast<sockaddr*>(&local_addr),
                                 sizeof(local_addr)) == SOCKET_ERROR) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        int local_len = sizeof(local_addr);
                        getsockname(sock.get(), reinterpret_cast<sockaddr*>(&local_addr),
                                    &local_len);

                        // Set non-blocking for drain loops.
                        u_long nonblocking = 1;
                        ioctlsocket(sock.get(), FIONBIO, &nonblocking);

                        // Create connection.
                        picoquic_cnx_t* cnx = picoquic_create_cnx(
                            quic.get(),
                            picoquic_null_connection_id,    // initial CID (auto-generated)
                            picoquic_null_connection_id,    // remote CID
                            reinterpret_cast<const sockaddr*>(&server_addr),
                            picoquic_current_time(),
                            0,                              // preferred version (latest)
                            options.server.c_str(),         // SNI
                            options.alpn.c_str(),           // ALPN
                            1);                             // client_mode = 1

                        if (cnx == nullptr) {
                            if (state.verbose) {
                                std::cerr << "[picoquic-client] picoquic_create_cnx failed\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Set per-connection callback context.
                        picoquic_set_callback(cnx, client_callback, ctx.get());

                        // Enable datagrams on this connection.
                        picoquic_cnx_set_pmtud_policy(cnx, picoquic_pmtud_delayed);

                        // Start the connection (triggers Initial packet).
                        if (picoquic_start_client_cnx(cnx) != 0) {
                            if (state.verbose) {
                                std::cerr << "[picoquic-client] picoquic_start_client_cnx failed\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Send initial handshake packet.
                        flush_outgoing(sock.get(), quic.get());

                        // Handshake loop — wait for picoquic_callback_ready.
                        auto handshake_deadline = steady_clock::now() + std::chrono::seconds(5);
                        while (!ctx->connected.load(std::memory_order_acquire) &&
                               !ctx->closed.load(std::memory_order_acquire) &&
                               steady_clock::now() < handshake_deadline &&
                               !stop_signal.load(std::memory_order_relaxed)) {
                            fd_set rfds;
                            FD_ZERO(&rfds);
                            FD_SET(sock.get(), &rfds);
                            timeval tv = wake_delay_to_timeval(quic.get(), 100'000);
                            select(0, &rfds, nullptr, nullptr, &tv);

                            drain_incoming(sock.get(), quic.get(), local_addr);
                            flush_outgoing(sock.get(), quic.get());
                        }

                        if (!ctx->connected.load(std::memory_order_acquire)) {
                            if (state.verbose) {
                                std::cerr << "[picoquic-client] handshake timeout\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        connected_workers.fetch_add(1, std::memory_order_release);

                        // Benchmark loop.
                        uint64_t sequence = static_cast<uint64_t>(worker_idx) << 40;
                        const uint32_t payload_size =
                            std::max<uint32_t>(16, options.payload_size);

                        while (!stop_signal.load(std::memory_order_acquire) &&
                               !ctx->closed.load(std::memory_order_acquire)) {
                            // Send datagrams while under max_outstanding.
                            while (ctx->pending_requests.size() < ctx->max_outstanding &&
                                   !stop_signal.load(std::memory_order_relaxed)) {
                                const uint64_t request_sequence = ++sequence;
                                std::vector<uint8_t> payload(payload_size);
                                fill_payload(payload, request_sequence);

                                int ret = picoquic_queue_datagram_frame(
                                    cnx, payload.size(), payload.data());
                                if (ret != 0) {
                                    if (state.verbose) {
                                        std::cerr
                                            << "[picoquic-client] queue_datagram_frame failed: "
                                            << ret << "\n";
                                    }
                                    break;
                                }

                                const uint64_t send_ts = now_ns();
                                ctx->pending_requests[request_sequence] = send_ts;
                                state.requests_sent.fetch_add(1, std::memory_order_relaxed);
                                state.bytes_sent.fetch_add(payload.size(),
                                                           std::memory_order_relaxed);
                            }

                            // Flush queued datagrams out.
                            flush_outgoing(sock.get(), quic.get());

                            // Receive with short timeout.
                            fd_set rfds;
                            FD_ZERO(&rfds);
                            FD_SET(sock.get(), &rfds);
                            timeval tv{};
                            tv.tv_sec = 0;
                            tv.tv_usec = 1000;  // 1 ms
                            int sel = select(0, &rfds, nullptr, nullptr, &tv);

                            if (sel > 0) {
                                drain_incoming(sock.get(), quic.get(), local_addr);
                            }

                            // Send any response packets (ACKs, etc.).
                            flush_outgoing(sock.get(), quic.get());

                            // Evict stale pending requests.
                            if (!ctx->pending_requests.empty()) {
                                const uint64_t cutoff = now_ns() - STALE_TIMEOUT_NS;
                                for (auto it = ctx->pending_requests.begin();
                                     it != ctx->pending_requests.end();) {
                                    if (it->second < cutoff) {
                                        it = ctx->pending_requests.erase(it);
                                        state.errors.fetch_add(1, std::memory_order_relaxed);
                                    } else {
                                        ++it;
                                    }
                                }
                            }
                        }

                        // Graceful close.
                        picoquic_close(cnx, 0);
                        flush_outgoing(sock.get(), quic.get());

                    } catch (const std::exception& ex) {
                        if (state.verbose) {
                            std::cerr << "[picoquic-client] worker " << worker_idx
                                      << " error: " << ex.what() << "\n";
                        }
                        state.errors.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }

            // Wait for at least one worker to connect.
            for (int i = 0;
                 i < 100 && connected_workers.load(std::memory_order_acquire) == 0; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (connected_workers.load(std::memory_order_acquire) == 0) {
                std::cerr << "[picoquic-client] No workers connected after 10s – aborting.\n";
                stop_signal.store(true, std::memory_order_release);
                for (auto& w : workers) w.join();
                summary.exit_code = 1;
                summary.errors = state.errors.load(std::memory_order_relaxed);
                return summary;
            }

            // Monitor loop.
            const auto benchmark_start = steady_clock::now();
            const auto monitor_end =
                benchmark_start + std::chrono::seconds(options.duration_seconds);
            uint64_t prev_completed = 0;
            while (steady_clock::now() < monitor_end) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                const uint64_t completed =
                    state.requests_completed.load(std::memory_order_relaxed);
                const uint64_t rps = completed - prev_completed;
                prev_completed = completed;
                std::cout << "RPS=" << rps << " Completed=" << completed
                          << " Sent=" << state.requests_sent.load(std::memory_order_relaxed)
                          << " Errors=" << state.errors.load(std::memory_order_relaxed) << "\n";
            }

            stop_signal.store(true, std::memory_order_release);
            for (auto& w : workers) w.join();

            const auto end = steady_clock::now();
            const double duration_seconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(end - benchmark_start)
                    .count() /
                1000.0;

            summary.exit_code = 0;
            summary.duration_seconds = duration_seconds;
            summary.requests_sent = state.requests_sent.load(std::memory_order_relaxed);
            summary.requests_completed =
                state.requests_completed.load(std::memory_order_relaxed);
            summary.bytes_sent = state.bytes_sent.load(std::memory_order_relaxed);
            summary.bytes_received = state.bytes_received.load(std::memory_order_relaxed);
            summary.errors = state.errors.load(std::memory_order_relaxed);

            const uint64_t samples = state.latency.samples.load(std::memory_order_relaxed);
            const uint64_t total_ns = state.latency.total_ns.load(std::memory_order_relaxed);
            summary.latency_min_ns =
                samples > 0 ? state.latency.min_ns.load(std::memory_order_relaxed) : 0;
            summary.latency_max_ns =
                samples > 0 ? state.latency.max_ns.load(std::memory_order_relaxed) : 0;
            summary.latency_avg_ns = samples > 0 ? (total_ns / samples) : 0;

            const double rps =
                duration_seconds > 0.0 ? (summary.requests_completed / duration_seconds) : 0.0;
            const double mbps =
                duration_seconds > 0.0
                    ? ((summary.bytes_received * 8.0) / (duration_seconds * 1'000'000.0))
                    : 0.0;

            std::cout << "\n===== Final Client Statistics =====\n";
            std::cout << "Duration: " << std::fixed << std::setprecision(2)
                      << duration_seconds << "s\n";
            std::cout << "Requests sent: " << summary.requests_sent << "\n";
            std::cout << "Requests completed: " << summary.requests_completed
                      << " (RPS=" << rps << ")\n";
            std::cout << "Errors: " << summary.errors << "\n";
            std::cout << "Bytes sent: " << summary.bytes_sent << "\n";
            std::cout << "Bytes received: " << summary.bytes_received << " (" << mbps
                      << " Mbps)\n";
            std::cout << "Latency min/avg/max: "
                      << (summary.latency_min_ns / 1'000'000.0) << "/"
                      << (summary.latency_avg_ns / 1'000'000.0) << "/"
                      << (summary.latency_max_ns / 1'000'000.0) << " ms\n";

            if (!options.stats_file.empty()) {
                std::ofstream out(options.stats_file, std::ios::trunc);
                if (out) {
                    out << "{\n";
                    out << "  \"backend\": \"picoquic\",\n";
                    out << "  \"duration_s\": " << std::fixed << std::setprecision(3)
                        << duration_seconds << ",\n";
                    out << "  \"requests_sent\": " << summary.requests_sent << ",\n";
                    out << "  \"requests_completed\": " << summary.requests_completed << ",\n";
                    out << "  \"errors\": " << summary.errors << ",\n";
                    out << "  \"bytes_sent\": " << summary.bytes_sent << ",\n";
                    out << "  \"bytes_received\": " << summary.bytes_received << ",\n";
                    out << "  \"latency_min_ns\": " << summary.latency_min_ns << ",\n";
                    out << "  \"latency_avg_ns\": " << summary.latency_avg_ns << ",\n";
                    out << "  \"latency_max_ns\": " << summary.latency_max_ns << "\n";
                    out << "}\n";
                }
            }

            return summary;
        } catch (const std::exception& ex) {
            summary.exit_code = 1;
            std::cerr << "picoquic client error: " << ex.what() << "\n";
            return summary;
        }
    }
};

}  // namespace

void register_picoquic_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        register_backend("picoquic", "picoquic backend (datagram echo)", []() {
            return std::make_unique<picoquic_backend_impl>();
        });
    });
}

}  // namespace winquicecho
