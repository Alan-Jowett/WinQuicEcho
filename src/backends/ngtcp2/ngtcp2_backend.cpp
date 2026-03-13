// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include "backends/ngtcp2/ngtcp2_backend.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "common/metrics.hpp"
#include "common/quic_factory.hpp"

namespace winquicecho {
namespace {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
constexpr size_t SERVER_CID_LEN = 8;
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

void generate_cid(ngtcp2_cid* cid, size_t len) {
    cid->datalen = len;
    if (RAND_bytes(cid->data, static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed in generate_cid");
    }
}

std::string cid_to_key(const ngtcp2_cid* cid) {
    return std::string(reinterpret_cast<const char*>(cid->data), cid->datalen);
}

std::string cid_to_key(const uint8_t* data, size_t len) {
    return std::string(reinterpret_cast<const char*>(data), len);
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

// RAII wrapper for SSL_CTX.
struct ssl_ctx_deleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) SSL_CTX_free(ctx);
    }
};
using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;

// RAII wrapper for SSL.
struct ssl_deleter {
    void operator()(SSL* ssl) const {
        if (ssl) SSL_free(ssl);
    }
};
using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

// RAII wrapper for ngtcp2_conn.
struct ngtcp2_conn_deleter {
    void operator()(ngtcp2_conn* conn) const {
        if (conn) ngtcp2_conn_del(conn);
    }
};
using ngtcp2_conn_ptr = std::unique_ptr<ngtcp2_conn, ngtcp2_conn_deleter>;

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

// ---------------------------------------------------------------------------
// ALPN callback for server TLS
// ---------------------------------------------------------------------------
static int server_alpn_select_cb(SSL*, const unsigned char** out, unsigned char* outlen,
                                 const unsigned char* in, unsigned int inlen, void* arg) {
    auto* alpn = static_cast<std::string*>(arg);
    const unsigned char* p = in;
    const unsigned char* end = in + inlen;
    while (p < end) {
        unsigned char len = *p++;
        if (static_cast<size_t>(end - p) < len) break;
        if (len == alpn->size() && std::memcmp(p, alpn->data(), len) == 0) {
            *out = p;
            *outlen = len;
            return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// ---------------------------------------------------------------------------
// ngtcp2 callbacks — shared helpers
// ---------------------------------------------------------------------------
static void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1) {
        // ngtcp2 rand_cb has no error return path; abort to avoid using weak randomness.
        std::abort();
    }
}

static ngtcp2_callbacks make_base_callbacks() {
    ngtcp2_callbacks cb{};
    // Crypto callbacks from ngtcp2_crypto_quictls.
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.rand = rand_cb;
    return cb;
}

// ============================================================================
// SERVER
// ============================================================================

struct server_state;

struct server_conn_context {
    ngtcp2_crypto_conn_ref conn_ref{};
    ngtcp2_conn_ptr conn;
    ssl_ptr ssl;
    sockaddr_storage remote_addr{};
    int remote_addrlen{0};
    server_state* state{nullptr};

    // Datagrams received during read_pkt, queued for echo.
    std::deque<std::vector<uint8_t>> echo_queue;
};

struct server_state {
    bool verbose{false};
    std::string alpn;
    SSL_CTX* ssl_ctx{nullptr};
    SOCKET sock{INVALID_SOCKET};
    sockaddr_in local_addr{};

    // CID → connection lookup.
    std::unordered_map<std::string, server_conn_context*> cid_map;
    // Owns the connection contexts.
    std::unordered_map<server_conn_context*, std::unique_ptr<server_conn_context>> connections;

    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> requests_echoed{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> bytes_sent{0};
};

static ngtcp2_conn* server_get_conn(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<server_conn_context*>(ref->user_data)->conn.get();
}

// Server recv_datagram: queue the datagram for echo.
static int server_recv_datagram_cb(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t datalen,
                                   void* user_data) {
    auto* ref = static_cast<ngtcp2_crypto_conn_ref*>(user_data);
    auto* ctx = static_cast<server_conn_context*>(ref->user_data);
    ctx->echo_queue.emplace_back(data, data + datalen);
    ctx->state->bytes_received.fetch_add(datalen, std::memory_order_relaxed);
    return 0;
}

// Server get_new_connection_id: generate CID and register in the CID map.
static int server_get_new_cid_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                                 void* user_data) {
    auto* ref = static_cast<ngtcp2_crypto_conn_ref*>(user_data);
    auto* ctx = static_cast<server_conn_context*>(ref->user_data);
    cid->datalen = cidlen;
    RAND_bytes(cid->data, static_cast<int>(cidlen));
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    ctx->state->cid_map[cid_to_key(cid)] = ctx;
    return 0;
}

// Flush pending echo datagrams and protocol packets for a server connection.
static void server_flush_output(server_conn_context* ctx) {
    uint8_t buf[MAX_UDP_PAYLOAD];
    ngtcp2_tstamp ts = now_ns();
    auto* state = ctx->state;

    // Send queued echo datagrams.
    while (!ctx->echo_queue.empty()) {
        auto& dgram = ctx->echo_queue.front();
        ngtcp2_vec datav;
        datav.base = dgram.data();
        datav.len = dgram.size();
        int accepted = 0;
        uint32_t flags = ctx->echo_queue.size() > 1 ? NGTCP2_WRITE_DATAGRAM_FLAG_MORE : 0;

        ngtcp2_ssize nwrite = ngtcp2_conn_writev_datagram(
            ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf), &accepted, flags, 0, &datav, 1,
            ts);

        if (accepted) {
            size_t dgram_size = dgram.size();
            ctx->echo_queue.pop_front();
            state->bytes_sent.fetch_add(dgram_size, std::memory_order_relaxed);
            state->requests_echoed.fetch_add(1, std::memory_order_relaxed);
        }

        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            continue;
        }
        if (nwrite < 0 || nwrite == 0) break;

        sendto(ctx->state->sock, reinterpret_cast<const char*>(buf), static_cast<int>(nwrite), 0,
               reinterpret_cast<sockaddr*>(&ctx->remote_addr), ctx->remote_addrlen);
    }

    // Flush remaining protocol packets (ACKs, etc.).
    for (;;) {
        ngtcp2_ssize nwrite =
            ngtcp2_conn_write_pkt(ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf), ts);
        if (nwrite <= 0) break;
        sendto(ctx->state->sock, reinterpret_cast<const char*>(buf), static_cast<int>(nwrite), 0,
               reinterpret_cast<sockaddr*>(&ctx->remote_addr), ctx->remote_addrlen);
    }
}

static void server_remove_connection(server_state* state, server_conn_context* ctx) {
    // Remove all CIDs for this connection from the lookup map.
    for (auto it = state->cid_map.begin(); it != state->cid_map.end();) {
        if (it->second == ctx) {
            it = state->cid_map.erase(it);
        } else {
            ++it;
        }
    }
    state->active_connections.fetch_sub(1, std::memory_order_relaxed);
    state->connections.erase(ctx);
}

static server_conn_context* server_create_connection(server_state* state, const ngtcp2_pkt_hd& hd,
                                                     const ngtcp2_path& path) {
    auto ctx = std::make_unique<server_conn_context>();
    ctx->state = state;
    ctx->conn_ref.get_conn = server_get_conn;
    ctx->conn_ref.user_data = ctx.get();
    std::memcpy(&ctx->remote_addr, path.remote.addr, path.remote.addrlen);
    ctx->remote_addrlen = static_cast<int>(path.remote.addrlen);

    // Create SSL for this connection.
    ctx->ssl.reset(SSL_new(state->ssl_ctx));
    if (!ctx->ssl) {
        if (state->verbose) std::cerr << "[ngtcp2-server] SSL_new failed\n";
        return nullptr;
    }
    SSL_set_app_data(ctx->ssl.get(), &ctx->conn_ref);
    SSL_set_accept_state(ctx->ssl.get());
    SSL_set_quic_early_data_enabled(ctx->ssl.get(), 0);

    // Build callbacks.
    ngtcp2_callbacks callbacks = make_base_callbacks();
    callbacks.recv_datagram = server_recv_datagram_cb;
    callbacks.get_new_connection_id = server_get_new_cid_cb;

    // Settings.
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    // Transport params.
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_data = 10 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_streams_bidi = 128;
    params.initial_max_streams_uni = 128;
    params.max_datagram_frame_size = 65535;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    // Generate server SCID.
    ngtcp2_cid scid;
    generate_cid(&scid, SERVER_CID_LEN);

    ngtcp2_conn* conn_raw = nullptr;
    int rv = ngtcp2_conn_server_new(&conn_raw, &hd.dcid, &scid, &path, hd.version, &callbacks,
                                    &settings, &params, nullptr, &ctx->conn_ref);
    if (rv != 0) {
        if (state->verbose) {
            std::cerr << "[ngtcp2-server] ngtcp2_conn_server_new failed: " << ngtcp2_strerror(rv)
                      << "\n";
        }
        return nullptr;
    }
    ctx->conn.reset(conn_raw);
    ngtcp2_conn_set_tls_native_handle(ctx->conn.get(), ctx->ssl.get());

    // Register the SCID in the CID map.
    state->cid_map[cid_to_key(&scid)] = ctx.get();

    state->active_connections.fetch_add(1, std::memory_order_relaxed);

    auto* raw_ptr = ctx.get();
    state->connections[raw_ptr] = std::move(ctx);
    return raw_ptr;
}

// ============================================================================
// CLIENT
// ============================================================================

struct client_state {
    bool verbose{false};
    std::atomic<uint64_t> requests_sent{0};
    std::atomic<uint64_t> requests_completed{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> errors{0};
    latency_accumulator latency;
};

struct client_conn_context {
    ngtcp2_crypto_conn_ref conn_ref{};
    ngtcp2_conn_ptr conn;
    ssl_ptr ssl;
    client_state* state{nullptr};
    uint32_t max_outstanding{1};

    // Pending requests: sequence → send_timestamp_ns.
    // Single-threaded per worker, no mutex needed.
    std::unordered_map<uint64_t, uint64_t> pending_requests;
};

static ngtcp2_conn* client_get_conn(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<client_conn_context*>(ref->user_data)->conn.get();
}

// Client recv_datagram: match sequence, compute latency.
static int client_recv_datagram_cb(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t datalen,
                                   void* user_data) {
    auto* ref = static_cast<ngtcp2_crypto_conn_ref*>(user_data);
    auto* ctx = static_cast<client_conn_context*>(ref->user_data);
    ctx->state->bytes_received.fetch_add(datalen, std::memory_order_relaxed);

    uint64_t sequence = 0;
    if (datalen >= sizeof(uint64_t)) {
        std::memcpy(&sequence, data, sizeof(uint64_t));
    }

    const uint64_t recv_ts = now_ns();
    auto it = ctx->pending_requests.find(sequence);
    if (it != ctx->pending_requests.end()) {
        ctx->state->latency.add_sample(recv_ts - it->second);
        ctx->state->requests_completed.fetch_add(1, std::memory_order_relaxed);
        ctx->pending_requests.erase(it);
    }
    return 0;
}

// Client get_new_connection_id: generate random CID and token.
static int client_get_new_cid_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                                 void*) {
    cid->datalen = cidlen;
    RAND_bytes(cid->data, static_cast<int>(cidlen));
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

// Flush protocol packets (ACKs, etc.) for a client connection.
static void client_flush_output(ngtcp2_conn* conn, SOCKET sock, const sockaddr* dest,
                                int destlen) {
    uint8_t buf[MAX_UDP_PAYLOAD];
    ngtcp2_tstamp ts = now_ns();
    for (;;) {
        ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(conn, nullptr, nullptr, buf, sizeof(buf), ts);
        if (nwrite <= 0) break;
        sendto(sock, reinterpret_cast<const char*>(buf), static_cast<int>(nwrite), 0, dest,
               destlen);
    }
}

// ---------------------------------------------------------------------------
// ngtcp2_backend class
// ---------------------------------------------------------------------------
class ngtcp2_backend final : public quic_backend {
  public:
    std::string_view name() const override { return "ngtcp2"; }

    int run_server(const server_options& options,
                   const std::atomic<bool>& shutdown_requested) override {
        try {
            winsock_scope winsock;

            if (options.cert_file.empty() || options.key_file.empty()) {
                throw std::runtime_error(
                    "ngtcp2 backend requires --cert-file and --key-file (PEM format).");
            }

            // Create SSL_CTX.
            ssl_ctx_ptr ssl_ctx(SSL_CTX_new(TLS_server_method()));
            if (!ssl_ctx) {
                throw std::runtime_error("SSL_CTX_new failed");
            }
            if (ngtcp2_crypto_quictls_configure_server_context(ssl_ctx.get()) != 0) {
                throw std::runtime_error("ngtcp2_crypto_quictls_configure_server_context failed");
            }
            if (SSL_CTX_use_certificate_chain_file(ssl_ctx.get(), options.cert_file.c_str()) != 1) {
                throw std::runtime_error("Failed to load certificate: " + options.cert_file);
            }
            if (SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), options.key_file.c_str(),
                                            SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error("Failed to load private key: " + options.key_file);
            }
            std::string alpn = options.alpn;
            SSL_CTX_set_alpn_select_cb(ssl_ctx.get(), server_alpn_select_cb, &alpn);

            // Create and bind UDP socket.
            udp_socket sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
            if (!sock.valid()) {
                throw std::runtime_error("socket() failed: " + std::to_string(WSAGetLastError()));
            }

            sockaddr_in local_addr{};
            local_addr.sin_family = AF_INET;
            local_addr.sin_addr.s_addr = INADDR_ANY;
            local_addr.sin_port = htons(options.port);
            if (bind(sock.get(), reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) ==
                SOCKET_ERROR) {
                throw std::runtime_error("bind() failed: " + std::to_string(WSAGetLastError()));
            }

            server_state state{};
            state.verbose = options.verbose;
            state.alpn = options.alpn;
            state.ssl_ctx = ssl_ctx.get();
            state.sock = sock.get();
            state.local_addr = local_addr;

            std::cout << "Server backend: ngtcp2\n" << std::flush;
            std::cout << "Listening on UDP port " << options.port << " with ALPN '" << options.alpn
                      << "'\n"
                      << std::flush;

            const auto start = steady_clock::now();
            uint64_t previous = 0;
            auto last_report = start;
            uint8_t recv_buf[MAX_UDP_PAYLOAD];

            while (!shutdown_requested.load(std::memory_order_relaxed)) {
                if (options.duration_seconds > 0) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                       steady_clock::now() - start)
                                       .count();
                    if (elapsed >= static_cast<int64_t>(options.duration_seconds)) break;
                }

                // Find minimum expiry across all connections for select timeout.
                ngtcp2_tstamp next_expiry = UINT64_MAX;
                for (auto& [ptr, conn_ctx] : state.connections) {
                    ngtcp2_tstamp exp = ngtcp2_conn_get_expiry(conn_ctx->conn.get());
                    if (exp < next_expiry) next_expiry = exp;
                }

                int timeout_ms = 100;
                ngtcp2_tstamp ts_now = now_ns();
                if (next_expiry != UINT64_MAX && next_expiry > ts_now) {
                    timeout_ms =
                        std::min<int>(static_cast<int>((next_expiry - ts_now) / 1'000'000), 100);
                    timeout_ms = std::max(timeout_ms, 1);
                } else if (next_expiry != UINT64_MAX) {
                    timeout_ms = 0;
                }

                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(sock.get(), &rfds);
                timeval tv;
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                int sel = select(0, &rfds, nullptr, nullptr, &tv);

                if (sel > 0 && FD_ISSET(sock.get(), &rfds)) {
                    sockaddr_storage remote{};
                    int remote_len = sizeof(remote);
                    int bytes = recvfrom(sock.get(), reinterpret_cast<char*>(recv_buf),
                                         sizeof(recv_buf), 0,
                                         reinterpret_cast<sockaddr*>(&remote), &remote_len);
                    if (bytes > 0) {
                        // Decode version and CIDs from the packet.
                        uint32_t version = 0;
                        const uint8_t* dcid_data = nullptr;
                        size_t dcidlen = 0;
                        const uint8_t* scid_data = nullptr;
                        size_t scidlen = 0;
                        int rv = ngtcp2_pkt_decode_version_cid(
                            &version, &dcid_data, &dcidlen, &scid_data, &scidlen, recv_buf,
                            static_cast<size_t>(bytes), SERVER_CID_LEN);

                        server_conn_context* conn_ctx = nullptr;

                        if (rv == 0 || rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
                            auto it = state.cid_map.find(cid_to_key(dcid_data, dcidlen));
                            if (it != state.cid_map.end()) {
                                conn_ctx = it->second;
                            }
                        }

                        if (!conn_ctx) {
                            // Check if this is a valid Initial packet.
                            ngtcp2_pkt_hd hd{};
                            rv = ngtcp2_accept(&hd, recv_buf, static_cast<size_t>(bytes));
                            if (rv == 0) {
                                ngtcp2_path path{};
                                path.local.addr =
                                    reinterpret_cast<ngtcp2_sockaddr*>(&state.local_addr);
                                path.local.addrlen = sizeof(state.local_addr);
                                path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote);
                                path.remote.addrlen = remote_len;
                                conn_ctx = server_create_connection(&state, hd, path);
                                if (state.verbose && conn_ctx) {
                                    std::cerr << "[ngtcp2-server] new connection accepted\n";
                                }
                            }
                        }

                        if (conn_ctx) {
                            // Update remote address (in case of NAT rebinding).
                            std::memcpy(&conn_ctx->remote_addr, &remote, remote_len);
                            conn_ctx->remote_addrlen = remote_len;

                            ngtcp2_path path{};
                            path.local.addr =
                                reinterpret_cast<ngtcp2_sockaddr*>(&state.local_addr);
                            path.local.addrlen = sizeof(state.local_addr);
                            path.remote.addr =
                                reinterpret_cast<ngtcp2_sockaddr*>(&conn_ctx->remote_addr);
                            path.remote.addrlen = conn_ctx->remote_addrlen;
                            ngtcp2_pkt_info pi{};

                            rv = ngtcp2_conn_read_pkt(conn_ctx->conn.get(), &path, &pi, recv_buf,
                                                      static_cast<size_t>(bytes), now_ns());
                            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                                if (state.verbose) {
                                    std::cerr << "[ngtcp2-server] connection draining/closing\n";
                                }
                                server_remove_connection(&state, conn_ctx);
                            } else if (rv != 0) {
                                if (state.verbose) {
                                    std::cerr << "[ngtcp2-server] read_pkt error: "
                                              << ngtcp2_strerror(rv) << "\n";
                                }
                                // Send CONNECTION_CLOSE.
                                uint8_t close_buf[MAX_UDP_PAYLOAD];
                                ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
                                    conn_ctx->conn.get(), nullptr, nullptr, close_buf,
                                    sizeof(close_buf),
                                    ngtcp2_err_infer_quic_transport_error_code(rv), nullptr, 0,
                                    now_ns());
                                if (nwrite > 0) {
                                    sendto(sock.get(), reinterpret_cast<const char*>(close_buf),
                                           static_cast<int>(nwrite), 0,
                                           reinterpret_cast<sockaddr*>(&conn_ctx->remote_addr),
                                           conn_ctx->remote_addrlen);
                                }
                                server_remove_connection(&state, conn_ctx);
                            } else {
                                server_flush_output(conn_ctx);
                            }
                        }
                    }
                }

                // Handle expired timers for all connections.
                ts_now = now_ns();
                std::vector<server_conn_context*> to_remove;
                for (auto& [ptr, conn_ctx] : state.connections) {
                    if (ts_now >= ngtcp2_conn_get_expiry(conn_ctx->conn.get())) {
                        int rv = ngtcp2_conn_handle_expiry(conn_ctx->conn.get(), ts_now);
                        if (rv != 0) {
                            if (state.verbose) {
                                std::cerr << "[ngtcp2-server] handle_expiry error: "
                                          << ngtcp2_strerror(rv) << "\n";
                            }
                            to_remove.push_back(ptr);
                            continue;
                        }
                        server_flush_output(conn_ctx.get());
                    }
                }
                for (auto* ptr : to_remove) {
                    server_remove_connection(&state, ptr);
                }

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

            // Graceful shutdown: close all connections.
            for (auto& [ptr, conn_ctx] : state.connections) {
                uint8_t close_buf[MAX_UDP_PAYLOAD];
                ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
                    conn_ctx->conn.get(), nullptr, nullptr, close_buf, sizeof(close_buf),
                    NGTCP2_NO_ERROR, nullptr, 0, now_ns());
                if (nwrite > 0) {
                    sendto(sock.get(), reinterpret_cast<const char*>(close_buf),
                           static_cast<int>(nwrite), 0,
                           reinterpret_cast<sockaddr*>(&conn_ctx->remote_addr),
                           conn_ctx->remote_addrlen);
                }
            }
            state.cid_map.clear();
            state.connections.clear();

            std::cout << "Final echoed requests: "
                      << state.requests_echoed.load(std::memory_order_relaxed) << "\n";
            return 0;
        } catch (const std::exception& ex) {
            std::cerr << "ngtcp2 server error: " << ex.what() << "\n";
            return 1;
        }
    }

    client_run_summary run_client(const client_options& options) override {
        client_run_summary summary{};
        try {
            winsock_scope winsock;

            // Create SSL_CTX for client.
            ssl_ctx_ptr ssl_ctx(SSL_CTX_new(TLS_client_method()));
            if (!ssl_ctx) {
                throw std::runtime_error("SSL_CTX_new failed");
            }
            if (ngtcp2_crypto_quictls_configure_client_context(ssl_ctx.get()) != 0) {
                throw std::runtime_error("ngtcp2_crypto_quictls_configure_client_context failed");
            }
            if (options.insecure) {
                SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
            } else {
                SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);
                SSL_CTX_set_default_verify_paths(ssl_ctx.get());
            }

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
                        // Create UDP socket.
                        udp_socket sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
                        if (!sock.valid()) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Bind to ephemeral port for local address.
                        sockaddr_in local_addr{};
                        local_addr.sin_family = AF_INET;
                        local_addr.sin_addr.s_addr = INADDR_ANY;
                        local_addr.sin_port = 0;
                        if (bind(sock.get(), reinterpret_cast<sockaddr*>(&local_addr),
                                 sizeof(local_addr)) == SOCKET_ERROR) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Get actual local address after bind.
                        int local_len = sizeof(local_addr);
                        getsockname(sock.get(), reinterpret_cast<sockaddr*>(&local_addr),
                                    &local_len);

                        // Create SSL for this connection.
                        ssl_ptr ssl(SSL_new(ssl_ctx.get()));
                        if (!ssl) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        auto ctx = std::make_unique<client_conn_context>();
                        ctx->state = &state;
                        ctx->max_outstanding = options.outstanding;
                        ctx->conn_ref.get_conn = client_get_conn;
                        ctx->conn_ref.user_data = ctx.get();

                        SSL_set_app_data(ssl.get(), &ctx->conn_ref);
                        SSL_set_connect_state(ssl.get());

                        // Set ALPN.
                        if (options.alpn.size() > 255) {
                            throw std::runtime_error("ALPN string exceeds 255 bytes");
                        }
                        std::vector<uint8_t> alpn_wire;
                        alpn_wire.push_back(static_cast<uint8_t>(options.alpn.size()));
                        alpn_wire.insert(alpn_wire.end(), options.alpn.begin(), options.alpn.end());
                        if (SSL_set_alpn_protos(ssl.get(), alpn_wire.data(),
                                                static_cast<unsigned int>(alpn_wire.size())) != 0) {
                            throw std::runtime_error("SSL_set_alpn_protos failed");
                        }

                        // Set SNI (required for TLS).
                        SSL_set_tlsext_host_name(ssl.get(), options.server.c_str());

                        // Build ngtcp2 path.
                        ngtcp2_path path{};
                        path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_addr);
                        path.local.addrlen = sizeof(local_addr);
                        path.remote.addr =
                            reinterpret_cast<ngtcp2_sockaddr*>(
                                const_cast<sockaddr_in*>(&server_addr));
                        path.remote.addrlen = sizeof(server_addr);

                        // Build callbacks.
                        ngtcp2_callbacks callbacks = make_base_callbacks();
                        callbacks.recv_datagram = client_recv_datagram_cb;
                        callbacks.get_new_connection_id = client_get_new_cid_cb;

                        // Settings.
                        ngtcp2_settings settings;
                        ngtcp2_settings_default(&settings);
                        settings.initial_ts = now_ns();

                        // Transport params.
                        ngtcp2_transport_params params;
                        ngtcp2_transport_params_default(&params);
                        params.initial_max_data = 10 * 1024 * 1024;
                        params.initial_max_stream_data_bidi_local = 256 * 1024;
                        params.initial_max_stream_data_bidi_remote = 256 * 1024;
                        params.initial_max_stream_data_uni = 256 * 1024;
                        params.initial_max_streams_bidi = 128;
                        params.initial_max_streams_uni = 128;
                        params.max_datagram_frame_size = 65535;

                        // Generate CIDs.
                        ngtcp2_cid dcid, scid;
                        generate_cid(&dcid, SERVER_CID_LEN);
                        generate_cid(&scid, SERVER_CID_LEN);

                        ngtcp2_conn* conn_raw = nullptr;
                        int rv = ngtcp2_conn_client_new(&conn_raw, &dcid, &scid, &path,
                                                        NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                                        &params, nullptr, &ctx->conn_ref);
                        if (rv != 0) {
                            if (state.verbose) {
                                std::cerr << "[ngtcp2-client] conn_client_new failed: "
                                          << ngtcp2_strerror(rv) << "\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }
                        ctx->conn.reset(conn_raw);
                        ctx->ssl = std::move(ssl);
                        ngtcp2_conn_set_tls_native_handle(ctx->conn.get(), ctx->ssl.get());

                        uint8_t buf[MAX_UDP_PAYLOAD];
                        uint8_t recv_buf[MAX_UDP_PAYLOAD];

                        // Handshake: write initial packets.
                        {
                            ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                                ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf), now_ns());
                            if (nwrite > 0) {
                                sendto(sock.get(), reinterpret_cast<const char*>(buf),
                                       static_cast<int>(nwrite), 0,
                                       reinterpret_cast<const sockaddr*>(&server_addr),
                                       sizeof(server_addr));
                            }
                        }

                        // Handshake loop.
                        bool handshake_done = false;
                        auto handshake_deadline =
                            steady_clock::now() + std::chrono::seconds(5);
                        while (!handshake_done && steady_clock::now() < handshake_deadline &&
                               !stop_signal.load(std::memory_order_relaxed)) {
                            fd_set rfds;
                            FD_ZERO(&rfds);
                            FD_SET(sock.get(), &rfds);

                            ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(ctx->conn.get());
                            ngtcp2_tstamp ts_now = now_ns();
                            int timeout_ms = 100;
                            if (expiry != UINT64_MAX && expiry > ts_now) {
                                timeout_ms = std::min<int>(
                                    static_cast<int>((expiry - ts_now) / 1'000'000), 100);
                                timeout_ms = std::max(timeout_ms, 1);
                            }

                            timeval tv;
                            tv.tv_sec = timeout_ms / 1000;
                            tv.tv_usec = (timeout_ms % 1000) * 1000;
                            int sel = select(0, &rfds, nullptr, nullptr, &tv);

                            if (sel > 0) {
                                sockaddr_storage from{};
                                int from_len = sizeof(from);
                                int bytes =
                                    recvfrom(sock.get(), reinterpret_cast<char*>(recv_buf),
                                             sizeof(recv_buf), 0,
                                             reinterpret_cast<sockaddr*>(&from), &from_len);
                                if (bytes > 0) {
                                    ngtcp2_path rpath{};
                                    rpath.local.addr =
                                        reinterpret_cast<ngtcp2_sockaddr*>(&local_addr);
                                    rpath.local.addrlen = sizeof(local_addr);
                                    rpath.remote.addr =
                                        reinterpret_cast<ngtcp2_sockaddr*>(&from);
                                    rpath.remote.addrlen = from_len;
                                    ngtcp2_pkt_info pi{};

                                    rv = ngtcp2_conn_read_pkt(ctx->conn.get(), &rpath, &pi,
                                                              recv_buf,
                                                              static_cast<size_t>(bytes),
                                                              now_ns());
                                    if (rv != 0 && rv != NGTCP2_ERR_DRAINING) {
                                        if (state.verbose) {
                                            std::cerr
                                                << "[ngtcp2-client] handshake read_pkt error: "
                                                << ngtcp2_strerror(rv) << "\n";
                                        }
                                        state.errors.fetch_add(1, std::memory_order_relaxed);
                                        return;
                                    }
                                }
                            }

                            // Handle timer expiry.
                            ts_now = now_ns();
                            if (ts_now >= ngtcp2_conn_get_expiry(ctx->conn.get())) {
                                rv = ngtcp2_conn_handle_expiry(ctx->conn.get(), ts_now);
                                if (rv != 0) {
                                    state.errors.fetch_add(1, std::memory_order_relaxed);
                                    return;
                                }
                            }

                            // Write handshake response packets.
                            for (;;) {
                                ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                                    ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf),
                                    now_ns());
                                if (nwrite <= 0) break;
                                sendto(sock.get(), reinterpret_cast<const char*>(buf),
                                       static_cast<int>(nwrite), 0,
                                       reinterpret_cast<const sockaddr*>(&server_addr),
                                       sizeof(server_addr));
                            }

                            handshake_done = ngtcp2_conn_get_handshake_completed(ctx->conn.get());
                        }

                        if (!handshake_done) {
                            if (state.verbose) {
                                std::cerr << "[ngtcp2-client] handshake timeout\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        // Check datagram support.
                        const ngtcp2_transport_params* remote_params =
                            ngtcp2_conn_get_remote_transport_params(ctx->conn.get());
                        if (!remote_params || remote_params->max_datagram_frame_size == 0) {
                            if (state.verbose) {
                                std::cerr
                                    << "[ngtcp2-client] server does not support datagrams\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        connected_workers.fetch_add(1, std::memory_order_release);

                        // Benchmark loop.
                        uint64_t sequence = static_cast<uint64_t>(worker_idx) << 40;
                        const uint32_t payload_size =
                            std::max<uint32_t>(16, options.payload_size);

                        while (!stop_signal.load(std::memory_order_acquire)) {
                            // Send datagrams while under max_outstanding.
                            while (ctx->pending_requests.size() < ctx->max_outstanding &&
                                   !stop_signal.load(std::memory_order_relaxed)) {
                                const uint64_t request_sequence = ++sequence;
                                std::vector<uint8_t> payload(payload_size);
                                fill_payload(payload, request_sequence);

                                ngtcp2_vec datav;
                                datav.base = payload.data();
                                datav.len = payload.size();
                                int accepted = 0;

                                ngtcp2_ssize nwrite = ngtcp2_conn_writev_datagram(
                                    ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf),
                                    &accepted, 0, 0, &datav, 1, now_ns());

                                if (nwrite < 0 && nwrite != NGTCP2_ERR_WRITE_MORE) {
                                    if (state.verbose) {
                                        std::cerr << "[ngtcp2-client] writev_datagram error: "
                                                  << ngtcp2_strerror(static_cast<int>(nwrite))
                                                  << "\n";
                                    }
                                    break;
                                }

                                if (accepted) {
                                    const uint64_t send_ts = now_ns();
                                    ctx->pending_requests[request_sequence] = send_ts;
                                    state.requests_sent.fetch_add(1, std::memory_order_relaxed);
                                    state.bytes_sent.fetch_add(payload.size(),
                                                              std::memory_order_relaxed);
                                }

                                if (nwrite > 0) {
                                    sendto(sock.get(), reinterpret_cast<const char*>(buf),
                                           static_cast<int>(nwrite), 0,
                                           reinterpret_cast<const sockaddr*>(&server_addr),
                                           sizeof(server_addr));
                                }

                                if (nwrite == 0 && !accepted) break;  // Congestion.
                            }

                            // Receive with short timeout.
                            fd_set rfds;
                            FD_ZERO(&rfds);
                            FD_SET(sock.get(), &rfds);
                            timeval tv;
                            tv.tv_sec = 0;
                            tv.tv_usec = 1000;  // 1 ms
                            int sel = select(0, &rfds, nullptr, nullptr, &tv);

                            if (sel > 0) {
                                for (;;) {
                                    sockaddr_storage from{};
                                    int from_len = sizeof(from);
                                    int bytes = recvfrom(
                                        sock.get(), reinterpret_cast<char*>(recv_buf),
                                        sizeof(recv_buf), 0,
                                        reinterpret_cast<sockaddr*>(&from), &from_len);
                                    if (bytes <= 0) break;

                                    ngtcp2_path rpath{};
                                    rpath.local.addr =
                                        reinterpret_cast<ngtcp2_sockaddr*>(&local_addr);
                                    rpath.local.addrlen = sizeof(local_addr);
                                    rpath.remote.addr =
                                        reinterpret_cast<ngtcp2_sockaddr*>(&from);
                                    rpath.remote.addrlen = from_len;
                                    ngtcp2_pkt_info pi{};

                                    rv = ngtcp2_conn_read_pkt(ctx->conn.get(), &rpath, &pi,
                                                              recv_buf,
                                                              static_cast<size_t>(bytes),
                                                              now_ns());
                                    if (rv != 0) {
                                        if (state.verbose) {
                                            std::cerr << "[ngtcp2-client] read_pkt error: "
                                                      << ngtcp2_strerror(rv) << "\n";
                                        }
                                        break;
                                    }

                                    // Check if more data is available (non-blocking peek).
                                    u_long avail = 0;
                                    ioctlsocket(sock.get(), FIONREAD, &avail);
                                    if (avail == 0) break;
                                }
                            }

                            // Handle timer expiry.
                            ngtcp2_tstamp ts_now = now_ns();
                            if (ts_now >= ngtcp2_conn_get_expiry(ctx->conn.get())) {
                                rv = ngtcp2_conn_handle_expiry(ctx->conn.get(), ts_now);
                                if (rv != 0 && state.verbose) {
                                    std::cerr << "[ngtcp2-client] handle_expiry error: "
                                              << ngtcp2_strerror(rv) << "\n";
                                }
                            }

                            // Flush protocol packets.
                            client_flush_output(ctx->conn.get(), sock.get(),
                                                reinterpret_cast<const sockaddr*>(&server_addr),
                                                sizeof(server_addr));

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
                        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
                            ctx->conn.get(), nullptr, nullptr, buf, sizeof(buf),
                            NGTCP2_NO_ERROR, nullptr, 0, now_ns());
                        if (nwrite > 0) {
                            sendto(sock.get(), reinterpret_cast<const char*>(buf),
                                   static_cast<int>(nwrite), 0,
                                   reinterpret_cast<const sockaddr*>(&server_addr),
                                   sizeof(server_addr));
                        }
                    } catch (const std::exception& ex) {
                        if (state.verbose) {
                            std::cerr << "[ngtcp2-client] worker " << worker_idx
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
                std::cerr << "[ngtcp2-client] No workers connected after 10s – aborting.\n";
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
                    out << "  \"backend\": \"ngtcp2\",\n";
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
            std::cerr << "ngtcp2 client error: " << ex.what() << "\n";
            return summary;
        }
    }
};

}  // namespace

void register_ngtcp2_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        register_backend("ngtcp2", "ngtcp2 + quictls backend (datagram echo)", []() {
            return std::make_unique<ngtcp2_backend>();
        });
    });
}

}  // namespace winquicecho
