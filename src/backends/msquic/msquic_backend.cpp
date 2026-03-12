// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#include "backends/msquic/msquic_backend.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <msquic.h>

#include "common/metrics.hpp"
#include "common/quic_factory.hpp"

namespace winquicecho {
namespace {

using steady_clock = std::chrono::steady_clock;

uint64_t now_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(steady_clock::now().time_since_epoch())
            .count());
}

std::string status_to_string(QUIC_STATUS status) {
    std::ostringstream stream;
    stream << "0x" << std::hex << static_cast<unsigned long>(status);
    return stream.str();
}

void throw_on_failure(QUIC_STATUS status, const std::string& message) {
    if (QUIC_FAILED(status)) {
        throw std::runtime_error(message + " (status=" + status_to_string(status) + ")");
    }
}

bool is_datagram_send_state_final(QUIC_DATAGRAM_SEND_STATE state) {
    return state >= QUIC_DATAGRAM_SEND_LOST_DISCARDED;
}

bool parse_sha1_hex(std::string text, QUIC_CERTIFICATE_HASH& hash) {
    text.erase(std::remove_if(text.begin(), text.end(),
                              [](unsigned char c) { return std::isspace(c) || c == ':'; }),
               text.end());
    if (text.size() != 40) {
        return false;
    }

    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    for (size_t i = 0; i < 20; ++i) {
        const int high = hex_value(text[2 * i]);
        const int low = hex_value(text[2 * i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        hash.ShaHash[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

class msquic_library {
  public:
    msquic_library() {
        QUIC_STATUS status = MsQuicOpen2(&api_);
        throw_on_failure(status, "MsQuicOpen2 failed");
    }

    ~msquic_library() {
        if (api_ != nullptr) {
            MsQuicClose(api_);
        }
    }

    msquic_library(const msquic_library&) = delete;
    msquic_library& operator=(const msquic_library&) = delete;

    const QUIC_API_TABLE* api() const { return api_; }

  private:
    const QUIC_API_TABLE* api_{nullptr};
};

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

struct datagram_send_context {
    std::vector<uint8_t> payload;
    QUIC_BUFFER quic_buffer;  // Must outlive DatagramSend (MsQuic stores the pointer).

    void init_buffer() {
        quic_buffer.Length = static_cast<uint32_t>(payload.size());
        quic_buffer.Buffer = payload.empty() ? nullptr : payload.data();
    }
};

// RAII wrapper for HQUIC handles.  Calls the supplied close function on
// destruction, preventing leaks when an exception is thrown mid-setup.
class quic_handle {
  public:
    using close_fn_t = void(QUIC_API*)(HQUIC);

    quic_handle() = default;
    quic_handle(HQUIC h, close_fn_t fn) : handle_(h), close_fn_(fn) {}
    ~quic_handle() { reset(); }

    quic_handle(const quic_handle&) = delete;
    quic_handle& operator=(const quic_handle&) = delete;
    quic_handle(quic_handle&& other) noexcept : handle_(other.handle_), close_fn_(other.close_fn_) {
        other.handle_ = nullptr;
    }
    quic_handle& operator=(quic_handle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            close_fn_ = other.close_fn_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    HQUIC get() const { return handle_; }
    void reset() {
        if (handle_) {
            close_fn_(handle_);
            handle_ = nullptr;
        }
    }

  private:
    HQUIC handle_{nullptr};
    close_fn_t close_fn_{nullptr};
};

struct server_state {
    const QUIC_API_TABLE* api{nullptr};
    HQUIC configuration{nullptr};
    bool verbose{false};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> requests_echoed{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::mutex connection_mutex;
    std::unordered_set<HQUIC> live_connections;
};

struct server_connection_context {
    server_state* state{nullptr};
    HQUIC connection{nullptr};
};

QUIC_STATUS QUIC_API server_connection_callback(HQUIC connection, void* context,
                                                QUIC_CONNECTION_EVENT* event) {
    auto* connection_ctx = reinterpret_cast<server_connection_context*>(context);
    server_state* state = connection_ctx->state;

    switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            if (state->verbose) {
                std::cerr << "[server] connection established\n";
            }
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
            const QUIC_BUFFER* received = event->DATAGRAM_RECEIVED.Buffer;
            if (received == nullptr) {
                if (state->verbose) {
                    std::cerr << "[server] datagram received with null buffer\n";
                }
                return QUIC_STATUS_SUCCESS;
            }

            if (state->verbose) {
                std::cerr << "[server] datagram received bytes=" << received->Length << "\n";
            }

            // TODO: consider a pool allocator for datagram_send_context to reduce
            // per-datagram heap allocation overhead in the hot path.
            auto* send_ctx = new datagram_send_context();
            send_ctx->payload.resize(received->Length);
            if (received->Length > 0) {
                std::memcpy(send_ctx->payload.data(), received->Buffer, received->Length);
            }
            send_ctx->init_buffer();

            QUIC_STATUS status = state->api->DatagramSend(
                connection, &send_ctx->quic_buffer, 1, QUIC_SEND_FLAG_NONE, send_ctx);
            if (QUIC_FAILED(status)) {
                if (state->verbose) {
                    std::cerr << "[server] DatagramSend failed: " << status_to_string(status) << "\n";
                }
                delete send_ctx;
                return QUIC_STATUS_SUCCESS;
            }

            // NOTE: bytes_sent/requests_echoed are incremented after DatagramSend
            // is queued, not after the send completes asynchronously.  For a
            // benchmark with unreliable datagrams this is acceptable — lost
            // sends are expected and counted as "sent" for throughput stats.
            state->bytes_received.fetch_add(received->Length, std::memory_order_relaxed);
            state->bytes_sent.fetch_add(received->Length, std::memory_order_relaxed);
            state->requests_echoed.fetch_add(1, std::memory_order_relaxed);

            if (state->verbose) {
                std::cerr << "[server] datagram echoed bytes=" << received->Length << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
            auto* send_ctx = reinterpret_cast<datagram_send_context*>(
                event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
            if (state->verbose) {
                std::cerr << "[server] datagram send state="
                          << static_cast<int>(event->DATAGRAM_SEND_STATE_CHANGED.State) << "\n";
            }
            if (send_ctx != nullptr &&
                is_datagram_send_state_final(event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                delete send_ctx;
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            if (state->verbose) {
                std::cerr << "[server] connection shutdown complete\n";
            }
            bool should_close = false;
            {
                std::lock_guard<std::mutex> lock(state->connection_mutex);
                should_close = state->live_connections.erase(connection) > 0;
            }
            if (should_close) {
                state->active_connections.fetch_sub(1, std::memory_order_relaxed);
                state->api->ConnectionClose(connection);
            }
            delete connection_ctx;
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            if (state->verbose) {
                std::cerr << "[server] transport shutdown status="
                          << status_to_string(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status)
                          << " errorCode=" << event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            if (state->verbose) {
                std::cerr << "[server] peer shutdown errorCode="
                          << event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        default:
            if (state->verbose) {
                std::cerr << "[server] connection event type="
                          << static_cast<int>(event->Type) << "\n";
            }
            return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API server_listener_callback(HQUIC, void* context, QUIC_LISTENER_EVENT* event) {
    auto* state = reinterpret_cast<server_state*>(context);
    if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        return QUIC_STATUS_SUCCESS;
    }

    auto* connection_ctx = new server_connection_context();
    connection_ctx->state = state;
    connection_ctx->connection = event->NEW_CONNECTION.Connection;

    state->api->SetCallbackHandler(event->NEW_CONNECTION.Connection,
                                   reinterpret_cast<void*>(server_connection_callback),
                                   connection_ctx);

    const QUIC_STATUS set_config_status =
        state->api->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, state->configuration);
    if (QUIC_FAILED(set_config_status)) {
        if (state->verbose) {
            std::cerr << "[server] ConnectionSetConfiguration failed: "
                      << status_to_string(set_config_status) << "\n";
        }
        delete connection_ctx;
        return set_config_status;
    }

    {
        std::lock_guard<std::mutex> lock(state->connection_mutex);
        state->live_connections.insert(event->NEW_CONNECTION.Connection);
    }
    state->active_connections.fetch_add(1, std::memory_order_relaxed);
    return QUIC_STATUS_SUCCESS;
}

struct client_state {
    bool verbose{false};
    std::atomic<uint64_t> requests_sent{0};
    std::atomic<uint64_t> requests_completed{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> errors{0};
    latency_accumulator latency;
};

struct client_connection_context {
    const QUIC_API_TABLE* api{nullptr};
    client_state* state{nullptr};
    uint32_t max_outstanding{1};

    std::mutex mutex;
    std::condition_variable cv;
    bool connected{false};
    bool failed{false};
    bool shutdown_complete{false};
    bool datagram_send_enabled{false};
    uint16_t max_datagram_send_length{0};

    // Maps sequence number → send timestamp (ns) for in-flight requests.
    std::unordered_map<uint64_t, uint64_t> pending_requests;
};

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

QUIC_STATUS QUIC_API client_connection_callback(HQUIC, void* context, QUIC_CONNECTION_EVENT* event) {
    auto* connection_ctx = reinterpret_cast<client_connection_context*>(context);

    switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            std::lock_guard<std::mutex> lock(connection_ctx->mutex);
            connection_ctx->connected = true;
            connection_ctx->cv.notify_one();
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
            {
                std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                connection_ctx->failed = true;
                connection_ctx->cv.notify_one();
            }
            if (connection_ctx->state->verbose) {
                std::cerr << "[client] shutdown by transport status="
                          << status_to_string(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status)
                          << " errorCode="
                          << static_cast<unsigned long long>(
                                 event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode)
                          << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
            {
                std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                connection_ctx->failed = true;
                connection_ctx->cv.notify_one();
            }
            if (connection_ctx->state->verbose) {
                std::cerr << "[client] shutdown by peer errorCode="
                          << static_cast<unsigned long long>(
                                 event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode)
                          << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
            const QUIC_BUFFER* received = event->DATAGRAM_RECEIVED.Buffer;
            if (received == nullptr) {
                return QUIC_STATUS_SUCCESS;
            }

            connection_ctx->state->bytes_received.fetch_add(received->Length, std::memory_order_relaxed);

            uint64_t sequence = 0;
            if (received->Length >= sizeof(uint64_t)) {
                std::memcpy(&sequence, received->Buffer, sizeof(uint64_t));
            }

            const uint64_t recv_ts = now_ns();

            {
                std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                auto it = connection_ctx->pending_requests.find(sequence);
                if (it != connection_ctx->pending_requests.end()) {
                    connection_ctx->state->latency.add_sample(recv_ts - it->second);
                    connection_ctx->state->requests_completed.fetch_add(1, std::memory_order_relaxed);
                    connection_ctx->pending_requests.erase(it);
                    connection_ctx->cv.notify_one();
                }
            }

            if (connection_ctx->state->verbose) {
                std::cout << "[client] datagram received bytes=" << received->Length
                          << " seq=" << sequence << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {
            {
                std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                connection_ctx->datagram_send_enabled =
                    event->DATAGRAM_STATE_CHANGED.SendEnabled != FALSE;
                connection_ctx->max_datagram_send_length =
                    event->DATAGRAM_STATE_CHANGED.MaxSendLength;
            }
            connection_ctx->cv.notify_one();
            if (connection_ctx->state->verbose) {
                std::cout << "[client] datagram state changed sendEnabled="
                          << (event->DATAGRAM_STATE_CHANGED.SendEnabled ? 1 : 0)
                          << " maxLen=" << event->DATAGRAM_STATE_CHANGED.MaxSendLength << "\n";
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
            auto* send_ctx = reinterpret_cast<datagram_send_context*>(
                event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
            if (connection_ctx->state->verbose) {
                std::cout << "[client] datagram send state="
                          << static_cast<int>(event->DATAGRAM_SEND_STATE_CHANGED.State) << "\n";
            }
            if (send_ctx != nullptr &&
                is_datagram_send_state_final(event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                delete send_ctx;
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            std::lock_guard<std::mutex> lock(connection_ctx->mutex);
            connection_ctx->shutdown_complete = true;
            connection_ctx->pending_requests.clear();
            connection_ctx->cv.notify_one();
            return QUIC_STATUS_SUCCESS;
        }
        default:
            return QUIC_STATUS_SUCCESS;
    }
}

class msquic_backend final : public quic_backend {
  public:
    std::string_view name() const override { return "msquic"; }

    int run_server(const server_options& options, const std::atomic<bool>& shutdown_requested) override {
        try {
            winsock_scope winsock;
            msquic_library library;
            const QUIC_API_TABLE* api = library.api();

            // RAII handles — destroyed in reverse order (listener → config → registration).
            quic_handle registration;
            quic_handle configuration;
            quic_handle listener;

            server_state state{};
            state.api = api;
            state.verbose = options.verbose;

            QUIC_REGISTRATION_CONFIG registration_config{};
            registration_config.AppName = "WinQuicEcho.Server";
            registration_config.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
            {
                HQUIC h = nullptr;
                throw_on_failure(api->RegistrationOpen(&registration_config, &h),
                                 "RegistrationOpen failed");
                registration = quic_handle(h, api->RegistrationClose);
            }

            QUIC_BUFFER alpn{};
            alpn.Length = static_cast<uint32_t>(options.alpn.size());
            alpn.Buffer = reinterpret_cast<uint8_t*>(const_cast<char*>(options.alpn.data()));
            QUIC_SETTINGS server_settings{};
            server_settings.PeerBidiStreamCount = 1024;
            server_settings.IsSet.PeerBidiStreamCount = TRUE;
            server_settings.PeerUnidiStreamCount = 1024;
            server_settings.IsSet.PeerUnidiStreamCount = TRUE;
            server_settings.DatagramReceiveEnabled = TRUE;
            server_settings.IsSet.DatagramReceiveEnabled = TRUE;
            {
                HQUIC h = nullptr;
                throw_on_failure(
                    api->ConfigurationOpen(registration.get(), &alpn, 1, &server_settings,
                                           sizeof(server_settings), nullptr, &h),
                    "ConfigurationOpen failed");
                configuration = quic_handle(h, api->ConfigurationClose);
            }
            state.configuration = configuration.get();

            QUIC_CREDENTIAL_CONFIG cred_config{};
            QUIC_CERTIFICATE_HASH cert_hash{};
            QUIC_CERTIFICATE_HASH_STORE hash_store{};
            QUIC_CERTIFICATE_FILE cert_file{};
            QUIC_CERTIFICATE_PKCS12 cert_pfx{};
            std::vector<uint8_t> cert_pfx_blob;
            if (!options.cert_hash.empty()) {
                if (!parse_sha1_hex(options.cert_hash, cert_hash)) {
                    throw std::runtime_error(
                        "Invalid --cert-hash. Expected 40 hex chars (SHA-1 thumbprint).");
                }
                hash_store.Flags = QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;
                std::memcpy(hash_store.ShaHash, cert_hash.ShaHash, sizeof(cert_hash.ShaHash));
                std::strncpy(hash_store.StoreName, options.cert_store.c_str(),
                             sizeof(hash_store.StoreName) - 1);
                hash_store.StoreName[sizeof(hash_store.StoreName) - 1] = '\0';
                cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
                cred_config.CertificateHashStore = &hash_store;
                cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
            } else if (!options.cert_file.empty() && !options.key_file.empty()) {
                cert_file.CertificateFile = options.cert_file.c_str();
                cert_file.PrivateKeyFile = options.key_file.c_str();
                cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
                cred_config.CertificateFile = &cert_file;
                cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
            } else if (!options.cert_pfx_file.empty()) {
                std::ifstream input(options.cert_pfx_file, std::ios::binary);
                if (!input) {
                    throw std::runtime_error("Failed to open --cert-pfx file: " +
                                             options.cert_pfx_file);
                }
                cert_pfx_blob.assign(std::istreambuf_iterator<char>(input),
                                     std::istreambuf_iterator<char>());
                if (cert_pfx_blob.empty()) {
                    throw std::runtime_error("PKCS#12/PFX file is empty: " +
                                             options.cert_pfx_file);
                }
                cert_pfx.Asn1Blob = cert_pfx_blob.data();
                cert_pfx.Asn1BlobLength = static_cast<uint32_t>(cert_pfx_blob.size());
                cert_pfx.PrivateKeyPassword =
                    options.cert_pfx_password.empty() ? nullptr : options.cert_pfx_password.c_str();
                cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
                cred_config.CertificatePkcs12 = &cert_pfx;
                cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
            } else {
                throw std::runtime_error(
                    "Server credentials are required. Provide --cert-hash, --cert-pfx, or --cert-file/--key-file.");
            }
            throw_on_failure(api->ConfigurationLoadCredential(configuration.get(), &cred_config),
                             "ConfigurationLoadCredential failed");

            {
                HQUIC h = nullptr;
                throw_on_failure(api->ListenerOpen(registration.get(), server_listener_callback, &state, &h),
                                 "ListenerOpen failed");
                listener = quic_handle(h, api->ListenerClose);
            }

            QUIC_ADDR local_address{};
            std::memset(&local_address, 0, sizeof(local_address));
            QuicAddrSetFamily(&local_address, QUIC_ADDRESS_FAMILY_INET);
            QuicAddrSetPort(&local_address, options.port);
            throw_on_failure(api->ListenerStart(listener.get(), &alpn, 1, &local_address),
                             "ListenerStart failed");

            if (options.verbose) {
                QUIC_ADDR bound{};
                uint32_t bound_size = sizeof(bound);
                const QUIC_STATUS get_param_status =
                    api->GetParam(listener.get(), QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &bound_size, &bound);
                if (QUIC_SUCCEEDED(get_param_status)) {
                    std::cout << "[server] bound family="
                              << static_cast<int>(bound.si_family)
                              << " port=" << QuicAddrGetPort(&bound) << "\n";
                } else {
                    std::cerr << "[server] failed to query listener address: "
                              << status_to_string(get_param_status) << "\n";
                }
            }

            std::cout << "Server backend: msquic\n" << std::flush;
            std::cout << "Listening on UDP port " << options.port << " with ALPN '" << options.alpn
                      << "'\n" << std::flush;

            const auto start = steady_clock::now();
            uint64_t previous = 0;
            while (!shutdown_requested.load(std::memory_order_relaxed)) {
                if (options.duration_seconds > 0) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                             steady_clock::now() - start)
                                             .count();
                    if (elapsed >= static_cast<int64_t>(options.duration_seconds)) {
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                const uint64_t current = state.requests_echoed.load(std::memory_order_relaxed);
                const uint64_t rps = current - previous;
                previous = current;
                std::cout << "RPS=" << rps
                          << " ActiveConnections="
                          << state.active_connections.load(std::memory_order_relaxed)
                          << " TotalEchoed=" << current << "\n" << std::flush;
            }

            api->ListenerStop(listener.get());
            std::vector<HQUIC> live_connections;
            {
                std::lock_guard<std::mutex> lock(state.connection_mutex);
                live_connections.reserve(state.live_connections.size());
                for (HQUIC connection : state.live_connections) {
                    live_connections.push_back(connection);
                }
            }
            for (HQUIC connection : live_connections) {
                api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            }

            for (int i = 0; i < 200; ++i) {
                if (state.active_connections.load(std::memory_order_relaxed) == 0) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }

            // Force-close any connections that didn't complete shutdown in time.
            // Without this, RAII handle cleanup (RegistrationClose) can block.
            {
                std::vector<HQUIC> orphaned;
                {
                    std::lock_guard<std::mutex> lock(state.connection_mutex);
                    orphaned.assign(state.live_connections.begin(), state.live_connections.end());
                    state.live_connections.clear();
                }
                for (HQUIC connection : orphaned) {
                    api->ConnectionClose(connection);
                }
            }

            // RAII guards close listener, configuration, and registration in
            // reverse order when leaving this scope.

            std::cout << "Final echoed requests: "
                      << state.requests_echoed.load(std::memory_order_relaxed) << "\n";
            return 0;
        } catch (const std::exception& ex) {
            std::cerr << "MsQuic server error: " << ex.what() << "\n";
            return 1;
        }
    }

    client_run_summary run_client(const client_options& options) override {
        client_run_summary summary{};
        try {
            winsock_scope winsock;
            msquic_library library;
            const QUIC_API_TABLE* api = library.api();

            // RAII handles — destroyed in reverse order (config → registration).
            quic_handle registration;
            quic_handle configuration;

            QUIC_REGISTRATION_CONFIG registration_config{};
            registration_config.AppName = "WinQuicEcho.Client";
            registration_config.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
            {
                HQUIC h = nullptr;
                throw_on_failure(api->RegistrationOpen(&registration_config, &h),
                                 "RegistrationOpen failed");
                registration = quic_handle(h, api->RegistrationClose);
            }

            QUIC_BUFFER alpn{};
            alpn.Length = static_cast<uint32_t>(options.alpn.size());
            alpn.Buffer = reinterpret_cast<uint8_t*>(const_cast<char*>(options.alpn.data()));
            QUIC_SETTINGS client_settings{};
            client_settings.DatagramReceiveEnabled = TRUE;
            client_settings.IsSet.DatagramReceiveEnabled = TRUE;
            {
                HQUIC h = nullptr;
                throw_on_failure(
                    api->ConfigurationOpen(registration.get(), &alpn, 1, &client_settings,
                                           sizeof(client_settings), nullptr, &h),
                    "ConfigurationOpen failed");
                configuration = quic_handle(h, api->ConfigurationClose);
            }

            QUIC_CREDENTIAL_CONFIG client_cred{};
            client_cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
            client_cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
            if (options.insecure) {
                client_cred.Flags = static_cast<QUIC_CREDENTIAL_FLAGS>(
                    client_cred.Flags | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
            }
            throw_on_failure(api->ConfigurationLoadCredential(configuration.get(), &client_cred),
                             "ConfigurationLoadCredential failed");

            client_state state{};
            state.verbose = options.verbose;

            const uint32_t worker_count = std::max<uint32_t>(1, options.connections);
            // Workers signal when connected so the monitoring loop can start the
            // benchmark clock after at least one connection is established.
            std::atomic<uint32_t> connected_workers{0};
            std::atomic<bool> stop_signal{false};

            std::vector<std::thread> workers;
            workers.reserve(worker_count);
            for (uint32_t worker = 0; worker < worker_count; ++worker) {
                workers.emplace_back([&, worker]() {
                    auto connection_ctx = std::make_unique<client_connection_context>();
                    connection_ctx->api = api;
                    connection_ctx->state = &state;
                    connection_ctx->max_outstanding = options.outstanding;
                    connection_ctx->pending_requests.reserve(connection_ctx->max_outstanding);

                    HQUIC connection = nullptr;
                    QUIC_STATUS status =
                        api->ConnectionOpen(registration.get(), client_connection_callback,
                                            connection_ctx.get(), &connection);
                    if (QUIC_FAILED(status)) {
                        state.errors.fetch_add(1, std::memory_order_relaxed);
                        return;
                    }

                    status = api->ConnectionStart(connection, configuration.get(), QUIC_ADDRESS_FAMILY_INET,
                                                  options.server.c_str(), options.port);
                    if (QUIC_FAILED(status)) {
                        if (state.verbose) {
                            std::cerr << "[client] ConnectionStart failed: " << status_to_string(status)
                                      << "\n";
                        }
                        state.errors.fetch_add(1, std::memory_order_relaxed);
                        api->ConnectionClose(connection);
                        return;
                    }

                    {
                        std::unique_lock<std::mutex> lock(connection_ctx->mutex);
                        if (!connection_ctx->cv.wait_for(lock, std::chrono::seconds(5),
                                                         [&] {
                                                             return connection_ctx->connected ||
                                                                    connection_ctx->failed;
                                                         })) {
                            if (state.verbose) {
                                std::cerr << "[client] connection timeout waiting for CONNECTED event\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 1);
                            api->ConnectionClose(connection);
                            return;
                        }
                        if (connection_ctx->failed) {
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            api->ConnectionClose(connection);
                            return;
                        }
                        if (!connection_ctx->cv.wait_for(
                                lock, std::chrono::seconds(5),
                                [&] { return connection_ctx->datagram_send_enabled; })) {
                            if (state.verbose) {
                                std::cerr << "[client] timeout waiting for datagram send to be enabled\n";
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 1);
                            api->ConnectionClose(connection);
                            return;
                        }
                    }

                    connected_workers.fetch_add(1, std::memory_order_release);

                    // Each worker gets a unique 24-bit keyspace (worker << 40),
                    // giving each worker up to 2^40 (~1 trillion) sequence numbers
                    // before collision with another worker's range.
                    uint64_t sequence = static_cast<uint64_t>(worker) << 40;
                    const uint32_t payload_size = std::max<uint32_t>(16, options.payload_size);

                    // Timeout for considering a pending request as lost (2 seconds).
                    constexpr uint64_t stale_timeout_ns = 2'000'000'000ULL;

                    while (!stop_signal.load(std::memory_order_acquire)) {
                        uint32_t effective_payload_size = payload_size;

                        // Wait for an available slot (pending < max_outstanding).
                        {
                            std::unique_lock<std::mutex> lock(connection_ctx->mutex);
                            if (!connection_ctx->cv.wait_for(
                                    lock, std::chrono::milliseconds(100), [&] {
                                        return connection_ctx->pending_requests.size() <
                                                   connection_ctx->max_outstanding ||
                                               connection_ctx->shutdown_complete ||
                                               connection_ctx->failed;
                                    })) {
                                // Timeout — evict stale pending entries so a lost
                                // datagram doesn't permanently stall the connection.
                                const uint64_t cutoff = now_ns() - stale_timeout_ns;
                                for (auto it = connection_ctx->pending_requests.begin();
                                     it != connection_ctx->pending_requests.end();) {
                                    if (it->second < cutoff) {
                                        it = connection_ctx->pending_requests.erase(it);
                                        state.errors.fetch_add(1, std::memory_order_relaxed);
                                    } else {
                                        ++it;
                                    }
                                }
                                continue;
                            }
                            if (connection_ctx->shutdown_complete || connection_ctx->failed) {
                                break;
                            }
                            if (connection_ctx->max_datagram_send_length > 0) {
                                effective_payload_size =
                                    std::min<uint32_t>(effective_payload_size,
                                                       connection_ctx->max_datagram_send_length);
                            }
                        }

                        const uint64_t request_sequence = ++sequence;
                        // TODO: consider a pool allocator for datagram_send_context to reduce
                        // per-datagram heap allocation overhead in the hot path.
                        auto* send_ctx = new datagram_send_context();
                        send_ctx->payload.resize(std::max<uint32_t>(16, effective_payload_size));
                        fill_payload(send_ctx->payload, request_sequence);
                        send_ctx->init_buffer();

                        const uint64_t send_ts = now_ns();
                        {
                            std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                            connection_ctx->pending_requests[request_sequence] = send_ts;
                        }

                        status = api->DatagramSend(connection, &send_ctx->quic_buffer, 1, QUIC_SEND_FLAG_NONE, send_ctx);
                        if (QUIC_FAILED(status)) {
                            if (state.verbose) {
                                std::cerr << "[client] DatagramSend failed: " << status_to_string(status)
                                          << "\n";
                            }
                            delete send_ctx;
                            {
                                std::lock_guard<std::mutex> lock(connection_ctx->mutex);
                                connection_ctx->pending_requests.erase(request_sequence);
                            }
                            state.errors.fetch_add(1, std::memory_order_relaxed);
                            continue;
                        }

                        state.requests_sent.fetch_add(1, std::memory_order_relaxed);
                        state.bytes_sent.fetch_add(send_ctx->quic_buffer.Length, std::memory_order_relaxed);
                    }

                    api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                    {
                        std::unique_lock<std::mutex> lock(connection_ctx->mutex);
                        connection_ctx->cv.wait_for(lock, std::chrono::seconds(2),
                                                    [&] { return connection_ctx->shutdown_complete; });
                    }
                    api->ConnectionClose(connection);
                    // connection_ctx is released by unique_ptr when the lambda exits.
                });
            }

            // Wait for at least one worker to connect before monitoring.
            for (int i = 0; i < 100 && connected_workers.load(std::memory_order_acquire) == 0; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (connected_workers.load(std::memory_order_acquire) == 0) {
                std::cerr << "[client] No workers connected after 10s – aborting.\n";
                stop_signal.store(true, std::memory_order_release);
                for (auto& worker : workers) {
                    worker.join();
                }
                // RAII guards close configuration and registration.
                summary.exit_code = 1;
                summary.errors = state.errors.load(std::memory_order_relaxed);
                return summary;
            }

            // The monitoring loop runs for the benchmark duration (starting now).
            const auto benchmark_start = steady_clock::now();
            const auto monitor_end =
                benchmark_start + std::chrono::seconds(options.duration_seconds);
            uint64_t prev_completed = 0;
            while (steady_clock::now() < monitor_end) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                const uint64_t completed = state.requests_completed.load(std::memory_order_relaxed);
                const uint64_t rps = completed - prev_completed;
                prev_completed = completed;
                std::cout << "RPS=" << rps << " Completed=" << completed
                          << " Sent=" << state.requests_sent.load(std::memory_order_relaxed)
                          << " Errors=" << state.errors.load(std::memory_order_relaxed) << "\n";
            }

            // Signal all workers to stop, then join.
            stop_signal.store(true, std::memory_order_release);

            for (auto& worker : workers) {
                worker.join();
            }

            // RAII guards close configuration and registration.

            const auto end = steady_clock::now();
            const double duration_seconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(end - benchmark_start).count() / 1000.0;

            summary.exit_code = 0;
            summary.duration_seconds = duration_seconds;
            summary.requests_sent = state.requests_sent.load(std::memory_order_relaxed);
            summary.requests_completed = state.requests_completed.load(std::memory_order_relaxed);
            summary.bytes_sent = state.bytes_sent.load(std::memory_order_relaxed);
            summary.bytes_received = state.bytes_received.load(std::memory_order_relaxed);
            summary.errors = state.errors.load(std::memory_order_relaxed);

            const uint64_t samples = state.latency.samples.load(std::memory_order_relaxed);
            const uint64_t total_ns = state.latency.total_ns.load(std::memory_order_relaxed);
            summary.latency_min_ns = samples > 0 ? state.latency.min_ns.load(std::memory_order_relaxed) : 0;
            summary.latency_max_ns = samples > 0 ? state.latency.max_ns.load(std::memory_order_relaxed) : 0;
            summary.latency_avg_ns = samples > 0 ? (total_ns / samples) : 0;

            const double rps =
                duration_seconds > 0.0 ? (summary.requests_completed / duration_seconds) : 0.0;
            const double mbps =
                duration_seconds > 0.0
                    ? ((summary.bytes_received * 8.0) / (duration_seconds * 1'000'000.0))
                    : 0.0;

            std::cout << "\n===== Final Client Statistics =====\n";
            std::cout << "Duration: " << std::fixed << std::setprecision(2) << duration_seconds
                      << "s\n";
            std::cout << "Requests sent: " << summary.requests_sent << "\n";
            std::cout << "Requests completed: " << summary.requests_completed << " (RPS=" << rps
                      << ")\n";
            std::cout << "Errors: " << summary.errors << "\n";
            std::cout << "Bytes sent: " << summary.bytes_sent << "\n";
            std::cout << "Bytes received: " << summary.bytes_received << " (" << mbps << " Mbps)\n";
            std::cout << "Latency min/avg/max: " << (summary.latency_min_ns / 1'000'000.0) << "/"
                      << (summary.latency_avg_ns / 1'000'000.0) << "/"
                      << (summary.latency_max_ns / 1'000'000.0) << " ms\n";

            if (!options.stats_file.empty()) {
                std::ofstream out(options.stats_file, std::ios::trunc);
                if (out) {
                    out << "{\n";
                    out << "  \"backend\": \"msquic\",\n";
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
            std::cerr << "MsQuic client error: " << ex.what() << "\n";
            return summary;
        }
    }
};

}  // namespace

void register_msquic_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        register_backend("msquic", "MsQuic C API backend", []() {
            return std::make_unique<msquic_backend>();
        });
    });
}

}  // namespace winquicecho
