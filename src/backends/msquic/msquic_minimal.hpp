// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>

typedef struct QUIC_HANDLE* HQUIC;

#define QUIC_API __cdecl
#define QUIC_STATUS HRESULT
#define QUIC_FAILED(X) FAILED(X)
#define QUIC_SUCCEEDED(X) SUCCEEDED(X)

#define QUIC_STATUS_SUCCESS S_OK
#define QUIC_STATUS_PENDING HRESULT_FROM_WIN32(ERROR_IO_PENDING)
#define QUIC_STATUS_INVALID_PARAMETER E_INVALIDARG
#define QUIC_STATUS_NOT_SUPPORTED E_NOINTERFACE
#define QUIC_STATUS_OUT_OF_MEMORY E_OUTOFMEMORY

typedef uint64_t QUIC_UINT62;

typedef ADDRESS_FAMILY QUIC_ADDRESS_FAMILY;
typedef SOCKADDR_INET QUIC_ADDR;

constexpr QUIC_ADDRESS_FAMILY QUIC_ADDRESS_FAMILY_UNSPEC = AF_UNSPEC;
constexpr QUIC_ADDRESS_FAMILY QUIC_ADDRESS_FAMILY_INET = AF_INET;
constexpr QUIC_ADDRESS_FAMILY QUIC_ADDRESS_FAMILY_INET6 = AF_INET6;

inline void QuicAddrSetFamily(QUIC_ADDR* addr, QUIC_ADDRESS_FAMILY family) {
    addr->si_family = family;
}

inline void QuicAddrSetPort(QUIC_ADDR* addr, uint16_t port) {
    addr->Ipv4.sin_port = htons(port);
}

inline uint16_t QuicAddrGetPort(const QUIC_ADDR* addr) {
    if (addr->si_family == QUIC_ADDRESS_FAMILY_INET6) {
        return ntohs(addr->Ipv6.sin6_port);
    }
    return ntohs(addr->Ipv4.sin_port);
}

typedef enum QUIC_EXECUTION_PROFILE {
    QUIC_EXECUTION_PROFILE_LOW_LATENCY = 0,
    QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT = 1,
    QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER = 2,
    QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME = 3,
} QUIC_EXECUTION_PROFILE;

typedef enum QUIC_CREDENTIAL_TYPE {
    QUIC_CREDENTIAL_TYPE_NONE = 0,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH = 1,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE = 2,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT = 3,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE = 4,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED = 5,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12 = 6,
} QUIC_CREDENTIAL_TYPE;

typedef enum QUIC_CREDENTIAL_FLAGS {
    QUIC_CREDENTIAL_FLAG_NONE = 0x00000000,
    QUIC_CREDENTIAL_FLAG_CLIENT = 0x00000001,
    QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS = 0x00000002,
    QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION = 0x00000004,
} QUIC_CREDENTIAL_FLAGS;

typedef enum QUIC_CERTIFICATE_HASH_STORE_FLAGS {
    QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE = 0x0000,
    QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE = 0x0001,
} QUIC_CERTIFICATE_HASH_STORE_FLAGS;

typedef enum QUIC_CONNECTION_SHUTDOWN_FLAGS {
    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE = 0x0000,
    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT = 0x0001,
} QUIC_CONNECTION_SHUTDOWN_FLAGS;

typedef enum QUIC_SEND_RESUMPTION_FLAGS {
    QUIC_SEND_RESUMPTION_FLAG_NONE = 0x0000,
    QUIC_SEND_RESUMPTION_FLAG_FINAL = 0x0001,
} QUIC_SEND_RESUMPTION_FLAGS;

typedef enum QUIC_STREAM_OPEN_FLAGS {
    QUIC_STREAM_OPEN_FLAG_NONE = 0x0000,
    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL = 0x0001,
    QUIC_STREAM_OPEN_FLAG_0_RTT = 0x0002,
    QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES = 0x0004,
} QUIC_STREAM_OPEN_FLAGS;

typedef enum QUIC_STREAM_START_FLAGS {
    QUIC_STREAM_START_FLAG_NONE = 0x0000,
    QUIC_STREAM_START_FLAG_IMMEDIATE = 0x0001,
    QUIC_STREAM_START_FLAG_FAIL_BLOCKED = 0x0002,
    QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL = 0x0004,
    QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT = 0x0008,
    QUIC_STREAM_START_FLAG_PRIORITY_WORK = 0x0010,
} QUIC_STREAM_START_FLAGS;

typedef enum QUIC_STREAM_SHUTDOWN_FLAGS {
    QUIC_STREAM_SHUTDOWN_FLAG_NONE = 0x0000,
    QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL = 0x0001,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND = 0x0002,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE = 0x0004,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 0x0006,
    QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE = 0x0008,
    QUIC_STREAM_SHUTDOWN_FLAG_INLINE = 0x0010,
} QUIC_STREAM_SHUTDOWN_FLAGS;

typedef enum QUIC_RECEIVE_FLAGS {
    QUIC_RECEIVE_FLAG_NONE = 0x0000,
    QUIC_RECEIVE_FLAG_0_RTT = 0x0001,
    QUIC_RECEIVE_FLAG_FIN = 0x0002,
} QUIC_RECEIVE_FLAGS;

typedef enum QUIC_SEND_FLAGS {
    QUIC_SEND_FLAG_NONE = 0x0000,
    QUIC_SEND_FLAG_ALLOW_0_RTT = 0x0001,
    QUIC_SEND_FLAG_START = 0x0002,
    QUIC_SEND_FLAG_FIN = 0x0004,
    QUIC_SEND_FLAG_DGRAM_PRIORITY = 0x0008,
    QUIC_SEND_FLAG_DELAY_SEND = 0x0010,
    QUIC_SEND_FLAG_CANCEL_ON_LOSS = 0x0020,
    QUIC_SEND_FLAG_PRIORITY_WORK = 0x0040,
    QUIC_SEND_FLAG_CANCEL_ON_BLOCKED = 0x0080,
} QUIC_SEND_FLAGS;

typedef enum QUIC_DATAGRAM_SEND_STATE {
    QUIC_DATAGRAM_SEND_UNKNOWN = 0,
    QUIC_DATAGRAM_SEND_SENT = 1,
    QUIC_DATAGRAM_SEND_LOST_SUSPECT = 2,
    QUIC_DATAGRAM_SEND_LOST_DISCARDED = 3,
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED = 4,
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS = 5,
    QUIC_DATAGRAM_SEND_CANCELED = 6,
} QUIC_DATAGRAM_SEND_STATE;

typedef struct QUIC_REGISTRATION_CONFIG {
    const char* AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
} QUIC_REGISTRATION_CONFIG;

typedef struct QUIC_CERTIFICATE_HASH {
    uint8_t ShaHash[20];
} QUIC_CERTIFICATE_HASH;

typedef struct QUIC_CERTIFICATE_HASH_STORE {
    QUIC_CERTIFICATE_HASH_STORE_FLAGS Flags;
    uint8_t ShaHash[20];
    char StoreName[128];
} QUIC_CERTIFICATE_HASH_STORE;

typedef struct QUIC_CERTIFICATE_FILE {
    const char* PrivateKeyFile;
    const char* CertificateFile;
} QUIC_CERTIFICATE_FILE;

typedef struct QUIC_CERTIFICATE_FILE_PROTECTED {
    const char* PrivateKeyFile;
    const char* CertificateFile;
    const char* PrivateKeyPassword;
} QUIC_CERTIFICATE_FILE_PROTECTED;

typedef struct QUIC_CERTIFICATE_PKCS12 {
    const uint8_t* Asn1Blob;
    uint32_t Asn1BlobLength;
    const char* PrivateKeyPassword;
} QUIC_CERTIFICATE_PKCS12;

typedef struct QUIC_CREDENTIAL_CONFIG {
    QUIC_CREDENTIAL_TYPE Type;
    QUIC_CREDENTIAL_FLAGS Flags;
    union {
        QUIC_CERTIFICATE_HASH* CertificateHash;
        QUIC_CERTIFICATE_HASH_STORE* CertificateHashStore;
        void* CertificateContext;
        QUIC_CERTIFICATE_FILE* CertificateFile;
        QUIC_CERTIFICATE_FILE_PROTECTED* CertificateFileProtected;
        QUIC_CERTIFICATE_PKCS12* CertificatePkcs12;
    };
    const char* Principal;
    void* Reserved;
    void* AsyncHandler;
    uint32_t AllowedCipherSuites;
    const char* CaCertificateFile;
} QUIC_CREDENTIAL_CONFIG;

typedef struct QUIC_BUFFER {
    uint32_t Length;
    uint8_t* Buffer;
} QUIC_BUFFER;

typedef struct QUIC_SETTINGS {
    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey : 1;
            uint64_t HandshakeIdleTimeoutMs : 1;
            uint64_t IdleTimeoutMs : 1;
            uint64_t MtuDiscoverySearchCompleteTimeoutUs : 1;
            uint64_t TlsClientMaxSendBuffer : 1;
            uint64_t TlsServerMaxSendBuffer : 1;
            uint64_t StreamRecvWindowDefault : 1;
            uint64_t StreamRecvBufferDefault : 1;
            uint64_t ConnFlowControlWindow : 1;
            uint64_t MaxWorkerQueueDelayUs : 1;
            uint64_t MaxStatelessOperations : 1;
            uint64_t InitialWindowPackets : 1;
            uint64_t SendIdleTimeoutMs : 1;
            uint64_t InitialRttMs : 1;
            uint64_t MaxAckDelayMs : 1;
            uint64_t DisconnectTimeoutMs : 1;
            uint64_t KeepAliveIntervalMs : 1;
            uint64_t CongestionControlAlgorithm : 1;
            uint64_t PeerBidiStreamCount : 1;
            uint64_t PeerUnidiStreamCount : 1;
            uint64_t MaxBindingStatelessOperations : 1;
            uint64_t StatelessOperationExpirationMs : 1;
            uint64_t MinimumMtu : 1;
            uint64_t MaximumMtu : 1;
            uint64_t SendBufferingEnabled : 1;
            uint64_t PacingEnabled : 1;
            uint64_t MigrationEnabled : 1;
            uint64_t DatagramReceiveEnabled : 1;
            uint64_t ServerResumptionLevel : 1;
            uint64_t MaxOperationsPerDrain : 1;
            uint64_t MtuDiscoveryMissingProbeCount : 1;
            uint64_t DestCidUpdateIdleTimeoutMs : 1;
            uint64_t GreaseQuicBitEnabled : 1;
            uint64_t EcnEnabled : 1;
            uint64_t HyStartEnabled : 1;
            uint64_t StreamRecvWindowBidiLocalDefault : 1;
            uint64_t StreamRecvWindowBidiRemoteDefault : 1;
            uint64_t StreamRecvWindowUnidiDefault : 1;
            uint64_t RESERVED : 26;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint64_t MtuDiscoverySearchCompleteTimeoutUs;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t CongestionControlAlgorithm;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t MaxBindingStatelessOperations;
    uint16_t StatelessOperationExpirationMs;
    uint16_t MinimumMtu;
    uint16_t MaximumMtu;
    uint8_t SendBufferingEnabled : 1;
    uint8_t PacingEnabled : 1;
    uint8_t MigrationEnabled : 1;
    uint8_t DatagramReceiveEnabled : 1;
    uint8_t ServerResumptionLevel : 2;
    uint8_t GreaseQuicBitEnabled : 1;
    uint8_t EcnEnabled : 1;
    uint8_t MaxOperationsPerDrain;
    uint8_t MtuDiscoveryMissingProbeCount;
    uint32_t DestCidUpdateIdleTimeoutMs;
    union {
        uint64_t Flags;
        struct {
            uint64_t HyStartEnabled : 1;
            uint64_t ReservedFlags : 63;
        };
    };
    uint32_t StreamRecvWindowBidiLocalDefault;
    uint32_t StreamRecvWindowBidiRemoteDefault;
    uint32_t StreamRecvWindowUnidiDefault;
} QUIC_SETTINGS;

typedef struct QUIC_NEW_CONNECTION_INFO QUIC_NEW_CONNECTION_INFO;

typedef enum QUIC_LISTENER_EVENT_TYPE {
    QUIC_LISTENER_EVENT_NEW_CONNECTION = 0,
    QUIC_LISTENER_EVENT_STOP_COMPLETE = 1,
    QUIC_LISTENER_EVENT_DOS_MODE_CHANGED = 2,
} QUIC_LISTENER_EVENT_TYPE;

typedef struct QUIC_LISTENER_EVENT {
    QUIC_LISTENER_EVENT_TYPE Type;
    union {
        struct {
            const QUIC_NEW_CONNECTION_INFO* Info;
            HQUIC Connection;
            const uint8_t* NewNegotiatedAlpn;
        } NEW_CONNECTION;
        struct {
            BOOLEAN AppCloseInProgress : 1;
            BOOLEAN RESERVED : 7;
        } STOP_COMPLETE;
        struct {
            BOOLEAN DosModeEnabled : 1;
            BOOLEAN RESERVED : 7;
        } DOS_MODE_CHANGED;
    };
} QUIC_LISTENER_EVENT;

typedef enum QUIC_CONNECTION_EVENT_TYPE {
    QUIC_CONNECTION_EVENT_CONNECTED = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = 1,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 2,
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = 3,
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = 12,
    QUIC_CONNECTION_EVENT_RESUMED = 13,
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = 14,
    QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = 15,
} QUIC_CONNECTION_EVENT_TYPE;

typedef struct QUIC_CONNECTION_EVENT {
    QUIC_CONNECTION_EVENT_TYPE Type;
    union {
        struct {
            BOOLEAN SessionResumed;
            uint8_t NegotiatedAlpnLength;
            const uint8_t* NegotiatedAlpn;
        } CONNECTED;
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;
        struct {
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;
        struct {
            BOOLEAN HandshakeCompleted : 1;
            BOOLEAN PeerAcknowledgedShutdown : 1;
            BOOLEAN AppCloseInProgress : 1;
        } SHUTDOWN_COMPLETE;
        struct {
            HQUIC Stream;
            QUIC_STREAM_OPEN_FLAGS Flags;
        } PEER_STREAM_STARTED;
        struct {
            BOOLEAN SendEnabled;
            uint16_t MaxSendLength;
        } DATAGRAM_STATE_CHANGED;
        struct {
            const QUIC_BUFFER* Buffer;
            QUIC_RECEIVE_FLAGS Flags;
        } DATAGRAM_RECEIVED;
        struct {
            void* ClientContext;
            QUIC_DATAGRAM_SEND_STATE State;
        } DATAGRAM_SEND_STATE_CHANGED;
    };
} QUIC_CONNECTION_EVENT;

typedef enum QUIC_STREAM_EVENT_TYPE {
    QUIC_STREAM_EVENT_START_COMPLETE = 0,
    QUIC_STREAM_EVENT_RECEIVE = 1,
    QUIC_STREAM_EVENT_SEND_COMPLETE = 2,
    QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN = 3,
    QUIC_STREAM_EVENT_PEER_SEND_ABORTED = 4,
    QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED = 5,
    QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE = 6,
    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE = 7,
    QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = 8,
    QUIC_STREAM_EVENT_PEER_ACCEPTED = 9,
    QUIC_STREAM_EVENT_CANCEL_ON_LOSS = 10,
} QUIC_STREAM_EVENT_TYPE;

typedef struct QUIC_STREAM_EVENT {
    QUIC_STREAM_EVENT_TYPE Type;
    union {
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ID;
            BOOLEAN PeerAccepted : 1;
            BOOLEAN RESERVED : 7;
        } START_COMPLETE;
        struct {
            uint64_t AbsoluteOffset;
            uint64_t TotalBufferLength;
            const QUIC_BUFFER* Buffers;
            uint32_t BufferCount;
            QUIC_RECEIVE_FLAGS Flags;
        } RECEIVE;
        struct {
            BOOLEAN Canceled;
            void* ClientContext;
        } SEND_COMPLETE;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_SEND_ABORTED;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_RECEIVE_ABORTED;
        struct {
            BOOLEAN Graceful;
        } SEND_SHUTDOWN_COMPLETE;
        struct {
            BOOLEAN ConnectionShutdown;
            BOOLEAN AppCloseInProgress : 1;
            BOOLEAN ConnectionShutdownByApp : 1;
            BOOLEAN ConnectionClosedRemotely : 1;
            BOOLEAN RESERVED : 5;
            QUIC_UINT62 ConnectionErrorCode;
            QUIC_STATUS ConnectionCloseStatus;
        } SHUTDOWN_COMPLETE;
        struct {
            uint64_t ByteCount;
        } IDEAL_SEND_BUFFER_SIZE;
        struct {
            QUIC_UINT62 ErrorCode;
        } CANCEL_ON_LOSS;
    };
} QUIC_STREAM_EVENT;

typedef QUIC_STATUS(QUIC_API* QUIC_LISTENER_CALLBACK_HANDLER)(HQUIC Listener, void* Context,
                                                              QUIC_LISTENER_EVENT* Event);
typedef QUIC_STATUS(QUIC_API* QUIC_CONNECTION_CALLBACK_HANDLER)(HQUIC Connection, void* Context,
                                                                QUIC_CONNECTION_EVENT* Event);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_CALLBACK_HANDLER)(HQUIC Stream, void* Context,
                                                            QUIC_STREAM_EVENT* Event);

typedef void(QUIC_API* QUIC_SET_CONTEXT_FN)(HQUIC Handle, void* Context);
typedef void*(QUIC_API* QUIC_GET_CONTEXT_FN)(HQUIC Handle);
typedef void(QUIC_API* QUIC_SET_CALLBACK_HANDLER_FN)(HQUIC Handle, void* Handler, void* Context);
typedef QUIC_STATUS(QUIC_API* QUIC_SET_PARAM_FN)(HQUIC Handle, uint32_t Param, uint32_t BufferLength,
                                                 const void* Buffer);
typedef QUIC_STATUS(QUIC_API* QUIC_GET_PARAM_FN)(HQUIC Handle, uint32_t Param,
                                                 uint32_t* BufferLength, void* Buffer);
typedef QUIC_STATUS(QUIC_API* QUIC_REGISTRATION_OPEN_FN)(const QUIC_REGISTRATION_CONFIG* Config,
                                                         HQUIC* Registration);
typedef void(QUIC_API* QUIC_REGISTRATION_CLOSE_FN)(HQUIC Registration);
typedef void(QUIC_API* QUIC_REGISTRATION_SHUTDOWN_FN)(HQUIC Registration, uint32_t Flags,
                                                      QUIC_UINT62 ErrorCode);
typedef QUIC_STATUS(QUIC_API* QUIC_CONFIGURATION_OPEN_FN)(HQUIC Registration,
                                                          const QUIC_BUFFER* const AlpnBuffers,
                                                          uint32_t AlpnBufferCount,
                                                          const QUIC_SETTINGS* Settings,
                                                          uint32_t SettingsSize, void* Context,
                                                          HQUIC* Configuration);
typedef void(QUIC_API* QUIC_CONFIGURATION_CLOSE_FN)(HQUIC Configuration);
typedef QUIC_STATUS(QUIC_API* QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN)(
    HQUIC Configuration, const QUIC_CREDENTIAL_CONFIG* CredConfig);
typedef QUIC_STATUS(QUIC_API* QUIC_LISTENER_OPEN_FN)(HQUIC Registration,
                                                     QUIC_LISTENER_CALLBACK_HANDLER Handler,
                                                     void* Context, HQUIC* Listener);
typedef void(QUIC_API* QUIC_LISTENER_CLOSE_FN)(HQUIC Listener);
typedef QUIC_STATUS(QUIC_API* QUIC_LISTENER_START_FN)(HQUIC Listener,
                                                      const QUIC_BUFFER* const AlpnBuffers,
                                                      uint32_t AlpnBufferCount,
                                                      const QUIC_ADDR* LocalAddress);
typedef void(QUIC_API* QUIC_LISTENER_STOP_FN)(HQUIC Listener);
typedef QUIC_STATUS(QUIC_API* QUIC_CONNECTION_OPEN_FN)(HQUIC Registration,
                                                       QUIC_CONNECTION_CALLBACK_HANDLER Handler,
                                                       void* Context, HQUIC* Connection);
typedef void(QUIC_API* QUIC_CONNECTION_CLOSE_FN)(HQUIC Connection);
typedef void(QUIC_API* QUIC_CONNECTION_SHUTDOWN_FN)(HQUIC Connection,
                                                    QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
                                                    QUIC_UINT62 ErrorCode);
typedef QUIC_STATUS(QUIC_API* QUIC_CONNECTION_START_FN)(HQUIC Connection, HQUIC Configuration,
                                                        QUIC_ADDRESS_FAMILY Family,
                                                        const char* ServerName, uint16_t ServerPort);
typedef QUIC_STATUS(QUIC_API* QUIC_CONNECTION_SET_CONFIGURATION_FN)(HQUIC Connection,
                                                                    HQUIC Configuration);
typedef QUIC_STATUS(QUIC_API* QUIC_CONNECTION_SEND_RESUMPTION_FN)(
    HQUIC Connection, QUIC_SEND_RESUMPTION_FLAGS Flags, uint16_t DataLength,
    const uint8_t* ResumptionData);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_OPEN_FN)(HQUIC Connection, QUIC_STREAM_OPEN_FLAGS Flags,
                                                   QUIC_STREAM_CALLBACK_HANDLER Handler, void* Context,
                                                   HQUIC* Stream);
typedef void(QUIC_API* QUIC_STREAM_CLOSE_FN)(HQUIC Stream);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_START_FN)(HQUIC Stream, QUIC_STREAM_START_FLAGS Flags);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_SHUTDOWN_FN)(HQUIC Stream,
                                                       QUIC_STREAM_SHUTDOWN_FLAGS Flags,
                                                       QUIC_UINT62 ErrorCode);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_SEND_FN)(HQUIC Stream, const QUIC_BUFFER* const Buffers,
                                                   uint32_t BufferCount, QUIC_SEND_FLAGS Flags,
                                                   void* ClientSendContext);
typedef void(QUIC_API* QUIC_STREAM_RECEIVE_COMPLETE_FN)(HQUIC Stream, uint64_t BufferLength);
typedef QUIC_STATUS(QUIC_API* QUIC_STREAM_RECEIVE_SET_ENABLED_FN)(HQUIC Stream, BOOLEAN IsEnabled);
typedef QUIC_STATUS(QUIC_API* QUIC_DATAGRAM_SEND_FN)(HQUIC Connection,
                                                     const QUIC_BUFFER* const Buffers,
                                                     uint32_t BufferCount, QUIC_SEND_FLAGS Flags,
                                                     void* ClientSendContext);

typedef struct QUIC_API_TABLE {
    QUIC_SET_CONTEXT_FN SetContext;
    QUIC_GET_CONTEXT_FN GetContext;
    QUIC_SET_CALLBACK_HANDLER_FN SetCallbackHandler;
    QUIC_SET_PARAM_FN SetParam;
    QUIC_GET_PARAM_FN GetParam;
    QUIC_REGISTRATION_OPEN_FN RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN RegistrationClose;
    QUIC_REGISTRATION_SHUTDOWN_FN RegistrationShutdown;
    QUIC_CONFIGURATION_OPEN_FN ConfigurationOpen;
    QUIC_CONFIGURATION_CLOSE_FN ConfigurationClose;
    QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN ConfigurationLoadCredential;
    QUIC_LISTENER_OPEN_FN ListenerOpen;
    QUIC_LISTENER_CLOSE_FN ListenerClose;
    QUIC_LISTENER_START_FN ListenerStart;
    QUIC_LISTENER_STOP_FN ListenerStop;
    QUIC_CONNECTION_OPEN_FN ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN ConnectionShutdown;
    QUIC_CONNECTION_START_FN ConnectionStart;
    QUIC_CONNECTION_SET_CONFIGURATION_FN ConnectionSetConfiguration;
    QUIC_CONNECTION_SEND_RESUMPTION_FN ConnectionSendResumptionTicket;
    QUIC_STREAM_OPEN_FN StreamOpen;
    QUIC_STREAM_CLOSE_FN StreamClose;
    QUIC_STREAM_START_FN StreamStart;
    QUIC_STREAM_SHUTDOWN_FN StreamShutdown;
    QUIC_STREAM_SEND_FN StreamSend;
    QUIC_STREAM_RECEIVE_COMPLETE_FN StreamReceiveComplete;
    QUIC_STREAM_RECEIVE_SET_ENABLED_FN StreamReceiveSetEnabled;
    QUIC_DATAGRAM_SEND_FN DatagramSend;
} QUIC_API_TABLE;

typedef QUIC_STATUS(QUIC_API* QUIC_OPEN_VERSION_FN)(uint32_t Version,
                                                    const QUIC_API_TABLE** QuicApi);
typedef void(QUIC_API* QUIC_CLOSE_FN)(const void* QuicApi);

constexpr uint32_t QUIC_API_VERSION_1 = 1;
constexpr uint32_t QUIC_API_VERSION_2 = 2;
