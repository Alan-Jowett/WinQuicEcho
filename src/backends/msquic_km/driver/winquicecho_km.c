// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

// WinQuicEcho kernel-mode QUIC echo server driver.
//
// This WDM driver loads the msquic.sys kernel-mode API (the same API surface
// used by http.sys and SMB server) and implements a datagram echo server that
// is controlled from user mode via IOCTLs through \\.\WinQuicEcho.

#include <ntddk.h>
#include <ntstrsafe.h>
#include <msquic.h>

#include "../ioctl.h"

// -----------------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DeviceCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DeviceIoControlHandler;

static NTSTATUS StartEchoServer(_In_ const WINQUICECHO_SERVER_CONFIG* Config);
static void     StopEchoServer(void);

// -----------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_SymlinkName  = RTL_CONSTANT_STRING(WINQUICECHO_SYMLINK_NAME);

// Echo server state — only one server instance at a time.
typedef struct _ECHO_SERVER_CTX {
    const QUIC_API_TABLE* MsQuic;
    HQUIC Registration;
    HQUIC Configuration;
    HQUIC Listener;

    volatile LONG64 ActiveConnections;
    volatile LONG64 RequestsEchoed;
    volatile LONG64 BytesReceived;
    volatile LONG64 BytesSent;
    volatile LONG Running;  // Interlocked; 1 = running, 0 = stopped.
    BOOLEAN Verbose;

    // Serialises Start/Stop; callbacks run at PASSIVE_LEVEL so a fast mutex
    // is appropriate.
    FAST_MUTEX Lock;
} ECHO_SERVER_CTX;

static ECHO_SERVER_CTX g_Server;

// -----------------------------------------------------------------------
// Datagram send context (allocated per echo reply)
// -----------------------------------------------------------------------
typedef struct _DGRAM_SEND_CTX {
    QUIC_BUFFER QuicBuffer;        // Must outlive DatagramSend; embedded, not stack-local.
    UINT8 Payload[ANYSIZE_ARRAY];  // Variable-length; real size = datagram length.
} DGRAM_SEND_CTX;

// Maximum datagram size we'll echo (defense against pool exhaustion).
#define MAX_ECHO_DATAGRAM_SIZE 65536

static DGRAM_SEND_CTX*
AllocSendCtx(
    _In_reads_bytes_(Length) const UINT8* Data,
    _In_ UINT32 Length)
{
    if (Length == 0 || Length > MAX_ECHO_DATAGRAM_SIZE) {
        return NULL;
    }
    SIZE_T AllocSize = FIELD_OFFSET(DGRAM_SEND_CTX, Payload) + Length;
    DGRAM_SEND_CTX* Ctx = (DGRAM_SEND_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, AllocSize, WINQUICECHO_POOL_TAG);
    if (Ctx != NULL) {
        RtlCopyMemory(Ctx->Payload, Data, Length);
    }
    return Ctx;
}

static void
FreeSendCtx(_In_ DGRAM_SEND_CTX* Ctx)
{
    if (Ctx != NULL) {
        ExFreePoolWithTag(Ctx, WINQUICECHO_POOL_TAG);
    }
}

// -----------------------------------------------------------------------
// Connection context (allocated per accepted connection)
// -----------------------------------------------------------------------
typedef struct _CONN_CTX {
    ECHO_SERVER_CTX* Server;
    HQUIC Connection;
} CONN_CTX;

static CONN_CTX*
AllocConnCtx(_In_ ECHO_SERVER_CTX* Server, _In_ HQUIC Connection)
{
    CONN_CTX* Ctx = (CONN_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(CONN_CTX), WINQUICECHO_POOL_TAG);
    if (Ctx != NULL) {
        Ctx->Server     = Server;
        Ctx->Connection = Connection;
    }
    return Ctx;
}

static void
FreeConnCtx(_In_ CONN_CTX* Ctx)
{
    if (Ctx != NULL) {
        ExFreePoolWithTag(Ctx, WINQUICECHO_POOL_TAG);
    }
}

// -----------------------------------------------------------------------
// Helper: is a datagram send state terminal?
// -----------------------------------------------------------------------
static BOOLEAN
IsSendStateFinal(QUIC_DATAGRAM_SEND_STATE State)
{
    return State >= QUIC_DATAGRAM_SEND_LOST_DISCARDED;
}

// -----------------------------------------------------------------------
// MsQuic server connection callback
// -----------------------------------------------------------------------
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event)
{
    CONN_CTX* ConnCtx = (CONN_CTX*)Context;
    ECHO_SERVER_CTX* Server = ConnCtx->Server;

    // Handle cleanup events even when shutting down to avoid leaks.
    if (!InterlockedCompareExchange(&Server->Running, 0, 0)) {
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            InterlockedDecrement64(&Server->ActiveConnections);
            Server->MsQuic->ConnectionClose(Connection);
            FreeConnCtx(ConnCtx);
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
            DGRAM_SEND_CTX* SendCtx = (DGRAM_SEND_CTX*)
                Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            if (SendCtx != NULL &&
                IsSendStateFinal(Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                FreeSendCtx(SendCtx);
            }
            break;
        }
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    switch (Event->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED:
        if (Server->Verbose) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "WinQuicEcho: connection established\n");
        }
        return QUIC_STATUS_SUCCESS;

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const QUIC_BUFFER* Received = Event->DATAGRAM_RECEIVED.Buffer;
        if (Received == NULL || Received->Length == 0) {
            return QUIC_STATUS_SUCCESS;
        }

        DGRAM_SEND_CTX* SendCtx = AllocSendCtx(Received->Buffer, Received->Length);
        if (SendCtx == NULL) {
            return QUIC_STATUS_SUCCESS;  // Drop on allocation failure.
        }

        SendCtx->QuicBuffer.Length = Received->Length;
        SendCtx->QuicBuffer.Buffer = SendCtx->Payload;

        QUIC_STATUS Status = Server->MsQuic->DatagramSend(
            Connection, &SendCtx->QuicBuffer, 1, QUIC_SEND_FLAG_NONE, SendCtx);
        if (QUIC_FAILED(Status)) {
            FreeSendCtx(SendCtx);
            return QUIC_STATUS_SUCCESS;
        }

        InterlockedAdd64(&Server->BytesReceived, (LONG64)Received->Length);
        InterlockedAdd64(&Server->BytesSent,     (LONG64)Received->Length);
        InterlockedIncrement64(&Server->RequestsEchoed);
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        DGRAM_SEND_CTX* SendCtx = (DGRAM_SEND_CTX*)
            Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
        if (SendCtx != NULL &&
            IsSendStateFinal(Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
            FreeSendCtx(SendCtx);
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        InterlockedDecrement64(&Server->ActiveConnections);
        Server->MsQuic->ConnectionClose(Connection);
        FreeConnCtx(ConnCtx);
        return QUIC_STATUS_SUCCESS;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        return QUIC_STATUS_SUCCESS;

    default:
        return QUIC_STATUS_SUCCESS;
    }
}

// -----------------------------------------------------------------------
// MsQuic server listener callback
// -----------------------------------------------------------------------
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
static
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event)
{
    UNREFERENCED_PARAMETER(Listener);
    ECHO_SERVER_CTX* Server = (ECHO_SERVER_CTX*)Context;

    if (Event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        return QUIC_STATUS_SUCCESS;
    }

    CONN_CTX* ConnCtx = AllocConnCtx(Server, Event->NEW_CONNECTION.Connection);
    if (ConnCtx == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Server->MsQuic->SetCallbackHandler(
        Event->NEW_CONNECTION.Connection,
        (void*)ServerConnectionCallback,
        ConnCtx);

    // Track the connection before calling ConnectionSetConfiguration so that
    // if it fails, the SHUTDOWN_COMPLETE callback (which will still fire) can
    // decrement the counter and free ConnCtx.
    InterlockedIncrement64(&Server->ActiveConnections);

    QUIC_STATUS Status = Server->MsQuic->ConnectionSetConfiguration(
        Event->NEW_CONNECTION.Connection, Server->Configuration);
    if (QUIC_FAILED(Status)) {
        // MsQuic will reject the connection and eventually deliver
        // SHUTDOWN_COMPLETE to our callback, which frees ConnCtx.
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

// -----------------------------------------------------------------------
// StartEchoServer — opens MsQuic, configures, starts listening.
// -----------------------------------------------------------------------
static
NTSTATUS
StartEchoServer(
    _In_ const WINQUICECHO_SERVER_CONFIG* Config)
{
    QUIC_STATUS QStatus;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    ExAcquireFastMutex(&g_Server.Lock);

    if (InterlockedCompareExchange(&g_Server.Running, 0, 0)) {
        ExReleaseFastMutex(&g_Server.Lock);
        return STATUS_ALREADY_REGISTERED;
    }

    // Reset counters.
    g_Server.ActiveConnections = 0;
    g_Server.RequestsEchoed    = 0;
    g_Server.BytesReceived     = 0;
    g_Server.BytesSent         = 0;
    g_Server.Verbose           = Config->Verbose;
    g_Server.MsQuic            = NULL;
    g_Server.Registration      = NULL;
    g_Server.Configuration     = NULL;
    g_Server.Listener          = NULL;

    // Open MsQuic kernel API (exported by msquic.sys).
    QStatus = MsQuicOpen2(&g_Server.MsQuic);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: MsQuicOpen2 failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Registration.
    QUIC_REGISTRATION_CONFIG RegConfig = {0};
    RegConfig.AppName          = "WinQuicEcho.KernelServer";
    RegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
    QStatus = g_Server.MsQuic->RegistrationOpen(&RegConfig, &g_Server.Registration);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: RegistrationOpen failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Configuration with ALPN and settings.
    QUIC_BUFFER Alpn = {0};
    Alpn.Length = (UINT32)strnlen(Config->Alpn, sizeof(Config->Alpn));
    Alpn.Buffer = (UINT8*)Config->Alpn;

    QUIC_SETTINGS Settings = {0};
    Settings.PeerBidiStreamCount    = 1024;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.PeerUnidiStreamCount   = 1024;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.DatagramReceiveEnabled = TRUE;
    Settings.IsSet.DatagramReceiveEnabled = TRUE;

    QStatus = g_Server.MsQuic->ConfigurationOpen(
        g_Server.Registration, &Alpn, 1,
        &Settings, sizeof(Settings),
        NULL, &g_Server.Configuration);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: ConfigurationOpen failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Load credential — Schannel certificate hash + store.
    QUIC_CERTIFICATE_HASH_STORE HashStore = {0};
    RtlCopyMemory(HashStore.ShaHash, Config->CertHash, sizeof(HashStore.ShaHash));
    RtlStringCbCopyA(HashStore.StoreName, sizeof(HashStore.StoreName), Config->CertStore);
    HashStore.Flags = QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE;

    QUIC_CREDENTIAL_CONFIG CredConfig = {0};
    CredConfig.Type                 = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
    CredConfig.CertificateHashStore = &HashStore;
    CredConfig.Flags                = QUIC_CREDENTIAL_FLAG_NONE;

    QStatus = g_Server.MsQuic->ConfigurationLoadCredential(
        g_Server.Configuration, &CredConfig);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: ConfigurationLoadCredential failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Open listener.
    QStatus = g_Server.MsQuic->ListenerOpen(
        g_Server.Registration, ServerListenerCallback, &g_Server, &g_Server.Listener);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: ListenerOpen failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Start listening.
    QUIC_ADDR LocalAddr = {0};
    QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&LocalAddr, Config->Port);

    QStatus = g_Server.MsQuic->ListenerStart(g_Server.Listener, &Alpn, 1, &LocalAddr);
    if (QUIC_FAILED(QStatus)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "WinQuicEcho: ListenerStart failed 0x%x\n", QStatus);
        NtStatus = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    InterlockedExchange(&g_Server.Running, 1);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "WinQuicEcho: kernel echo server started on port %u\n",
               (unsigned)Config->Port);

Exit:
    if (!NT_SUCCESS(NtStatus)) {
        // Clean up on failure.
        if (g_Server.Listener != NULL) {
            g_Server.MsQuic->ListenerClose(g_Server.Listener);
            g_Server.Listener = NULL;
        }
        if (g_Server.Configuration != NULL) {
            g_Server.MsQuic->ConfigurationClose(g_Server.Configuration);
            g_Server.Configuration = NULL;
        }
        if (g_Server.Registration != NULL) {
            g_Server.MsQuic->RegistrationClose(g_Server.Registration);
            g_Server.Registration = NULL;
        }
        if (g_Server.MsQuic != NULL) {
            MsQuicClose(g_Server.MsQuic);
            g_Server.MsQuic = NULL;
        }
    }

    ExReleaseFastMutex(&g_Server.Lock);
    return NtStatus;
}

// -----------------------------------------------------------------------
// StopEchoServer — stops listener, drains connections, closes MsQuic.
// -----------------------------------------------------------------------
static
void
StopEchoServer(void)
{
    ExAcquireFastMutex(&g_Server.Lock);

    if (!InterlockedCompareExchange(&g_Server.Running, 0, 0)) {
        ExReleaseFastMutex(&g_Server.Lock);
        return;
    }

    // Signal callbacks to stop processing new datagrams.
    InterlockedExchange(&g_Server.Running, 0);

    if (g_Server.Listener != NULL) {
        g_Server.MsQuic->ListenerStop(g_Server.Listener);
        g_Server.MsQuic->ListenerClose(g_Server.Listener);
        g_Server.Listener = NULL;
    }

    // Shut down the registration to trigger graceful close of all connections.
    // This ensures SHUTDOWN_COMPLETE fires for every connection so callbacks
    // finish and ConnCtx/SendCtx are freed before we close the API table.
    if (g_Server.Registration != NULL) {
        g_Server.MsQuic->RegistrationShutdown(
            g_Server.Registration, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }

    // Wait for active connections to drain (RegistrationShutdown triggers it).
    for (int i = 0; i < 200; ++i) {
        if (InterlockedCompareExchange64(&g_Server.ActiveConnections, 0, 0) == 0) {
            break;
        }
        LARGE_INTEGER Delay;
        Delay.QuadPart = -250000;  // 25 ms in 100-ns units, relative.
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    if (g_Server.Configuration != NULL) {
        g_Server.MsQuic->ConfigurationClose(g_Server.Configuration);
        g_Server.Configuration = NULL;
    }
    if (g_Server.Registration != NULL) {
        g_Server.MsQuic->RegistrationClose(g_Server.Registration);
        g_Server.Registration = NULL;
    }
    if (g_Server.MsQuic != NULL) {
        MsQuicClose(g_Server.MsQuic);
        g_Server.MsQuic = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "WinQuicEcho: kernel echo server stopped (echoed=%lld)\n",
               (long long)g_Server.RequestsEchoed);

    ExReleaseFastMutex(&g_Server.Lock);
}

// -----------------------------------------------------------------------
// IRP handlers
// -----------------------------------------------------------------------
_Use_decl_annotations_
NTSTATUS
DeviceCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DeviceIoControlHandler(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesReturned = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_WINQUICECHO_START_SERVER: {
        if (IrpSp->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(WINQUICECHO_SERVER_CONFIG)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        WINQUICECHO_SERVER_CONFIG* Config =
            (WINQUICECHO_SERVER_CONFIG*)Irp->AssociatedIrp.SystemBuffer;
        // Ensure null termination of string fields.
        Config->Alpn[sizeof(Config->Alpn) - 1]         = '\0';
        Config->CertStore[sizeof(Config->CertStore) - 1] = '\0';
        Status = StartEchoServer(Config);
        break;
    }

    case IOCTL_WINQUICECHO_STOP_SERVER:
        StopEchoServer();
        Status = STATUS_SUCCESS;
        break;

    case IOCTL_WINQUICECHO_GET_STATS: {
        if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(WINQUICECHO_SERVER_STATS)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        WINQUICECHO_SERVER_STATS* Stats =
            (WINQUICECHO_SERVER_STATS*)Irp->AssociatedIrp.SystemBuffer;
        Stats->ActiveConnections = (UINT64)InterlockedCompareExchange64(
            &g_Server.ActiveConnections, 0, 0);
        Stats->RequestsEchoed = (UINT64)InterlockedCompareExchange64(
            &g_Server.RequestsEchoed, 0, 0);
        Stats->BytesReceived = (UINT64)InterlockedCompareExchange64(
            &g_Server.BytesReceived, 0, 0);
        Stats->BytesSent = (UINT64)InterlockedCompareExchange64(
            &g_Server.BytesSent, 0, 0);
        Stats->Running = (BOOLEAN)InterlockedCompareExchange(&g_Server.Running, 0, 0);
        BytesReturned = sizeof(WINQUICECHO_SERVER_STATS);
        break;
    }

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information  = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// -----------------------------------------------------------------------
// DriverEntry / DriverUnload
// -----------------------------------------------------------------------
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(WINQUICECHO_DEVICE_NAME);

    ExInitializeFastMutex(&g_Server.Lock);

    // FILE_DEVICE_SECURE_OPEN applies the device's security descriptor to
    // every open. The default ACL restricts access to SYSTEM and Administrators.
    Status = IoCreateDevice(
        DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&g_SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
    DriverObject->DriverUnload                          = DriverUnload;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "WinQuicEcho: kernel driver loaded\n");
    return STATUS_SUCCESS;
}

void
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    StopEchoServer();

    IoDeleteSymbolicLink(&g_SymlinkName);
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "WinQuicEcho: kernel driver unloaded\n");
}
