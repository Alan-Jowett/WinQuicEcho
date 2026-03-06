// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

// Shared IOCTL definitions for the WinQuicEcho kernel-mode driver.
// Included by both the kernel driver (winquicecho_km.c) and the
// user-mode backend (msquic_km_backend.cpp).

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Custom device type (range 0x8000-0xFFFF is vendor-defined).
#define WINQUICECHO_DEVICE_TYPE 0x8000

// IOCTL codes — METHOD_BUFFERED.  START/STOP require write access;
// GET_STATS only needs read access.
#define IOCTL_WINQUICECHO_START_SERVER \
    CTL_CODE(WINQUICECHO_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_WINQUICECHO_STOP_SERVER \
    CTL_CODE(WINQUICECHO_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_WINQUICECHO_GET_STATS \
    CTL_CODE(WINQUICECHO_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

// Device object and symbolic link names.
#define WINQUICECHO_DEVICE_NAME   L"\\Device\\WinQuicEcho"
#define WINQUICECHO_SYMLINK_NAME  L"\\DosDevices\\WinQuicEcho"
#define WINQUICECHO_USERMODE_PATH "\\\\.\\WinQuicEcho"
#define WINQUICECHO_USERMODE_PATHW L"\\\\.\\WinQuicEcho"

// Pool tag for kernel allocations: 'WQEK' (little-endian).
#define WINQUICECHO_POOL_TAG ((ULONG)'KEQW')

#pragma pack(push, 1)

// Input for IOCTL_WINQUICECHO_START_SERVER.
typedef struct _WINQUICECHO_SERVER_CONFIG {
    UINT16 Port;
    char Alpn[64];
    UINT8 CertHash[20];        // SHA-1 thumbprint
    char CertStore[32];         // Certificate store name (e.g. "MY")
    BOOLEAN Verbose;
} WINQUICECHO_SERVER_CONFIG;

// Output for IOCTL_WINQUICECHO_GET_STATS.
typedef struct _WINQUICECHO_SERVER_STATS {
    UINT64 ActiveConnections;
    UINT64 RequestsEchoed;
    UINT64 BytesReceived;
    UINT64 BytesSent;
    BOOLEAN Running;
} WINQUICECHO_SERVER_STATS;

#pragma pack(pop)
