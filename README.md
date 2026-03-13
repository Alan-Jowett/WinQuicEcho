<!-- SPDX-License-Identifier: MIT
  Copyright (c) 2026 WinQuicEcho contributors -->

# WinQuicEcho

Windows QUIC echo benchmark in the style of `WinUDPShardedEcho`, with a pluggable backend interface so different QUIC implementations can be compared under the same client/server contract.

## Backends

- `msquic` (default) — user-mode MsQuic (msquic.dll), always built
- `msquic-km` — kernel-mode MsQuic (msquic.sys), the same API surface used by http.sys and SMB server
- `ngtcp2` (optional) — [ngtcp2](https://github.com/ngtcp2/ngtcp2) with quictls TLS, requires OpenSSL
- `picoquic` (optional) — [picoquic](https://github.com/nicterq/picoquic) with picotls, requires OpenSSL

The architecture is intentionally backend-neutral, so new QUIC libraries can be added by implementing `quic_backend` and registering it in the factory.

## Build

### Default (msquic only)

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

### With optional backends (ngtcp2 / picoquic)

Both ngtcp2 and picoquic require an OpenSSL-compatible TLS library. Install via [vcpkg](https://vcpkg.io):

```powershell
vcpkg install openssl:x64-windows
```

Then enable one or both backends. Since the default vcpkg triplet (`x64-windows`) uses the
dynamic CRT (`/MD`), pass `-DWINQUICECHO_STATIC_CRT=OFF` to avoid linker mismatches:

```powershell
cmake -S . -B build -A x64 `
    -DCMAKE_TOOLCHAIN_FILE="<vcpkg-root>/scripts/buildsystems/vcpkg.cmake" `
    -DWINQUICECHO_STATIC_CRT=OFF `
    -DWINQUICECHO_BUILD_NGTCP2=ON `
    -DWINQUICECHO_BUILD_PICOQUIC=ON
cmake --build build --config Release
```

## Certificate setup

### MsQuic (Schannel)

For Windows Schannel-based MsQuic, the easiest path is certificate thumbprint mode:

```powershell
.\scripts\generate-dev-cert.ps1
```

Use the printed thumbprint with `--cert-hash`.

### ngtcp2 / picoquic (OpenSSL PEM)

Generate a PEM certificate and private key:

```powershell
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost"
```

Pass via `--cert-file cert.pem --key-file key.pem`.

## Usage

### Server

```powershell
# MsQuic (Schannel)
.\echo_server --backend msquic --port 5001 --cert-hash <THUMBPRINT>

# ngtcp2 (PEM)
.\echo_server --backend ngtcp2 --port 5001 --cert-file cert.pem --key-file key.pem

# picoquic (PEM)
.\echo_server --backend picoquic --port 5001 --cert-file cert.pem --key-file key.pem
```

Optional:

- `--duration <seconds>`: stop after N seconds (0 = run until Ctrl+C)
- `--alpn <name>`: ALPN (default `echo`)
- `--verbose`
- `--cert-store <store>`: certificate store name (default `MY`)
- `--cert-file <path> --key-file <path>`: OpenSSL credential path (optional alternative)
- `--cert-pfx <path> [--cert-pfx-password <password>]`: OpenSSL PKCS#12/PFX path (optional alternative)

### Client

```powershell
# Works with any backend — specify which client-side QUIC library to use
# Use --insecure to skip certificate validation when testing with self-signed dev certs
.\echo_client --backend msquic --server 127.0.0.1 --port 5001 --connections 8 --duration 15 --payload 64 --insecure
.\echo_client --backend ngtcp2  --server 127.0.0.1 --port 5001 --connections 8 --duration 15 --payload 64 --insecure
.\echo_client --backend picoquic --server 127.0.0.1 --port 5001 --connections 8 --duration 15 --payload 64 --insecure
```

Optional:

- `--insecure`: skip server certificate validation (default for benchmark convenience)
- `--stats-file <path>`: write final JSON stats
- `--alpn <name>`: ALPN (default `echo`)
- `--verbose`

## Kernel-mode backend (`msquic-km`)

The `msquic-km` backend runs the server-side echo logic inside a WDM kernel
driver (`winquicecho_km.sys`) that calls msquic.sys directly — the same path
http.sys and SMB server use.  The user-mode `echo_server.exe` communicates
with the driver via IOCTLs for start/stop/stats.

### Prerequisites

1. **Windows Driver Kit (WDK)** for Visual Studio 2022.
2. **MsQuic kernel-mode artefacts** — headers and import library.  Obtain by:
   - Building MsQuic from source with kernel mode:
     ```powershell
     .\scripts\build.ps1 -Config Release -Tls schannel -Arch x64 -Kernel
     ```
   - Or extracting from the `Microsoft.Native.Quic.MsQuic.Schannel` NuGet package.
3. **msquic.sys** installed on the target machine (Windows Server 2022+ / Windows 11+
   ship with an inbox version, or install from MsQuic releases).
4. **Test signing** enabled for development:
   ```powershell
   bcdedit /set testsigning on
   # Reboot required
   ```

### Building the kernel driver

```powershell
.\scripts\build-km-driver.ps1 -MsQuicKernelDir <path-to-msquic-kernel-output>
```

This produces `build\km\winquicecho_km.sys`.

### Installing the driver

```powershell
# Requires Administrator
.\scripts\install-km-driver.ps1 -SysFile build\km\winquicecho_km.sys

# To uninstall:
.\scripts\install-km-driver.ps1 -Uninstall
```

### Running with the kernel backend

The certificate must be in the **Local Machine** certificate store (the kernel
driver uses `QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE`):

```powershell
.\echo_server --backend msquic-km --port 5001 --cert-hash <THUMBPRINT>
```

The client remains user-mode (`--backend msquic`); only the server side runs
in kernel mode.

> **Note:** File-based and PFX certificate credentials are not supported in
> kernel mode.  Use `--cert-hash` with a Schannel thumbprint.

## Plugging in additional QUIC libraries

1. Add a new backend implementation under `src\backends\<name>\`.
2. Implement `winquicecho::quic_backend` (see `src\common\quic_backend.hpp`).
3. Register it via `register_backend(...)`.
4. Select it at runtime with `--backend <name>`.

## Notes

- Metrics currently focus on request completion rate (RPS), bytes, and latency (min/avg/max).
- Stream-per-request mode is used to provide clear request boundaries for the echo benchmark.
- All backends use the same datagram payload format (8-byte sequence + 8-byte timestamp + padding), enabling cross-backend testing (e.g., ngtcp2 client ↔ msquic server).
- ngtcp2 and picoquic are fetched from source via CMake `FetchContent` — no manual library install is needed beyond OpenSSL.
