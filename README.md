<!-- SPDX-License-Identifier: MIT
  Copyright (c) 2026 WinQuicEcho contributors -->

# WinQuicEcho

Windows QUIC echo benchmark in the style of `WinUDPShardedEcho`, with a pluggable backend interface so different QUIC implementations can be compared under the same client/server contract.

## Current backend

- `msquic` (default)

The architecture is intentionally backend-neutral, so new QUIC libraries can be added by implementing `quic_backend` and registering it in the factory.

## Build

```powershell
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Certificate setup (MsQuic server)

For Windows Schannel-based MsQuic, the easiest path is certificate thumbprint mode:

```powershell
.\scripts\generate-dev-cert.ps1
```

Use the printed thumbprint with `--cert-hash`.

## Usage

### Server

```powershell
.\echo_server --backend msquic --port 5001 --cert-hash <THUMBPRINT>
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
.\echo_client --backend msquic --server 127.0.0.1 --port 5001 --connections 8 --duration 15 --payload 64
```

Optional:

- `--insecure`: skip server certificate validation (default for benchmark convenience)
- `--stats-file <path>`: write final JSON stats
- `--alpn <name>`: ALPN (default `echo`)
- `--verbose`

## Plugging in additional QUIC libraries

1. Add a new backend implementation under `src\backends\<name>\`.
2. Implement `winquicecho::quic_backend` (see `src\common\quic_backend.hpp`).
3. Register it via `register_backend(...)`.
4. Select it at runtime with `--backend <name>`.

## Notes

- Metrics currently focus on request completion rate (RPS), bytes, and latency (min/avg/max).
- Stream-per-request mode is used to provide clear request boundaries for the echo benchmark.
