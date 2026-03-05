<!-- SPDX-License-Identifier: MIT
  Copyright (c) 2026 WinQuicEcho contributors -->

# Copilot Instructions — WinQuicEcho

## Build

Windows-only (CMake fails with `FATAL_ERROR` on non-Windows). MsQuic is fetched from source via `FetchContent` — no manual dependency install required.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Outputs: `build\Release\echo_server.exe`, `build\Release\echo_client.exe`, `build\Release\msquic.dll`.

## Test

Integration test (requires a built tree and runs server+client with an ephemeral certificate):

```powershell
# Via CTest (from the build directory)
ctest --test-dir build -C Release

# Directly (useful for tweaking parameters)
.\tests\integration\echo-roundtrip.ps1 -BuildDir build -Config Release -Port 15443 -Duration 5 -Connections 2
```

The test exits with code 77 (skip) if `msquic.dll` is not found, so CTest reports it as skipped on runners without QUIC.

## Architecture

WinQuicEcho is a QUIC echo benchmark with a **pluggable backend** design:

- **`quic_backend`** (`src\common\quic_backend.hpp`) — abstract interface every backend must implement. Exposes `run_server()` and `run_client()`.
- **Backend factory** (`src\common\quic_factory.hpp/cpp`) — global registry. Backends call `register_backend()` at startup; executables call `create_backend()` by name.
- **`msquic` backend** (`src\backends\msquic\`) — the only backend today. Uses Microsoft's MsQuic with Schannel TLS. Both server and client logic live in `msquic_backend.cpp`.
- **Executables** (`src\server\main.cpp`, `src\client\main.cpp`) — thin CLI wrappers that parse args, pick a backend from the factory, and delegate.

To add a new QUIC backend: implement `quic_backend` under `src\backends\<name>\`, call `register_backend()`, and link it into the executables.

## Key conventions

- **Namespace**: all project code lives in `winquicecho`.
- **Code style**: Google-based `.clang-format` with 4-space indent, 100-column limit, `Left` pointer alignment.
- **Headers**: `#pragma once`; include paths are relative to `src/` (e.g., `"common/quic_backend.hpp"`).
- **SPDX headers**: every source and script file starts with `// SPDX-License-Identifier: MIT` (or `#` equivalent).
- **Commit messages**: conventional-commit style (`feat:`, `fix:`, `docs:`, etc.).
- **Benchmark stability**: preserve default behavior and benchmark comparability unless explicitly asked to change it. Keep backend interfaces backend-neutral.
- **Metrics**: `latency_accumulator` in `metrics.hpp` uses lock-free atomics (`compare_exchange_weak`); follow the same pattern for new counters.
- **CLI args**: both executables use the in-tree `arg_parser` (header-only, `src\common\arg_parser.hpp`). Don't introduce external arg-parsing libraries.
- **Certificate setup**: Schannel thumbprint mode (`--cert-hash`) is the primary path on Windows. `scripts\generate-dev-cert.ps1` creates a dev cert.
