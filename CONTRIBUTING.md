<!-- SPDX-License-Identifier: MIT
  Copyright (c) 2026 WinQuicEcho contributors -->
# Contributing to WinQuicEcho

Thanks for helping improve `WinQuicEcho` — a C++ QUIC echo benchmark used to compare backend implementations on Windows.

## Quick Start

```pwsh
git clone https://github.com/<your-username>/WinQuicEcho.git
cd WinQuicEcho
git checkout -b feature/my-change
mkdir build
cd build
cmake -S .. -B . -A x64
cmake --build . --config Release
```

## Guidelines

- Keep changes focused and minimal.
- Follow existing code style and naming.
- Prefer benchmark-safe changes (avoid adding heavy dependencies).
- Update docs when behavior or usage changes.

## Validation

Before opening a PR:

- Build successfully with CMake on Windows.
- Run any available tests/checks for changed behavior.
- Include concise reproduction and verification notes in the PR.

## Commit Messages

Use short, clear commits, for example:

- `feat: add backend selection flag`
- `fix: handle connection shutdown event`
- `docs: update benchmark usage`

## Pull Request Checklist

- [ ] Branch is up to date with `master`
- [ ] Build succeeds locally
- [ ] Relevant tests/checks executed
- [ ] Documentation updated (if needed)
