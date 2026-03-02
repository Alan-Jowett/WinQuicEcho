<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 WinQuicEcho contributors
-->

This repository uses GitHub Copilot and coding agents.

Contributor guidance:

- Keep responses concise and code-focused.
- Prefer small, targeted edits over broad refactors.
- Preserve benchmark behavior and defaults unless explicitly requested.
- Validate changes by building and running relevant checks before proposing commits.

Agent requirements:

- Do not commit code without local validation output.
- When changing runtime behavior, include a short note on impact to benchmark comparability.
- Keep backend interfaces stable and backend-neutral.
