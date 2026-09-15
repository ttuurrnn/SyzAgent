#!/usr/bin/env bash
set -euo pipefail

if command -v codex >/dev/null 2>&1; then
    exec codex "$@"
fi

echo "codex CLI not found. Install Codex CLI or set SYZDIRECT_CODEX_CMD." >&2
exit 127
