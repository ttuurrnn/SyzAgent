#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL_BIN="$REPO_ROOT/.runtime/gemini-cli/node_modules/.bin/gemini"

if [ -x "$LOCAL_BIN" ]; then
    if [ -f "$HOME/.nvm/nvm.sh" ]; then
        # Gemini CLI currently requires Node 20+.
        # Use the user's nvm-managed Node when available so the launcher does
        # not depend on the system node version.
        # shellcheck disable=SC1090
        source "$HOME/.nvm/nvm.sh" >/dev/null 2>&1
        nvm use 20 >/dev/null 2>&1 || true
    fi
    exec "$LOCAL_BIN" "$@"
fi

if command -v gemini >/dev/null 2>&1; then
    exec gemini "$@"
fi

echo "gemini CLI not found. Install @google/gemini-cli or set SYZDIRECT_GEMINI_CMD." >&2
exit 127
