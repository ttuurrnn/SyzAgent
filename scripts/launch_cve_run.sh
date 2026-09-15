#!/usr/bin/env bash
# Single-instance CVE directed-fuzz launcher.
#
# Usage: scripts/launch_cve_run.sh CVE-YYYY-NNNNN [hours_per_round] [j] [agent_rounds]
# Env:   FROM_STAGE=  COMMIT_OVERRIDE=  FUNC_OVERRIDE=  FILE_OVERRIDE=
#        VERIFY_PATCH=1  RUN_TAG=<label>  SYZDIRECT_LINUX_TEMPLATE=/path/to/linux.git
#        XI=<n>       (execution index; 0=proactive-seed, 1+=plain agent-loop)
set -euo pipefail

CVE="${1:?usage: $0 CVE-YYYY-NNNNN [hours_per_round] [j] [agent_rounds]}"
HOURS="${2:-1}"
J="${3:-8}"
AGENT_ROUNDS="${4:-10}"
FROM_STAGE="${FROM_STAGE:-}"
CONFIG_OVERRIDE="${CONFIG_OVERRIDE:-}"
COMMIT_OVERRIDE="${COMMIT_OVERRIDE:-}"
FUNC_OVERRIDE="${FUNC_OVERRIDE:-}"
FILE_OVERRIDE="${FILE_OVERRIDE:-}"
VERIFY_PATCH="${VERIFY_PATCH:-}"
XI="${XI:-0}"
RUN_TAG="${RUN_TAG:-}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME_BASE="${SYZDIRECT_RUNTIME:-$REPO_ROOT/.runtime/cve}"
WORKDIR_NAME="${CVE,,}"
WORKDIR_NAME="${WORKDIR_NAME//-/_}"
if [ -n "$RUN_TAG" ]; then
    SAFE_TAG="${RUN_TAG//[^A-Za-z0-9_.-]/_}"
    WORKDIR_NAME="${WORKDIR_NAME}__${SAFE_TAG}"
fi
WORKDIR="$RUNTIME_BASE/$WORKDIR_NAME"
LOGDIR="$RUNTIME_BASE/logs"
mkdir -p "$WORKDIR" "$LOGDIR"
DEFAULT_GEMINI_CMD="$REPO_ROOT/scripts/gemini_cli.sh"
DEFAULT_CODEX_CMD="$REPO_ROOT/scripts/codex_cli.sh"
LOOKUP_CURATED="$REPO_ROOT/scripts/lookup_curated_cve.py"
SAFE_CVE_NAME="${CVE,,}"
SAFE_CVE_NAME="${SAFE_CVE_NAME//-/_}"
CANONICAL_WORKDIR="$RUNTIME_BASE/$SAFE_CVE_NAME"
SYZDIRECT_LINUX_TEMPLATE="${SYZDIRECT_LINUX_TEMPLATE:-}"

DEFAULT_VM_IMAGE="$REPO_ROOT/.runtime/images/bullseye.qcow2"
DEFAULT_SSH_KEY="$REPO_ROOT/.runtime/images/bullseye.id_rsa"

unset LLM_DECISION_CMD OPENCODE_MODEL OPENCODE_VARIANT
export SYZDIRECT_LLM_BACKEND="${SYZDIRECT_LLM_BACKEND:-auto}"
export SYZDIRECT_CODEX_MODEL="${SYZDIRECT_CODEX_MODEL:-gpt-5.4}"
export SYZDIRECT_CODEX_CMD="${SYZDIRECT_CODEX_CMD:-$DEFAULT_CODEX_CMD}"
export SYZDIRECT_CODEX_SANDBOX="${SYZDIRECT_CODEX_SANDBOX:-read-only}"
export SYZDIRECT_GEMINI_MODEL="${SYZDIRECT_GEMINI_MODEL:-gemini-2.5-pro}"
export SYZDIRECT_GEMINI_CMD="${SYZDIRECT_GEMINI_CMD:-$DEFAULT_GEMINI_CMD}"
export SYZDIRECT_LLM_MODEL="${SYZDIRECT_LLM_MODEL:-qwen2.5-coder:14b}"
export SYZDIRECT_OLLAMA_URL="${SYZDIRECT_OLLAMA_URL:-http://localhost:11434}"
export GEMINI_CLI_TRUST_WORKSPACE="${GEMINI_CLI_TRUST_WORKSPACE:-true}"
export SYZDIRECT_RUNTIME="$RUNTIME_BASE"
export SYZDIRECT_VM_IMAGE="${SYZDIRECT_VM_IMAGE:-$DEFAULT_VM_IMAGE}"
export SYZDIRECT_SSH_KEY="${SYZDIRECT_SSH_KEY:-$DEFAULT_SSH_KEY}"
export SYZDIRECT_FUZZER_DIR="$REPO_ROOT/deps/SyzDirect/source/syzdirect/syzdirect_fuzzer"
export LD_LIBRARY_PATH="$HOME/ollama/lib/ollama:/usr/lib/wsl/lib:${LD_LIBRARY_PATH:-}"

# Ensure fuzzer binaries are built before pipeline starts
if [ ! -f "$SYZDIRECT_FUZZER_DIR/bin/syz-manager" ]; then
    echo "[launch] syz-manager missing — rebuilding fuzzer binaries..."
    (cd "$SYZDIRECT_FUZZER_DIR" && make) || { echo "[launch] ERROR: failed to build fuzzer"; exit 1; }
fi
export PATH="$HOME/ollama/bin:$PATH"

if { [ -z "$COMMIT_OVERRIDE" ] || [ -z "$FUNC_OVERRIDE" ] || [ -z "$FILE_OVERRIDE" ]; } && [ -f "$LOOKUP_CURATED" ]; then
    if CURATED_JSON="$(python3 "$LOOKUP_CURATED" --cve "$CVE" 2>/dev/null)"; then
        readarray -t CURATED_FIELDS < <(python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
if sys.argv[1] == "1":
    print(data.get("fix_commit", "") or "")
else:
    print(data.get("checkout_commit", "") or data.get("fix_commit", "") or "")
print(data.get("function", "") or "")
print(data.get("file", "") or "")
' "${VERIFY_PATCH:+1}" <<<"$CURATED_JSON")
        [ -z "$COMMIT_OVERRIDE" ] && COMMIT_OVERRIDE="${CURATED_FIELDS[0]:-}"
        [ -z "$FUNC_OVERRIDE" ] && FUNC_OVERRIDE="${CURATED_FIELDS[1]:-}"
        [ -z "$FILE_OVERRIDE" ] && FILE_OVERRIDE="${CURATED_FIELDS[2]:-}"
    fi
fi

if [ -z "$SYZDIRECT_LINUX_TEMPLATE" ]; then
    candidate="$RUNTIME_BASE/$SAFE_CVE_NAME/srcs/case_0"
    if [ "$candidate" != "$WORKDIR/srcs/case_0" ] && [ -d "$candidate/.git" ]; then
        SYZDIRECT_LINUX_TEMPLATE="$candidate"
    fi
fi

proactive_flag=()
# Skip auto proactive-seed generation when caller supplied a hand-crafted
# seed corpus — otherwise the pipeline's semantic/llm-seed paths overwrite
# the user's seed in agent_round_1/corpus.db.
if [ "$XI" = "0" ] && [ -z "${SEED_CORPUS_OVERRIDE:-}" ]; then
    proactive_flag=(--proactive-seed)
fi

echo "[launch] CVE=$CVE  xi=$XI  ${HOURS}h×${AGENT_ROUNDS}rounds=$(( HOURS * AGENT_ROUNDS ))h+  cpus=$J"
echo "[launch] workdir=$WORKDIR"
if [ -n "$RUN_TAG" ]; then
    echo "[launch] run_tag=$RUN_TAG"
fi
echo "[launch] proactive=$([ ${#proactive_flag[@]} -gt 0 ] && echo yes || echo no)"
if [ "${SYZDIRECT_LLM_BACKEND}" = "gemini" ]; then
    if ! "$SYZDIRECT_GEMINI_CMD" --version >/dev/null 2>&1; then
        echo "[launch] gemini CLI is unavailable. Checked SYZDIRECT_GEMINI_CMD=$SYZDIRECT_GEMINI_CMD" >&2
        exit 2
    fi
    if [ -z "${GEMINI_API_KEY:-}" ] && [ -z "${GOOGLE_API_KEY:-}" ]; then
        echo "[launch] warning: no Gemini API key / Vertex API key configured." >&2
        echo "[launch] Headless Gemini may stop for interactive auth. Probe with:" >&2
        echo "[launch]   python3 scripts/check_gemini_headless.py" >&2
    fi
    echo "[launch] llm=gemini:${SYZDIRECT_GEMINI_MODEL:-default}"
elif [ "${SYZDIRECT_LLM_BACKEND}" = "codex" ]; then
    if ! "$SYZDIRECT_CODEX_CMD" --version >/dev/null 2>&1; then
        echo "[launch] codex CLI is unavailable. Checked SYZDIRECT_CODEX_CMD=$SYZDIRECT_CODEX_CMD" >&2
        exit 2
    fi
    echo "[launch] llm=codex:${SYZDIRECT_CODEX_MODEL:-gpt-5.4}"
else
    echo "[launch] llm=${SYZDIRECT_LLM_BACKEND}:$SYZDIRECT_LLM_MODEL"
fi
if [ -n "$SYZDIRECT_LINUX_TEMPLATE" ]; then
    echo "[launch] linux_template=$SYZDIRECT_LINUX_TEMPLATE"
fi

cd "$REPO_ROOT/source/syzdirect/Runner"
extra=()
[ -n "$FROM_STAGE" ]      && extra+=(--from-stage "$FROM_STAGE")
[ -n "$CONFIG_OVERRIDE" ] && extra+=(--config "$CONFIG_OVERRIDE")
[ -n "$SYZDIRECT_LINUX_TEMPLATE" ] && extra+=(--linux-template "$SYZDIRECT_LINUX_TEMPLATE")
[ -n "$COMMIT_OVERRIDE" ] && extra+=(--commit "$COMMIT_OVERRIDE")
[ -n "$FUNC_OVERRIDE" ]   && extra+=(--function "$FUNC_OVERRIDE")
[ -n "$FILE_OVERRIDE" ]   && extra+=(--file "$FILE_OVERRIDE")
[ -n "$VERIFY_PATCH" ]    && extra+=(--verify-patch)
[ -n "${SEED_CORPUS_OVERRIDE:-}" ] && extra+=(--seed-corpus "$SEED_CORPUS_OVERRIDE")

exec python3 -u run_hunt.py new \
    --cve "$CVE" \
    -workdir "$WORKDIR" \
    -j "$J" \
    -uptime "$HOURS" \
    --agent-rounds "$AGENT_ROUNDS" \
    --agent-uptime "$HOURS" \
    --hunt-mode hybrid \
    --xi "$XI" \
    "${proactive_flag[@]}" \
    "${extra[@]}"
