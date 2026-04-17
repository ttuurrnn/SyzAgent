#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Run a SyzDirect dataset case with repo-local defaults.

Usage:
  bash scripts/run_case.sh CASE_ID [extra run_dataset_case.py args]

Environment:
  RUN_CASE_CONFIG=<repo>/configs/run_case.env
  DATASET_KIND=known-bugs|patches
  MODE=agent-loop|syzdirect|baseline
  BUDGET_HOURS=1
  REPETITIONS=1
  SYZDIRECT_ROOT=<repo>/deps/SyzDirect
  OUTPUT_ROOT=<repo>/.runtime
  VM_CPU=1
  KERNEL_CMDLINE_EXTRA='maxcpus=1 net.ifnames=0 biosdevname=0'
  SUDO_PASSWORD=<optional sudo password for image build / KVM setup>
  AGENT_CHECK_INTERVAL=300
  AGENT_MAX_INTERVENTIONS=5
  LLM_DECISION_CMD=<optional watcher decision hook>
  OPENCODE_MODEL=<optional model for scripts/opencode_llm_decider.py>
  OPENCODE_VARIANT=<optional variant for scripts/opencode_llm_decider.py>
EOF
}

if [ $# -eq 0 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

CASE_ID="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_CASE_CONFIG="${RUN_CASE_CONFIG:-$REPO_ROOT/configs/run_case.env}"

restore_env_overrides() {
    local name
    for name in "$@"; do
        local flag_name="__had_${name}"
        local value_name="__value_${name}"
        if [ "${!flag_name:-0}" = "1" ]; then
            export "$name=${!value_name}"
        fi
    done
}

CONFIG_VARS=(
    DATASET_KIND
    MODE
    BUDGET_HOURS
    REPETITIONS
    SYZDIRECT_ROOT
    OUTPUT_ROOT
    VM_CPU
    KERNEL_CMDLINE_EXTRA
    SUDO_PASSWORD
    AGENT_CHECK_INTERVAL
    AGENT_MAX_INTERVENTIONS
    LLM_DECISION_CMD
    OPENCODE_MODEL
    OPENCODE_VARIANT
    OPENCODE_AGENT
    OPENCODE_DIR
)

for name in "${CONFIG_VARS[@]}"; do
    had_var="__had_${name}"
    value_var="__value_${name}"
    if [ -n "${!name+x}" ]; then
        printf -v "$had_var" '%s' 1
        printf -v "$value_var" '%s' "${!name}"
    else
        printf -v "$had_var" '%s' 0
    fi
done

if [ -f "$RUN_CASE_CONFIG" ]; then
    # shellcheck disable=SC1090
    source "$RUN_CASE_CONFIG"
    restore_env_overrides "${CONFIG_VARS[@]}"
fi

export VM_CPU="${VM_CPU:-1}"
export KERNEL_CMDLINE_EXTRA="${KERNEL_CMDLINE_EXTRA:-maxcpus=1 net.ifnames=0 biosdevname=0}"

exec python3 "$REPO_ROOT/scripts/run_dataset_case.py" \
    --case-id "$CASE_ID" \
    --dataset-kind "${DATASET_KIND:-known-bugs}" \
    --mode "${MODE:-agent-loop}" \
    --budget-hours "${BUDGET_HOURS:-1}" \
    --repetitions "${REPETITIONS:-1}" \
    --syzdirect-root "${SYZDIRECT_ROOT:-$REPO_ROOT/deps/SyzDirect}" \
    --output-root "${OUTPUT_ROOT:-$REPO_ROOT/.runtime}" \
    "$@"
