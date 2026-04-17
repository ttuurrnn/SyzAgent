#!/bin/bash
#
# SyzDirect Experiment Runner
#
# Runs experiments with different configurations and collects results.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WORK_DIR="${WORK_DIR:-$REPO_ROOT/.runtime/manual}"
SYZDIRECT_DIR="${SYZDIRECT_DIR:-$REPO_ROOT}"
SCRIPTS_DIR="$SYZDIRECT_DIR/scripts"
SOURCE_DIR="$SYZDIRECT_DIR/source"
BASELINE_SYZKALLER_DIR="${BASELINE_SYZKALLER_DIR:-$REPO_ROOT/deps/syzkaller}"
SYZDIRECT_FUZZER_DIR="${SYZDIRECT_FUZZER_DIR:-$REPO_ROOT/deps/SyzDirect/source/syzdirect/syzdirect_fuzzer}"
KERNEL_SRC_DIR="${KERNEL_SRC_DIR:-$WORK_DIR/linux-src}"
KERNEL_BUILD_DIR="${KERNEL_BUILD_DIR:-$WORK_DIR/linux-build}"
IMAGE_DIR="${IMAGE_DIR:-$WORK_DIR/images}"
IMAGE_PATH="${IMAGE_PATH:-$IMAGE_DIR/bullseye.qcow2}"
SSHKEY_PATH="${SSHKEY_PATH:-$IMAGE_DIR/bullseye.id_rsa}"
HIT_INDEX="${HIT_INDEX:-0}"
VM_CPU="${VM_CPU:-1}"
KERNEL_CMDLINE_EXTRA="${KERNEL_CMDLINE_EXTRA:-maxcpus=1 net.ifnames=0 biosdevname=0}"
AGENT_CHECK_INTERVAL="${AGENT_CHECK_INTERVAL:-300}"
AGENT_MAX_INTERVENTIONS="${AGENT_MAX_INTERVENTIONS:-5}"
LLM_DECISION_CMD="${LLM_DECISION_CMD:-}"

mkdir -p "$WORK_DIR"

maybe_enable_kvm() {
    [ -e /dev/kvm ] || return 1
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        return 0
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        return 1
    fi
    if sudo -n chmod a+rw /dev/kvm >/dev/null 2>&1 && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        return 0
    fi
    if [ -n "${SUDO_PASSWORD:-}" ]; then
        if printf '%s\n' "$SUDO_PASSWORD" | sudo -S chmod a+rw /dev/kvm >/dev/null 2>&1 &&
            [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
            return 0
        fi
    fi
    printf '[WARN] /dev/kvm exists but is not accessible; falling back to TCG\n' >&2
    return 1
}

if [ -z "${QEMU_ARGS+x}" ]; then
    if maybe_enable_kvm; then
        QEMU_ARGS="-enable-kvm -cpu host,migratable=off"
    else
        QEMU_ARGS="-accel tcg -cpu max"
    fi
fi

# Default parameters
EXPERIMENT_TYPE="${1:-baseline}"  # baseline, syzdirect, agent-loop
TARGET_FILE="${2:-}"
BUDGET_HOURS="${3:-1}"
REPETITIONS="${4:-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

json_field() {
    local file="$1"
    local path="$2"
    local default_value="${3:-}"
    python3 - "$file" "$path" "$default_value" <<'PY'
import json
import sys

file_path, field_path, default = sys.argv[1:4]
try:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print(default)
    raise SystemExit(0)

value = data
if field_path:
    for key in field_path.split("."):
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            value = None
            break

if value is None:
    value = default

if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
PY
}

json_template_count() {
    local file="$1"
    python3 - "$file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print(0)
    raise SystemExit(0)

if isinstance(data, list):
    print(len(data))
elif isinstance(data, dict):
    if isinstance(data.get("template_count"), int):
        print(data["template_count"])
    else:
        templates = data.get("templates")
        if templates is None:
            templates = data.get("enhanced_templates")
        print(len(templates) if isinstance(templates, list) else 0)
else:
    print(0)
PY
}

ensure_nonempty_templates() {
    local template_file="$1"
    local context="$2"
    local count
    count=$(json_template_count "$template_file")
    if [ "$count" -le 0 ]; then
        log_error "$context produced no templates; refusing to start fuzzing with an empty call set"
        return 1
    fi
    return 0
}

allocate_local_port() {
    python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

get_baseline_syzkaller_dir() {
    echo "$BASELINE_SYZKALLER_DIR"
}

get_baseline_manager() {
    local root
    root="$(get_baseline_syzkaller_dir)"
    echo "$root/bin/syz-manager"
}

get_syzdirect_root() {
    local candidates=(
        "$SYZDIRECT_FUZZER_DIR"
        "$SYZDIRECT_DIR/syzdirect_fuzzer"
        "$SYZDIRECT_DIR"
    )
    for candidate in "${candidates[@]}"; do
        if [ -x "$candidate/bin/syz-manager" ]; then
            echo "$candidate"
            return
        fi
    done
    echo "$(get_baseline_syzkaller_dir)"
}

get_syzdirect_manager() {
    local root
    root="$(get_syzdirect_root)"
    echo "$root/bin/syz-manager"
}

activate_python_env() {
    source "$SYZDIRECT_DIR/venv/bin/activate" 2>/dev/null || true
}

manager_supports_callfile() {
    local manager_bin="$1"
    local syzdirect_root="$2"
    [ "$manager_bin" = "$syzdirect_root/bin/syz-manager" ]
}

write_manager_config() {
    local config_path="$1"
    local http_addr="$2"
    local workdir="$3"
    local syzkaller_root="$4"
    local include_kernel_src="${5:-false}"
    local include_hitindex="${6:-false}"

    cat > "$config_path" << EOF
{
    "target": "linux/amd64",
    "http": "$http_addr",
    "workdir": "$workdir",
    "kernel_obj": "$KERNEL_BUILD_DIR",
EOF
    if [ "$include_kernel_src" = "true" ]; then
        cat >> "$config_path" << EOF
    "kernel_src": "$KERNEL_SRC_DIR",
EOF
    fi
    cat >> "$config_path" << EOF
    "image": "$IMAGE_PATH",
    "sshkey": "$SSHKEY_PATH",
EOF
    if [ "$include_hitindex" = "true" ]; then
        cat >> "$config_path" << EOF
    "hitindex": $HIT_INDEX,
EOF
    fi
    cat >> "$config_path" << EOF
    "syzkaller": "$syzkaller_root",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$KERNEL_BUILD_DIR/bzImage",
        "cmdline": "$KERNEL_CMDLINE_EXTRA",
        "qemu_args": "$QEMU_ARGS",
        "cpu": $VM_CPU,
        "mem": 2048
    }
}
EOF
}

run_manager_session() {
    local manager_bin="$1"
    local config_path="$2"
    local log_path="$3"
    local budget_seconds="$4"
    local http_addr="$5"
    local monitor_dir="$6"
    shift 6
    local extra_args=("$@")
    local manager_pid
    local monitor_pid

    (
        timeout "${budget_seconds}s" \
            "$manager_bin" -config "$config_path" "${extra_args[@]}" \
            2>&1 | tee "$log_path"
    ) &
    manager_pid=$!

    monitor_fuzzing "$monitor_dir" "$manager_pid" "$budget_seconds" "$http_addr" &
    monitor_pid=$!

    wait "$manager_pid" || true
    kill "$monitor_pid" 2>/dev/null || true
}

MANAGER_SESSION_PID=""
MANAGER_MONITOR_PID=""

start_manager_session() {
    local manager_bin="$1"
    local config_path="$2"
    local log_path="$3"
    local budget_seconds="$4"
    local http_addr="$5"
    local monitor_dir="$6"
    shift 6
    local extra_args=("$@")

    (
        timeout "${budget_seconds}s" \
            "$manager_bin" -config "$config_path" "${extra_args[@]}" \
            2>&1 | tee "$log_path"
    ) &
    MANAGER_SESSION_PID=$!

    monitor_fuzzing "$monitor_dir" "$MANAGER_SESSION_PID" "$budget_seconds" "$http_addr" &
    MANAGER_MONITOR_PID=$!
}

remaining_budget_seconds() {
    local deadline_epoch="$1"
    local now
    now=$(date +%s)
    if [ "$deadline_epoch" -le "$now" ]; then
        echo 0
    else
        echo $((deadline_epoch - now))
    fi
}

restart_continuous_manager() {
    local manager_bin="$1"
    local config_path="$2"
    local log_path="$3"
    local deadline_epoch="$4"
    local http_addr="$5"
    local monitor_dir="$6"
    shift 6
    local extra_args=("$@")
    local remaining
    remaining=$(remaining_budget_seconds "$deadline_epoch")
    if [ "$remaining" -le 0 ]; then
        return 1
    fi
    start_manager_session \
        "$manager_bin" \
        "$config_path" \
        "$log_path" \
        "$remaining" \
        "$http_addr" \
        "$monitor_dir" \
        "${extra_args[@]}"
}

apply_intervention_templates() {
    local decision="$1"
    local source_templates="$2"
    local triage_file="$3"
    local output_dir="$4"

    local related_output="$output_dir/related_enhanced_templates.json"
    local object_output="$output_dir/object_enhanced_templates.json"

    case "$decision" in
        intervene_r1|intervene_r3)
            python3 "$SOURCE_DIR/agent/related_syscall_agent.py" \
                --templates "$source_templates" \
                --triage "$triage_file" \
                --output "$related_output"
            printf '%s\n' "$related_output"
            ;;
        intervene_r2)
            python3 "$SOURCE_DIR/agent/object_synthesis_agent.py" \
                --triage "$triage_file" \
                --templates "$source_templates" \
                --output "$object_output"
            printf '%s\n' "$object_output"
            ;;
        intervene_mixed)
            python3 "$SOURCE_DIR/agent/related_syscall_agent.py" \
                --templates "$source_templates" \
                --triage "$triage_file" \
                --output "$related_output"
            local mixed_source="$source_templates"
            if [ -f "$related_output" ] && [ "$(json_template_count "$related_output")" != "0" ]; then
                mixed_source="$related_output"
            fi
            python3 "$SOURCE_DIR/agent/object_synthesis_agent.py" \
                --triage "$triage_file" \
                --templates "$mixed_source" \
                --output "$object_output"
            if [ -f "$object_output" ] && [ "$(json_template_count "$object_output")" != "0" ]; then
                printf '%s\n' "$object_output"
            else
                printf '%s\n' "$mixed_source"
            fi
            ;;
        *)
            printf '%s\n' "$source_templates"
            ;;
    esac
}

stop_manager_session() {
    if [ -n "$MANAGER_SESSION_PID" ] && kill -0 "$MANAGER_SESSION_PID" 2>/dev/null; then
        kill "$MANAGER_SESSION_PID" 2>/dev/null || true
        wait "$MANAGER_SESSION_PID" 2>/dev/null || true
    fi
    if [ -n "$MANAGER_MONITOR_PID" ] && kill -0 "$MANAGER_MONITOR_PID" 2>/dev/null; then
        kill "$MANAGER_MONITOR_PID" 2>/dev/null || true
        wait "$MANAGER_MONITOR_PID" 2>/dev/null || true
    fi
}

wait_manager_session() {
    if [ -n "$MANAGER_SESSION_PID" ]; then
        wait "$MANAGER_SESSION_PID" 2>/dev/null || true
    fi
    if [ -n "$MANAGER_MONITOR_PID" ] && kill -0 "$MANAGER_MONITOR_PID" 2>/dev/null; then
        kill "$MANAGER_MONITOR_PID" 2>/dev/null || true
        wait "$MANAGER_MONITOR_PID" 2>/dev/null || true
    fi
}

require_target_file() {
    local target_file="$1"
    local mode_name="$2"
    if [ -n "$target_file" ]; then
        return 0
    fi
    log_error "Target file required for $mode_name"
    exit 1
}

target_has_source_location() {
    local target_file="$1"
    local target_path
    local target_line
    target_path=$(json_field "$target_file" "file_path" "")
    target_line=$(json_field "$target_file" "line" "0")
    [ -n "$target_path" ] && [ "$target_path" != "null" ] && [ "$target_line" != "0" ]
}

create_empty_distance_file() {
    local target_file="$1"
    local output_file="$2"
    local target_id
    target_id=$(json_field "$target_file" "target_id" "unknown")
    cat > "$output_file" << EOF
{
  "format_version": 1,
  "target_id": "$target_id",
  "target_file": "",
  "target_line": 0,
  "bb_distances": {},
  "bb_metadata": {},
  "func_distances": {},
  "syscall_entry_distances": {},
  "runtime_distance_map": {}
}
EOF
}

run_static_analysis() {
    local target_file="$1"
    local output_file="$2"
    local log_file="$3"
    python3 "$SOURCE_DIR/analyzer/syscall_analyzer.py" \
        --kernel "$KERNEL_SRC_DIR" \
        --target "$target_file" \
        --output "$output_file" \
        2>&1 | tee "$log_file"
}

run_distance_analysis() {
    local target_file="$1"
    local output_file="$2"
    local log_file="$3"
    local target_path
    local target_line
    local target_func
    
    if ! target_has_source_location "$target_file"; then
        log_warn "Target spec has no file_path/line; writing empty distance map"
        create_empty_distance_file "$target_file" "$output_file"
        printf '%s\n' "[WARN] No source location in target spec, skipped distance calculation" > "$log_file"
        return 0
    fi
    
    target_path=$(json_field "$target_file" "file_path" "")
    target_line=$(json_field "$target_file" "line" "0")
    target_func=$(json_field "$target_file" "function" "")
    
    local cmd=(
        python3 "$SOURCE_DIR/distance/distance_calculator.py"
        --kernel "$KERNEL_SRC_DIR"
        --target-file "$target_path"
        --target-line "$target_line"
        --output "$output_file"
    )
    if [ -n "$target_func" ] && [ "$target_func" != "null" ]; then
        cmd+=(--target-func "$target_func")
    fi
    
    "${cmd[@]}" 2>&1 | tee "$log_file"
}

prepare_syzkaller_runtime() {
    local base_root="$1"
    local runtime_root="$2"
    local seed_dir="$3"
    
    mkdir -p "$runtime_root"
    cp -as "$base_root"/. "$runtime_root"/ 2>/dev/null || true
    mkdir -p "$runtime_root/sys/linux/test"
    
    if [ -d "$seed_dir" ]; then
        find "$seed_dir" -maxdepth 1 -type f -name '*.syz' -exec cp {} "$runtime_root/sys/linux/test/" \;
    fi
}

prepare_template_artifacts() {
    local template_file="$1"
    local artifact_dir="$2"
    local syzkaller_root="$3"
    
    mkdir -p "$artifact_dir/programs"
    python3 "$SOURCE_DIR/template/template_generator.py" \
        --templates "$template_file" \
        --callfile-output "$artifact_dir/callfile.json" \
        --program-output "$artifact_dir/programs"
    
    prepare_syzkaller_runtime "$syzkaller_root" "$artifact_dir/runtime-syzkaller" "$artifact_dir/programs"
}

#
# Run baseline syzkaller (non-directed)
#
run_baseline_syzkaller() {
    local target_id="$1"
    local budget_seconds="$2"
    local run_dir="$WORK_DIR/runs/baseline-syzkaller/${target_id}_$(date +%Y%m%d_%H%M%S)"
    local syzkaller_root
    local manager_bin
    local http_port
    local http_addr
    
    syzkaller_root="$(get_baseline_syzkaller_dir)"
    manager_bin="$(get_baseline_manager)"
    http_port="$(allocate_local_port)"
    http_addr="127.0.0.1:${http_port}"
    
    log_step "Running baseline syzkaller for $target_id"
    log_info "Budget: ${budget_seconds}s, Output: $run_dir"
    
    mkdir -p "$run_dir"

    write_manager_config \
        "$run_dir/config.cfg" \
        "$http_addr" \
        "$run_dir/workdir" \
        "$syzkaller_root" \
        false \
        false

    timeout "${budget_seconds}s" \
        "$manager_bin" -config "$run_dir/config.cfg" \
        2>&1 | tee "$run_dir/manager.log" || true
    
    # Collect results
    collect_results "$run_dir" "baseline" "$target_id"
    
    echo "$run_dir"
}

#
# Run SyzDirect (directed fuzzing)
#
run_syzdirect() {
    local target_id="$1"
    local target_file="$2"
    local budget_seconds="$3"
    local run_dir="$WORK_DIR/runs/baseline-syzdirect/${target_id}_$(date +%Y%m%d_%H%M%S)"
    local syzdirect_root
    local manager_bin
    local callfile_arg=()
    local http_port
    local http_addr
    
    syzdirect_root="$(get_syzdirect_root)"
    manager_bin="$(get_syzdirect_manager)"
    http_port="$(allocate_local_port)"
    http_addr="127.0.0.1:${http_port}"
    
    log_step "Running SyzDirect for $target_id"
    log_info "Target: $target_file"
    log_info "Budget: ${budget_seconds}s, Output: $run_dir"
    
    mkdir -p "$run_dir"/{templates,distances,logs,artifacts}
    
    activate_python_env
    
    # Step 1: Static Analysis
    log_info "Step 1: Running static analysis..."
    run_static_analysis "$target_file" "$run_dir/templates/analysis.json" "$run_dir/logs/analysis.log"
    
    # Step 2: Distance Calculation
    log_info "Step 2: Computing distances..."
    run_distance_analysis "$target_file" "$run_dir/distances/distances.json" "$run_dir/logs/distance.log"
    
    # Step 3: Template Generation
    log_info "Step 3: Generating templates..."
    python3 "$SOURCE_DIR/template/template_generator.py" \
        --analysis "$run_dir/templates/analysis.json" \
        --distances "$run_dir/distances/distances.json" \
        --output "$run_dir/templates" \
        2>&1 | tee "$run_dir/logs/template.log"
    ensure_nonempty_templates "$run_dir/templates/templates.json" "template generation"
    
    log_info "Step 3b: Preparing SyzDirect template artifacts..."
    prepare_template_artifacts "$run_dir/templates/templates.json" "$run_dir/artifacts" "$syzdirect_root"
    if manager_supports_callfile "$manager_bin" "$syzdirect_root"; then
        callfile_arg=(-callfile "$run_dir/artifacts/callfile.json")
    else
        log_warn "SyzDirect manager binary not found; running without -callfile support"
    fi
    
    # Step 4: Run directed fuzzing
    log_info "Step 4: Running directed fuzzing..."
    
    write_manager_config \
        "$run_dir/config.cfg" \
        "$http_addr" \
        "$run_dir/workdir" \
        "$run_dir/artifacts/runtime-syzkaller" \
        true \
        true

    run_manager_session \
        "$manager_bin" \
        "$run_dir/config.cfg" \
        "$run_dir/manager.log" \
        "$budget_seconds" \
        "$http_addr" \
        "$run_dir" \
        "${callfile_arg[@]}"
    
    # Collect results
    collect_results "$run_dir" "syzdirect" "$target_id"
    
    echo "$run_dir"
}

#
# Run Agent-Enhanced Loop
#
run_agent_loop() {
    local target_id="$1"
    local target_file="$2"
    local total_budget_seconds="$3"
    local max_rounds="${4:-$AGENT_MAX_INTERVENTIONS}"
    local check_interval="$AGENT_CHECK_INTERVAL"
    if [ "$check_interval" -le 0 ]; then
        check_interval=300
    fi
    
    local run_dir="$WORK_DIR/runs/agent-loop/${target_id}_$(date +%Y%m%d_%H%M%S)"
    
    log_step "Running Agent-Enhanced Loop for $target_id"
    log_info "Total budget: ${total_budget_seconds}s, Max interventions: $max_rounds"
    log_info "Check interval: ${check_interval}s"
    log_info "Output: $run_dir"
    
    mkdir -p "$run_dir"/{rounds,templates,logs,triage,distances,artifacts}
    
    activate_python_env
    
    # Initial analysis bundle
    log_info "Initial static analysis..."
    run_static_analysis "$target_file" "$run_dir/templates/initial_analysis.json" "$run_dir/logs/initial_analysis.log"
    
    log_info "Initial distance calculation..."
    run_distance_analysis "$target_file" "$run_dir/distances/initial_distances.json" "$run_dir/logs/initial_distance.log"
    
    log_info "Initial template generation..."
    python3 "$SOURCE_DIR/template/template_generator.py" \
        --analysis "$run_dir/templates/initial_analysis.json" \
        --distances "$run_dir/distances/initial_distances.json" \
        --output "$run_dir/templates" \
        2>&1 | tee "$run_dir/logs/initial_template.log"
    
    current_templates="$run_dir/templates/templates.json"
    ensure_nonempty_templates "$current_templates" "initial template generation"
    local syzdirect_root
    local manager_bin
    local http_port
    local http_addr
    local callfile_arg=()
    local llm_hook_args=()
    local intervention_count=0
    local cycle=0
    local cleanup_trap_set=0
    local deadline_epoch
    deadline_epoch=$(($(date +%s) + total_budget_seconds))

    syzdirect_root="$(get_syzdirect_root)"
    manager_bin="$(get_syzdirect_manager)"
    http_port="$(allocate_local_port)"
    http_addr="127.0.0.1:${http_port}"

    prepare_template_artifacts "$current_templates" "$run_dir/artifacts" "$syzdirect_root"
    if manager_supports_callfile "$manager_bin" "$syzdirect_root"; then
        callfile_arg=(-callfile "$run_dir/artifacts/callfile.json")
    fi
    if [ -n "$LLM_DECISION_CMD" ]; then
        llm_hook_args=(--llm-hook-cmd "$LLM_DECISION_CMD")
    fi

    write_manager_config \
        "$run_dir/config.cfg" \
        "$http_addr" \
        "$run_dir/workdir" \
        "$run_dir/artifacts/runtime-syzkaller" \
        true \
        true

    log_info "Starting continuous fuzzing manager..."
    start_manager_session \
        "$manager_bin" \
        "$run_dir/config.cfg" \
        "$run_dir/manager.log" \
        "$total_budget_seconds" \
        "$http_addr" \
        "$run_dir" \
        "${callfile_arg[@]}"
    trap 'stop_manager_session' INT TERM EXIT
    cleanup_trap_set=1

    while kill -0 "$MANAGER_SESSION_PID" 2>/dev/null; do
        sleep "$check_interval"
        if ! kill -0 "$MANAGER_SESSION_PID" 2>/dev/null; then
            break
        fi

        cycle=$((cycle + 1))
        local window_dir="$run_dir/triage/window_$cycle"
        mkdir -p "$window_dir"

        log_info "Scoring fuzzing health for window $cycle..."
        python3 "$SOURCE_DIR/agent/fuzzing_health_monitor.py" \
            --metrics "$run_dir/logs/metrics.jsonl" \
            --manager-log "$run_dir/manager.log" \
            --window-seconds "$check_interval" \
            --output "$window_dir/decision.json" \
            "${llm_hook_args[@]}" \
            --manager-alive

        local decision
        local status
        local reason
        local score
        local exec_delta
        local cover_delta
        local crash_delta
        local distance_delta
        decision=$(json_field "$window_dir/decision.json" "decision" "continue")
        status=$(json_field "$window_dir/decision.json" "status" "unknown")
        reason=$(json_field "$window_dir/decision.json" "reason" "")
        score=$(json_field "$window_dir/decision.json" "score" "0")
        exec_delta=$(json_field "$window_dir/decision.json" "exec_delta" "0")
        cover_delta=$(json_field "$window_dir/decision.json" "cover_delta" "0")
        crash_delta=$(json_field "$window_dir/decision.json" "crash_delta" "0")
        distance_delta=$(json_field "$window_dir/decision.json" "distance_delta" "n/a")
        log_info "Window $cycle health: status=$status decision=$decision score=$score exec_delta=$exec_delta cover_delta=$cover_delta crash_delta=$crash_delta distance_delta=$distance_delta"
        if [ -n "$reason" ] && [ "$reason" != "null" ]; then
            log_info "Decision reason: $reason"
        fi

        save_round_summary "$window_dir" "$cycle" "$status" "$window_dir/decision.json" ""

        if [ "$decision" = "stop" ]; then
            log_warn "Stopping continuous fuzzing after watcher decision"
            stop_manager_session
            break
        fi

        case "$decision" in
            intervene_r1|intervene_r2|intervene_r3|intervene_mixed)
                intervention_count=$((intervention_count + 1))
                if [ "$intervention_count" -gt "$max_rounds" ]; then
                    log_warn "Reached maximum intervention count ($max_rounds); stopping continuous fuzzing"
                    stop_manager_session
                    break
                fi

                log_info "Preparing intervention for decision: $decision"
                stop_manager_session
                generate_execution_logs "$run_dir" "$current_templates"

                python3 "$SOURCE_DIR/agent/failure_triage.py" \
                    --logs "$run_dir/execution_logs.json" \
                    --static-info "$current_templates" \
                    --output "$window_dir/triage_result.json" \
                    2>&1 | tee "$window_dir/triage.log"

                local intervention_target
                intervention_target=$(apply_intervention_templates \
                    "$decision" \
                    "$current_templates" \
                    "$window_dir/triage_result.json" \
                    "$window_dir")

                if [ -f "$intervention_target" ] && [ "$(json_template_count "$intervention_target")" != "0" ]; then
                    current_templates="$intervention_target"
                    rm -rf "$run_dir/artifacts"
                    prepare_template_artifacts "$current_templates" "$run_dir/artifacts" "$syzdirect_root"
                    callfile_arg=()
                    if manager_supports_callfile "$manager_bin" "$syzdirect_root"; then
                        callfile_arg=(-callfile "$run_dir/artifacts/callfile.json")
                    fi
                    write_manager_config \
                        "$run_dir/config.cfg" \
                        "$http_addr" \
                        "$run_dir/workdir" \
                        "$run_dir/artifacts/runtime-syzkaller" \
                        true \
                        true
                    if ! restart_continuous_manager \
                        "$manager_bin" \
                        "$run_dir/config.cfg" \
                        "$run_dir/manager.log" \
                        "$deadline_epoch" \
                        "$http_addr" \
                        "$run_dir" \
                        "${callfile_arg[@]}"; then
                        log_warn "No remaining budget after intervention; stopping"
                        break
                    fi
                    save_round_summary "$window_dir" "$cycle" "$decision" "$window_dir/triage_result.json" "$intervention_target"
                    continue
                fi

                log_warn "Intervention did not produce usable templates; stopping continuous fuzzing"
                save_round_summary "$window_dir" "$cycle" "$decision" "$window_dir/triage_result.json" "$intervention_target"
                break
                ;;
        esac

        if [ "$intervention_count" -ge "$max_rounds" ]; then
            log_warn "Reached maximum intervention count ($max_rounds); stopping continuous fuzzing"
            stop_manager_session
            break
        fi
    done

    wait_manager_session
    if [ "$cleanup_trap_set" -eq 1 ]; then
        trap - INT TERM EXIT
    fi
    
    # Final summary
    generate_final_report "$run_dir"
    collect_results "$run_dir" "agent-loop" "$target_id"
    
    echo "$run_dir"
}

#
# Helper: Run short fuzzing session
#
run_short_fuzz() {
    local round_dir="$1"
    local templates="$2"
    local budget="$3"
    local syzdirect_root
    local manager_bin
    local callfile_arg=()
    local http_port
    local http_addr
    
    syzdirect_root="$(get_syzdirect_root)"
    manager_bin="$(get_syzdirect_manager)"
    http_port="$(allocate_local_port)"
    http_addr="127.0.0.1:${http_port}"
    prepare_template_artifacts "$templates" "$round_dir/artifacts" "$syzdirect_root"
    if manager_supports_callfile "$manager_bin" "$syzdirect_root"; then
        callfile_arg=(-callfile "$round_dir/artifacts/callfile.json")
    fi

    write_manager_config \
        "$round_dir/config.cfg" \
        "$http_addr" \
        "$round_dir/workdir" \
        "$round_dir/artifacts/runtime-syzkaller" \
        false \
        true

    run_manager_session \
        "$manager_bin" \
        "$round_dir/config.cfg" \
        "$round_dir/manager.log" \
        "$budget" \
        "$http_addr" \
        "$round_dir" \
        "${callfile_arg[@]}"
}

#
# Helper: Generate execution logs from syzkaller output
#
generate_execution_logs() {
    local round_dir="$1"
    local templates_file="$2"
    
    python3 - "$round_dir" "$templates_file" << 'PY'
import json
import math
import re
import sys
import time
from pathlib import Path

round_dir = Path(sys.argv[1])
templates_file = Path(sys.argv[2])

def load_json(path):
    if not path.exists():
        return None
    with open(path, 'r') as f:
        return json.load(f)

template_data = load_json(templates_file) or {}
if isinstance(template_data, list):
    templates = template_data
    target_id = templates[0].get('target_id') if templates else 'unknown'
else:
    templates = template_data.get('templates') or template_data.get('enhanced_templates') or []
    target_id = template_data.get('target_id', 'unknown')

metrics = []
metrics_path = round_dir / 'logs' / 'metrics.jsonl'
if metrics_path.exists():
    with open(metrics_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                metrics.append(json.loads(line))
            except json.JSONDecodeError:
                pass

manager_log = (round_dir / 'manager.log').read_text(encoding='utf-8', errors='ignore') \
    if (round_dir / 'manager.log').exists() else ''
error_counts = {
    errno: len(re.findall(rf'\b{errno}\b', manager_log))
    for errno in ('EINVAL', 'EPERM', 'EFAULT', 'ENOENT', 'EACCES')
}
all_target_calls_disabled = 'all target calls are disabled' in manager_log.lower()

last_metrics = metrics[-1] if metrics else {}
crash_count = 0
crash_dir = round_dir / 'workdir' / 'crashes'
if crash_dir.exists():
    crash_count = sum(1 for path in crash_dir.rglob('*') if path.is_file())

logs = []
fallback_distance = 100.0
if templates:
    finite_dists = []
    for template in templates:
        dist = template.get('estimated_distance', float('inf'))
        try:
            dist = float(dist)
        except (TypeError, ValueError):
            dist = float('inf')
        if math.isfinite(dist):
            finite_dists.append(dist)
    if finite_dists:
        fallback_distance = min(finite_dists)

timestamp = int(time.time())
if not templates:
    templates = [{'template_id': f'{target_id}_template_1', 'estimated_distance': fallback_distance}]

for idx, template in enumerate(templates, 1):
    template_id = template.get('template_id', f'{target_id}_template_{idx}')
    template_distance = template.get('estimated_distance', fallback_distance)
    try:
        template_distance = float(template_distance)
    except (TypeError, ValueError):
        template_distance = fallback_distance
    if not math.isfinite(template_distance):
        template_distance = fallback_distance
    metric = metrics[min(idx - 1, len(metrics) - 1)] if metrics else {}
    logs.append({
        'timestamp': metric.get('timestamp', timestamp),
        'seed_id': f'{template_id}_seed',
        'template_id': template_id,
        'syscall_distances': {},
        'seed_distance': template_distance,
        'template_distance': template_distance,
        'reached_target': False,
        'crash': crash_count > 0,
        'fatal_error': all_target_calls_disabled,
        'errno_counts': error_counts,
        'coverage_new': bool(metric.get('exec_total', 0) or last_metrics.get('exec_total', 0)),
        'iteration': idx,
    })

with open(round_dir / 'execution_logs.json', 'w') as f:
    json.dump(logs, f, indent=2)
PY
}

#
# Helper: Check if round showed improvement
#
check_improvement() {
    local round_dir="$1"
    
    # Check triage result for improvement indicators
    local confidence
    local min_distance
    confidence=$(json_field "$round_dir/triage_result.json" "confidence" "0")
    min_distance=$(json_field "$round_dir/triage_result.json" "distance_analysis.min_distance" "999")
    
    # Simple heuristic: improvement if confidence > 0.5 or distance decreased
    if awk "BEGIN { exit !($confidence > 0.5) }"; then
        return 0
    fi
    
    if awk "BEGIN { exit !($min_distance < 25) }"; then
        return 0
    fi
    
    return 1
}

#
# Helper: Save round summary
#
save_round_summary() {
    local round_dir="$1"
    local round_num="$2"
    local failure_class="$3"
    local triage_file="${4:-$round_dir/triage_result.json}"
    local enhanced_templates="${5:-$round_dir/enhanced_templates.json}"
    
    cat > "$round_dir/summary.json" << EOF
{
    "round": $round_num,
    "failure_class": "$failure_class",
    "timestamp": "$(date -Iseconds)",
    "triage_file": "$triage_file",
    "enhanced_templates": "$enhanced_templates"
}
EOF
}

#
# Helper: Monitor fuzzing progress
#
monitor_fuzzing() {
    local run_dir="$1"
    local manager_pid="$2"
    local budget="$3"
    local http_addr="$4"
    local interval=15
    
    local elapsed=0
    while [ $elapsed -lt $budget ] && kill -0 $manager_pid 2>/dev/null; do
        sleep $interval
        elapsed=$((elapsed + interval))
        
        # Log progress
        echo "[$(date)] Elapsed: ${elapsed}s / ${budget}s" >> "$run_dir/logs/monitor.log"
        local metrics
        metrics=$(curl -fsS "http://${http_addr}/metrics" 2>/dev/null || true)
        if [ -n "$metrics" ]; then
            local exec_total corpus crashes distance_min
            exec_total=$(printf '%s\n' "$metrics" | awk '/^syz_exec_total / {print int($2)}' | tail -n 1)
            corpus=$(printf '%s\n' "$metrics" | awk '/^syz_corpus_cover / {print int($2)}' | tail -n 1)
            crashes=$(printf '%s\n' "$metrics" | awk '/^syz_crash_total / {print int($2)}' | tail -n 1)
            distance_min=$(printf '%s\n' "$metrics" | awk '
                /^syz_distance_min / {print $2}
                /^syz_dist_min / {print $2}
                /^syzgo_distance_min / {print $2}
                /^syzgo_best_distance / {print $2}
            ' | tail -n 1)
            exec_total=${exec_total:-0}
            corpus=${corpus:-0}
            crashes=${crashes:-0}
            if [ -n "$distance_min" ]; then
                printf '{"timestamp":%s,"elapsed":%s,"exec_total":%s,"corpus_cover":%s,"crashes":%s,"distance_min":%s}\n' \
                    "$(date +%s)" "$elapsed" "$exec_total" "$corpus" "$crashes" "$distance_min" >> "$run_dir/logs/metrics.jsonl"
            else
                printf '{"timestamp":%s,"elapsed":%s,"exec_total":%s,"corpus_cover":%s,"crashes":%s}\n' \
                    "$(date +%s)" "$elapsed" "$exec_total" "$corpus" "$crashes" >> "$run_dir/logs/metrics.jsonl"
            fi
        fi
    done
}

#
# Helper: Collect results
#
collect_results() {
    local run_dir="$1"
    local run_type="$2"
    local target_id="${3:-unknown}"
    local crash_count
    local corpus_count
    local live_crash_count=0
    local live_corpus_count=0
    local round_crash_count=0
    local round_corpus_count=0
    
    log_info "Collecting results for $run_type run..."
    
    if [ "$run_type" = "agent-loop" ]; then
        if [ -d "$run_dir/workdir/crashes" ]; then
            live_crash_count=$(find "$run_dir/workdir/crashes" -type f 2>/dev/null | wc -l || echo 0)
        fi
        if [ -d "$run_dir/workdir/corpus" ]; then
            live_corpus_count=$(find "$run_dir/workdir/corpus" -type f 2>/dev/null | wc -l || echo 0)
        fi
        if [ -d "$run_dir/rounds" ]; then
            round_crash_count=$(find "$run_dir/rounds" -path '*/workdir/crashes/*' -type f 2>/dev/null | wc -l || echo 0)
            round_corpus_count=$(find "$run_dir/rounds" -path '*/workdir/corpus/*' -type f 2>/dev/null | wc -l || echo 0)
        fi
        crash_count=$((live_crash_count + round_crash_count))
        corpus_count=$((live_corpus_count + round_corpus_count))
    else
        crash_count=$(find "$run_dir/workdir/crashes" -type f 2>/dev/null | wc -l || echo 0)
        corpus_count=$(find "$run_dir/workdir/corpus" -type f 2>/dev/null | wc -l || echo 0)
    fi
    
    # Create results summary
    cat > "$run_dir/results.json" << EOF
{
    "run_type": "$run_type",
    "target_id": "$target_id",
    "run_dir": "$run_dir",
    "timestamp": "$(date -Iseconds)",
    "crashes": $crash_count,
    "corpus_size": $corpus_count
}
EOF
    
    log_info "Results saved to $run_dir/results.json"
}

#
# Helper: Generate final report
#
generate_final_report() {
    local run_dir="$1"
    
    log_info "Generating final report..."
    
    python3 - "$run_dir" <<'PY'
import json
from datetime import datetime
from pathlib import Path
import sys

run_dir = Path(sys.argv[1])
rounds = []
round_dirs = list((run_dir / "rounds").glob("round_*")) + list((run_dir / "rounds").glob("cycle_*"))
round_dirs += list((run_dir / "triage").glob("window_*"))
for round_dir in sorted(round_dirs):
    summary_path = round_dir / "summary.json"
    if not summary_path.exists():
        continue
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            rounds.append(json.load(f))
    except Exception:
        continue

report = {
    "experiment_type": "agent-loop",
    "run_dir": str(run_dir),
    "timestamp": datetime.now().astimezone().isoformat(),
    "total_rounds": len(rounds),
    "rounds": rounds,
    "final_status": "complete",
}

with open(run_dir / "final_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
PY
    
    log_info "Final report saved to $run_dir/final_report.json"
}

#
# Main
#
main() {
    local target_id
    local budget_seconds

    case "$EXPERIMENT_TYPE" in
        baseline)
            require_target_file "$TARGET_FILE" "baseline"
            target_id=$(json_field "$TARGET_FILE" "target_id" "")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_baseline_syzkaller "$target_id" "$budget_seconds"
            done
            ;;
            
        syzdirect)
            require_target_file "$TARGET_FILE" "syzdirect"
            target_id=$(json_field "$TARGET_FILE" "target_id" "")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_syzdirect "$target_id" "$TARGET_FILE" "$budget_seconds"
            done
            ;;
            
        agent-loop)
            require_target_file "$TARGET_FILE" "agent-loop"
            target_id=$(json_field "$TARGET_FILE" "target_id" "")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_agent_loop "$target_id" "$TARGET_FILE" "$budget_seconds"
            done
            ;;
            
        *)
            log_error "Unknown experiment type: $EXPERIMENT_TYPE"
            echo "Usage: $0 <baseline|syzdirect|agent-loop> <target.json> [budget_hours] [repetitions]"
            exit 1
            ;;
    esac
}

main
