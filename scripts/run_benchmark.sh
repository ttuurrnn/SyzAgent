#!/bin/bash
#
# run_benchmark.sh - 실제 퍼징 벤치마크 실행 스크립트
#
# Usage:
#   ./run_benchmark.sh version-a [options]    # 논문 기반
#   ./run_benchmark.sh version-b [options]    # syzkaller 정의 기반
#   ./run_benchmark.sh both [options]         # 둘 다
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="/work"
SYZDIRECT_DIR="${WORK_DIR}/SyzDirect"
SYZKALLER_DIR="${WORK_DIR}/syzkaller"
LINUX_BUILD="${WORK_DIR}/linux-build"
IMAGES_DIR="${WORK_DIR}/images"
RUNS_DIR="${WORK_DIR}/runs"

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Usage: $0 <version> [options]

Versions:
  version-a     논문 기반 벤치마크 (21개 타깃)
  version-b     Syzkaller 정의 기반 (자동 추출)
  both          둘 다 실행

Options:
  --timeout SECONDS     타깃당 타임아웃 (기본: 1800초 = 30분)
  --per-level N         Version B: 레벨당 타깃 수 (기본: 3)
  --levels L1 L2 ...    Version B: 특정 레벨만
  --filter R1/R2/R3     Version A: 특정 실패 유형만
  --parse-only          Version B: 파싱만 (퍼징 안함)
  --list                타깃 목록만 출력
  --skip-check          환경 체크 스킵
  --help                이 도움말

Examples:
  $0 version-a --timeout 3600
  $0 version-b --per-level 5 --levels 4 5 6
  $0 both --timeout 1800
EOF
    exit 1
}

check_environment() {
    log_info "환경 체크 중..."
    
    local errors=0
    
    # syzkaller 빌드 확인
    if [[ -x "${SYZKALLER_DIR}/bin/syz-manager" ]]; then
        log_ok "syzkaller 빌드됨"
    else
        log_warn "syzkaller 빌드 안됨 → 시뮬레이션 모드"
        errors=$((errors + 1))
    fi
    
    # 커널 빌드 확인
    if [[ -f "${LINUX_BUILD}/vmlinux" ]]; then
        log_ok "커널 빌드됨"
    else
        log_warn "커널 빌드 안됨 → 시뮬레이션 모드"
        errors=$((errors + 1))
    fi
    
    # VM 이미지 확인
    if [[ -f "${IMAGES_DIR}/bullseye.img" ]]; then
        log_ok "VM 이미지 있음"
    else
        log_warn "VM 이미지 없음 → 시뮬레이션 모드"
        errors=$((errors + 1))
    fi
    
    # Python 모듈 확인
    if python3 -c "import json, subprocess, dataclasses" 2>/dev/null; then
        log_ok "Python 환경 정상"
    else
        log_error "Python 환경 문제"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -gt 2 ]]; then
        log_warn "일부 환경이 준비되지 않아 시뮬레이션 모드로 실행됩니다."
        log_warn "실제 퍼징을 위해 다음을 실행하세요:"
        echo "  cd ${SYZDIRECT_DIR} && ./scripts/setup_environment.sh"
    fi
    
    return 0
}

run_version_a() {
    log_info "Version A: 논문 기반 벤치마크 실행"
    
    local timeout="${1:-1800}"
    local filter="$2"
    local list_only="$3"
    
    cd "${SYZDIRECT_DIR}"
    
    local cmd="python3 source/benchmark/paper_benchmark.py"
    
    if [[ "$list_only" == "true" ]]; then
        $cmd --list
        return
    fi
    
    cmd="$cmd --run --timeout $timeout"
    
    if [[ -n "$filter" ]]; then
        cmd="$cmd --filter $filter"
    fi
    
    log_info "실행: $cmd"
    eval $cmd
}

run_version_b() {
    log_info "Version B: Syzkaller 정의 기반 벤치마크 실행"
    
    local timeout="${1:-1800}"
    local per_level="${2:-3}"
    local levels="$3"
    local parse_only="$4"
    
    cd "${SYZDIRECT_DIR}"
    
    local cmd="python3 source/benchmark/syzkaller_benchmark.py"
    cmd="$cmd --syzkaller ${SYZKALLER_DIR}"
    
    if [[ "$parse_only" == "true" ]]; then
        $cmd --parse
        return
    fi
    
    cmd="$cmd --run --timeout $timeout --per-level $per_level"
    
    if [[ -n "$levels" ]]; then
        cmd="$cmd --levels $levels"
    fi
    
    log_info "실행: $cmd"
    eval $cmd
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    local version="$1"
    shift
    
    # 옵션 파싱
    local timeout=1800
    local per_level=3
    local levels=""
    local filter=""
    local parse_only=false
    local list_only=false
    local skip_check=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --per-level)
                per_level="$2"
                shift 2
                ;;
            --levels)
                shift
                while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                    levels="$levels $1"
                    shift
                done
                ;;
            --filter)
                filter="$2"
                shift 2
                ;;
            --parse-only)
                parse_only=true
                shift
                ;;
            --list)
                list_only=true
                shift
                ;;
            --skip-check)
                skip_check=true
                shift
                ;;
            --help)
                usage
                ;;
            *)
                log_error "알 수 없는 옵션: $1"
                usage
                ;;
        esac
    done
    
    # 환경 체크
    if [[ "$skip_check" != "true" ]]; then
        check_environment
    fi
    
    echo ""
    echo "======================================================================"
    echo "  SyzDirect Benchmark Runner"
    echo "======================================================================"
    echo "  Version:     $version"
    echo "  Timeout:     ${timeout}초/타깃"
    echo "  Output:      ${RUNS_DIR}/"
    echo "======================================================================"
    echo ""
    
    case "$version" in
        version-a|a|A)
            run_version_a "$timeout" "$filter" "$list_only"
            ;;
        version-b|b|B)
            run_version_b "$timeout" "$per_level" "$levels" "$parse_only"
            ;;
        both)
            log_info "=== Version A 실행 ==="
            run_version_a "$timeout" "$filter" "$list_only"
            
            echo ""
            log_info "=== Version B 실행 ==="
            run_version_b "$timeout" "$per_level" "$levels" "$parse_only"
            ;;
        *)
            log_error "알 수 없는 버전: $version"
            usage
            ;;
    esac
    
    log_info "벤치마크 완료!"
    log_info "결과 위치:"
    echo "  - Version A: ${RUNS_DIR}/paper_benchmark/"
    echo "  - Version B: ${RUNS_DIR}/syzkaller_benchmark/"
}

main "$@"
