#!/bin/bash
# SyzDirect Environment Setup Script
# Clone 후 이 스크립트를 실행하면 파이프라인 실행에 필요한 모든 빌드를 수행합니다.
#
# Usage: ./scripts/setup.sh [--jobs N]
#   --jobs N : 병렬 빌드 수 (기본: 물리 코어의 절반, OOM 방지)
#
# 필요 조건:
#   - Ubuntu 20.04+ / Debian 11+
#   - 최소 32GB RAM (48GB+ 권장), 50GB+ 디스크
#   - sudo 권한 (의존성 설치)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/source"
SYZDIRECT_DIR="$SOURCE_DIR/syzdirect"

# Parse arguments
JOBS=$(( $(nproc) / 2 ))
[ "$JOBS" -lt 2 ] && JOBS=2
while [[ $# -gt 0 ]]; do
    case $1 in
        --jobs) JOBS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log() { echo -e "\n\033[1;32m[setup]\033[0m $1"; }
err() { echo -e "\n\033[1;31m[error]\033[0m $1" >&2; exit 1; }

########################################
# Step 0: Install system dependencies
########################################
log "Step 0: Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential cmake ninja-build git \
    python3 python3-pip \
    golang-go \
    libelf-dev libssl-dev flex bison bc \
    qemu-system-x86 debootstrap \
    wget curl lld \
    2>/dev/null

pip3 install --quiet pandas openpyxl 2>/dev/null || true

########################################
# Step 1: Download and build LLVM 18.1.8 with SyzDirect patches
########################################
LLVM_DIR="$SOURCE_DIR/llvm-project-18.1.8.src"
LLVM_LINK="$SOURCE_DIR/llvm-project-new"
PATCH_FILE="$SYZDIRECT_DIR/llvm18_patches/syzdirect_llvm18.patch"

if [ -f "$LLVM_DIR/build/bin/clang" ]; then
    log "Step 1: LLVM 18.1.8 already built, skipping."
else
    log "Step 1: Downloading LLVM 18.1.8..."
    cd "$SOURCE_DIR"

    if [ ! -d "$LLVM_DIR" ]; then
        TARBALL="llvm-project-18.1.8.src.tar.xz"
        if [ ! -f "$TARBALL" ]; then
            wget -q --show-progress \
                "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/$TARBALL"
        fi
        log "Extracting LLVM source..."
        tar xf "$TARBALL"
        rm -f "$TARBALL"
    fi

    # Apply SyzDirect patches
    if [ -f "$PATCH_FILE" ]; then
        log "Applying SyzDirect patches to LLVM..."
        cd "$LLVM_DIR"
        patch -p0 --forward < "$PATCH_FILE" || {
            log "Patches may already be applied, continuing..."
        }
    else
        err "Patch file not found: $PATCH_FILE"
    fi

    # Build LLVM
    log "Building LLVM 18.1.8 (this may take 30-60 minutes)..."
    mkdir -p "$LLVM_DIR/build"
    cd "$LLVM_DIR/build"
    cmake -G Ninja ../llvm \
        -DLLVM_ENABLE_PROJECTS="clang;lld" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_ENABLE_ASSERTIONS=ON \
        -DLLVM_USE_LINKER=lld \
        2>&1 | tail -5

    ninja -j"$JOBS" 2>&1 | tail -20
    [ -f bin/clang ] || err "LLVM build failed"
    log "LLVM build complete."
fi

# Create symlink
ln -sfn "$LLVM_DIR" "$LLVM_LINK"
log "Symlink: llvm-project-new -> $(basename "$LLVM_DIR")"

########################################
# Step 2: Build interface_generator (syzdirect_function_model)
########################################
FM_DIR="$SYZDIRECT_DIR/syzdirect_function_model"
FM_BIN="$FM_DIR/build/lib/interface_generator"

if [ -f "$FM_BIN" ]; then
    log "Step 2: interface_generator already built, skipping."
else
    log "Step 2: Building interface_generator..."
    cd "$FM_DIR"
    mkdir -p build && cd build
    cmake ../src \
        -DLLVM_DIR="$LLVM_DIR/build/lib/cmake/llvm" \
        -DCMAKE_CXX_FLAGS="-std=c++17" \
        2>&1 | tail -5
    make -j"$JOBS" 2>&1 | tail -10
    [ -f lib/interface_generator ] || err "interface_generator build failed"
    log "interface_generator build complete."
fi

########################################
# Step 3: Build target_analyzer (syzdirect_kernel_analysis)
########################################
KA_DIR="$SYZDIRECT_DIR/syzdirect_kernel_analysis"
KA_BIN="$KA_DIR/build/lib/target_analyzer"

if [ -f "$KA_BIN" ]; then
    log "Step 3: target_analyzer already built, skipping."
else
    log "Step 3: Building target_analyzer..."
    cd "$KA_DIR"
    mkdir -p build && cd build
    cmake ../src \
        -DLLVM_DIR="$LLVM_DIR/build/lib/cmake/llvm" \
        -DCMAKE_CXX_FLAGS="-std=c++17" \
        2>&1 | tail -5
    make -j"$JOBS" 2>&1 | tail -10
    [ -f lib/target_analyzer ] || err "target_analyzer build failed"
    log "target_analyzer build complete."
fi

########################################
# Step 4: Build syzkaller fuzzer
########################################
FUZZER_DIR="$SYZDIRECT_DIR/syzdirect_fuzzer"
SYZ_MANAGER="$FUZZER_DIR/bin/syz-manager"

if [ -f "$SYZ_MANAGER" ]; then
    log "Step 4: syzkaller fuzzer already built, skipping."
else
    log "Step 4: Building syzkaller fuzzer..."
    cd "$FUZZER_DIR"
    if [ -f Makefile ]; then
        make -j"$JOBS" 2>&1 | tail -10
        [ -f bin/syz-manager ] || err "syzkaller build failed"
        log "syzkaller build complete."
    else
        log "WARNING: syzkaller Makefile not found. Manual build required."
        log "  Original syzkaller commit: a371c43c33b6f901421f93b655442363c072d251"
        log "  See source/README.md for details."
    fi
fi

########################################
# Step 5: Verify
########################################
log "Verifying installation..."

PASS=true
check() {
    if [ -f "$1" ]; then
        echo "  [OK] $2"
    else
        echo "  [MISSING] $2: $1"
        PASS=false
    fi
}

check "$LLVM_DIR/build/bin/clang"     "clang 18.1.8"
check "$FM_BIN"                        "interface_generator"
check "$KA_BIN"                        "target_analyzer"
check "$SYZ_MANAGER"                   "syz-manager"

if $PASS; then
    log "All components built successfully!"
    log ""
    log "Usage:"
    log "  cd source/syzdirect/Runner"
    log "  python3 run_hunt.py new --cve CVE-XXXX-XXXXX"
    log ""
    log "See README.md for full documentation."
else
    err "Some components are missing. Check the output above."
fi
