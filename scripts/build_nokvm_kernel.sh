#!/bin/bash
set -e

CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang
SRC=/work/syzdirect_workdir/srcs/case_2
BUILD=/work/syzdirect_workdir/nokvm_build

echo "[1] 빌드 디렉토리 준비..."
mkdir -p "$BUILD"
cp /work/nokvm_kernel.config "$BUILD/.config"

echo "[2] olddefconfig 적용..."
cd "$SRC"
make ARCH=x86_64 CC="$CLANG" O="$BUILD" olddefconfig 2>&1 | tail -5

echo "[3] 비활성화 옵션 재확인..."
grep -E "SLUB_DEBUG|DEBUG_OBJECTS|DEBUG_LIST|FAILSLAB" "$BUILD/.config" | head -10

echo "[4] KCOV 확인..."
grep "^CONFIG_KCOV" "$BUILD/.config"

echo "[5] 커널 빌드 시작 (1-2시간 소요)..."
make ARCH=x86_64 CC="$CLANG" O="$BUILD" -j$(nproc) 2>&1 | tee /tmp/nokvm_build.log | tail -f &
BUILD_PID=$!
echo "빌드 PID: $BUILD_PID"
echo "로그: /tmp/nokvm_build.log"
echo "tail -f /tmp/nokvm_build.log 로 진행 확인 가능"
wait $BUILD_PID
BUILD_EXIT=$?

if [ $BUILD_EXIT -eq 0 ]; then
    echo "[완료] 빌드 성공!"
    ls -lh "$BUILD/arch/x86/boot/bzImage"
    cp "$BUILD/arch/x86/boot/bzImage" /work/syzdirect_workdir/instrumented/case_2/bzImage_nokvm
    cp "$BUILD/vmlinux" /work/syzdirect_workdir/instrumented/case_2/vmlinux_nokvm
    echo "출력: bzImage_nokvm, vmlinux_nokvm"
else
    echo "[실패] 빌드 에러 (exit: $BUILD_EXIT)"
    tail -20 /tmp/nokvm_build.log
fi
