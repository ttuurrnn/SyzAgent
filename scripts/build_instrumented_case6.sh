#!/bin/bash
set -e

echo "=== Case 6: vmci_queuepair.c:542 거리 주입 커널 빌드 ==="

SRC_DIR=/work/syzdirect_workdir/srcs/case_6
DIST_DIR=/work/syzdirect_workdir/tpa/case_6/distance_xidx0
TARGET_FUNC=qp_broker_alloc
BUILD_DIR=/work/syzdirect_workdir/kwithdist/case_6/build
OUT_DIR=/work/syzdirect_workdir/kwithdist/case_6
CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang

mkdir -p $BUILD_DIR $OUT_DIR

echo "1. Makefile.kcov 작성..."
cat > $SRC_DIR/scripts/Makefile.kcov << KCOV
# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-\$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=$SRC_DIR -fsanitize-coverage-distance-dir=$DIST_DIR -fsanitize-coverage-target-function=$TARGET_FUNC
kcov-flags-\$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-\$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=\$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := \$(kcov-flags-y)
KCOV

echo "2. .config 복사..."
cp /work/syzdirect_workdir/bcs/case_6/.config $BUILD_DIR/
echo "CONFIG_UBSAN=n" >> $BUILD_DIR/.config
echo "CONFIG_KCOV=y" >> $BUILD_DIR/.config

echo "3. 소스 클린..."
cd $SRC_DIR
make clean > /dev/null 2>&1 || true
make mrproper > /dev/null 2>&1 || true

echo "4. olddefconfig..."
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig

echo "5. 커널 빌드 시작 (30~60분 소요)..."
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j$(nproc) 2>&1 | tee $OUT_DIR/build.log | tail -5

echo "6. bzImage 복사..."
cp $BUILD_DIR/arch/x86/boot/bzImage $OUT_DIR/bzImage
echo "완료: $OUT_DIR/bzImage"
