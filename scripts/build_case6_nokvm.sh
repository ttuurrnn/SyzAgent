#!/bin/bash
set -e

echo "=== Case 6 nokvm 거리 계측 커널 빌드 ==="

SRC_DIR=/work/syzdirect_workdir/srcs/case_6
DIST_DIR=/work/syzdirect_workdir/tpa/case_6/distance_xidx0
TARGET_FUNC=qp_broker_alloc
BUILD_DIR=/work/syzdirect_workdir/kwithdist/case_6/nokvm_build
OUT_DIR=/work/syzdirect_workdir/kwithdist/case_6
CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang

mkdir -p $BUILD_DIR $OUT_DIR

echo "1. nokvm config 복사 (디버그 옵션 없는 안정 config)..."
cp /work/nokvm_kernel.config $BUILD_DIR/.config
echo "CONFIG_KCOV=y" >> $BUILD_DIR/.config
echo "CONFIG_KCOV_INSTRUMENT_ALL=n" >> $BUILD_DIR/.config
echo "CONFIG_UBSAN=n" >> $BUILD_DIR/.config

echo "2. Makefile.kcov 거리 계측 설정..."
cat > $SRC_DIR/scripts/Makefile.kcov << KCOV
# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-\$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=$SRC_DIR -fsanitize-coverage-distance-dir=$DIST_DIR -fsanitize-coverage-target-function=$TARGET_FUNC
kcov-flags-\$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-\$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=\$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := \$(kcov-flags-y)
KCOV

echo "3. olddefconfig..."
cd $SRC_DIR
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig 2>&1 | tail -3

echo "4. 커널 빌드 시작..."
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j$(nproc) 2>&1 | tee $OUT_DIR/nokvm_build.log | tail -5

echo "5. bzImage 복사..."
cp $BUILD_DIR/arch/x86/boot/bzImage $OUT_DIR/bzImage_nokvm
echo "완료: $OUT_DIR/bzImage_nokvm"
