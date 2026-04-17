#!/bin/bash
set -e

echo "=== Step 5: Instrumenting Case 2 Kernel with Distance ==="

SRC_DIR=/work/syzdirect_workdir/srcs/case_2
DIST_DIR=/work/syzdirect_workdir/tpa/case_2/distance_xidx0
TARGET_FUNC=nbd_genl_connect
BUILD_DIR=/work/syzdirect_workdir/instrumented/case_2/temp_build
OUT_DIR=/work/syzdirect_workdir/instrumented/case_2

echo "1. Preparing Makefile.kcov..."
cat > $SRC_DIR/scripts/Makefile.kcov << 'EOF'
# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=/work/syzdirect_workdir/srcs/case_2 -fsanitize-coverage-distance-dir=/work/syzdirect_workdir/tpa/case_2/distance_xidx0 -fsanitize-coverage-target-function=nbd_genl_connect
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := $(kcov-flags-y)
EOF

echo "2. Preparing build directory..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cp /work/syzdirect_workdir/bcs/case_2/.config $BUILD_DIR/
echo "CONFIG_UBSAN=n" >> $BUILD_DIR/.config
echo "CONFIG_KCOV=y" >> $BUILD_DIR/.config

echo "3. Cleaning source..."
cd $SRC_DIR
make clean > /dev/null 2>&1
make mrproper > /dev/null 2>&1

echo "4. Building instrumented kernel (this takes 30-60 min)..."
CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang

echo "   - Running olddefconfig..."
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig

echo "   - Building kernel with -j4..."
echo "   - This will take a while. Progress will be shown below."
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j4

echo ""
echo "5. Copying results..."
mkdir -p $OUT_DIR
cp $BUILD_DIR/arch/x86/boot/bzImage $OUT_DIR/bzImage_xidx0
cp $BUILD_DIR/vmlinux $OUT_DIR/vmlinux_0

echo ""
echo "✅ Step 5 완료!"
echo "   bzImage: $OUT_DIR/bzImage_xidx0"
echo "   vmlinux: $OUT_DIR/vmlinux_0"
ls -lh $OUT_DIR/bzImage_xidx0
ls -lh $OUT_DIR/vmlinux_0
