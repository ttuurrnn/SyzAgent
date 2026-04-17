#!/bin/bash
set -e

echo "=== Case 2 SyzDirect Fuzzing 준비 ==="

INSTRUMENTED_DIR=/work/syzdirect_workdir/instrumented/case_2
KWITHDIST_DIR=/work/syzdirect_workdir/kwithdist/case_2
BZIMAGE_SRC=$INSTRUMENTED_DIR/bzImage_xidx0
BZIMAGE_DST=$KWITHDIST_DIR/bzImage_0
FUZZ_DIR=/work/syzdirect_workdir/fuzzres/case_2/xidx_0/run0
CONFIG=$FUZZ_DIR/config.cfg
CALLFILE=/work/syzdirect_workdir/fuzzinps/case_2/inp_0.json
SYZ_MANAGER=/work/SyzDirect/source/syzdirect/syzdirect_fuzzer/bin/syz-manager

echo "1. Step 5 빌드 완료 확인..."
if [ ! -f "$BZIMAGE_SRC" ]; then
    echo "❌ bzImage_xidx0 없음. Step 5 빌드가 완료되지 않았습니다."
    echo "   빌드 로그: tail -f /work/build_instrumented_case2_new.log"
    exit 1
fi
echo "   ✅ bzImage_xidx0 found"

echo "2. bzImage를 kwithdist로 복사..."
mkdir -p $KWITHDIST_DIR
cp $BZIMAGE_SRC $BZIMAGE_DST
echo "   ✅ $BZIMAGE_DST"

echo "3. qcow2 이미지 확인..."
if [ ! -f "/work/images/bullseye.qcow2" ]; then
    echo "   qcow2 변환 중..."
    qemu-img convert -f raw -O qcow2 /work/images/bullseye.img /work/images/bullseye.qcow2
fi
echo "   ✅ bullseye.qcow2"

echo "4. workdir 준비..."
mkdir -p $FUZZ_DIR/workdir

echo "5. syz-manager 실행..."
mkdir -p /work/logs
echo "   Config: $CONFIG"
echo "   Callfile: $CALLFILE"
echo "   HTTP: http://localhost:2345"
echo ""

nohup $SYZ_MANAGER -config=$CONFIG -callfile=$CALLFILE -uptime=24 \
    > /work/logs/case2_fuzz.log 2>&1 &
echo "PID: $!"
echo ""
echo "✅ 퍼징 시작! 로그: tail -f /work/logs/case2_fuzz.log"
echo "   웹 대시보드: http://localhost:2345 (포트포워딩 필요)"
