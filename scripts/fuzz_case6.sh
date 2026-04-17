#!/bin/bash
set -e

SYZ_MANAGER=/work/SyzDirect/source/syzdirect/syzdirect_fuzzer/bin/syz-manager
CONFIG=/work/syzdirect_workdir/fuzzres/case_6/xidx_0/run0/config.cfg
CALLFILE=/work/syzdirect_workdir/fuzzinps/case_6/inp_0.json
BENCHFILE=/work/syzdirect_workdir/fuzzres/case_6/xidx_0/run0/benchfile.txt
LOG=/work/logs/case6_fuzz.log

mkdir -p /work/logs
mkdir -p /work/syzdirect_workdir/fuzzres/case_6/xidx_0/run0/workdir

# 기존 퍼저 종료
if pgrep -f "syz-manager.*case_6" > /dev/null 2>&1; then
    echo "[!] 기존 syz-manager 종료 중..."
    pkill -f "syz-manager.*case_6" || true
    sleep 2
fi

echo "[*] Case 6 퍼징 시작"
echo "    타겟: drivers/misc/vmw_vmci/vmci_queuepair.c:542"
echo "    syscall: ioctl\$IOCTL_VMCI_QUEUEPAIR_ALLOC"
echo "    로그: $LOG"
echo "    대시보드: http://localhost:2346"
echo ""

nohup $SYZ_MANAGER -config=$CONFIG -callfile=$CALLFILE -uptime=24 \
    > $LOG 2>&1 &
FUZZ_PID=$!
echo "[+] syz-manager PID: $FUZZ_PID"
echo $FUZZ_PID > /work/case6_fuzz.pid

echo ""
echo "[*] benchfile 생성 대기 중..."
for i in $(seq 1 30); do
    [ -f "$BENCHFILE" ] && break
    sleep 2
    printf "."
done
echo ""

if [ -f "$BENCHFILE" ]; then
    echo "[+] 모니터링 시작"
    /work/watch_distance.sh "$BENCHFILE" 30
else
    echo "[!] benchfile 미생성. 로그 확인: tail -f $LOG"
fi
