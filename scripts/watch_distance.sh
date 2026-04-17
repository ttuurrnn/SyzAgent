#!/bin/bash
# Distance 모니터링 스크립트
# 사용법: ./watch_distance.sh [benchfile] [갱신주기(초, 기본 30)]

BENCH="${1:-/work/syzdirect_workdir/fuzzres/case_6/xidx_0/run0/benchfile.txt}"
INTERVAL="${2:-30}"
LOG_DIR="/work/logs"
LOG_FILE="$LOG_DIR/distance_log_$(date '+%Y%m%d_%H%M%S').csv"
mkdir -p "$LOG_DIR"

parse_bench() {
python3 - "$1" << 'PYEOF'
import json, re, sys

bench = sys.argv[1]
try:
    content = open(bench).read()
    objects = re.findall(r'\{[^{}]+\}', content, re.DOTALL)
    if not objects:
        print("NO_DATA"); sys.exit(0)

    records = []
    for o in objects:
        try: records.append(json.loads(o))
        except: pass

    if not records:
        print("NO_DATA"); sys.exit(0)

    last = records[-1]
    min_d  = last.get('min distance', -1)
    max_d  = last.get('max distance', -1)
    exec_t = last.get('exec total', 0)
    corpus = last.get('corpus', 0)
    uptime = last.get('uptime', 0)

    # 전체 레코드에서 min_distance 추이
    all_min = [r.get('min distance', -1) for r in records if r.get('min distance', -1) >= 0]
    all_up  = [r.get('uptime', 0) for r in records if r.get('min distance', -1) >= 0]

    print(f"{min_d}|{max_d}|{exec_t}|{corpus}|{uptime}|{len(records)}")
    # 추이 데이터: uptime,min_dist 쌍
    pairs = [f"{u},{m}" for u,m in zip(all_up, all_min)]
    print(";".join(pairs[-60:]))  # 최근 60개
PYEOF
}

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         SyzDirect Distance Monitor - Case 6                 ║"
echo "║  타겟: vmci_queuepair.c:542 (ioctl\$IOCTL_VMCI_QUEUEPAIR)   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "파일: $BENCH"
echo "갱신: ${INTERVAL}초마다  |  Ctrl+C 종료"
echo ""

PREV_MIN=-1
PREV_EXEC=0
PREV_UPTIME=0
START_MIN=-1
DECREASE_COUNT=0
TOTAL_DECREASE=0
LAST_DECREASE_TIME="-"

# CSV 헤더 작성
echo "timestamp,uptime_s,elapsed_min,min_dist,max_dist,total_drop,delta_dist,exec_total,exec_per_min,corpus,decrease_count,avg_decrease_per_event,dist_per_min,event" \
    > "$LOG_FILE"
echo "[*] 기록 파일: $LOG_FILE"

while true; do
    LINES=$(parse_bench "$BENCH" 2>/dev/null)
    LINE1=$(echo "$LINES" | head -1)
    LINE2=$(echo "$LINES" | tail -1)

    if [ "$LINE1" = "NO_DATA" ] || [ -z "$LINE1" ]; then
        echo "  ⏳ 데이터 대기 중..."
        sleep "$INTERVAL"
        continue
    fi

    IFS='|' read -r MIN_D MAX_D EXEC CORPUS UPTIME RECS <<< "$LINE1"
    NOW=$(date '+%H:%M:%S')

    # 초기값 설정
    [ "$START_MIN" = "-1" ] && START_MIN="$MIN_D"

    # 분당 exec 속도
    DT=$(( UPTIME - PREV_UPTIME ))
    DE=$(( EXEC - PREV_EXEC ))
    if [ "$DT" -gt 0 ]; then
        EPS=$(( DE / DT ))
        EPM=$(( EPS * 60 ))
    else
        EPM=0
    fi

    # 거리 감소 감지
    DIST_FLAG=""
    if [ "$PREV_MIN" != "-1" ] && [ "$MIN_D" != "-1" ]; then
        DELTA=$(( PREV_MIN - MIN_D ))
        if [ "$DELTA" -gt 0 ]; then
            DECREASE_COUNT=$(( DECREASE_COUNT + 1 ))
            TOTAL_DECREASE=$(( TOTAL_DECREASE + DELTA ))
            LAST_DECREASE_TIME="$NOW (-${DELTA})"
            DIST_FLAG=" ◀ 감소! -${DELTA}"
        fi
    fi

    # 평균 감소량
    if [ "$DECREASE_COUNT" -gt 0 ]; then
        AVG_DEC=$(( TOTAL_DECREASE / DECREASE_COUNT ))
    else
        AVG_DEC=0
    fi

    # 총 감소량
    if [ "$START_MIN" != "-1" ] && [ "$MIN_D" != "-1" ]; then
        TOTAL_DROP=$(( START_MIN - MIN_D ))
    else
        TOTAL_DROP=0
    fi

    # 분당 거리 감소량 (단순 계산: 총 감소 / 경과 분)
    if [ "$UPTIME" -gt 60 ]; then
        ELAPSED_MIN=$(( UPTIME / 60 ))
        DPM=$(echo "scale=2; $TOTAL_DROP / $ELAPSED_MIN" | bc 2>/dev/null || echo "0")
    else
        DPM="0"
    fi

    # 타겟 도달 여부
    if [ "$MIN_D" = "0" ]; then
        DIST_FLAG=" ★ 타겟 도달!"
    fi

    # 화면 출력
    printf "\033[2J\033[H"  # 화면 클리어
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         SyzDirect Distance Monitor - Case 6                 ║"
    echo "║  타겟: vmci_queuepair.c:542 (ioctl\$IOCTL_VMCI_QUEUEPAIR)   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo "  갱신: $NOW  |  레코드: ${RECS}개"
    echo ""
    echo "┌─────────────────── 현재 거리 ───────────────────────────────┐"
    printf "│  MIN dist : %-10s  MAX dist : %-10s              │\n" "$MIN_D" "$MAX_D"
    printf "│  시작 dist: %-10s  총 감소량: %-10s              │\n" "$START_MIN" "$TOTAL_DROP"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "┌─────────────────── 퍼징 속도 ───────────────────────────────┐"
    printf "│  총 exec  : %-12s  Corpus : %-10s             │\n" "$EXEC" "$CORPUS"
    printf "│  분당 exec: %-12s  경과   : %d분 %d초               │\n" "${EPM}/min" "$(( UPTIME/60 ))" "$(( UPTIME%60 ))"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "┌─────────────────── 거리 감소 통계 ──────────────────────────┐"
    printf "│  감소 횟수  : %-10s  평균 감소량  : %-8s/회        │\n" "${DECREASE_COUNT}회" "$AVG_DEC"
    printf "│  분당 감소량: %-10s  마지막 감소  : %-20s│\n" "${DPM}/min" "$LAST_DECREASE_TIME"
    echo "└─────────────────────────────────────────────────────────────┘"

    if [ -n "$DIST_FLAG" ]; then
        echo ""
        echo "  *** $DIST_FLAG ***"
    fi

    # 최근 거리 추이 (미니 그래프)
    if [ -n "$LINE2" ] && [ "$LINE2" != "$LINE1" ]; then
        echo ""
        echo "  최근 min_dist 추이:"
        python3 -c "
pairs = '$LINE2'.split(';')
if len(pairs) > 1:
    vals = []
    for p in pairs[-20:]:
        try: vals.append(int(p.split(',')[1]))
        except: pass
    if vals:
        mn, mx = min(vals), max(vals)
        rng = max(mx - mn, 1)
        bar = ''
        for v in vals:
            h = int((mx - v) / rng * 7)
            bar += '▁▂▃▄▅▆▇█'[h]
        print(f'  [{bar}]')
        print(f'   {mn} ← min  max → {mx}')
" 2>/dev/null
    fi

    # 이벤트 태그
    CSV_EVENT="normal"
    [ "$MIN_D" = "0" ] && CSV_EVENT="target_reached"
    [ -n "$DIST_FLAG" ] && [ "$MIN_D" != "0" ] && CSV_EVENT="decreased"

    # CSV 한 줄 기록
    DELTA_FOR_LOG=0
    if [ "$PREV_MIN" != "-1" ] && [ "$MIN_D" != "-1" ]; then
        DELTA_FOR_LOG=$(( PREV_MIN - MIN_D ))
        [ "$DELTA_FOR_LOG" -lt 0 ] && DELTA_FOR_LOG=0
    fi
    ELAPSED_MIN_VAL=$(( UPTIME / 60 ))

    echo "${NOW},${UPTIME},${ELAPSED_MIN_VAL},${MIN_D},${MAX_D},${TOTAL_DROP},${DELTA_FOR_LOG},${EXEC},${EPM},${CORPUS},${DECREASE_COUNT},${AVG_DEC},${DPM},${CSV_EVENT}" \
        >> "$LOG_FILE"

    PREV_MIN="$MIN_D"
    PREV_EXEC="$EXEC"
    PREV_UPTIME="$UPTIME"

    sleep "$INTERVAL"
done
