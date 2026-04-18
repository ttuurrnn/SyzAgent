# 실험 환경 구성 가이드 (이호준용)

SyzAgent(LLM 에이전트 포함) vs 순수 SyzDirect 비교 실험

---

## 요구 사항

- Ubuntu 22.04 / Debian 11 이상 (WSL2 포함)
- RAM: 48GB 이상 권장 (최소 32GB)
- 디스크: 100GB 이상 여유 공간
- CPU: 8코어 이상
- QEMU + KVM (없으면 TCG로 자동 폴백)

---

## 1. 환경 설치

```bash
git clone https://github.com/ttuurrnn/SyzAgent.git
cd SyzAgent

# 전체 자동 설치 (LLVM 18 빌드 포함, 30~60분 소요)
bash scripts/setup.sh

# 이호준처럼 51~100번을 맡는 경우: 설치 후 3-way CSV까지 생성
bash scripts/setup.sh \
  --workdir-base /home/$USER/work_real \
  --cases 51-100 \
  --cases-output rolling_cases_51_100_local.csv
```

setup.sh가 하는 작업:
1. 시스템 패키지 설치 (build-essential, cmake, golang, qemu 등)
2. LLVM 18.1.8 + SyzDirect 패치 → 빌드
3. interface_generator (C++ 정적 분석 도구) 빌드
4. target_analyzer (거리 계산 도구) 빌드
5. syzkaller fuzzer 빌드
6. `--workdir-base`를 주면 3-way rolling CSV 생성

설치 완료 후 확인:
```bash
python3 scripts/doctor.py
```

---

## 2. 실험 데이터셋

`generated_datasets/syzdirect_100/` 에 SyzDirect CCS'23 논문 기준 93개 케이스가 들어 있다.
각 케이스는 xlsx 파일 1개 (커널 커밋, 타겟 함수/파일, recommend syscall 포함).

---

## 3. 실험 실행

### 비교 실험 (SyzAgent vs SyzDirect)

`run_rolling_pipeline.py`가 세 조건을 자동으로 동시에 실행한다.
- **agent** (`workdir_agent`): LLM 에이전트 루프 포함 (SyzAgent)
- **baseline** (`workdir_baseline`): 에이전트 없는 순수 SyzDirect
- **proactive** (`workdir_proactive`): agent loop + proactive seed

```bash
cd /path/to/SyzAgent

# 51~100 담당자가 setup.sh에서 만든 CSV로 실행
python3 -u run_rolling_pipeline.py \
  --cases-csv rolling_cases_51_100_local.csv \
  --fuzz-hours 6 \
  --fuzz-slots 3 \
  2>&1 | tee bg_logs/rolling_pipeline/main_51_100.log &

# 새 실험 시작
python3 -u run_rolling_pipeline.py \
  --cases-csv rolling_cases_100.csv \
  --fuzz-hours 6 \
  --fuzz-slots 5 \
  2>&1 | tee bg_logs/rolling_pipeline/main.log &
```

- `--fuzz-hours 6`: 케이스당 6시간 퍼징
- `--fuzz-slots 5`: 동시에 최대 5개 케이스 퍼징 (RAM에 따라 조절)
- 빌드(step1~5)는 순차적으로, 퍼징(step6)은 병렬로 진행

tmux 사용 시:
```bash
tmux new-session -d -s syzagent_exp
tmux send-keys -t syzagent_exp "cd /path/to/SyzAgent && python3 -u run_rolling_pipeline.py --cases-csv rolling_cases_100.csv --fuzz-hours 6 --fuzz-slots 5" Enter
```

---

## 4. workdir 경로 설정

`make_cases_csv.py`로 본인 환경에 맞는 CSV를 생성한다. 직접 수정해야 한다면 `workdir_agent`, `workdir_baseline`, `workdir_proactive` 세 경로를 모두 맞춘다.

```csv
# case_id, dataset_xlsx, workdir_agent, workdir_baseline, workdir_proactive, build_j, fuzz_j, linux_template
51, .../case_51.xlsx, /your/path/workdir_agent, /your/path/workdir_baseline, /your/path/workdir_proactive, 4, 2, /optional/linux/src
```

- `workdir_agent`: agent 버전(SyzAgent)이 사용할 작업 디렉토리
- `workdir_baseline`: baseline 버전(순수 SyzDirect)이 사용할 작업 디렉토리
- `workdir_proactive`: proactive seed 조건이 사용할 작업 디렉토리
- `build_j`: 빌드 병렬 수 (RAM 여유에 따라 설정, 권장 4)
- `fuzz_j`: 퍼징 VM 수 (기본 2)

---

## 5. 진행 상황 모니터링

```bash
# 전체 진행 로그
tail -f bg_logs/rolling_pipeline/main.log

# 특정 케이스 빌드 로그
tail -f bg_logs/rolling_pipeline/build_case_3.log

# 퍼징 세션 목록
tmux list-sessions | grep rolling

# 특정 케이스 퍼징 상태
tmux attach -t rolling_agent_case_3
```

---

## 6. 결과 수집

퍼징 완료 후 `analyze_results.py`로 결과 수집:

```bash
python3 scripts/analyze_results.py \
  --workdir-agent /your/path/workdir_agent \
  --workdir-baseline /your/path/workdir_baseline \
  --output results_summary.csv
```

각 케이스의 결과:
- `fuzzres/case_N/xidx_0/logs0/manager.log` — syz-manager 로그
- 크래시: `fuzzres/case_N/xidx_0/crashes/` 디렉토리
- 목표 함수 도달 여부: `TARGET_REACHED` 로그 메시지 확인

결과 요약 지표:
| 지표 | 의미 |
|------|------|
| `TARGET_REACHED` | 타겟 함수 도달 성공 여부 |
| `dist_min` | 달성한 최소 거리 |
| `crashes` | 발견한 크래시 수 |
| `coverage` | 커버리지 |

---

## 7. 환경 변수

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # LLM 에이전트 필요 (SyzAgent만)
export SYZDIRECT_RUNTIME=/path/to/img  # QEMU 이미지 경로 (기본: /home/ai/syzdirect-runtime/cve)
```

QEMU 이미지가 없으면 자동으로 생성 시도함.

---

## 8. 단일 케이스 테스트

전체 실험 전에 케이스 1개로 환경 검증:

```bash
python3 run_hunt.py dataset \
  -dataset generated_datasets/syzdirect_100/case_3.xlsx \
  -workdir /tmp/test_workdir \
  -j 4 \
  -actions prepare_for_manual_instrument compile_kernel_bitcode analyze_kernel_syscall extract_syscall_entry instrument_kernel_with_distance fuzz \
  -uptime 1
```

성공하면 `workdir/kwithdist/case_3/bzImage_0`이 생성된다.
