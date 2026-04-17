# SyzAgent: SyzDirect + LLM Agent Loop

SyzDirect(CCS 2023) 기반 directed kernel fuzzer에 **LLM 에이전트 루프**를 결합한 프로젝트.
퍼징 중 거리가 감소하지 않으면 실패를 분류(R1/R2/R3/R4)하고, LLM으로 템플릿/시드를 자동 강화하여 재퍼징한다.

---

## 구성 요소

### 1. SyzDirect 엔진 (`source/syzdirect/`)
- **Runner/run_hunt.py** — 통합 실행기 (3가지 모드)
- **Runner/Fuzz.py** — QEMU 멀티런 퍼징
- **Runner/Compilation.py** — 커널 빌드 호환성 (clang 버전 완화, kcov 패치)
- **syzdirect_function_model/** — LLVM 기반 syscall-to-target 정적 분석
- **syzdirect_fuzzer/** — 거리 기반 에너지 할당 syzkaller fork

### 2. Agent Loop (`source/agent/`)
- **fuzzing_health_monitor.py** — 퍼징 건강도 모니터링 (exec/s, cover/s, distance_delta)
- **failure_triage.py** — R1(syscall 오식별) / R2(인자 생성 실패) / R3(의존 체인 부족) / R4(distance stall) 분류
- **related_syscall_agent.py** — R3 대응: 누락 syscall 체인 보강
- **object_synthesis_agent.py** — R2 대응: 복잡 오브젝트 생성 파이프라인

### 3. Runner R4/Seed Loop (`source/syzdirect/Runner/`)
- **agent_health.py** — raw distance + relevant distance + dist/coverage stall 분리
- **agent_triage.py** — `primary / secondary / evidence` 기반 R1/R2/R3/R4 triage
- **agent_loop.py** — proactive seed, R4 roadmap, target metadata sync, seed reinjection
- **llm_enhance.py** — roadmap 기반 syscall/seed 제안, seed scoring/validation/rejection logging
- **pipeline_new_cve.py** — workdir 기준 target metadata 복구 및 prebuilt target setup

### 4. 분석 도구 (`source/analyzer/`, `source/distance/`, `source/template/`)
- syscall 정적 분석, BB 거리 계산, syzlang 템플릿 생성

---

## 실행 방법

### run_hunt.py — 3가지 모드

```bash
# 모드 1: dataset — xlsx 기반 배치 퍼징 (Main.py 대체)
python3 source/syzdirect/Runner/run_hunt.py dataset \
  --xlsx source/syzdirect/Runner/dataset_hunt.xlsx \
  --actions 1 2 3 4 5 6

# 모드 2: new — CVE 번호 하나로 원클릭 실행
python3 source/syzdirect/Runner/run_hunt.py new \
  --cve CVE-2023-XXXXX \
  --kernel-commit <commit-hash>

# 모드 3: fuzz — 이미 빌드된 타겟으로 퍼징만 실행
python3 source/syzdirect/Runner/run_hunt.py fuzz \
  --workdir /path/to/workdir
```

### Agent Loop (자동 triage + 템플릿 강화)

`--agent-rounds` 옵션을 주면 퍼징 후 자동으로 agent loop이 돈다:
1. 퍼징 실행 → 2. 건강도 평가 → 3. 실패 분류(R1/R2/R3/R4) → 4. callfile/seed 강화 → 5. 재퍼징

```bash
# CVE 원클릭 + agent loop 3라운드 (라운드당 6시간 퍼징)
python3 source/syzdirect/Runner/run_hunt.py new \
  --cve CVE-2025-XXXXX --commit abc123 \
  --function vuln_func --file net/core/sock.c \
  --agent-rounds 3 --agent-uptime 6

# 프리빌트 타겟 + agent loop
python3 source/syzdirect/Runner/run_hunt.py fuzz \
  --targets 0 --agent-rounds 5

# proactive seed + R4 distance-stall loop
python3 source/syzdirect/Runner/run_hunt.py fuzz \
  -workdir /path/to/workdir \
  --targets 0 \
  --agent-rounds 5 \
  --agent-uptime 1 \
  --hunt-mode hybrid \
  --stall-timeout 1800 \
  --dist-stall-timeout 900 \
  --proactive-seed \
  -j 8

# agent loop 없이 기존 동작 (--agent-rounds 0 또는 생략)
python3 source/syzdirect/Runner/run_hunt.py fuzz --targets 0 3 5
```

### 케이스 실행 (스크립트)

```bash
bash scripts/run_case.sh 74                    # 전체 실행
bash scripts/run_case.sh 74 --prepare-only     # 메타데이터만
BUDGET_HOURS=2 bash scripts/run_case.sh 74     # 시간 조정
```

---

## 타겟 데이터셋 (`dataset_hunt.xlsx`)

| idx | 타겟 | 커널 커밋 | syscall |
|-----|------|----------|---------|
| 0 | `net/sched/cls_tcindex.c:309` | ac0b8b327a56 | setsockopt |
| 1 | `sound/core/seq/seq_timer.c:300` | ac0b8b327a56 | ioctl |
| 2 | `drivers/block/nbd.c:2006` | ac0b8b327a56 | sendmsg |
| 3 | `net/sched/sch_taprio.c:919` | ac0b8b327a56 | setsockopt |
| 4 | `drivers/block/nbd.c:1809` | ac0b8b327a56 | ioctl |
| 5 | `net/xfrm/xfrm_compat.c:571` | ac0b8b327a56 | sendmsg |

---

## 실행 흐름

```
run_hunt.py (dataset/new/fuzz) + --agent-rounds N
    │
    ├── [1] 커널 빌드 (clang 버전 완화 + kcov 패치 자동 적용)
    ├── [2] LLVM bitcode 컴파일
    ├── [3] 정적 분석 (SyzDirect C++ 도구: interface_generator, target_analyzer)
    ├── [4] BB 거리 계산 → 에너지 할당 맵
    ├── [5] 거리 계측 커널 빌드
    │
    ▼
    [6] QEMU 퍼징 (syz-manager, 로그 캡처)
    │
    ├── --agent-rounds 0 → 여기서 끝 (기존 SyzDirect 동작)
    │
    └── --agent-rounds N → Agent Loop 진입
         │
         ▼
    ┌──────────────────────────────────┐
    │  [A] 건강도 평가                 │
    │      (exec/s, cover/s, crashes)  │
    │                                  │
    │  [B] 실패 분류                   │
    │      R1: target calls disabled   │
    │          → RelatedSyscallAgent   │
    │      R2: EINVAL/EFAULT 다수      │
    │          → ObjectSynthesisAgent  │
    │      R3: 커버리지 정체           │
    │          → RelatedSyscallAgent   │
    │      R4: 거리 정체               │
    │          → roadmap + seed loop   │
    │                                  │
    │  [C] callfile 강화               │
    │      (syscall 체인 확장/보강)    │
    │                                  │
    │  [D] seed corpus 재주입          │
    │                                  │
    │  [E] 강화된 callfile로 재퍼징    │
    │      ↓                           │
    │      다음 라운드로 반복          │
    └──────────────────────────────────┘
```

---

## 최근 R4 / Seed 변경

- `dist_stall_timeout` 과 coverage stall을 분리해 R4를 더 정확하게 triage
- `relevant distance` / `relevant program count` 를 health 판단에 반영
- workdir 기준 target metadata 복구로 stale target 오염 감소
- proactive seed 및 R4 seed generation 추가
- seed candidate에 대해 선택/탈락 이유와 decoded netlink shape를 로그로 출력
- source snippet 기반 target-type 보정으로 stale `target_file` 이 있어도 filter/qdisc 구분 강화

R4 로그에서 확인할 핵심 포인트:
- `Target metadata: function=... file=...`
- `Seed selection basis: target_type=... snippet_type=...`
- `Raw candidate analysis:`
- `Rejected candidate seeds:` / `Selected candidate seeds:`

---

## 주요 버그 수정

- **Fuzz.py 포트 충돌**: `runCount` 초기화 위치를 루프 밖으로 이동
- **kcov 패치 탭 이스케이프**: raw string(`r"""`) 제거로 실제 탭 삽입
- **SyscallAnalyze import**: `__init__.py` 추가 및 import 경로 수정
- **LLVM 18 업그레이드**: opaque pointer API 전면 대응 (C++ 엔진 11개 파일), distance pipeline 6개 버그 수정

---

## Quick Start (새 머신에서 처음부터)

```bash
git clone https://github.com/whysocscs/syzdirect-research.git
cd syzdirect-research
./scripts/setup.sh          # 전체 환경 자동 구성 (30-60분)
```

현재 최신 R4/seed 수정이 포함된 브랜치는:

```bash
git checkout merge-temp
```

`setup.sh`가 하는 일:
1. 시스템 의존성 설치 (build-essential, cmake, golang, qemu 등)
2. LLVM 18.1.8 다운로드 → SyzDirect 패치 적용 → 빌드
3. interface_generator (C++ 정적 분석 도구) 빌드
4. target_analyzer (거리 계산 도구) 빌드
5. syzkaller fuzzer 빌드

완료 후 바로 파이프라인 실행 가능:

```bash
cd source/syzdirect/Runner
python3 run_hunt.py new --cve CVE-2025-XXXXX
```

**요구 사항**: Ubuntu 20.04+ / Debian 11+, 최소 32GB RAM (48GB+ 권장), 50GB+ 디스크

---

## 환경 (수동 설정)

- Ubuntu 22.04 / WSL2
- Python 3, Go, LLVM/Clang 18
- QEMU + KVM (없으면 TCG 폴백)

```bash
make bootstrap   # 의존성 설치
make doctor      # 환경 체크
```
