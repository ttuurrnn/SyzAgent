# Retargetable CFGAgent: 공개 및 새 타깃 이식 가이드

## 1. 문서 목적

이 문서는 현재 작업 중인 CFGAgent/SyzAgent 변경을 특정 CVE 전용 실험 코드와
분리하여, 다른 Linux 커널 함수와 subsystem을 대상으로 재사용할 수 있는 형태로
공개하기 위한 기준을 정한다.

현재 공개 준비 브랜치는 `feature/retargetable-cfgagent`이다. 이 브랜치에는 기존
작업 디렉터리의 수정 사항이 그대로 보존되어 있지만, 아직 모든 변경이 커밋 가능한
상태라는 뜻은 아니다. 기능 코드, CVE별 실험 코드, 실행 산출물과 별도 SyzDirect
저장소 변경을 먼저 분리해야 한다.

## 2. 공개하려는 기능 범위

공개 대상의 기본 실행 흐름은 다음과 같다.

```text
커널 소스와 target 함수 입력
  -> target 관련 syscall 및 호출 경로 분석
  -> target basic-block distance 생성
  -> 초기 corpus/seed 구성
  -> syz-manager 실행
  -> coverage 및 distance 변화 진단
  -> 정체 원인 분류
  -> syscall, trigger 조건 또는 seed 재계획
  -> 다음 fuzzing round 실행
  -> crash 수집 및 분류
```

공개 버전은 특정 CVE의 발견을 재현한다고 주장하는 패키지가 아니라, target 함수와
실행 설정을 교체할 수 있는 directed kernel fuzzing 도구로 정의한다.

## 3. 권장 커밋 구성

### Commit 1: 정적 분석과 distance 정확도

대상 파일:

```text
source/syzdirect/Runner/SyscallAnalyze/TargetPointAnalyze.py
source/syzdirect/syzdirect_function_model/src/CMakeLists.txt
source/syzdirect/syzdirect_function_model/src/lib/*.cc
source/syzdirect/syzdirect_kernel_analysis/src/CMakeLists.txt
source/syzdirect/syzdirect_kernel_analysis/src/lib/Analyzer.cc
source/syzdirect/syzdirect_kernel_analysis/src/lib/Distance.cc
```

기능:

- 최신 LLVM의 opaque pointer 및 익명/중첩 구조체 처리
- 파일시스템, 네트워크 및 device callback 추출 보강
- target 관련 syscall을 기준으로 signature 범위 제한
- 다른 subsystem의 shared helper에서 생기는 가짜 근거리 경로 완화
- target에 실제로 도달하지 않은 `UINT_MAX`와 유효 distance 구분

권장 메시지:

```text
Improve target extraction and directed-distance accuracy
```

### Commit 2: fuzzing health 진단과 agent 재계획

대상 파일:

```text
source/agent/failure_triage.py
source/agent/distance_enhancement_agent.py
source/syzdirect/Runner/agent_health.py
source/syzdirect/Runner/agent_loop.py
source/syzdirect/Runner/agent_planner.py
source/syzdirect/Runner/agent_triage.py
source/syzdirect/Runner/crash_triage.py
source/syzdirect/Runner/llm_enhance.py
source/syzdirect/Runner/semantic_seed.py
source/syzdirect/Runner/syscall_normalize.py
source/syzdirect/Runner/syscall_scoring.py
```

기능:

- coverage stall과 distance stall 분리
- 짧은 stateful 실행에서 발생하는 false `dist=0` 탐지
- current-round distance와 cross-round best distance 분리
- target 문맥에 따른 syscall 후보 점수화
- 수동 seed corpus를 agent round 사이에서 유지
- 실패 원인에 맞춘 trigger 조건 및 syzkaller program 재생성
- 이미 실패한 seed의 단순 변형 반복 억제

`source/agent/distance_enhancement_agent.py`는 현재 새 파일이지만
`syzagent/pipeline.py`와 테스트에서 import하므로 이 커밋에서 빠지면 안 된다.

권장 메시지:

```text
Add distance-stall diagnosis and target-aware replanning
```

### Commit 3: 일반 실행 파이프라인과 CLI

대상 파일:

```text
source/syzdirect/Runner/Config.py
source/syzdirect/Runner/Fuzz.py
source/syzdirect/Runner/kernel_build.py
source/syzdirect/Runner/paths.py
source/syzdirect/Runner/pipeline_new_cve.py
source/syzdirect/Runner/pipeline_validate.py
source/syzdirect/Runner/run_hunt.py
syzagent/__init__.py
syzagent/__main__.py
syzagent/cli.py
syzagent/pipeline.py
```

기능:

- target 함수, kernel source/commit, runtime, seed corpus와 시간 예산 설정
- 분석, kernel build, fuzzing, triage 단계 연결
- 새 target 실행과 기존 dataset 실행을 CLI에서 분리
- LLM backend와 실행 경로를 환경변수로 구성

권장 메시지:

```text
Generalize the CFGAgent runner for configurable kernel targets
```

### Commit 4: 집중 실행기와 seed profile

파일시스템 target에 우선 적용할 파일:

```text
scripts/launch_postmount_probe.py
scripts/make_postmount_seeds.py
```

기능:

- seed-only corpus 생성
- target callfile 기반 syscall whitelist 적용
- generic syscall이 활성화된 경우 불필요한 `$variant` 비활성화
- 마운트 후 파일 조작, 확장 속성, growth, readonly 및 lifecycle seed 생성
- 격리된 workdir에서 `syz-manager` 실행

공개 전에는 다음 리팩터링이 필요하다.

1. `launch_postmount_probe.py`의 공통 실행 부분을
   `launch_target_probe.py`로 분리한다.
2. `/home/user/...` 기본 경로를 저장소 상대 경로 또는 환경변수로 교체한다.
3. filesystem 전용 seed 생성은 별도 profile/plugin으로 유지한다.
4. network, BPF, io_uring 등은 각 subsystem별 seed profile을 추가하도록 한다.
5. 새 target은 source code 수정 없이 target manifest로 선택할 수 있게 한다.

권장 메시지:

```text
Add seed-only targeted probing with pluggable seed profiles
```

### Commit 5: 설치, 문서 및 회귀 테스트

대상 파일:

```text
README.md
configs/run_case.env.example
scripts/bootstrap_host.sh
scripts/doctor.py
scripts/setup.sh
tests/
docs/RETARGETABLE_CFGAGENT_RELEASE_GUIDE.md
```

README에서 직접 언급하는 스크립트는 문서와 함께 커밋하거나 해당 설명을 제거해야
한다. 현재 후보는 다음과 같다.

```text
scripts/build_recent_cve_targets.py
scripts/check_gemini_headless.py
scripts/codex_cli.sh
scripts/gemini_cli.sh
scripts/launch_cve_run.sh
scripts/lookup_curated_cve.py
scripts/prepare_gemini_rerun.py
scripts/run_recent_cves.py
scripts/summarize_cve_runs.py
scripts/summarize_smoke_runs.py
```

현재 로컬 단위 테스트 기준은 `python3 -m pytest -q tests`이며, 공개 직전에는 깨끗한
clone에서도 같은 명령이 통과해야 한다.

권장 메시지:

```text
Document and test the retargetable CFGAgent workflow
```

## 4. SyzDirect fork 처리

`deps/SyzDirect`는 상위 SyzAgent 저장소와 다른 Git 저장소이며 상위 `.gitignore`의
`deps/` 규칙으로 제외된다. 따라서 이 디렉터리의 변경은 SyzAgent 커밋에 포함되지
않는다.

재사용에 필요한 일반 변경 후보:

```text
source/syzdirect/syzdirect_fuzzer/Makefile
source/syzdirect/syzdirect_fuzzer/syz-manager/manager.go
source/syzdirect/syzdirect_fuzzer/syz-fuzzer/testing.go
```

이 변경은 별도 SyzDirect fork에 커밋하고 SyzAgent에서 다음 두 값을 이용해 정확한
revision을 고정해야 한다.

```text
SYZDIRECT_REPO=https://github.com/<account>/SyzDirect.git
SYZDIRECT_REF=<full-commit-sha>
```

`scripts/setup.sh`도 위 값 또는 동일한 설정 파일을 읽어 해당 revision을 checkout해야
한다. 원본 SyzDirect의 최신 `main`을 매번 shallow clone하면 재현 가능한 빌드가
되지 않는다.

io_uring, socket 및 AF_ALG syscall description 변경은 공통 manager 변경과 분리하여
subsystem별 선택적 커밋으로 올린다. `syz-sysgen`으로 생성되는 `sys_*.go` 파일과 빌드
산출물은 생성 절차가 확인되지 않는 한 직접 추가하지 않는다.

## 5. 새 target 이식 계약

새 target 하나는 최소한 다음 정보를 제공해야 한다.

```text
target_id
linux_repository
kernel_commit
target_source_file
target_function
target_basic_block 또는 target line
kernel_config
entry_syscalls
related_syscalls
seed_profile 또는 seed_corpus
vm_image
ssh_key
runtime_budget
expected_target_evidence
known_crash_exclusions
```

권장 manifest 예시:

```json
{
  "target_id": "example_target",
  "kernel_commit": "<full-commit-sha>",
  "target_source_file": "fs/example/example.c",
  "target_function": "example_target_function",
  "entry_syscalls": ["openat"],
  "related_syscalls": ["read", "write", "close"],
  "seed_profile": "filesystem-postmount",
  "runtime_budget_minutes": 180
}
```

비밀정보와 호스트 절대경로는 manifest에 넣지 않고 환경변수나 ignore된 로컬 설정에
둔다.

## 6. 커밋하면 안 되는 데이터

다음 항목은 기능 코드와 함께 GitHub에 올리지 않는다.

```text
.analysis/                         # 대형 정적 분석 및 별도 Git checkout
artifacts/                         # 실행 및 증거 산출물
reports/                           # 실험/제보 보고서
callee.txt
caller.txt
constraintsDebug
kernel_signature_full
kernel_signature_with_info_full
source/syzdirect/Runner/output.json
source/syzdirect/slimconfig*
logs/
runs/
results/
workdir/
*.img
*.qcow2
vmlinux
bzImage
```

다음 자료는 필요할 경우 core 브랜치가 아닌 별도 artifact release로 제공한다.

- 특정 CVE의 crafted image 및 reproducer
- CVE별 kernel config와 crash log
- maintainer 메일 및 제출 패킷
- 취약점별 분석 보고서
- 실험 corpus DB
- 아직 공개되지 않은 취약점의 target manifest

API key, OAuth cache, SSH private key, sudo password와 개인 이메일 credential은 어떤
브랜치나 release에도 포함하지 않는다.

## 7. CVE 및 발견 provenance 주의사항

도구가 target-specific corpus를 실행했다는 사실과 도구가 특정 CVE를 최초 발견했다는
주장은 다르다. CVE discovery를 주장하려면 최소한 다음 provenance가 연결되어야 한다.

```text
run manifest
full kernel commit
original syzkaller program
crafted input image 또는 payload
first crash log 및 console
minimized reproducer
vulnerable/fixed build 비교 로그
보고에 실제로 첨부한 파일과 SHA-256
보고 메일 Message-ID 또는 공개 URL
seed 및 program lineage
agent prompt/response 또는 round log
```

위 연결이 없으면 README와 논문에서 `CFGAgent discovered CVE-X`라고 쓰지 않는다.
대신 확인 가능한 수준에 따라 `targeted fuzzing run`, `post-disclosure reproduction`,
`team-reported issue`처럼 범위를 제한한다.

## 8. 공개 전 검증 gate

다음 조건을 모두 만족한 뒤에만 기능 브랜치를 원격에 공개한다.

- [ ] `git diff --check`가 오류 없이 통과한다.
- [ ] `python3 -m pytest -q tests`가 깨끗한 clone에서 통과한다.
- [ ] C++ analyzer 두 개가 깨끗한 build directory에서 빌드된다.
- [ ] SyzDirect fork revision이 full SHA로 고정된다.
- [ ] 문서가 언급하는 모든 스크립트가 실제 커밋에 포함된다.
- [ ] 모든 `/home/user`, `/mnt/c`, 개인 디렉터리 기본값을 제거하거나 설정화한다.
- [ ] API key, token, password 및 private key가 Git history에 없다.
- [ ] 대형 산출물과 별도 `.git` 디렉터리가 staging되지 않았다.
- [ ] 최소 하나의 공개 가능한 sample target으로 end-to-end smoke test를 통과한다.
- [ ] distance hit는 target basic-block trace나 target-specific coverage로 교차 확인한다.
- [ ] crash는 target과 무관한 known crash DB와 대조한다.
- [ ] README의 성능 및 CVE 관련 문장은 보존된 증거 범위를 넘지 않는다.

## 9. 안전한 staging 및 push 절차

`git add .`는 사용하지 않는다. 각 커밋에서 위 파일 목록만 명시적으로 staging한다.

검사 순서:

```bash
git status --short
git diff --check
python3 -m pytest -q tests
git diff --cached --stat
git diff --cached
```

원격 push는 모든 커밋과 clean-clone smoke test가 끝난 뒤 수행한다.

```bash
git push -u origin feature/retargetable-cfgagent
```

상위 SyzAgent와 SyzDirect fork는 서로 다른 원격과 commit SHA를 가지므로 각각 따로
push하고, 상위 저장소 문서 및 setup에서 두 revision의 관계를 기록한다.

## 10. 현재 상태

문서 작성 시점의 확인 결과:

- 작업 브랜치: `feature/retargetable-cfgagent`
- Python 테스트: 36개 통과
- tracked 수정: 40개 파일
- tracked diff: 약 2,733 insertions / 439 deletions
- 해결 필요: `git diff --check`의 trailing whitespace 6건
- 해결 필요: 실행용 스크립트의 `/home/user/...` 기본경로 설정화
- 해결 필요: SyzDirect fork 및 고정 revision 구성
- 해결 필요: 공통 코드와 CVE별/실험별 스크립트 분리

이 상태는 공개용 브랜치의 시작점이며, 아직 전체 변경을 한 번에 commit/push할 단계는
아니다.
