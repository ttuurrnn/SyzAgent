# SyzAgent 분석 종합 보고서

**프로젝트**: SyzDirect (CCS 2023) R1/R2/R3 실패 지점 분석 및 에이전트 보완 연구
**커널 버전**: Linux 6.1.0
**실험 기간**: 2026-02-07 ~ 2026-03-04

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [전체 케이스 요약](#2-전체-케이스-요약)
3. [케이스별 상세 분석](#3-케이스별-상세-분석)
   - [Case 0 — cls_tcindex.c:309 (R1 FAIL)](#case-0--cls_tcindexc309--r1-fail)
   - [Case 1 — seq_timer.c:300 (R1 SUCCESS)](#case-1--seq_timerc300--r1-success)
   - [Case 2 — nbd.c:2006 (R1 SUCCESS)](#case-2--nbdc2006--r1-success)
   - [Case 3 — sch_taprio.c:919 (R1 NOISY)](#case-3--sch_taprioc919--r1-noisy)
   - [Case 4 — nbd.c:1809 (R1 FAIL)](#case-4--nbdc1809--r1-fail)
4. [R1/R2/R3 실험 — 실제 퍼징 결과](#4-r1r2r3-실험--실제-퍼징-결과)
5. [Case 2 퍼징 실행 가이드 (Step 5~6)](#5-case-2-퍼징-실행-가이드-step-56)
6. [식별된 실패 패턴 종합](#6-식별된-실패-패턴-종합)
7. [개발한 도구](#7-개발한-도구)
8. [빌드 및 운영 교훈](#8-빌드-및-운영-교훈)
9. [향후 계획](#9-향후-계획)

---

## 1. 프로젝트 개요

### SyzDirect 파이프라인

```
Step 1: PrepareSourceCode      → kcov 패치 적용
Step 2: CompileKernelToBitcode → emit-llvm.sh 로 .bc 생성
Step 3: AnalyzeKernelInterface → interface_generator → kernel_signature_full + kernelCode2syscall.json
Step 4: AnalyzeTargetPoints    → target_analyzer → CompactOutput.json + distance 파일
Step 5: InstrumentDistance     → 거리 기반 커널 빌드
Step 6: Fuzz                   → syzkaller 기반 퍼징
```

### 연구 목표

SyzDirect의 세 실패 유형을 분류하고 에이전트 루프로 보완 가능성 검증:

| 유형 | 정의 | 진단 지표 |
|------|------|----------|
| **R1** | 타겟 도달 syscall 식별 실패 | CompactOutput.json이 비어있거나 false positive만 존재 |
| **R2** | 복잡한 인자/오브젝트 생성 실패 | 높은 smash 수, 타겟 근접 but 도달 불가 |
| **R3** | syscall 컨텍스트(의존 체인) 부족 | 커버리지 조기 정체, candidate=0 |

---

## 2. 전체 케이스 요약

### R1 분석 (Step 1~4)

| Case | 타겟 파일:라인 | 서브시스템 | 인터페이스 패턴 | 호출 깊이 | R1 결과 | 유효/전체 | Precision |
|------|--------------|-----------|----------------|----------|---------|---------|-----------|
| 0 | `net/sched/cls_tcindex.c:309` | TC (Traffic Control) | rtnl_register | 간접 | **FAIL** | 0/0 | N/A |
| 1 | `sound/core/seq/seq_timer.c:300` | ALSA Sequencer | ioctl (표준) | 직접 | **SUCCESS** | 3/6 | 50% |
| 2 | `drivers/block/nbd.c:2006` | NBD (Network Block) | genetlink | 직접 핸들러 | **SUCCESS** | 1/1 | 100% |
| 3 | `net/sched/sch_taprio.c:919` | TC (taprio qdisc) | rtnl_register | 간접 | **NOISY** | 0/16 | 0% |
| 4 | `drivers/block/nbd.c:1809` | NBD | genetlink callee | 1단계 깊음 | **FAIL** | 0/3 | 0% |

**R1 성공률: 40% (2/5)**

### 빌드 통계

| Case | Bitcode 파일 | Distance 파일 | Interface Signature | Subset 전략 |
|------|------------|-------------|-------------------|------------|
| 0 | 2,358 | 2,104 | 3,802 | 없음 |
| 1 | 6,856 | 3,676 | 9,682 | drivers/ 제외 (4,128) |
| 2 | 6,767 | 3,692 | 16,240 | drivers/block만 포함 (4,058) |
| 3 | 6,737 | 3,672 | 11,328 | drivers/ 제외 |
| 4 | 6,767 | 2,703 | 9,054 | drivers/block만 포함 |

### R1/R2/R3 실제 퍼징 결과 (4시간 실행)

| Bug | 예상 유형 | Executed | Coverage | Smash | 타겟 도달 | 판정 |
|-----|---------|---------|---------|-------|---------|------|
| B029 (`gre_build_header`) | R1 | 665,390 | 52,198 blocks | ~12 | ✗ | R1 확인 |
| B040 (`sta_apply_parameters`) | R3 | 611,165 | 46,929 (plateau) | 117 | ✗ | R3 확인 |
| B054 (`xfrm_user_rcv_msg_compat`) | R2 | 819,447 | 55,802 blocks | **2,290** | ✗ | R2 확인 |

---

## 3. 케이스별 상세 분석

### Case 0 — cls_tcindex.c:309 — R1 FAIL

**분석일**: 2026-02-07
**타겟 함수**: `tcindex_alloc_perfect_hash()`
**커밋**: `3f2db250099f`

#### 실제 콜 체인

```
sendmsg(netlink)
  → rtnetlink_rcv_msg
    → tc_new_tfilter          (rtnl_register로 등록: cls_api.c:3749)
      → tp->ops->change       (함수 포인터 간접 호출)
        → tcindex_change
          → tcindex_set_parms
            → tcindex_alloc_perfect_hash  ← TARGET (line 309)
```

#### 파이프라인 결과

| 항목 | 값 |
|------|-----|
| .llbc 파일 | 2,358개 |
| kernel_signature_full | 3,802줄 |
| 매핑된 handler | 275개 |
| **CompactOutput.json** | **비어있음 (0개)** |

#### 실패 원인

TC 서브시스템은 `rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_new_tfilter, ...)` 패턴으로 핸들러를 등록한다. interface_generator는 `file_operations`, `proto_ops` 기반 구조체는 인식하지만, rtnetlink 메시지 핸들러 등록 패턴은 지원하지 않아 매핑 0개 생성.

- 결정론적 실패: 동일 bitcode로 반복해도 항상 동일한 결과
- R2/R3는 R1 성공 이후에만 평가 가능 → 이 케이스는 측정 불가

#### LLM 에이전트 보완 방향

LLM이 제공해야 할 정보:
1. 진입 syscall: `sendmsg$nl_route` (AF_NETLINK/NETLINK_ROUTE)
2. 필요 리소스: `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` + `RTM_NEWTFILTER` 메시지 구성
3. 복잡도 프로파일: 도달거리 높음 / 리소스 의존성 높음 / syzlang 복잡도 중간

---

### Case 1 — seq_timer.c:300 — R1 SUCCESS

**분석일**: 2026-02-08
**타겟 함수**: `snd_seq_timer_open()`
**커밋**: `83e197a8414c`

#### 실제 콜 체인

```
ioctl(fd, SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER, ...)
  → snd_seq_ioctl_set_queue_timer()
    → snd_seq_queue_timer_open()
      → snd_seq_timer_open()
        → [line 300: TARGET]
```

#### 파이프라인 결과

| 항목 | 값 |
|------|-----|
| .llbc 파일 | 6,856개 |
| kernel_signature_full | 9,682개 |
| CompactOutput.json | **6개 매핑** |

#### 매핑 결과 평가

| Syscall | 평가 |
|---------|------|
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER` | ✅ 직접 경로 |
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT` | ✅ `snd_seq_queue_use` 경유 |
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_INFO` | ✅ 조건부 경로 |
| `ioctl$SNDRV_SEQ_IOCTL_CREATE_QUEUE` | ❌ 전제조건 (직접 아님) |
| `delete_module` | ❌ KERNEL_CLIENT 관련 false positive |
| `kexec_load` | ❌ KERNEL_CLIENT 관련 false positive |

**Precision 50%, Recall 100%** — 모든 유효 경로 발견, false positive 3개 포함

#### R1 성공 요인

- 표준 ioctl 인터페이스 사용 → interface_generator 정상 인식
- 직접적인 함수 호출 체인 (콜그래프 추적 용이)
- Case 0과 대조: 동일 netlink 계열이지만 등록 패턴이 표준적

---

### Case 2 — nbd.c:2006 — R1 SUCCESS

**분석일**: 2026-02-09
**타겟 함수**: `nbd_genl_connect()` (직접 genl_ops 핸들러)

#### 타겟 코드

```c
static const struct genl_small_ops nbd_connect_genl_ops[] = {
    { .cmd = NBD_CMD_CONNECT, .doit = nbd_genl_connect },  // 직접 등록
};

static int nbd_genl_connect(...) {
    if (info->attrs[NBD_ATTR_DEAD_CONN_TIMEOUT]) {
        kcov_mark_block(0);  // ← TARGET (line 2006)
    }
}
```

#### 실제 콜 체인

```
sendmsg(fd, msg, flags)
  → netlink_sendmsg()
    → genl_rcv_msg()
      → nbd_genl_connect()   [genl_small_ops.doit]
        → [line 2006: TARGET]
```

#### 파이프라인 결과

| 항목 | 값 |
|------|-----|
| CompactOutput.json | **1개 매핑 (100% precision)** |
| 매핑 syscall | `sendmsg` (NBD_ATTR_SIZE_BYTES=2, NBD_ATTR_SOCKETS=7) |

**Precision 100%, Recall 100%** — Generic Netlink (`genl_small_ops`) 패턴 완벽 지원

#### 빌드 교훈

- `CC=... make` (환경변수)는 Kbuild에서 무시됨 → `make CC=...` (make 인자)를 사용해야 함
- kcov.h 와 kcov.c 모두 패치되어야 함, 파일 존재 여부만이 아닌 내용 확인 필요

---

### Case 3 — sch_taprio.c:919 — R1 NOISY

**분석일**: 2026-02-10
**타겟 함수**: `parse_taprio_schedule()` (caller: `taprio_change`)

#### 실제 콜 체인

```
sendmsg(netlink, RTM_NEWQDISC)
  → rtnetlink_rcv_msg()
    → tc_modify_qdisc()
      → taprio_change()
        → parse_taprio_schedule()
          → [line 919: TARGET]
```

#### 파이프라인 결과

CompactOutput.json: **16개 매핑, 유효 0개**

대부분 "taprio" 문자열 매칭에 의한 노이즈:
`bind$xdp`, `getsockopt$inet_buf`, `ioctl$sock_bt_bnep_BNEPCONNADD`, `setsockopt$inet6_*` 등

#### Case 0과의 비교

| 항목 | Case 0 | Case 3 |
|------|--------|--------|
| 인터페이스 | rtnl_register | rtnl_register |
| 매핑 결과 | 0개 (깨끗한 실패) | 16개 (모두 false positive) |
| 실질 효과 | 동일 — 올바른 syscall 미발견 |
| 위험도 | 낮음 (즉시 실패) | **더 높음 (퍼징 자원 낭비)** |

---

### Case 4 — nbd.c:1809 — R1 FAIL

**분석일**: 2026-02-11
**타겟 함수**: `nbd_dev_add()` (caller: `nbd_genl_connect`)

#### Case 2와의 결정적 차이

| 항목 | Case 2 (`nbd_genl_connect`) | Case 4 (`nbd_dev_add`) |
|------|---------------------------|----------------------|
| 타겟 유형 | genl_ops 직접 핸들러 | 핸들러가 호출하는 callee |
| 호출 깊이 | 0 (직접 등록 함수) | 1 (한 단계 더 깊음) |
| R1 결과 | **SUCCESS** 1/1 | **FAIL** 0/3 |

TPA 디버그 로그 확인:
```
[DEBUG] Current cmdEntryFunc: nbd_dev_add in interface json: 0
```

`nbd_dev_add`가 interface_generator에서 진입점으로 인식되지 않음. TPA가 `nbd_genl_connect → nbd_dev_add` 콜체인을 역추적하지 못하고, 무관한 snapshot/cgroup syscall을 매핑.

**결론**: 타겟 함수가 등록된 핸들러 자체이면 성공, 그 callee이면 실패 — 1단계 깊이 차이가 결정적.

---

## 4. R1/R2/R3 실험 — 실제 퍼징 결과

**실험 일자**: 2026-03-03 ~ 2026-03-04
**환경**: SyzDirect 퍼저, 4시간 실행, QEMU x86_64 4GB, 거리 instrumented 커널 (6,521개 .dist 파일)

### B029 — R1: Missing Dependent Syscalls (`gre_build_header`, v5.13)

| 지표 | 값 |
|------|-----|
| Executed | 665,390 |
| Coverage | 52,198 blocks |
| Smash | ~12 |
| Corpus | 59,180 |
| 타겟 도달 | ✗ |

**분석**: 퍼저가 넓게 탐색하면서 대규모 corpus를 생성했지만 `gre_build_header`에 도달하지 못함. GRE 터널은 raw 소켓 + 터널 설정이라는 특정 syscall 시퀀스가 필요하지만 자동 생성 불가. Smash가 매우 낮음 → 타겟 근처에도 가지 못함. **Classic R1**.

---

### B040 — R3: Insufficient Syscall Context (`sta_apply_parameters`, v5.11)

| 지표 | 값 |
|------|-----|
| Executed | 611,165 |
| Coverage | 46,929 blocks (plateau) |
| Smash | 117 |
| Candidate | 0 (최종 단계) |
| 타겟 도달 | ✗ |

**분석**: 커버리지가 초기에 정체 (~46,913 → 46,929, Δ=16). mac80211의 `sta_apply_parameters`는 연결된 BSS, 스테이션 관리 상태 머신이라는 풀 무선 컨텍스트가 필요. 퍼저가 syscall 레벨 천장에 부딪힘. **Classic R3**.

---

### B054 — R2: Object/Parameter Generation Failure (`xfrm_user_rcv_msg_compat`, v5.13)

| 지표 | 값 |
|------|-----|
| Executed | 819,447 |
| Coverage | 55,802 blocks |
| **Smash** | **2,290** |
| 타겟 도달 | ✗ (near-miss) |

**분석**: Smash 2,290은 B040(R3)의 **19.6배**. 핵심 R2 시그널 — 퍼저가 `xfrm_user_rcv_msg_compat` 근처 경로를 반복적으로 발견하고 mutation을 시도하지만, 32비트 compat 메시지 구조가 정밀한 레이아웃을 요구하여 랜덤 mutation이 실패. **Classic R2**.

### 실패 유형 판별 지표

```
R1 (B029):  smash ≈ 12,   corpus=59k (광범위),  coverage 꾸준히 증가, 타겟 근접 없음
R3 (B040):  smash = 117,  corpus ≈ 0,  coverage 조기 정체 (천장 도달), candidate=0
R2 (B054):  smash = 2290, corpus ≈ 0,  coverage 정체,  smash 매우 높음 (타겟 근처 집중 mutation)
```

**Smash 수가 R1/R2/R3 최강 판별자**: R1 < R3 << R2

### B036 시도 — R3: sound/core/seq (`snd_seq_queue_alloc`, 실패)

- distance 분석 0개 — `snd_seq_queue_alloc`이 커널 인터페이스 syscall 매핑으로 도달 불가
- Callfile JSON 파싱 오류 (Python 에러 주석이 출력에 삽입됨)
- 해결책: ALSA seq ioctl 진입점이 포함된 수동 callfile 필요

---

## 5. Case 2 퍼징 실행 가이드 (Step 5~6)

R1 분석이 완료된 Case 2 (`nbd_genl_connect`, Precision 100%)에 대한 Step 5~6 실행 방법.

### Step 5: InstrumentDistance (거리 기반 커널 빌드)

```bash
# Makefile.kcov 수정 (거리 instrumentation 삽입)
SRC_DIR=/work/syzdirect_workdir/srcs/case_2
DIST_DIR=/work/syzdirect_workdir/tpa/case_2/distance_xidx0

cat > $SRC_DIR/scripts/Makefile.kcov << 'EOF'
kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += \
  -fsanitize-coverage=trace-pc,second \
  -fsanitize-coverage-kernel-src-dir=/work/syzdirect_workdir/srcs/case_2 \
  -fsanitize-coverage-distance-dir=/work/syzdirect_workdir/tpa/case_2/distance_xidx0 \
  -fsanitize-coverage-target-function=nbd_genl_connect
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS) += -fsanitize-coverage=trace-cmp
export CFLAGS_KCOV := $(kcov-flags-y)
EOF

# 빌드
BUILD_DIR=/work/syzdirect_workdir/instrumented/case_2/temp_build
mkdir -p $BUILD_DIR
cp /work/syzdirect_workdir/bcs/case_2/.config $BUILD_DIR/

CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j2

# 결과 복사
mkdir -p /work/syzdirect_workdir/instrumented/case_2
cp $BUILD_DIR/arch/x86/boot/bzImage /work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0
```

예상 소요 시간: 30분 ~ 1시간

### Step 6: Fuzz (실제 퍼징)

```bash
# Config 파일 생성
cat > /work/case2_fuzz_config.json << 'EOF'
{
    "target": "linux/amd64",
    "http": "0.0.0.0:56741",
    "workdir": "/work/syzdirect_workdir/fuzz_result/case_2/xidx0/run0",
    "kernel_obj": "/work/syzdirect_workdir/instrumented/case_2",
    "image": "/work/images/bullseye.img",
    "sshkey": "/work/images/bullseye.id_rsa",
    "syzkaller": "/work/SyzDirect/source/syzdirect/syzdirect_fuzzer",
    "procs": 2,
    "type": "qemu",
    "hitindex": 0,
    "vm": {
        "count": 2,
        "kernel": "/work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0",
        "cpu": 2,
        "mem": 2048
    }
}
EOF

# 퍼징 실행 (1시간 테스트)
cd /work/SyzDirect/source/syzdirect/syzdirect_fuzzer
bin/syz-manager \
  -config=/work/case2_fuzz_config.json \
  -callfile=/work/syzdirect_workdir/fuzz_inp/case_2/callfile_xidx0 \
  -uptime=3600
```

### R3 실패 패턴 수집 포인트

```bash
WORKDIR=/work/syzdirect_workdir/fuzz_result/case_2/xidx0/run0

# 거리 감소 여부 모니터링
grep -i "distance" $WORKDIR/manager.log | tail -20

# 에러 통계
grep -i "EINVAL\|EPERM\|EFAULT" $WORKDIR/executor.*.log | wc -l

# 타겟 도달 여부
grep -i "target hit\|nbd_genl_connect" $WORKDIR/*.log
```

예상 R3 실패 시나리오:
1. sendmsg 호출되지만 AF_NETLINK가 아닌 family 사용
2. Generic Netlink NBD family 등록 미발견 (nlmsg_type 오류)
3. NBD_ATTR_SIZE_BYTES, NBD_ATTR_SOCKETS 속성 누락
4. CAP_NET_ADMIN 권한 문제

---

## 6. 식별된 실패 패턴 종합

### 패턴 1: 미지원 등록 패턴 (Case 0, 3)

- **원인**: `rtnl_register()` 패턴을 interface_generator가 인식 못함
- **영향**: 0개 (깨끗한 실패) 또는 노이즈 (false positive 대량)
- **해당 서브시스템**: `net/sched` (TC), 기타 rtnetlink 기반 서브시스템 전체
- **결정론적**: 동일 패턴이면 항상 실패

### 패턴 2: 콜체인 깊이 한계 (Case 4)

- **원인**: 타겟 함수가 등록된 핸들러의 callee일 때 역추적 불가
- **영향**: 무관한 syscall로 잘못 매핑
- **비교**: 같은 파일(nbd.c)이라도 핸들러 직접 → 성공, callee 1단계 → 실패

### 성공 조건 (Case 1, 2)

- 타겟이 직접 등록된 핸들러 함수 내부에 위치
- 지원 패턴: `file_operations`, `proto_ops`, `ioctl`, `genetlink` (`genl_small_ops`)
- 표준적인 콜체인 (과도한 함수 포인터 간접 참조 없음)

---

## 7. 개발한 도구

### 복잡도 프로파일러 (`source/benchmark/complexity_benchmark.py`)

타겟의 4축 복잡도 분석으로 SyzDirect 실패 가능성 예측:

| 축 | 측정 내용 |
|----|----------|
| **Reaching Distance** | syscall 진입점에서 타겟까지의 콜 깊이, BB 거리 |
| **Argument Complexity** | 시그니처 인자 타입/개수, 리소스 의존성 |
| **Resource Dependency** | D[resource] 체인, 사전 설정 요구사항 |
| **Syzlang Complexity** | 변형 개수, 파라미터 수, 중첩 깊이 |

출력: 0~100 복합 점수 (높을수록 실패 가능성 높음)

### 에이전트 루프 (`source/agent/`)

| 파일 | 역할 |
|------|------|
| `failure_triage.py` | 퍼징 로그 분석 → R1/R2/R3 분류 |
| `related_syscall_agent.py` | R3 대응: 누락된 predecessor syscall 추가, constraint 정제 |
| `object_synthesis_agent.py` | R2 대응: 파일시스템 이미지 생성 파이프라인, 복잡 오브젝트 합성 |

---

## 8. 빌드 및 운영 교훈

### 빌드 환경

| 교훈 | 설명 |
|------|------|
| CC 전달 방식 | `CC=... make` (환경변수)는 Kbuild에서 무시됨 → `make CC=...` 사용 |
| kcov 패치 | kcov.h/kcov.c가 있어도 `mark_block` 함수 유무 별도 확인 |
| RAM 요구량 | 7GB → 15GB로 증설 (TPA OOM 회피) |
| interface_generator cwd | output을 현재 디렉토리에 생성 → `cd $WDIR` 필수 |
| kcov 빌드 실패 | B040/B054의 `kcov.c:498: cannot assign to vm_flags` → v6.3 kcov.c로 교체 + 거리 패치 재적용 |

### SyzDirect 내부 동작

| 교훈 | 설명 |
|------|------|
| TPA 바이너리 | `target_analyzer` (`interface_generator` 아님) |
| TPA 인자 | `--kernel-interface-file` (단일 대시도 동작) |
| TPA 탐색 방식 | bitcode에서 `kcov_mark_block()` 탐색 (`--target-point` 아님) |
| Subset 전략 | drivers/ 제외하거나 관련 디렉토리만 포함하여 메모리 절약 |
| kernel_signature_full | `dist_flag=0`: 3필드, `dist_flag=1`: 5필드 |
| chunk 분할 | TPA는 청크 분할 시 콜그래프 단절 → 전체 실행 필요; interface_generator는 청크 분할 OK |

---

## 9. 향후 계획

### 단기 (R2/R3 분석 완료)

- [ ] Case 1, 2에 대해 InstrumentDistance + 실제 퍼징 실행
- [ ] SyzDirect 가이던스 유무에 따른 커버리지/버그 발견율 비교
- [ ] B054 (R2)에 ObjectSynthesisAgent 적용 → 올바른 compat 메시지 구조 생성

### 중기 (에이전트 검증)

- [ ] B029 (R1)에 RelatedSyscallAgent 적용 → GRE 터널 설정 syscall 주입
- [ ] LLM이 제안한 syscall 수동 검증 후 Precision/Recall 측정
- [ ] End-to-end 테스트: 에이전트 보완 → SyzDirect 파이프라인 → 실제 버그 트리거

### 장기 (확장 실험)

- [ ] 현재 5개 케이스 → 통계적 유의성 확보를 위한 추가 케이스 분석
- [ ] rtnl_register 패턴 에이전트 보완 (Case 0, 3) — 전체 TC 서브시스템 커버리지

---

*Report compiled from: case_0~4_analysis_report.md, FULL_PROJECT_REPORT.md, R1R2R3_experiment_report.md, run_case2_fuzzing.md*
*Last updated: 2026-03-14*
