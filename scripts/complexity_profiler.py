#!/usr/bin/env python3
"""
SyzDirect 타깃 복잡도 프로파일러 (프로토타입)
case_0 데이터 기반으로 4가지 복잡도 축을 추출한다.

축 1: 도달 거리 (call depth) - kernel_signature_full의 BB distance
축 2: 인자 구조 복잡도 - signature의 arg 타입/개수
축 3: 선행 리소스 의존성 - D[resource] 의존 여부 및 깊이
축 4: syzlang 타입 정의 복잡도 - syzkaller sys/linux/*.txt 파싱
"""

import os
import re
import json
from collections import defaultdict
from pathlib import Path


# ─── 축 1: 도달 거리 (BB distance from entry to target-related block) ───

def parse_kernel_signature(sig_path):
    """kernel_signature_full 파싱.
    포맷: signature distance_flag func bb_id entry_func
    """
    entries = []
    with open(sig_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # signature 부분과 나머지 분리
            parts = line.split()
            if len(parts) < 3:
                continue

            sig = parts[0]  # e.g. modify_ldt|C[0]|C[]|C[]
            # 나머지: distance_flag func bb_id entry_func (반복 가능)
            rest = parts[1:]

            sig_parts = sig.split('|')
            syscall_name = sig_parts[0]
            args = sig_parts[1:]

            # distance_flag는 첫번째 숫자
            try:
                dist_flag = int(rest[0])
            except (ValueError, IndexError):
                continue

            # func, bb_id, entry_func 추출
            # dist_flag=0: "func_name" (3 fields total)
            # dist_flag=1: "inner_func bb_id entry_func" (5 fields total)
            if dist_flag == 0 and len(rest) >= 2:
                inner_func = rest[1]
                bb_id = 0
                entry_func = rest[1]
            elif dist_flag == 1 and len(rest) >= 4:
                inner_func = rest[1]
                try:
                    bb_id = int(rest[2])
                except ValueError:
                    bb_id = 0
                entry_func = rest[3]
            elif len(rest) >= 2:
                inner_func = rest[1]
                bb_id = 0
                entry_func = rest[-1]
            else:
                inner_func = "unknown"
                bb_id = 0
                entry_func = "unknown"

            entries.append({
                'syscall': syscall_name,
                'args': args,
                'dist_flag': dist_flag,
                'inner_func': inner_func,
                'bb_id': bb_id,
                'entry_func': entry_func,
                'raw_sig': sig,
            })
    return entries


def calc_call_depth_metrics(entries):
    """syscall별 call depth / BB distance 메트릭"""
    syscall_metrics = defaultdict(lambda: {
        'max_bb_id': 0,
        'min_bb_id': float('inf'),
        'entry_count': 0,
        'unique_inner_funcs': set(),
        'unique_entry_funcs': set(),
        'dist_flag_1_count': 0,  # reachable with conditions
        'dist_flag_0_count': 0,  # direct
    })

    for e in entries:
        m = syscall_metrics[e['syscall']]
        m['max_bb_id'] = max(m['max_bb_id'], e['bb_id'])
        m['min_bb_id'] = min(m['min_bb_id'], e['bb_id'])
        m['entry_count'] += 1
        m['unique_inner_funcs'].add(e['inner_func'])
        m['unique_entry_funcs'].add(e['entry_func'])
        if e['dist_flag'] == 1:
            m['dist_flag_1_count'] += 1
        else:
            m['dist_flag_0_count'] += 1

    return syscall_metrics


# ─── 축 2: 인자 구조 복잡도 ───

def calc_arg_complexity(entries):
    """signature의 arg 타입/개수 기반 복잡도"""
    syscall_args = defaultdict(lambda: {
        'max_arg_count': 0,
        'arg_types': set(),
        'has_device_dep': False,
        'has_socket_dep': False,
        'device_types': set(),
        'const_value_count': 0,
        'unique_signatures': set(),
    })

    for e in entries:
        sc = e['syscall']
        m = syscall_args[sc]
        m['max_arg_count'] = max(m['max_arg_count'], len(e['args']))
        m['unique_signatures'].add(e['raw_sig'])

        for arg in e['args']:
            # 타입 추출: C[], D[], S[], P[] 등
            type_match = re.match(r'^([A-Z])', arg)
            if type_match:
                m['arg_types'].add(type_match.group(1))

            if arg.startswith('D['):
                m['has_device_dep'] = True
                dev = arg[2:-1] if arg.endswith(']') else arg[2:]
                m['device_types'].add(dev)
                if 'socket' in dev:
                    m['has_socket_dep'] = True

            if arg.startswith('C[') and arg != 'C[]':
                m['const_value_count'] += 1

    return syscall_args


# ─── 축 3: 선행 리소스 의존성 ───

def calc_resource_dependency(entries, syzlang_dir):
    """D[resource] 의존성 분석 + syzlang resource 체인"""

    # kernel_signature에서 리소스 의존성 추출
    resource_deps = defaultdict(lambda: {
        'requires_resource': False,
        'resource_types': set(),
        'dep_chain_depth': 0,  # 리소스 생성에 필요한 단계 수
    })

    for e in entries:
        sc = e['syscall']
        for arg in e['args']:
            if arg.startswith('D['):
                resource_deps[sc]['requires_resource'] = True
                dev = arg[2:].rstrip(']')
                resource_deps[sc]['resource_types'].add(dev)

    # syzlang에서 resource 생성 체인 파싱
    resource_creators = {}  # resource_type -> [creating syscalls]
    if os.path.isdir(syzlang_dir):
        for txt_file in Path(syzlang_dir).glob('*.txt'):
            try:
                content = txt_file.read_text(errors='ignore')
            except:
                continue

            # "resource fd_xxx[fd]" 패턴 찾기
            for m in re.finditer(r'^resource\s+(\w+)\[(\w+)\]', content, re.MULTILINE):
                res_name = m.group(1)
                parent = m.group(2)
                if res_name not in resource_creators:
                    resource_creators[res_name] = {'parent': parent, 'creators': []}

            # "syscall_name(...) resource_type" 패턴 (리턴 타입이 리소스)
            for m in re.finditer(r'^(\w+)\$?(\w*)\(.*?\)\s+(\w+)', content, re.MULTILINE):
                ret_type = m.group(3)
                syscall = m.group(1)
                if ret_type in resource_creators:
                    resource_creators[ret_type]['creators'].append(syscall)

    # 의존 체인 깊이 계산
    def chain_depth(res_type, visited=None):
        if visited is None:
            visited = set()
        if res_type in visited:
            return 0
        visited.add(res_type)
        if res_type not in resource_creators:
            return 0
        parent = resource_creators[res_type].get('parent', '')
        if parent and parent != res_type and parent in resource_creators:
            return 1 + chain_depth(parent, visited)
        return 1

    for sc, dep in resource_deps.items():
        max_depth = 0
        for res in dep['resource_types']:
            # socket-[family]-[type]-[proto] 형태 매핑
            if res.startswith('socket'):
                max_depth = max(max_depth, 1)  # socket() 한 번 필요
            elif res in resource_creators:
                max_depth = max(max_depth, chain_depth(res))
            else:
                # 알 수 없는 리소스 = 최소 1단계 필요
                max_depth = max(max_depth, 1)
        dep['dep_chain_depth'] = max_depth

    return resource_deps, resource_creators


# ─── 축 4: syzlang 타입 정의 복잡도 ───

def calc_syzlang_complexity(syscall_names, syzlang_dir):
    """syzkaller sys/linux/*.txt에서 syscall 정의 구조 복잡도 측정"""

    syscall_defs = defaultdict(lambda: {
        'defined': False,
        'variant_count': 0,
        'total_params': 0,
        'max_params': 0,
        'has_ptr_args': False,
        'has_struct_args': False,
        'nested_depth': 0,
        'definition_lines': [],
        'file': '',
    })

    if not os.path.isdir(syzlang_dir):
        return syscall_defs

    # 모든 syzlang 파일에서 syscall 정의 찾기
    for txt_file in Path(syzlang_dir).glob('*.txt'):
        try:
            content = txt_file.read_text(errors='ignore')
        except:
            continue

        for sc_name in syscall_names:
            # "syscall_name(" 또는 "syscall_name$variant(" 패턴
            pattern = rf'^({re.escape(sc_name)}(?:\$\w+)?)\((.*?)\)'
            for m in re.finditer(pattern, content, re.MULTILINE):
                full_name = m.group(1)
                params_str = m.group(2)

                d = syscall_defs[sc_name]
                d['defined'] = True
                d['variant_count'] += 1
                d['file'] = txt_file.name

                # 파라미터 분석
                if params_str.strip():
                    # 간단한 파라미터 카운팅 (중첩 괄호 고려)
                    depth = 0
                    param_count = 1
                    for ch in params_str:
                        if ch in '([':
                            depth += 1
                        elif ch in ')]':
                            depth -= 1
                        elif ch == ',' and depth == 0:
                            param_count += 1

                    d['total_params'] += param_count
                    d['max_params'] = max(d['max_params'], param_count)

                    if 'ptr[' in params_str:
                        d['has_ptr_args'] = True
                    if 'struct' in params_str or '{' in params_str:
                        d['has_struct_args'] = True

                    # 중첩 깊이 (ptr[in, ptr[...]] 등)
                    max_nest = 0
                    cur_nest = 0
                    for ch in params_str:
                        if ch == '[':
                            cur_nest += 1
                            max_nest = max(max_nest, cur_nest)
                        elif ch == ']':
                            cur_nest -= 1
                    d['nested_depth'] = max(d['nested_depth'], max_nest)

                d['definition_lines'].append(m.group(0)[:120])

    return syscall_defs


# ─── 통합 프로파일 생성 ───

def build_profile(case_dir, syzlang_dir, target_info):
    sig_path = os.path.join(case_dir, 'kernel_signature_full')
    if not os.path.exists(sig_path):
        print(f"ERROR: {sig_path} not found")
        return None

    print(f"=== 타깃: {target_info['file']}:{target_info['line']} ({target_info['type']}) ===\n")

    # 파싱
    entries = parse_kernel_signature(sig_path)
    print(f"총 엔트리: {len(entries)}")

    syscall_names = sorted(set(e['syscall'] for e in entries))
    print(f"고유 syscall: {len(syscall_names)} → {syscall_names}\n")

    # 축 1: call depth
    depth_metrics = calc_call_depth_metrics(entries)

    # 축 2: 인자 복잡도
    arg_metrics = calc_arg_complexity(entries)

    # 축 3: 리소스 의존성
    res_deps, res_creators = calc_resource_dependency(entries, syzlang_dir)

    # 축 4: syzlang 정의 복잡도
    syzlang_metrics = calc_syzlang_complexity(syscall_names, syzlang_dir)

    # ─── 통합 테이블 출력 ───
    print("=" * 120)
    print(f"{'syscall':<16} {'entries':>7} {'funcs':>5} {'maxBB':>5} "
          f"{'args':>4} {'types':>6} {'res_dep':>7} {'res_type':<30} "
          f"{'syz_var':>7} {'syz_par':>7} {'syz_nest':>8}")
    print("-" * 120)

    profile_rows = []
    for sc in syscall_names:
        dm = depth_metrics[sc]
        am = arg_metrics[sc]
        rd = res_deps[sc]
        sl = syzlang_metrics[sc]

        res_type_str = ', '.join(sorted(rd['resource_types']))[:28] if rd['resource_types'] else '-'
        type_str = ''.join(sorted(am['arg_types']))

        row = {
            'syscall': sc,
            # 축 1: 도달 거리
            'entry_count': dm['entry_count'],
            'unique_funcs': len(dm['unique_inner_funcs']),
            'max_bb_id': dm['max_bb_id'],
            'dist_conditional': dm['dist_flag_1_count'],
            'dist_direct': dm['dist_flag_0_count'],
            # 축 2: 인자 복잡도
            'max_arg_count': am['max_arg_count'],
            'arg_types': type_str,
            'unique_sigs': len(am['unique_signatures']),
            'has_device': am['has_device_dep'],
            'has_socket': am['has_socket_dep'],
            # 축 3: 리소스 의존성
            'requires_resource': rd['requires_resource'],
            'resource_types': sorted(rd['resource_types']),
            'dep_chain_depth': rd['dep_chain_depth'],
            # 축 4: syzlang 복잡도
            'syzlang_defined': sl['defined'],
            'syzlang_variants': sl['variant_count'],
            'syzlang_max_params': sl['max_params'],
            'syzlang_nested_depth': sl['nested_depth'],
        }
        profile_rows.append(row)

        print(f"{sc:<16} {dm['entry_count']:>7} {len(dm['unique_inner_funcs']):>5} {dm['max_bb_id']:>5} "
              f"{am['max_arg_count']:>4} {type_str:>6} {'Y' if rd['requires_resource'] else 'N':>7} {res_type_str:<30} "
              f"{sl['variant_count']:>7} {sl['max_params']:>7} {sl['nested_depth']:>8}")

    print("=" * 120)

    # ─── 복합 복잡도 점수 계산 ───
    print("\n=== 복합 복잡도 점수 (높을수록 SyzDirect가 실패할 가능성 높음) ===\n")

    for row in sorted(profile_rows, key=lambda r: _composite_score(r), reverse=True):
        score = _composite_score(row)
        breakdown = _score_breakdown(row)
        print(f"  {row['syscall']:<16} 총점={score:>5.1f}  {breakdown}")

    # JSON 저장
    output = {
        'target': target_info,
        'total_entries': len(entries),
        'unique_syscalls': len(syscall_names),
        'profiles': profile_rows,
    }

    out_path = os.path.join(os.path.dirname(case_dir), 'complexity_profile_case_0.json')

    # set을 list로 변환
    def convert_sets(obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, dict):
            return {k: convert_sets(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [convert_sets(i) for i in obj]
        return obj

    with open(out_path, 'w') as f:
        json.dump(convert_sets(output), f, indent=2, ensure_ascii=False)
    print(f"\n저장됨: {out_path}")

    return output


def _composite_score(row):
    """복합 복잡도 점수 (0~100 스케일)"""
    s = 0.0

    # 축 1: 도달 거리 (경로 다양성) - max 25점
    func_score = min(row['unique_funcs'] * 2, 15)
    bb_score = min(row['max_bb_id'] / 10, 10)
    s += func_score + bb_score

    # 축 2: 인자 복잡도 - max 25점
    arg_score = min(row['max_arg_count'] * 3, 12)
    sig_score = min(row['unique_sigs'] / 5, 8)
    dev_score = 5 if row['has_device'] else 0
    s += arg_score + sig_score + dev_score

    # 축 3: 리소스 의존성 - max 25점
    if row['requires_resource']:
        s += 10
        s += min(row['dep_chain_depth'] * 5, 15)

    # 축 4: syzlang 복잡도 - max 25점
    if row['syzlang_defined']:
        s += min(row['syzlang_variants'] * 2, 10)
        s += min(row['syzlang_max_params'] * 2, 10)
        s += min(row['syzlang_nested_depth'] * 2.5, 5)

    return round(s, 1)


def _score_breakdown(row):
    """점수 내역"""
    parts = []

    # 축 1
    d = min(row['unique_funcs'] * 2, 15) + min(row['max_bb_id'] / 10, 10)
    parts.append(f"도달={d:.0f}")

    # 축 2
    a = min(row['max_arg_count'] * 3, 12) + min(row['unique_sigs'] / 5, 8) + (5 if row['has_device'] else 0)
    parts.append(f"인자={a:.0f}")

    # 축 3
    r = 0
    if row['requires_resource']:
        r = 10 + min(row['dep_chain_depth'] * 5, 15)
    parts.append(f"의존={r:.0f}")

    # 축 4
    z = 0
    if row['syzlang_defined']:
        z = min(row['syzlang_variants'] * 2, 10) + min(row['syzlang_max_params'] * 2, 10) + min(row['syzlang_nested_depth'] * 2.5, 5)
    parts.append(f"syzlang={z:.0f}")

    return '  '.join(parts)


if __name__ == '__main__':
    case_0_interface = '/work/syzdirect_workdir/interfaces/case_0'
    syzlang_dir = '/work/syzkaller/sys/linux'
    target_info = {
        'file': 'net/sched/cls_tcindex.c',
        'line': 309,
        'type': 'patch',
        'commit': '3f2db250099f',
        'case_idx': 0,
    }

    build_profile(case_0_interface, syzlang_dir, target_info)
