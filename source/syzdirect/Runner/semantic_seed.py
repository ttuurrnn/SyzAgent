"""
SyzDirect Runner — Semantic Seed Synthesis Pipeline.

Generic kernel source analysis → call-chain extraction → prerequisite
resolution → branch predicate extraction → structured seed plan → domain
encoder → seed validation.

Architecture:
  1. Generic analyzer   — reads kernel source, extracts call chains,
                          prerequisites, and branch predicates
  2. Plan IR            — JSON representation of what the seed must do
  3. Domain encoders    — netlink, ioctl, bpf, etc. (registry-based)
  4. Seed validator     — checks seeds against extracted constraints
  5. LLM integration    — multi-step prompts for analysis + synthesis
"""

import json
import os
import re
import shutil
import struct
import subprocess


def _rg_bin():
    """Resolve the ripgrep binary path, falling back to known locations."""
    path = shutil.which("rg")
    if path:
        return path
    for candidate in (
        "/usr/local/lib/node_modules/@github/copilot/ripgrep/bin/linux-x64/rg",
        "/usr/local/lib/node_modules/@openai/codex/bin/rg",
        "/usr/bin/rg",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "rg"


def _find_function_definition(src_dir, function_name, hint_file=""):
    """Find the most plausible source file defining function_name."""
    if not src_dir or not os.path.isdir(src_dir) or not function_name:
        return ""
    search_roots = []
    if hint_file:
        hinted = os.path.join(src_dir, os.path.dirname(hint_file))
        if os.path.isdir(hinted):
            search_roots.append(hinted)
    search_roots.append(src_dir)
    pattern = rf"^[a-zA-Z_][^;\n]*\b{re.escape(function_name)}\s*\("
    for root in search_roots:
        try:
            result = subprocess.run(
                [_rg_bin(), "-n", "-g", "*.c", pattern, root],
                capture_output=True, text=True, timeout=20,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if result.returncode != 0 or not result.stdout.strip():
            continue
        first = result.stdout.strip().splitlines()[0]
        return os.path.relpath(first.split(":", 1)[0], src_dir)
    return ""


def normalize_target_metadata(src_dir, target_function, target_file):
    """Resolve stale target metadata against the source tree."""
    resolved_file = target_file or ""
    full_path = os.path.join(src_dir, resolved_file) if resolved_file else ""
    if not resolved_file or not os.path.exists(full_path):
        guessed = _find_function_definition(src_dir, target_function, target_file)
        if guessed:
            resolved_file = guessed
            full_path = os.path.join(src_dir, resolved_file)
    elif target_function:
        try:
            result = subprocess.run(
                [_rg_bin(), "-n", rf"\b{re.escape(target_function)}\s*\(", full_path],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            result = None
        if not result or result.returncode != 0 or not result.stdout.strip():
            guessed = _find_function_definition(src_dir, target_function, target_file)
            if guessed:
                resolved_file = guessed
    return {"target_function": target_function, "target_file": resolved_file}


def _collect_function_ranges(filepath):
    """Collect function ranges from a C file, handling multi-line definitions."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
    except OSError:
        return [], []

    ranges = []
    i = 0
    while i < len(lines):
        window = "".join(lines[i:i + 6])
        m = re.match(
            r'^\s*(?:static\s+|inline\s+|const\s+|__always_inline\s+|__maybe_unused\s+|'
            r'noinline\s+|asmlinkage\s+|__init\s+|__latent_entropy\s+|__net_init\s+|'
            r'__sched\s+|__releases\([^)]+\)\s+|__acquires\([^)]+\)\s+)*'
            r'[a-zA-Z_][\w\s\*\(\),]*?\b([a-zA-Z_]\w+)\s*\([^;]*\)\s*\{',
            window,
            re.DOTALL,
        )
        if not m:
            i += 1
            continue
        name = m.group(1)
        brace_depth = 0
        started = False
        end = i
        for j in range(i, len(lines)):
            brace_depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            end = j
            if started and brace_depth <= 0 and j > i:
                break
        ranges.append({"name": name, "start": i, "end": end})
        i = end + 1

    return lines, ranges


# ══════════════════════════════════════════════════════════════════════════
# Phase 1: Generic Call-Chain Extraction
# ══════════════════════════════════════════════════════════════════════════

def extract_call_chain(src_dir, target_function, target_file, max_depth=8):
    """Trace callers of target_function back toward syscall entry points.

    Returns a list of dicts: [{function, file, line, dispatch_hint}, ...]
    ordered from syscall entry (index 0) down to target (last element).
    """
    if not os.path.isdir(src_dir):
        return []
    normalized = normalize_target_metadata(src_dir, target_function, target_file)
    target_file = normalized.get("target_file", target_file)

    chain = []
    visited = {target_function}
    frontier = [{"function": target_function, "file": target_file}]

    for depth in range(max_depth):
        if not frontier:
            break
        cur = frontier[0]
        fn = cur["function"]

        # Find callers of fn in kernel source
        callers = _find_callers(src_dir, fn, cur.get("file", ""))
        if not callers:
            break

        # Pick the most relevant caller (prefer same file, then net/sched, etc.)
        best = _pick_best_caller(callers, cur.get("file", ""), visited)
        if not best:
            break

        visited.add(best["function"])
        chain.append(best)
        frontier = [best]

        # Stop if we hit a known syscall entry pattern
        if _is_syscall_entry(best["function"]):
            break

    # Reverse: syscall entry first, target last
    chain.reverse()
    chain.append({"function": target_function, "file": target_file,
                   "line": 0, "dispatch_hint": "target"})
    return chain


def _find_callers(src_dir, function_name, hint_file=""):
    """Find functions that call function_name in kernel source."""
    callers = []
    # Search in hint file's directory first, then broader
    search_dirs = []
    if hint_file:
        hint_dir = os.path.join(src_dir, os.path.dirname(hint_file))
        if os.path.isdir(hint_dir):
            search_dirs.append(hint_dir)
    search_dirs.append(src_dir)

    seen = set()
    for sdir in search_dirs:
        try:
            result = subprocess.run(
                [_rg_bin(), "-l", "-g", "*.c", rf"\b{re.escape(function_name)}\s*\(", sdir],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        for fpath in result.stdout.strip().split("\n"):
            fpath = fpath.strip()
            if not fpath or fpath in seen:
                continue
            seen.add(fpath)
            caller_info = _extract_caller_from_file(fpath, function_name, src_dir)
            callers.extend(caller_info)

    return callers


def _extract_caller_from_file(filepath, callee_name, src_dir):
    """Find which function(s) in filepath call callee_name."""
    results = []
    lines, ranges = _collect_function_ranges(filepath)
    if not lines or not ranges:
        return results
    rel_path = os.path.relpath(filepath, src_dir) if src_dir else filepath

    for fr in ranges:
        if fr["name"] == callee_name:
            continue
        body = lines[fr["start"]:fr["end"] + 1]
        for idx, line in enumerate(body):
            if re.search(rf'\b{re.escape(callee_name)}\s*\(', line):
                abs_line = fr["start"] + idx
                context_start = max(fr["start"], abs_line - 3)
                context = "".join(lines[context_start:abs_line + 1])
                dispatch = _extract_dispatch_hint(context, callee_name)
                results.append({
                    "function": fr["name"],
                    "file": rel_path,
                    "line": abs_line + 1,
                    "dispatch_hint": dispatch,
                })
                break

    return results


def _extract_dispatch_hint(context, callee_name):
    """Extract what dispatch mechanism leads to this call."""
    # ops->change(), ops->init(), etc.
    if re.search(r'->(\w+)\s*\(', context):
        m = re.search(r'->(\w+)\s*\(', context)
        return f"ops->{m.group(1)}"
    # switch/case
    if "switch" in context or "case " in context:
        return "switch_dispatch"
    # Direct call
    return "direct_call"


def _pick_best_caller(callers, hint_file, visited):
    """Pick the most relevant caller, preferring same subsystem."""
    if not callers:
        return None

    hint_dir = os.path.dirname(hint_file) if hint_file else ""

    def score(c):
        fn = c["function"]
        if fn in visited:
            return -1
        s = 0
        # Same directory = high priority
        if hint_dir and c.get("file", "").startswith(hint_dir):
            s += 10
        # Known handler patterns
        if any(p in fn for p in ("_rcv", "_handler", "_dispatch", "_new", "_change")):
            s += 5
        # Avoid noise
        if any(fn.startswith(p) for p in ("__trace", "trace_", "perf_")):
            s -= 20
        return s

    ranked = sorted(callers, key=score, reverse=True)
    for c in ranked:
        if c["function"] not in visited and score(c) >= 0:
            return c
    return None


_SYSCALL_ENTRY_PATTERNS = re.compile(
    r'(SYSCALL_DEFINE|sys_|__sys_|compat_sys_|'
    r'rtnetlink_rcv|genl_rcv|netlink_rcv|'
    r'sock_sendmsg|sock_recvmsg|'
    r'vfs_ioctl|do_vfs_ioctl|'
    r'__x64_sys_|__arm64_sys_)'
)


def _is_syscall_entry(func_name):
    return bool(_SYSCALL_ENTRY_PATTERNS.search(func_name))


# ══════════════════════════════════════════════════════════════════════════
# Phase 2: Prerequisite Extraction
# ══════════════════════════════════════════════════════════════════════════

def extract_prerequisites(src_dir, call_chain):
    """For each function in the call chain, extract validation/error paths.

    Returns a list of prerequisite dicts:
    [{"function": ..., "conditions": [...], "dependencies": [...]}]
    """
    prereqs = []
    for entry in call_chain:
        fn = entry["function"]
        fpath = entry.get("file", "")
        full_path = os.path.join(src_dir, fpath) if fpath else ""

        if not full_path or not os.path.exists(full_path):
            continue

        source = _read_function_source(full_path, fn)
        if not source:
            continue

        conditions = _extract_error_conditions(source)
        dependencies = _extract_dependencies(source)
        prereqs.append({
            "function": fn,
            "file": fpath,
            "conditions": conditions,
            "dependencies": dependencies,
            "source_snippet": source[:2000],  # cap for LLM prompt
        })

    return prereqs


def _read_function_source(filepath, func_name, max_lines=80):
    """Read the source of a specific function from a file."""
    lines, ranges = _collect_function_ranges(filepath)
    if not lines or not ranges:
        return ""
    fr = next((r for r in ranges if r["name"] == func_name), None)
    if not fr:
        return ""
    start = fr["start"]
    end = min(fr["end"] + 1, start + max_lines)
    return "".join(lines[start:end])


def _extract_error_conditions(source):
    """Extract if-return-error patterns from function source."""
    conditions = []
    # Pattern: if (...) { return -EINVAL; }  or  if (!x) return -ERANGE;
    for m in re.finditer(
        r'if\s*\(([^)]{1,120})\)\s*(?:\{[^}]*)?return\s+(-\w+|err\w*)',
        source, re.DOTALL
    ):
        cond = m.group(1).strip()
        err = m.group(2).strip()
        conditions.append({"condition": cond, "error": err})

    # Pattern: if (!x) goto err;
    for m in re.finditer(r'if\s*\(([^)]{1,80})\)\s*goto\s+(\w*err\w*)', source):
        conditions.append({"condition": m.group(1).strip(), "error": f"goto {m.group(2)}"})

    return conditions


def _extract_dependencies(source):
    """Extract object/resource dependencies from function source."""
    deps = []

    # Patterns indicating resource lookup/creation
    dep_patterns = [
        (r'(\w+)\s*=\s*(\w*find\w*|lookup\w*|get\w*)\s*\(', "lookup"),
        (r'(\w+)\s*=\s*(\w*alloc\w*|create\w*|init\w*)\s*\(', "create"),
        (r'if\s*\(\s*!(\w+)\s*\)', "null_check"),
        (r'nla_parse\w*\s*\([^,]+,\s*(\w+)', "nla_policy"),
    ]
    for pattern, dep_type in dep_patterns:
        for m in re.finditer(pattern, source):
            deps.append({"type": dep_type, "name": m.group(1), "detail": m.group(0)[:80]})

    error_assignments = {}
    for m in re.finditer(r'\b(err\w*|ret\w*|rc)\s*=\s*([a-zA-Z_]\w*)\s*\(([^)]*)\)', source):
        error_assignments[m.group(1)] = {
            "helper": m.group(2),
            "detail": m.group(0)[:120],
        }
    for m in re.finditer(r'if\s*\(\s*(err\w*|ret\w*|rc)\s*\)\s*return\s+\1\s*;', source):
        info = error_assignments.get(m.group(1))
        if not info:
            continue
        helper = info["helper"]
        dep_type = "error_propagation"
        if any(tok in helper for tok in ("find", "lookup", "get")):
            dep_type = "lookup_guard"
        elif any(tok in helper for tok in ("create", "alloc", "init", "parse")):
            dep_type = "setup_guard"
        deps.append({"type": dep_type, "name": helper, "detail": info["detail"]})

    source_map = {}
    for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*=\s*([^;]+);', source):
        source_map[m.group(1)] = m.group(2).strip()[:120]
    for m in re.finditer(r'if\s*\(\s*!\s*([a-zA-Z_]\w*)\s*\)', source):
        var = m.group(1)
        if var in source_map:
            deps.append({"type": "required_value", "name": var, "detail": source_map[var]})

    return deps


# ══════════════════════════════════════════════════════════════════════════
# Phase 3: Branch Predicate Extraction (near target)
# ══════════════════════════════════════════════════════════════════════════

def extract_branch_predicates(src_dir, target_function, target_file, call_chain=None, context_lines=30):
    """Extract branch conditions that gate the call to target_function.

    Reads the caller of target_function and extracts if-conditions
    that surround the call site.
    """
    predicates = []
    search_sites = []
    if call_chain and len(call_chain) >= 2:
        search_sites.append((call_chain[-2].get("file", ""), target_function))
    if target_file:
        search_sites.append((target_file, target_function))

    seen = set()
    for rel_file, callee in search_sites:
        if not rel_file or rel_file in seen:
            continue
        seen.add(rel_file)
        full_path = os.path.join(src_dir, rel_file)
        if not os.path.exists(full_path):
            continue
        try:
            with open(full_path) as f:
                lines = f.readlines()
        except OSError:
            continue

        for i, line in enumerate(lines):
            if not re.search(rf'\b{re.escape(callee)}\s*\(', line):
                continue
            start = max(0, i - context_lines)
            context = lines[start:i + 1]
            for j, ctx_line in enumerate(context):
                if_match = re.match(r'\s*if\s*\((.+)\)\s*\{?\s*$', ctx_line)
                if if_match:
                    cond = if_match.group(1).strip()
                    predicates.append({
                        "condition": cond,
                        "line": start + j + 1,
                        "context": "".join(context[max(0, j - 2):j + 3]).strip(),
                    })

    return predicates


# ══════════════════════════════════════════════════════════════════════════
# Phase 3.5: nla_policy / enum extraction
# ══════════════════════════════════════════════════════════════════════════

def extract_nla_policy(src_dir, target_file, kind_name=""):
    """Extract netlink attribute policy definitions from kernel source.

    Returns a dict: {attr_name: {"type": nla_type, "index": int, "size": int}}
    """
    full_path = os.path.join(src_dir, target_file) if target_file else ""
    if not full_path or not os.path.exists(full_path):
        return {}

    try:
        with open(full_path) as f:
            source = f.read()
    except OSError:
        return {}

    policies = {}

    # Find policy arrays: static const struct nla_policy xxx_policy[...] = { ... };
    # Use a two-step approach: find the start, then brace-match the body.
    policy_start = re.compile(
        r'(?:static\s+)?(?:const\s+)?struct\s+nla_policy\s+(\w+)\s*\[[^\]]*\]\s*=\s*\{',
        re.DOTALL,
    )
    for m in policy_start.finditer(source):
        policy_name = m.group(1)
        # Brace-match from the opening '{'
        start = m.end() - 1  # position of '{'
        depth, i = 0, start
        while i < len(source):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = source[start + 1:i]

        # Parse [ATTR_NAME] = { .type = NLA_XXX },
        for attr_m in re.finditer(
            r'\[(\w+)\]\s*=\s*\{([^}]*)\}', body
        ):
            attr_name = attr_m.group(1)
            attr_body = attr_m.group(2)

            nla_type = ""
            type_m = re.search(r'\.type\s*=\s*(\w+)', attr_body)
            if type_m:
                nla_type = type_m.group(1)

            policies[attr_name] = {
                "policy_array": policy_name,
                "nla_type": nla_type,
                "size": _nla_type_size(nla_type),
            }

    # Resolve enum values for attribute indices
    names = set(policies.keys())
    enum_values = _extract_enum_values(source, names)

    # If not found in target file, search UAPI headers
    unresolved = names - set(enum_values.keys())
    if unresolved and src_dir:
        header_dirs = [
            os.path.join(src_dir, "include", "uapi", "linux"),
            os.path.join(src_dir, "include", "linux"),
        ]
        for hdir in header_dirs:
            if not unresolved or not os.path.isdir(hdir):
                continue
            for hfile in os.listdir(hdir):
                if not hfile.endswith(".h"):
                    continue
                try:
                    with open(os.path.join(hdir, hfile)) as hf:
                        hdr_source = hf.read()
                except OSError:
                    continue
                found = _extract_enum_values(hdr_source, unresolved)
                enum_values.update(found)
                unresolved -= set(found.keys())

    for attr_name, info in policies.items():
        if attr_name in enum_values:
            info["index"] = enum_values[attr_name]

    return policies


def _nla_type_size(nla_type):
    """Map NLA_* type to expected payload size in bytes."""
    return {
        "NLA_U8": 1, "NLA_U16": 2, "NLA_U32": 4, "NLA_U64": 8,
        "NLA_S8": 1, "NLA_S16": 2, "NLA_S32": 4, "NLA_S64": 8,
        "NLA_FLAG": 0, "NLA_STRING": -1, "NLA_NUL_STRING": -1,
        "NLA_BINARY": -1, "NLA_NESTED": -1,
    }.get(nla_type, -1)


def _extract_enum_values(source, names_of_interest):
    """Extract enum constant values from source, for names in names_of_interest."""
    values = {}
    # Find enum blocks
    for m in re.finditer(r'enum\s*\w*\s*\{([^}]+)\}', source, re.DOTALL):
        body = m.group(1)
        idx = 0
        for line in body.split(","):
            line = line.strip()
            if not line or line.startswith("/*") or line.startswith("//"):
                continue
            # Handle NAME = VALUE
            eq_match = re.match(r'(\w+)\s*=\s*(\d+)', line)
            if eq_match:
                name = eq_match.group(1)
                idx = int(eq_match.group(2))
                if name in names_of_interest:
                    values[name] = idx
                idx += 1
                continue
            # Handle plain NAME
            name_match = re.match(r'(\w+)', line)
            if name_match:
                name = name_match.group(1)
                if name in names_of_interest:
                    values[name] = idx
                idx += 1

    return values


# ══════════════════════════════════════════════════════════════════════════
# Phase 4: Seed Plan IR
# ══════════════════════════════════════════════════════════════════════════

def build_seed_plan(call_chain, prerequisites, predicates, nla_policy, target_function, target_file):
    """Combine all analysis into a structured seed plan.

    The plan is a JSON-serializable dict that describes exactly what
    a seed program needs to do, in domain-agnostic terms.
    """
    # Detect domain from target_file
    domain = _detect_domain(target_file)

    # Build prerequisite sequence
    prereq_sequence = []
    for prereq in prerequisites:
        for dep in prereq.get("dependencies", []):
            if dep["type"] in ("lookup", "null_check"):
                prereq_sequence.append({
                    "action": "ensure_exists",
                    "object": dep["name"],
                    "detail": dep["detail"],
                    "source_function": prereq["function"],
                })
            elif dep["type"] == "create":
                prereq_sequence.append({
                    "action": "create",
                    "object": dep["name"],
                    "detail": dep["detail"],
                    "source_function": prereq["function"],
                })

    # Build condition list
    conditions = []
    for pred in predicates:
        conditions.append({
            "expression": pred["condition"],
            "line": pred.get("line", 0),
            "context": pred.get("context", ""),
        })

    # Build attribute specs from nla_policy
    attr_specs = {}
    for attr_name, info in nla_policy.items():
        attr_specs[attr_name] = {
            "index": info.get("index"),
            "nla_type": info.get("nla_type", ""),
            "size": info.get("size", -1),
        }

    plan = {
        "target_function": target_function,
        "target_file": target_file,
        "domain": domain,
        "call_chain": [
            {"function": c["function"], "file": c.get("file", ""),
             "dispatch": c.get("dispatch_hint", "")}
            for c in call_chain
        ],
        "prerequisite_sequence": prereq_sequence,
        "branch_conditions": conditions,
        "attribute_specs": attr_specs,
        "source_snippets": {
            p["function"]: p.get("source_snippet", "")
            for p in prerequisites if p.get("source_snippet")
        },
    }
    plan["execution_requirements"] = _derive_execution_requirements(plan)
    return plan


def _derive_execution_requirements(plan):
    """Derive structural execution requirements from the generic plan."""
    req = {
        "message_sequence": [],
        "required_option_attrs": False,
        "prefer_update_shape": False,
        "required_kinds": [],
    }
    target_file = plan.get("target_file", "")
    call_chain = [c.get("function", "") for c in plan.get("call_chain", [])]
    if plan.get("domain") == "tc_netlink":
        basename = os.path.basename(target_file)
        target_kind = ""
        for fn in reversed(call_chain):
            m = re.search(r'(tcindex|u32|flower|matchall|bpf|pfifo|prio|teql|ingress|clsact)', fn)
            if m:
                target_kind = m.group(1)
                break
        if target_kind:
            req["required_kinds"].append(target_kind)
        if basename.startswith("cls_") or basename.startswith("act_"):
            req["message_sequence"] = [0x24, 0x2C]
            req["required_option_attrs"] = True
        elif basename.startswith("sch_"):
            req["message_sequence"] = [0x24]
        if any(any(tok in fn for tok in ("change", "update", "replace", "modify", "alloc",
                                         "set_limit", "set_parms")) for fn in call_chain):
            req["prefer_update_shape"] = True
        # Child qdisc files (sch_fifo.c, sch_pfifo.c) always need parent setup
        if basename in ("sch_fifo.c", "sch_pfifo.c", "sch_pfifo_fast.c"):
            req["prefer_update_shape"] = True
    return req


def _detect_domain(target_file):
    """Detect kernel subsystem domain from file path."""
    if not target_file:
        return "unknown"
    if "net/sched" in target_file:
        return "tc_netlink"
    if "net/netlink" in target_file or "net/core/rtnetlink" in target_file:
        return "netlink"
    if "net/" in target_file:
        return "network"
    if "drivers/" in target_file:
        return "driver_ioctl"
    if "fs/" in target_file:
        return "filesystem"
    if "kernel/bpf" in target_file or "net/core/filter" in target_file:
        return "bpf"
    return "unknown"


# ══════════════════════════════════════════════════════════════════════════
# Phase 5: Domain Encoders (registry-based)
# ══════════════════════════════════════════════════════════════════════════

class DomainEncoder:
    """Base class for domain-specific message/struct encoders."""

    def can_handle(self, plan):
        return False

    def generate_seeds(self, plan):
        """Return list of {"name": ..., "text": ...} seed programs."""
        return []


class TCNetlinkEncoder(DomainEncoder):
    """Encoder for TC (traffic control) netlink messages."""

    def can_handle(self, plan):
        return plan.get("domain") in ("tc_netlink",)

    def generate_seeds(self, plan):
        target_file = plan.get("target_file", "")
        target_func = plan.get("target_function", "")
        attr_specs = plan.get("attribute_specs", {})
        conditions = plan.get("branch_conditions", [])

        # Infer TC kind from target function name
        kind = self._infer_kind(target_func, plan.get("call_chain", []))
        if not kind:
            # Generic classifier dispatcher (cls_api.c) — try common kinds
            if self._is_generic_classifier(target_file):
                all_programs = []
                for k in ("flower", "u32", "basic", "matchall"):
                    all_programs.extend(
                        self._build_programs(k, "filter", attr_specs, {},
                                             prefer_update=False))
                return all_programs
            return []

        # Detect target type from file
        target_type = self._detect_type(target_file)

        # Build attribute values that satisfy branch conditions
        attr_values = self._solve_conditions(conditions, attr_specs, kind)

        # Merge LLM-solved condition values into attr_values
        for sol in plan.get("solved_values", []):
            vals = sol.get("values", {})
            if not vals:
                continue
            # If LLM provided hash/mask/shift combos, add as variants
            if any(k in vals for k in ("hash", "mask", "shift")):
                def _to_int(v, default):
                    try:
                        return int(v, 0) if isinstance(v, str) else int(v)
                    except (ValueError, TypeError):
                        return default
                variant = {
                    "hash": _to_int(vals.get("hash", 0x10), 0x10),
                    "mask": _to_int(vals.get("mask", 0x000f), 0x000f),
                    "shift": _to_int(vals.get("shift", 0), 0),
                }
                existing = attr_values.get("hash_variants", [])
                if variant not in existing:
                    existing.append(variant)
                    attr_values["hash_variants"] = existing
            # Apply any other field-level overrides
            for k, v in vals.items():
                if k not in ("hash", "mask", "shift") and isinstance(v, (int, float)):
                    attr_values[k] = v

        # Generate seed programs with proper prerequisite sequence
        exec_req = plan.get("execution_requirements", {})
        prefer_update = exec_req.get("prefer_update_shape", False)
        return self._build_programs(kind, target_type, attr_specs, attr_values,
                                    prefer_update=prefer_update)

    _KIND_MAP = {
        "tcindex": "tcindex", "pfifo": "pfifo", "tbf": "tbf",
        "htb": "htb", "hfsc": "hfsc", "sfq": "sfq",
        "fq_codel": "fq_codel", "codel": "codel", "netem": "netem",
        "cbq": "cbq", "qfq": "qfq", "u32": "u32", "cls_u32": "u32",
        "flower": "flower", "matchall": "matchall", "bpf": "bpf",
        "red": "red", "choke": "choke", "drr": "drr",
        "teql": "teql", "ingress": "ingress", "clsact": "clsact",
        "route": "route4", "fw": "fw",
    }
    # TC source convention: short prefix → full kind name
    _PREFIX_ALIASES = {
        "fl_": "flower", "mall_": "matchall", "basic_": "basic",
        "route4_": "route4", "fw_": "fw", "cls_u32": "u32",
    }

    def _infer_kind(self, target_func, call_chain):
        candidates = [target_func] + [c["function"] for c in call_chain]
        # Pass 1: exact prefix match
        for fn in candidates:
            for prefix, kind in self._KIND_MAP.items():
                if fn.startswith(prefix):
                    return kind
        # Pass 2: TC short-prefix aliases (fl_ → flower, mall_ → matchall)
        for fn in candidates:
            for prefix, kind in self._PREFIX_ALIASES.items():
                if fn.startswith(prefix):
                    return kind
        # Pass 3: infer from source file name (cls_flower.c → flower)
        for c in call_chain:
            basename = os.path.basename(c.get("file", ""))
            m = re.match(r'cls_(\w+)\.c', basename)
            if m and m.group(1) not in ("api", "route"):
                return self._KIND_MAP.get(m.group(1), m.group(1))
            m = re.match(r'sch_(\w+)\.c', basename)
            if m and m.group(1) not in ("api", "generic"):
                return self._KIND_MAP.get(m.group(1), m.group(1))
        return None

    def _detect_type(self, target_file):
        basename = os.path.basename(target_file)
        if basename.startswith("cls_"):
            return "filter"
        if basename.startswith("act_"):
            return "action"
        return "qdisc"

    @staticmethod
    def _is_generic_classifier(target_file):
        """Check if target is a generic TC classifier dispatcher (not kind-specific)."""
        basename = os.path.basename(target_file or "")
        return basename in ("cls_api.c", "act_api.c")

    def _solve_conditions(self, conditions, attr_specs, kind):
        """Try to solve branch predicates into concrete attribute values.

        This is the key semantic step: read conditions like
        'p->hash > (p->mask >> p->shift)' and produce values that satisfy them.
        """
        values = {}

        for cond in conditions:
            expr = cond.get("expression", "")

            # Pattern: hash > (mask >> shift) → need hash > mask >> shift
            if re.search(r'hash.*>.*mask.*>>.*shift', expr, re.IGNORECASE):
                # Multiple valid combinations
                values.setdefault("hash_variants", [
                    {"hash": 0x10, "mask": 0x000f, "shift": 0},  # 16 > 15
                    {"hash": 0x20, "mask": 0x001f, "shift": 0},  # 32 > 31
                    {"hash": 0x08, "mask": 0x0007, "shift": 0},  # 8 > 7
                    {"hash": 0x40, "mask": 0x003f, "shift": 0},  # 64 > 63
                    {"hash": 0x10, "mask": 0x001f, "shift": 1},  # 16 > 15
                ])

            # Pattern: mask >> shift < SOME_LIMIT (e.g. valid_perfect_hash)
            m = re.search(r'mask\s*>>\s*shift\s*<\s*(\d+)', expr, re.IGNORECASE)
            if m:
                limit = int(m.group(1))
                values["perfect_hash_limit"] = limit

            # Pattern: !cp->perfect && !cp->h (first filter creation)
            if re.search(r'!.*perfect.*&&.*!.*\bh\b', expr, re.IGNORECASE):
                values["first_filter"] = True

            # Pattern: protocol check
            if re.search(r'protocol\s*[!=]', expr, re.IGNORECASE):
                values["needs_protocol"] = True

        return values

    def _build_programs(self, kind, target_type, attr_specs, attr_values,
                        prefer_update=False):
        """Generate syzkaller programs from solved conditions."""
        programs = []

        # Resolve attribute indices from specs
        idx_map = {}
        for attr_name, spec in attr_specs.items():
            idx = spec.get("index")
            if idx is not None:
                # Normalize: TCA_TCINDEX_HASH → hash
                short = attr_name.split("_")[-1].lower()
                idx_map[short] = idx

        hash_variants = attr_values.get("hash_variants", [
            {"hash": 0x10, "mask": 0x000f, "shift": 0},
        ])

        for vi, variant in enumerate(hash_variants):
            h = variant["hash"]
            mask = variant["mask"]
            shift = variant.get("shift", 0)

            # Build TCA_OPTIONS with kind-specific attrs
            opts = b""
            if "hash" in idx_map:
                opts += _nlattr_u32(idx_map["hash"], h)
            else:
                opts += _nlattr_u32(1, h)  # fallback TCA_TCINDEX_HASH=1

            if "mask" in idx_map:
                opts += _nlattr_u16(idx_map["mask"], mask)
            else:
                opts += _nlattr_u16(2, mask)

            if "shift" in idx_map:
                opts += _nlattr_u32(idx_map["shift"], shift)
            else:
                opts += _nlattr_u32(3, shift)

            # fall_through
            ft_idx = idx_map.get("fall_through", idx_map.get("fallthrough", 4))
            opts += _nlattr_u32(ft_idx, 1)

            # classid
            classid_idx = idx_map.get("classid", 5)
            opts += _nlattr_u32(classid_idx, 0x00010001)

            tca_options = _nlattr_bytes(2, opts)  # TCA_OPTIONS=2

            if target_type == "filter":
                programs.extend(
                    self._filter_programs(kind, tca_options, h, mask, shift, vi)
                )
            else:
                programs.extend(
                    self._qdisc_programs(kind, tca_options, vi,
                                         prefer_update=prefer_update)
                )

        # Also generate update sequences (create → change with different params)
        if len(hash_variants) >= 2:
            programs.extend(
                self._update_programs(kind, target_type, attr_specs,
                                      idx_map, hash_variants)
            )

        return programs

    def _filter_programs(self, kind, tca_options, h, mask, shift, idx):
        """Generate filter prerequisite programs (qdisc first, then filter)."""
        progs = []

        # Flower and similar classifiers need kind-specific TCA_OPTIONS.
        # The generic hash/mask options fail because flower's TCA_FLOWER_INDEV
        # (type=2) expects NLA_STRING but our generic encoder sends u16.
        if kind == "flower":
            tca_options = _build_flower_options()
        elif kind in ("u32", "basic", "matchall"):
            # These kinds can use the generic hash/mask attrs for now
            pass

        attr_values = {"hash": h, "mask": mask, "shift": shift,
                       "fall_through": 1, "classid": 0x00010001}

        # Try multiple parent qdisc types
        for qdisc_kind in ("prio", "ingress"):
            if qdisc_kind == "ingress":
                parent_qdisc = 0xfffffff1  # TC_H_INGRESS
                filter_parent = 0xfffffff1
                qdisc_handle = 0xffff0000
            else:
                parent_qdisc = 0xffff0000  # TC_H_ROOT
                filter_parent = 0x00010000
                qdisc_handle = 0x00010000

            info = ((1 & 0xffff) << 16) | 3  # prio=1, protocol=ETH_P_ALL

            # Prefer syzkaller typed format (survives mutation better)
            typed_qdisc = _typed_qdisc_msg(qdisc_kind, qdisc_handle, parent_qdisc)
            typed_filter = _typed_filter_msg(kind, filter_parent, info, attr_values)

            base = 0x7f0000001000 + idx * 0x10000

            if typed_qdisc and typed_filter:
                # Typed format — syzkaller understands the structure
                prog_text = (
                    "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                    + _make_sendmsg_typed(typed_qdisc, base, 0)
                    + _make_sendmsg_typed(typed_filter, base, 1)
                )
            else:
                # ANYBLOB fallback for unknown kinds
                if qdisc_kind == "ingress":
                    qdisc_opts = b""
                else:
                    prio_qopt = struct.pack('<I', 3) + bytes([1,2,2,2,1,2,0,0,1,1,1,1,1,1,1,1])
                    qdisc_opts = _nlattr_bytes(2, prio_qopt)
                hex_qdisc = _build_netlink_msg(
                    qdisc_kind, 0x24, parent=parent_qdisc, handle=qdisc_handle,
                    extra_attrs=qdisc_opts,
                )
                hex_filter = _build_netlink_msg(
                    kind, 0x2c, parent=filter_parent, info=info,
                    extra_attrs=tca_options,
                )
                prog_text = (
                    "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                    + _make_sendmsg(hex_qdisc, base, 0)
                    + _make_sendmsg(hex_filter, base, 1)
                )

            progs.append({
                "name": f"sem_{kind}_{qdisc_kind}_h{h:x}_m{mask:x}_s{shift}_{idx}",
                "text": prog_text,
            })

        return progs

    def _qdisc_programs(self, kind, tca_options, idx, prefer_update=False):
        base = 0x7f0000001000 + idx * 0x10000
        # TBF needs struct tc_tbf_qopt, not the generic hash/mask attrs
        if kind == "tbf":
            tca_options = _build_tbf_options()
        hex_new = _build_netlink_msg(kind, 0x24, extra_attrs=tca_options)
        programs = [{
            "name": f"sem_{kind}_qdisc_{idx}",
            "text": (
                "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                + _make_sendmsg(hex_new, base, 0)
            ),
        }]

        if prefer_update:
            # Multi-step: create qdisc → change qdisc (triggers child state)
            # Step 1: NLM_F_CREATE (0x0405) — create tbf qdisc at root, handle auto-assigned
            #         tbf_init → tbf_change: q->qdisc == noop, creates bfifo child
            # Step 2: NO NLM_F_CREATE (0x0005), handle=0 — change existing root qdisc
            #         Kernel: clid=TC_H_ROOT → q=dev->qdisc (existing tbf), handle=0 →
            #         skips handle mismatch check → falls through to qdisc_change() →
            #         tbf_change: now q->qdisc != noop_qdisc → fifo_set_limit() called ✓
            hex_create = _build_netlink_msg(kind, 0x24, extra_attrs=tca_options,
                                            flags=0x0405)  # NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE
            hex_change = _build_netlink_msg(kind, 0x24, extra_attrs=tca_options,
                                            handle=0, flags=0x0005)  # NLM_F_REQUEST|NLM_F_ACK only
            programs.append({
                "name": f"sem_{kind}_qdisc_update_{idx}",
                "text": (
                    "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                    + _make_sendmsg(hex_create, base, 0)
                    + _make_sendmsg(hex_change, base, 1)
                ),
            })

        return programs

    def _update_programs(self, kind, target_type, attr_specs, idx_map, variants):
        """Generate create-then-update programs (state transition)."""
        if len(variants) < 2:
            return []

        programs = []
        v1, v2 = variants[0], variants[1]

        for pair_idx, (va, vb) in enumerate([(v1, v2), (v2, v1)]):
            av_a = {"hash": va["hash"], "mask": va["mask"],
                    "shift": va.get("shift", 0), "fall_through": 1,
                    "classid": 0x00010001}
            av_b = {"hash": vb["hash"], "mask": vb["mask"],
                    "shift": vb.get("shift", 0), "fall_through": 1,
                    "classid": 0x00010001}

            info = ((1 & 0xffff) << 16) | 3

            if target_type == "filter":
                typed_qdisc = _typed_qdisc_msg("prio", 0x00010000, 0xffff0000)
                typed_fa = _typed_filter_msg(kind, 0x00010000, info, av_a)
                typed_fb = _typed_filter_msg(kind, 0x00010000, info, av_b,
                                             handle=1)

                base = 0x7f0000020000 + pair_idx * 0x10000

                if typed_qdisc and typed_fa and typed_fb:
                    prog_text = (
                        "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                        + _make_sendmsg_typed(typed_qdisc, base, 0)
                        + _make_sendmsg_typed(typed_fa, base, 1)
                        + _make_sendmsg_typed(typed_fb, base, 2)
                    )
                else:
                    # ANYBLOB fallback
                    opts_a = self._encode_variant(idx_map, va)
                    opts_b = self._encode_variant(idx_map, vb)
                    tca_a = _nlattr_bytes(2, opts_a)
                    tca_b = _nlattr_bytes(2, opts_b)
                    prio_qopt = struct.pack('<I', 3) + bytes([1,2,2,2,1,2,0,0,1,1,1,1,1,1,1,1])
                    hex_qdisc = _build_netlink_msg("prio", 0x24, handle=0x00010000,
                                                   extra_attrs=_nlattr_bytes(2, prio_qopt))
                    hex_filter_a = _build_netlink_msg(
                        kind, 0x2c, parent=0x00010000, info=info,
                        extra_attrs=tca_a,
                    )
                    hex_filter_b = _build_netlink_msg(
                        kind, 0x2c, parent=0x00010000, handle=1,
                        info=info, extra_attrs=tca_b,
                    )
                    prog_text = (
                        "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                        + _make_sendmsg(hex_qdisc, base, 0)
                        + _make_sendmsg(hex_filter_a, base, 1)
                        + _make_sendmsg(hex_filter_b, base, 2)
                    )
            else:
                opts_a = self._encode_variant(idx_map, va)
                opts_b = self._encode_variant(idx_map, vb)
                tca_a = _nlattr_bytes(2, opts_a)
                tca_b = _nlattr_bytes(2, opts_b)
                hex_new = _build_netlink_msg(kind, 0x24, extra_attrs=tca_a)
                hex_chg = _build_netlink_msg(kind, 0x25, extra_attrs=tca_b)
                base = 0x7f0000020000 + pair_idx * 0x10000
                prog_text = (
                    "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                    + _make_sendmsg(hex_new, base, 0)
                    + _make_sendmsg(hex_chg, base, 1)
                )

            programs.append({
                "name": f"sem_{kind}_update_{pair_idx}",
                "text": prog_text,
            })

        return programs

    def _encode_variant(self, idx_map, variant):
        opts = b""
        opts += _nlattr_u32(idx_map.get("hash", 1), variant["hash"])
        opts += _nlattr_u16(idx_map.get("mask", 2), variant["mask"])
        opts += _nlattr_u32(idx_map.get("shift", 3), variant.get("shift", 0))
        ft_idx = idx_map.get("fall_through", idx_map.get("fallthrough", 4))
        opts += _nlattr_u32(ft_idx, 1)
        opts += _nlattr_u32(idx_map.get("classid", 5), 0x00010001)
        return opts


class GenericNetlinkEncoder(DomainEncoder):
    """Fallback encoder for generic netlink subsystem targets."""

    def can_handle(self, plan):
        return plan.get("domain") in ("network", "netlink")

    def generate_seeds(self, plan):
        # Generic: just produce socket + sendmsg skeleton
        # LLM will fill in details via the prompt
        return []


class IoctlEncoder(DomainEncoder):
    """Encoder for ioctl-based driver targets."""

    def can_handle(self, plan):
        return plan.get("domain") in ("driver_ioctl",)

    def generate_seeds(self, plan):
        # Skeleton: open device + ioctl
        # Specific ioctl numbers come from plan analysis
        return []


# Encoder registry
_ENCODERS = [
    TCNetlinkEncoder(),
    GenericNetlinkEncoder(),
    IoctlEncoder(),
]


def get_encoder(plan):
    """Find a domain encoder that can handle this plan."""
    for enc in _ENCODERS:
        if enc.can_handle(plan):
            return enc
    return None


# ══════════════════════════════════════════════════════════════════════════
# Phase 6: Seed Validation
# ══════════════════════════════════════════════════════════════════════════

def validate_seed(seed_text, plan):
    """Validate a seed program against the seed plan constraints.

    Returns (is_valid, issues_list).
    """
    issues = []

    if not seed_text or not seed_text.strip():
        return False, ["empty program"]

    # Check prerequisite ordering
    prereqs = plan.get("prerequisite_sequence", [])
    domain = plan.get("domain", "")

    if domain == "tc_netlink":
        issues.extend(_validate_tc_seed(seed_text, plan))

    issues.extend(_validate_execution_requirements(seed_text, plan))

    # Check that ANYBLOB hex strings are valid
    for m in re.finditer(r'ANYBLOB="([0-9a-fA-F]*)"', seed_text):
        hex_str = m.group(1)
        if len(hex_str) % 2 != 0:
            issues.append(f"odd-length hex in ANYBLOB: {len(hex_str)} chars")
        if len(hex_str) < 32:  # minimum nlmsghdr(16B) = 32 hex chars
            issues.append(f"ANYBLOB too short for netlink message: {len(hex_str)} chars")

    # Check memory addresses don't overlap
    addrs = re.findall(r'0x7f0000([0-9a-fA-F]+)', seed_text)
    if len(addrs) != len(set(addrs)):
        issues.append("duplicate memory addresses in sendmsg calls")

    return len(issues) == 0, issues


def _validate_execution_requirements(seed_text, plan):
    issues = []
    req = plan.get("execution_requirements", {})
    if not req:
        return issues

    # Extract message types from ANYBLOB or typed format
    nl_types = []
    blobs = re.findall(r'ANYBLOB="([0-9a-fA-F]+)"', seed_text)
    nl_types.extend(_extract_nlmsg_type(blob) for blob in blobs)

    # Typed format: @newqdisc → 0x24, @newtfilter → 0x2c, etc.
    _TYPED_MSG_TYPES = {
        "newqdisc": 0x24, "delqdisc": 0x25, "getqdisc": 0x26,
        "newtclass": 0x28, "deltclass": 0x29,
        "newtfilter": 0x2c, "deltfilter": 0x2d, "gettfilter": 0x2e,
        "newtaction": 0x30, "deltaction": 0x31,
    }
    for m in re.finditer(r'@(\w+)=\{', seed_text):
        msg_name = m.group(1)
        if msg_name in _TYPED_MSG_TYPES:
            nl_types.append(_TYPED_MSG_TYPES[msg_name])

    sequence = req.get("message_sequence", [])
    if sequence:
        seq_idx = 0
        for nl_type in nl_types:
            if seq_idx < len(sequence) and nl_type == sequence[seq_idx]:
                seq_idx += 1
        if seq_idx < len(sequence):
            issues.append(
                "missing required message sequence "
                + " -> ".join(f"0x{x:02x}" for x in sequence)
            )

    if req.get("required_option_attrs"):
        # ANYBLOB path
        for blob in blobs:
            msg = _decode_tc_anyblob(blob)
            if msg and msg["nl_type"] == 0x2C and not msg["has_options"]:
                issues.append("filter/action message missing required TCA_OPTIONS")
        # Typed format: filter_kind_options implies TCA_OPTIONS is present
        if not blobs and '@filter_kind_options' not in seed_text:
            if any(t == 0x2c for t in nl_types):
                issues.append("filter message missing required TCA_OPTIONS")

    return issues


def _validate_tc_seed(seed_text, plan):
    """TC-specific validation."""
    issues = []
    target_file = plan.get("target_file", "")
    basename = os.path.basename(target_file)

    blobs = re.findall(r'ANYBLOB="([0-9a-fA-F]+)"', seed_text)

    # Typed-format seeds: validate structure via @-syntax
    if not blobs:
        has_qdisc = bool(re.search(r'@new(?:qdisc|tclass)', seed_text))
        has_filter = bool(re.search(r'@newtfilter', seed_text))
        has_kind = bool(re.search(r'@(?:qdisc_kind_options|filter_kind_options)', seed_text))

        if not has_qdisc and not has_filter:
            issues.append("no ANYBLOB or typed TC messages found")
            return issues

        if basename.startswith("cls_"):
            if not has_qdisc:
                issues.append("filter target needs qdisc creation message")
            if not has_filter:
                issues.append("filter target needs filter creation message")
            if not has_kind:
                issues.append("missing kind_options in typed message")

            # Extract hash/mask/shift from typed format for value validation
            h_m = re.search(r'TCA_TCINDEX_HASH=\{[^}]*,\s*[^}]*,\s*0x([0-9a-fA-F]+)\}', seed_text)
            m_m = re.search(r'TCA_TCINDEX_MASK=\{[^}]*,\s*[^}]*,\s*0x([0-9a-fA-F]+)\}', seed_text)
            s_m = re.search(r'TCA_TCINDEX_SHIFT=\{[^}]*,\s*[^}]*,\s*0x([0-9a-fA-F]+)\}', seed_text)
            if h_m and m_m and s_m:
                h = int(h_m.group(1), 16)
                m = int(m_m.group(1), 16)
                s = int(s_m.group(1), 16)
                shifted = m >> s if s < 32 else 0
                if h <= shifted:
                    issues.append(
                        f"hash({h}) must be > mask>>shift({shifted}) "
                        f"for perfect hash path [mask={m:#x}, shift={s}]"
                    )

        return issues

    # For filter targets: first message should be qdisc (type 0x24),
    # second should be filter (type 0x2c)
    if basename.startswith("cls_") and len(blobs) >= 2:
        first_type = _extract_nlmsg_type(blobs[0])
        second_type = _extract_nlmsg_type(blobs[1])
        if first_type != 0x24:
            issues.append(f"filter target needs RTM_NEWQDISC(0x24) first, got 0x{first_type:x}")
        if second_type != 0x2c:
            issues.append(f"filter target needs RTM_NEWTFILTER(0x2c) second, got 0x{second_type:x}")

    # Check each message has TCA_KIND
    for i, blob in enumerate(blobs):
        msg_bytes = bytes.fromhex(blob)
        if len(msg_bytes) >= 36:  # nlmsghdr(16) + tcmsg(20)
            # Look for TCA_KIND (type=1) in rtattrs
            attrs_start = 36
            if not _has_nla_type(msg_bytes[attrs_start:], 1):
                issues.append(f"message {i}: missing TCA_KIND attribute")

    # For filter target: check TCA_OPTIONS in filter message
    if basename.startswith("cls_") and len(blobs) >= 2:
        filter_bytes = bytes.fromhex(blobs[1])
        if len(filter_bytes) >= 36:
            if not _has_nla_type(filter_bytes[36:], 2):
                issues.append("filter message missing TCA_OPTIONS")

    # Validate attribute types/sizes against nla_policy from plan
    attr_specs = plan.get("attribute_specs", {})
    for i, blob in enumerate(blobs):
        attr_issues = _validate_nla_attrs(blob, attr_specs, i)
        issues.extend(attr_issues)

    # Semantic validation: check parameter values satisfy branch conditions
    solved = plan.get("solved_values", [])
    hash_variants = plan.get("_accepted_hash_variants")  # set by encoder
    if basename.startswith("cls_") and len(blobs) >= 2:
        filter_attrs = _extract_options_attrs(blobs[1])
        if filter_attrs:
            h = filter_attrs.get(1)    # TCA_TCINDEX_HASH (index 1)
            m = filter_attrs.get(2)    # TCA_TCINDEX_MASK (index 2)
            s = filter_attrs.get(3)    # TCA_TCINDEX_SHIFT (index 3)
            if h is not None and m is not None and s is not None:
                shifted = m >> s if s < 32 else 0
                if h <= shifted:
                    issues.append(
                        f"hash({h}) must be > mask>>shift({shifted}) "
                        f"for perfect hash path [mask={m:#x}, shift={s}]"
                    )

    return issues


def _extract_options_attrs(hex_blob):
    """Extract attribute index→integer value map from inside TCA_OPTIONS.

    Parses the netlink message, finds TCA_OPTIONS (type=2), then reads
    nested attributes as u16/u32 values.
    """
    try:
        msg = bytes.fromhex(hex_blob)
    except ValueError:
        return {}
    if len(msg) < 36:
        return {}
    # Walk top-level attrs to find TCA_OPTIONS (type=2)
    off = 36
    opts_start = opts_end = None
    while off + 4 <= len(msg):
        nla_len, nla_type = struct.unpack_from("<HH", msg, off)
        if nla_len < 4 or off + nla_len > len(msg):
            break
        if nla_type == 2:
            opts_start = off + 4
            opts_end = off + nla_len
            break
        off += (nla_len + 3) & ~3
    if opts_start is None:
        return {}
    # Walk nested attrs inside TCA_OPTIONS
    result = {}
    off = opts_start
    while off + 4 <= opts_end:
        nla_len, nla_type = struct.unpack_from("<HH", msg, off)
        if nla_len < 4 or off + nla_len > opts_end:
            break
        payload = msg[off + 4: off + nla_len]
        if len(payload) == 4:
            result[nla_type] = struct.unpack_from("<I", payload)[0]
        elif len(payload) == 2:
            result[nla_type] = struct.unpack_from("<H", payload)[0]
        off += (nla_len + 3) & ~3
    return result


def _extract_nlmsg_type(hex_blob):
    """Extract nlmsg_type from a netlink message hex string."""
    try:
        msg = bytes.fromhex(hex_blob)
        if len(msg) >= 6:
            return struct.unpack_from("<H", msg, 4)[0]
    except (ValueError, struct.error):
        pass
    return 0


def _decode_tc_anyblob(hex_blob):
    try:
        msg = bytes.fromhex(hex_blob)
    except ValueError:
        return None
    if len(msg) < 36:
        return None
    try:
        _len, nl_type, flags, _seq, _pid = struct.unpack_from("<IHHII", msg, 0)
        _family, _pad1, _pad2, _pad3, ifindex, handle, parent, info = struct.unpack_from("<BBBBIIII", msg, 16)
    except struct.error:
        return None
    decoded = {
        "nl_type": nl_type,
        "flags": flags,
        "ifindex": ifindex,
        "handle": handle,
        "parent": parent,
        "info": info,
        "has_options": False,
    }
    off = 36
    while off + 4 <= len(msg):
        try:
            nla_len, nla_type = struct.unpack_from("<HH", msg, off)
        except struct.error:
            break
        if nla_len < 4 or off + nla_len > len(msg):
            break
        if nla_type == 2:
            decoded["has_options"] = True
            break
        off += (nla_len + 3) & ~3
    return decoded


def _has_nla_type(attr_bytes, target_type):
    """Check if rtattr data contains an attribute with the given type."""
    offset = 0
    while offset + 4 <= len(attr_bytes):
        nla_len, nla_type = struct.unpack_from("<HH", attr_bytes, offset)
        if nla_len < 4:
            break
        if nla_type == target_type:
            return True
        offset += (nla_len + 3) & ~3  # align to 4
    return False


def _validate_nla_attrs(hex_blob, attr_specs, msg_idx):
    """Validate NLA attribute sizes against known policy.

    Only validates attrs INSIDE TCA_OPTIONS (type=2), not top-level rtattrs,
    because top-level types (TCA_KIND=1) collide with kind-specific enum indices.
    """
    issues = []
    try:
        msg = bytes.fromhex(hex_blob)
    except ValueError:
        return [f"message {msg_idx}: invalid hex"]

    if len(msg) < 36:
        return []

    # Find TCA_OPTIONS (type=2) in top-level rtattrs
    offset = 36
    options_data = None
    while offset + 4 <= len(msg):
        nla_len, nla_type = struct.unpack_from("<HH", msg, offset)
        if nla_len < 4:
            break
        if nla_type == 2:  # TCA_OPTIONS
            options_data = msg[offset + 4:offset + nla_len]
            break
        offset += (nla_len + 3) & ~3

    if options_data is None:
        return []

    # Parse nested attrs inside TCA_OPTIONS
    off = 0
    while off + 4 <= len(options_data):
        nla_len, nla_type = struct.unpack_from("<HH", options_data, off)
        if nla_len < 4:
            break
        payload_len = nla_len - 4

        for attr_name, spec in attr_specs.items():
            if spec.get("index") == nla_type and spec.get("size", -1) > 0:
                expected = spec["size"]
                if payload_len != expected:
                    issues.append(
                        f"message {msg_idx}: attr {attr_name}(type={nla_type}) "
                        f"payload={payload_len}B, expected={expected}B"
                    )

        off += (nla_len + 3) & ~3

    return issues


# ══════════════════════════════════════════════════════════════════════════
# Netlink message builder helpers
# ══════════════════════════════════════════════════════════════════════════

def _nlattr_u32(attr_type, value):
    return struct.pack("<HHI", 8, attr_type, value)


def _nlattr_u16(attr_type, value):
    return struct.pack("<HHH", 6, attr_type, value) + b"\x00\x00"


def _nlattr_bytes(attr_type, data):
    nla_len = 4 + len(data)
    padded = data + (b"\x00" * ((4 - (len(data) % 4)) % 4))
    return struct.pack("<HH", nla_len, attr_type) + padded


def _build_flower_options():
    """Build minimal valid TCA_OPTIONS bytes for a flower classifier filter.

    Uses empty key attrs (catch-all) + TCA_FLOWER_FLAGS=SKIP_HW to avoid
    HW offload requirements. This allows fl_change to complete without
    key validation errors, reaching tcf_exts_init_ex.

    The current generic hash/mask options fail because TCA_FLOWER_INDEV (=2)
    expects NLA_STRING but gets a u16, causing nla_parse_nested to reject it
    before calling tcf_exts_init_ex.
    """
    # TCA_FLOWER_FLAGS = 22, NLA_U32, value=TCA_CLS_FLAGS_SKIP_HW(1)
    tca_flags = _nlattr_u32(22, 0x1)
    return _nlattr_bytes(2, tca_flags)  # TCA_OPTIONS=2


def _build_tbf_options(limit=0x10000, rate_bps=0x00100000, burst=0x4000):
    """Build valid TCA_OPTIONS bytes for a TBF qdisc.

    tbf_change requires:
      - TCA_TBF_PARMS with struct tc_tbf_qopt (36 bytes)
        rate.rate > 0, limit > 0
      - TCA_TBF_BURST (index=6) to set max_size directly (avoids
        psched_ns_t2l computation that might return 0)
    """
    # struct tc_ratespec: cell_log(u8), linklayer(u8), overhead(u16),
    #                     cell_align(i16), mpu(u16), rate(u32) = 12 bytes
    rate_spec = struct.pack('<BBHhHI', 0, 1, 0, 0, 0, rate_bps)
    peak_spec = struct.pack('<BBHhHI', 0, 0, 0, 0, 0, 0)  # no peak rate
    # struct tc_tbf_qopt: rate + peakrate + limit + buffer + mtu = 36 bytes
    tbf_qopt = rate_spec + peak_spec + struct.pack('<III', limit, burst, 0)
    tca_parms = _nlattr_bytes(1, tbf_qopt)         # TCA_TBF_PARMS = 1
    tca_burst = _nlattr_u32(6, burst)              # TCA_TBF_BURST = 6 (overrides max_size)
    return _nlattr_bytes(2, tca_parms + tca_burst)  # TCA_OPTIONS = 2


def _build_netlink_msg(kind, msg_type, ifindex=1, parent=0xffff0000,
                       handle=0, info=0, extra_attrs=b"",
                       flags=0x0405):
    """Build a TC netlink message, return hex string.

    Default flags 0x0405 = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE.
    For "change existing" messages, pass flags=0x0005 (no NLM_F_CREATE).
    """
    kind_bytes = kind.encode() + b'\x00'
    tca_kind = _nlattr_bytes(1, kind_bytes)
    tcmsg = struct.pack('<BBBBIIII', 0, 0, 0, 0, ifindex, handle, parent, info)
    body = tcmsg + tca_kind + extra_attrs
    total_len = 16 + len(body)
    nlmsghdr = struct.pack('<IHHII', total_len, msg_type, flags, 1, 0)
    return (nlmsghdr + body).hex()


def _make_sendmsg(hex_bytes, base_addr, slot):
    """Generate a sendmsg$nl_route_sched line (ANYBLOB fallback)."""
    msg_len = len(hex_bytes) // 2
    hdr = base_addr + slot * 0x2000
    iov = hdr - 0xfc0
    buf = hdr - 0xf80
    return (
        f'sendmsg$nl_route_sched(r0, &(0x{hdr:x})={{0x0, 0x0, '
        f'&(0x{iov:x})=[{{&(0x{buf:x})=ANY=[@ANYBLOB="{hex_bytes}"],'
        f' 0x{msg_len:x}}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)\n'
    )


# ── Syzkaller typed-format generators ────────────────────────────────────
#
# Syzkaller deserializes ANYBLOB seeds through its own type system, which
# can mis-parse netlink attribute structures.  Generating seeds in the
# native typed format avoids this and lets the fuzzer mutate them
# intelligently.

# Map of well-known TC qdisc kinds to their syzkaller union member names
# and TCA_OPTIONS format generators.
_QDISC_KIND_MAP = {
    "prio": "q_prio",
    "rr": "q_rr",
    "ingress": "q_ingress",
    "bfifo": "q_bfifo",
    "pfifo": "q_pfifo",
    "tbf": "q_tbf",
    "htb": "q_htb",
    "netem": "q_netem",
    "sfq": "q_sfq",
}

# Map of well-known TC filter kinds to their syzkaller union member names
_FILTER_KIND_MAP = {
    "tcindex": "f_tcindex",
    "u32": "f_u32",
    "flower": "f_flower",
    "basic": "f_basic",
    "bpf": "f_bpf",
    "cgroup": "f_cgroup",
    "fw": "f_fw",
    "matchall": "f_matchall",
    "route": "f_route",
}

# Map of tcindex attribute names to their syzkaller union member names
_TCINDEX_ATTR_MAP = {
    1: "TCA_TCINDEX_HASH",
    2: "TCA_TCINDEX_MASK",
    3: "TCA_TCINDEX_SHIFT",
    4: "TCA_TCINDEX_FALL_THROUGH",
    5: "TCA_TCINDEX_CLASSID",
}


def _typed_tcm_handle(val):
    """Format a tcm_handle as {minor, major} for syzkaller."""
    minor = val & 0xffff
    major = (val >> 16) & 0xffff
    return f"{{0x{minor:x}, 0x{major:x}}}"


def _typed_prio_options():
    """TCA_OPTIONS for prio qdisc: tc_prio_qopt{bands=3, priomap[16]}."""
    priomap = ", ".join(["0x1", "0x2", "0x2", "0x2", "0x1", "0x2",
                         "0x0", "0x0", "0x1", "0x1", "0x1", "0x1",
                         "0x1", "0x1", "0x1", "0x1"])
    return f"{{0x18, 0x2, {{0x3, [{priomap}]}}}}"


def _typed_tcindex_attrs(attr_values):
    """Generate tcindex_policy array items in syzkaller typed format.

    Returns a string like:
      [@TCA_TCINDEX_HASH={0x8, 0x1, 0x10}, @TCA_TCINDEX_MASK={0x6, 0x2, 0xf}, ...]
    """
    items = []
    h = attr_values.get("hash", 0x10)
    mask = attr_values.get("mask", 0xf)
    shift = attr_values.get("shift", 0)
    ft = attr_values.get("fall_through", 1)
    classid = attr_values.get("classid", 0x00010001)

    # TCA_TCINDEX_HASH: nlattr[1, int32]
    items.append(f"@TCA_TCINDEX_HASH={{0x8, 0x1, 0x{h:x}}}")
    # TCA_TCINDEX_MASK: nlattr[2, int16]
    items.append(f"@TCA_TCINDEX_MASK={{0x6, 0x2, 0x{mask:x}}}")
    # TCA_TCINDEX_SHIFT: nlattr[3, int32]
    items.append(f"@TCA_TCINDEX_SHIFT={{0x8, 0x3, 0x{shift:x}}}")
    # TCA_TCINDEX_FALL_THROUGH: nlattr[4, int32]
    items.append(f"@TCA_TCINDEX_FALL_THROUGH={{0x8, 0x4, 0x{ft:x}}}")
    # TCA_TCINDEX_CLASSID: nlattr[5, tcm_handle]
    items.append(f"@TCA_TCINDEX_CLASSID={{0x8, 0x5, {_typed_tcm_handle(classid)}}}")

    return "[" + ", ".join(items) + "]"


def _typed_filter_attrs(kind, attr_values):
    """Generate filter TCA_OPTIONS content in typed format.

    Returns the full tca_kind_options_t content:
      {{TCA_KIND_nla}, {TCA_OPTIONS_nla_len, TCA_OPTIONS_nla_type, [attrs]}}
    """
    member = _FILTER_KIND_MAP.get(kind)
    if not member:
        return None

    kind_nla_len = 4 + len(kind) + 1  # nla header + string + null
    kind_nla_len = (kind_nla_len + 3) & ~3  # align to 4

    if kind == "tcindex":
        inner = _typed_tcindex_attrs(attr_values)
        # Estimate TCA_OPTIONS nla_len (not critical — syzkaller auto-adjusts)
        opts_nla_len = 0x2c  # rough estimate
        return f"@{member}={{{{0x{kind_nla_len:x}}}, {{0x{opts_nla_len:x}, 0x2, {inner}}}}}"

    return None


def _typed_qdisc_msg(kind, handle, parent, ifindex=1, flags=0x601):
    """Generate a typed @newqdisc message string."""
    member = _QDISC_KIND_MAP.get(kind)

    tcmsg = (f"{{0x0, 0x0, 0x0, 0x{ifindex:x}, "
             f"{_typed_tcm_handle(handle)}, "
             f"{_typed_tcm_handle(parent)}, "
             f"{{0x0, 0x0}}}}")

    if kind == "prio" and member:
        kind_nla = "{0x9}"  # nla_len for "prio\0" = 5 + 4header = 9
        opts = _typed_prio_options()
        attrs = f"[@qdisc_kind_options=@{member}={{{kind_nla}, {opts}}}]"
    elif kind == "ingress":
        # ingress qdisc has no TCA_OPTIONS
        attrs = "[]"
    else:
        # Fallback: return None to use ANYBLOB
        return None

    return f"@newqdisc={{0x0, 0x24, 0x{flags:x}, 0x0, 0x0, {tcmsg}, {attrs}}}"


def _typed_filter_msg(kind, parent, info, attr_values, ifindex=1, handle=0,
                      flags=0x601):
    """Generate a typed @newtfilter message string."""
    typed_attrs = _typed_filter_attrs(kind, attr_values)
    if typed_attrs is None:
        return None

    tcmsg = (f"{{0x0, 0x0, 0x0, 0x{ifindex:x}, "
             f"{_typed_tcm_handle(handle)}, "
             f"{_typed_tcm_handle(parent)}, "
             f"{_typed_tcm_handle(info)}}}")

    attrs = f"[@filter_kind_options={typed_attrs}]"
    return f"@newtfilter={{0x0, 0x2c, 0x{flags:x}, 0x0, 0x0, {tcmsg}, {attrs}}}"


def _make_sendmsg_typed(typed_msg, base_addr, slot, msg_len=0x60):
    """Generate a sendmsg$nl_route_sched line using syzkaller typed format."""
    hdr = base_addr + slot * 0x2000
    iov = hdr - 0xfc0
    buf = hdr - 0xf80
    return (
        f'sendmsg$nl_route_sched(r0, &(0x{hdr:x})={{0x0, 0x0, '
        f'&(0x{iov:x})={{&(0x{buf:x})={typed_msg},'
        f' 0x{msg_len:x}}}}}, 0x0)\n'
    )


# ══════════════════════════════════════════════════════════════════════════
# LLM-Assisted Semantic Analysis (multi-step)
# ══════════════════════════════════════════════════════════════════════════

def llm_semantic_analysis(plan, llm_call_fn):
    """Use LLM to enrich the seed plan with deeper semantic understanding.

    Takes the statically-extracted plan and asks LLM to:
    1. Verify/correct the call chain
    2. Identify missing prerequisites
    3. Solve branch predicates into concrete values
    4. Suggest additional seed variants

    Args:
        plan: seed plan dict from build_seed_plan()
        llm_call_fn: callable(prompt, timeout) → str or None

    Returns:
        Enriched plan dict with LLM additions.
    """
    if not llm_call_fn:
        return plan

    # Build a focused prompt with the extracted analysis
    chain_text = "\n".join(
        f"  {i}. {c['function']} ({c.get('file','')}) [{c.get('dispatch','')}]"
        for i, c in enumerate(plan.get("call_chain", []))
    )

    prereq_text = "\n".join(
        f"  - {p['action']}: {p['object']} in {p.get('source_function','')}"
        for p in plan.get("prerequisite_sequence", [])
    )

    cond_text = "\n".join(
        f"  - {c['expression']}"
        for c in plan.get("branch_conditions", [])
    )

    attr_text = "\n".join(
        f"  - {name}: index={s.get('index','?')}, type={s.get('nla_type','?')}, size={s.get('size','?')}B"
        for name, s in plan.get("attribute_specs", {}).items()
    )

    prompt = f"""You are a Linux kernel expert analyzing code paths for a directed fuzzer.

TARGET: {plan['target_function']} in {plan['target_file']}
DOMAIN: {plan['domain']}

STATIC ANALYSIS extracted the following. Verify and enrich it.

CALL CHAIN (from entry to target):
{chain_text or '  (none extracted)'}

PREREQUISITES (resource dependencies):
{prereq_text or '  (none extracted)'}

BRANCH CONDITIONS gating target:
{cond_text or '  (none extracted)'}

NLA POLICY attributes:
{attr_text or '  (none extracted)'}

TASKS:
1. Verify the call chain. Add any missing intermediate functions.
2. For each branch condition, provide CONCRETE VALUES that satisfy it.
3. Check the attribute type indices. Are they correct?
4. What is the MINIMUM syscall sequence to reach {plan['target_function']}?

Return ONLY JSON:
{{
  "call_chain_corrections": ["any missing functions or wrong order"],
  "prerequisites": [
    {{"step": 1, "action": "create qdisc", "message_type": "RTM_NEWQDISC", "kind": "...", "required_attrs": {{}}}}
  ],
  "condition_solutions": [
    {{"condition": "expr", "values": {{"field": value}}, "explanation": "why these values work"}}
  ],
  "attr_corrections": [
    {{"attr_name": "...", "correct_index": N, "correct_size": N, "reason": "..."}}
  ],
  "seed_variants": [
    {{"description": "what this variant tests", "key_values": {{}}}}
  ]
}}"""

    try:
        text = llm_call_fn(prompt, timeout=300)
        if not text:
            return plan

        start, end = text.find("{"), text.rfind("}") + 1
        if start < 0 or end <= start:
            return plan

        enrichment = json.loads(text[start:end])
        plan["llm_enrichment"] = enrichment

        # Apply attr corrections
        for correction in enrichment.get("attr_corrections", []):
            attr_name = correction.get("attr_name", "")
            if attr_name in plan.get("attribute_specs", {}):
                if "correct_index" in correction:
                    plan["attribute_specs"][attr_name]["index"] = correction["correct_index"]
                if "correct_size" in correction:
                    plan["attribute_specs"][attr_name]["size"] = correction["correct_size"]

        # Add condition solutions
        for sol in enrichment.get("condition_solutions", []):
            plan.setdefault("solved_values", []).append(sol)

    except (json.JSONDecodeError, Exception) as e:
        print(f"  [semantic] LLM enrichment failed: {e}")

    return plan


# ══════════════════════════════════════════════════════════════════════════
# Top-level: run full semantic pipeline
# ══════════════════════════════════════════════════════════════════════════

def run_semantic_pipeline(src_dir, target_function, target_file, llm_call_fn=None):
    """Run the full semantic analysis pipeline.

    Returns:
        (plan, seeds) where plan is the analysis dict and seeds is a list
        of {"name": ..., "text": ...} seed programs.
    """
    normalized = normalize_target_metadata(src_dir, target_function, target_file)
    target_function = normalized.get("target_function", target_function)
    target_file = normalized.get("target_file", target_file)
    print(f"  [semantic] Target metadata: function={target_function} file={target_file}")

    print(f"  [semantic] Phase 1: Extracting call chain for {target_function}...")
    call_chain = extract_call_chain(src_dir, target_function, target_file)
    if call_chain:
        print(f"  [semantic]   Chain depth: {len(call_chain)}")
        for c in call_chain:
            print(f"    → {c['function']} [{c.get('dispatch_hint', '')}]")

    print(f"  [semantic] Phase 2: Extracting prerequisites...")
    prerequisites = extract_prerequisites(src_dir, call_chain)
    total_conds = sum(len(p.get("conditions", [])) for p in prerequisites)
    total_deps = sum(len(p.get("dependencies", [])) for p in prerequisites)
    print(f"  [semantic]   {total_conds} error conditions, {total_deps} dependencies")

    print(f"  [semantic] Phase 3: Extracting branch predicates...")
    predicates = extract_branch_predicates(src_dir, target_function, target_file, call_chain=call_chain)
    print(f"  [semantic]   {len(predicates)} branch predicates near target")
    for p in predicates:
        print(f"    · if ({p['condition']})")

    print(f"  [semantic] Phase 3.5: Extracting nla_policy/enum...")
    nla_policy = extract_nla_policy(src_dir, target_file)
    if nla_policy:
        print(f"  [semantic]   {len(nla_policy)} attributes defined")
        for name, spec in nla_policy.items():
            print(f"    · {name}: idx={spec.get('index','?')} type={spec.get('nla_type','')} size={spec.get('size','')}B")

    print(f"  [semantic] Phase 4: Building seed plan...")
    plan = build_seed_plan(
        call_chain, prerequisites, predicates, nla_policy,
        target_function, target_file,
    )

    # Enrich with LLM if available
    if llm_call_fn:
        print(f"  [semantic] Phase 4.5: LLM semantic enrichment...")
        plan = llm_semantic_analysis(plan, llm_call_fn)
        if plan.get("llm_enrichment"):
            enrichment = plan["llm_enrichment"]
            corrections = enrichment.get("attr_corrections", [])
            if corrections:
                print(f"  [semantic]   LLM corrected {len(corrections)} attribute(s)")
            variants = enrichment.get("seed_variants", [])
            if variants:
                print(f"  [semantic]   LLM suggested {len(variants)} additional variant(s)")

    print(f"  [semantic] Phase 5: Generating seeds via domain encoder...")
    encoder = get_encoder(plan)
    seeds = []
    if encoder:
        seeds = encoder.generate_seeds(plan)
        print(f"  [semantic]   Encoder produced {len(seeds)} seed program(s)")
    else:
        print(f"  [semantic]   No encoder for domain '{plan.get('domain', 'unknown')}'")

    # Validate seeds
    valid_seeds = []
    for seed in seeds:
        ok, issues = validate_seed(seed.get("text", ""), plan)
        if ok:
            valid_seeds.append(seed)
        else:
            print(f"  [semantic]   Rejected seed '{seed.get('name','')}': {'; '.join(issues)}")

    print(f"  [semantic] Phase 6: {len(valid_seeds)}/{len(seeds)} seeds passed validation")
    return plan, valid_seeds
