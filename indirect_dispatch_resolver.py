"""
V7: Indirect Dispatch Resolver

Resolves function pointer registration patterns in kernel source that LLVM
CallGraph analysis cannot follow. Augments kernelCode2syscall.json (k2s) with
handler→syscall mappings discovered from source-level grep.

Problem: Kernel subsystems register handler functions via APIs like
rtnl_register(), genl_register_family(), etc. These create indirect call edges
invisible to LLVM. As a result, kernel_signature_full and k2s miss paths like
sendmsg → tc_modify_qdisc → tbf_change → fifo_set_limit.

Solution: Grep kernel source for registration calls, extract handler functions,
map them to syzkaller syscall names, and inject into k2s.
"""

import json
import logging
import os
import re
import subprocess
from typing import Optional

log = logging.getLogger("indirect_dispatch")

# ── Registration pattern definitions ──
# Each entry defines:
#   grep_pattern: regex to find registration calls in source
#   handler_extractor: how to extract handler function names from the match
#   syscalls: syzkaller syscall names that reach this dispatch
#   related: related syscalls needed as prerequisites (e.g. socket creation)
#   ops_struct: if handlers are in an ops struct, the struct type name
#   ops_fields: which fields in the ops struct are handler functions

DISPATCH_PATTERNS = {
    # ── Netlink route (TC, routing, etc.) ──
    "rtnl_register": {
        "grep_pattern": r"rtnl_register\w*\s*\(",
        "syscalls": ["sendmsg$nl_route", "sendmsg$nl_route_sched"],
        "related": ["socket$nl_route"],
        "handler_arg_indices": [2, 3],  # doit, dumpit
    },
    # ── TC qdisc ops ──
    "register_qdisc": {
        "grep_pattern": r"register_qdisc\s*\(",
        "syscalls": ["sendmsg$nl_route_sched"],
        "related": ["socket$nl_route"],
        "ops_struct": "Qdisc_ops",
        "ops_fields": ["enqueue", "dequeue", "init", "reset", "destroy",
                        "change", "dump", "dump_stats"],
    },
    # ── TC classifier ops ──
    "register_tcf_proto_ops": {
        "grep_pattern": r"register_tcf_proto_ops\s*\(",
        "syscalls": ["sendmsg$nl_route_sched"],
        "related": ["socket$nl_route"],
        "ops_struct": "tcf_proto_ops",
        "ops_fields": ["classify", "init", "destroy", "change", "dump",
                        "walk", "bind_class"],
    },
    # ── TC action ops ──
    "tcf_register_action": {
        "grep_pattern": r"tcf_register_action\s*\(",
        "syscalls": ["sendmsg$nl_route_sched"],
        "related": ["socket$nl_route"],
        "ops_struct": "tc_action_ops",
        "ops_fields": ["act", "init", "cleanup", "dump"],
    },
    # ── Netfilter netlink ──
    "nfnetlink_subsys_register": {
        "grep_pattern": r"nfnetlink_subsys_register\s*\(",
        "syscalls": ["sendmsg$nl_netfilter"],
        "related": ["socket$nl_netfilter"],
        "ops_struct": "nfnetlink_subsystem",
        "ops_fields": ["cb"],  # array of callbacks
    },
    # ── nftables expression types ──
    "nft_register_expr": {
        "grep_pattern": r"nft_register_expr\s*\(",
        "syscalls": ["sendmsg$nl_netfilter"],
        "related": ["socket$nl_netfilter"],
        "ops_struct": "nft_expr_type",
        "ops_fields": ["eval", "init", "destroy", "dump"],
    },
    # ── xtables match/target ──
    "xt_register_match": {
        "grep_pattern": r"xt_register_match\w*\s*\(",
        "syscalls": ["setsockopt$IP_SET_OP_GET_BYNAME"],
        "related": ["socket$inet"],
        "ops_struct": "xt_match",
        "ops_fields": ["match", "checkentry", "destroy"],
    },
    "xt_register_target": {
        "grep_pattern": r"xt_register_target\w*\s*\(",
        "syscalls": ["setsockopt$IP_SET_OP_GET_BYNAME"],
        "related": ["socket$inet"],
        "ops_struct": "xt_target",
        "ops_fields": ["target", "checkentry", "destroy"],
    },
    # ── Generic netlink ──
    "genl_register_family": {
        "grep_pattern": r"genl_register_family\s*\(",
        "syscalls": ["sendmsg$nl_generic"],
        "related": ["socket$nl_generic"],
        "ops_struct": "genl_family",
        "ops_fields": ["doit", "dumpit", "done"],
    },
    # ── xfrm ──
    "xfrm_register_km": {
        "grep_pattern": r"xfrm_register_km\s*\(",
        "syscalls": ["sendmsg$nl_xfrm"],
        "related": ["socket$nl_xfrm"],
        "ops_struct": "xfrm_mgr",
        "ops_fields": ["notify", "acquire", "compile_policy", "new_mapping",
                        "notify_policy", "migrate"],
    },
    # ── TCP congestion control ──
    "tcp_register_congestion_control": {
        "grep_pattern": r"tcp_register_congestion_control\s*\(",
        "syscalls": ["setsockopt$inet_tcp_TCP_CONGESTION"],
        "related": ["socket$inet_tcp"],
        "ops_struct": "tcp_congestion_ops",
        "ops_fields": ["ssthresh", "cong_avoid", "cong_control", "init",
                        "release", "set_state"],
    },
    # ── Socket family ──
    "sock_register": {
        "grep_pattern": r"sock_register\s*\(",
        "syscalls": ["socket"],
        "related": [],
        "ops_struct": "net_proto_family",
        "ops_fields": ["create"],
    },
    # ── Bluetooth ──
    "bt_sock_register": {
        "grep_pattern": r"bt_sock_register\s*\(",
        "syscalls": ["socket$bt_hci", "socket$bt_l2cap", "socket$bt_sco",
                      "socket$bt_rfcomm"],
        "related": [],
        "ops_struct": "net_proto_family",
        "ops_fields": ["create"],
    },
    # ── rtnl link (virtual netdev creation) ──
    "rtnl_link_register": {
        "grep_pattern": r"rtnl_link_register\s*\(",
        "syscalls": ["sendmsg$nl_route"],
        "related": ["socket$nl_route"],
        "ops_struct": "rtnl_link_ops",
        "ops_fields": ["newlink", "changelink", "dellink", "setup"],
    },
    # ── Netfilter hooks ──
    "nf_register_net_hook": {
        "grep_pattern": r"nf_register_net_hooks?\s*\(",
        "syscalls": ["sendmsg$nl_netfilter", "setsockopt$IP_SET_OP_GET_BYNAME"],
        "related": ["socket$nl_netfilter", "socket$inet"],
        "ops_struct": "nf_hook_ops",
        "ops_fields": ["hook"],
    },
    # ── AF_ALG crypto ──
    "af_alg_register_type": {
        "grep_pattern": r"af_alg_register_type\s*\(",
        "syscalls": ["sendmsg$alg"],
        "related": ["socket$alg"],
        "ops_struct": "af_alg_type",
        "ops_fields": ["accept", "setkey", "bind"],
    },
    # ── vsock transport ──
    "vsock_core_register": {
        "grep_pattern": r"vsock_core_register\s*\(",
        "syscalls": ["connect$vsock_stream", "sendmsg$vsock"],
        "related": ["socket$vsock_stream"],
        "ops_struct": "vsock_transport",
        "ops_fields": ["connect", "dgram_enqueue", "stream_enqueue"],
    },
    # ── I/O scheduler ──
    "elv_register": {
        "grep_pattern": r"elv_register\s*\(",
        "syscalls": ["ioctl$BLKFLSBUF"],
        "related": ["openat$sda"],
        "ops_struct": "elevator_type",
        "ops_fields": ["ops"],
    },
    # ── conntrack helper ──
    "nf_conntrack_helper_register": {
        "grep_pattern": r"nf_conntrack_helper_register\s*\(",
        "syscalls": ["sendmsg$nl_netfilter"],
        "related": ["socket$nl_netfilter"],
        "ops_struct": "nf_conntrack_helper",
        "ops_fields": ["help"],
    },
    # ── inet protocol registration ──
    "inet_register_protosw": {
        "grep_pattern": r"inet6?_register_protosw\s*\(",
        "syscalls": ["socket$inet_tcp", "socket$inet_udp", "socket$inet_sctp"],
        "related": [],
        "ops_struct": "inet_protosw",
        "ops_fields": ["ops"],
    },
}


def grep_source(src_dir: str, pattern: str, file_glob: str = "*.c") -> list[dict]:
    """Run grep on kernel source and return matches."""
    try:
        result = subprocess.run(
            ["grep", "-rn", "-E", pattern, "--include", file_glob, src_dir],
            capture_output=True, text=True, timeout=60
        )
        matches = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) >= 3:
                matches.append({
                    "file": parts[0],
                    "line": int(parts[1]),
                    "text": parts[2].strip(),
                })
        return matches
    except (subprocess.TimeoutExpired, Exception) as e:
        log.warning(f"grep failed for pattern {pattern}: {e}")
        return []


def extract_function_args(text: str) -> list[str]:
    """Extract function call arguments from a line of C code.
    Handles nested parens but not multi-line calls."""
    # Find the opening paren
    paren_start = text.find("(")
    if paren_start == -1:
        return []

    depth = 0
    args = []
    current = ""
    for ch in text[paren_start:]:
        if ch == "(":
            depth += 1
            if depth > 1:
                current += ch
        elif ch == ")":
            depth -= 1
            if depth == 0:
                args.append(current.strip())
                break
            current += ch
        elif ch == "," and depth == 1:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    return args


def read_multiline_call(filepath: str, start_line: int, max_lines: int = 10) -> str:
    """Read a function call that may span multiple lines."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
        text = ""
        depth = 0
        for i in range(start_line - 1, min(start_line - 1 + max_lines, len(lines))):
            line = lines[i]
            text += " " + line.strip()
            depth += line.count("(") - line.count(")")
            if depth <= 0 and "(" in text:
                break
        return text
    except Exception:
        return ""


def extract_ops_struct_functions(filepath: str, struct_name: str,
                                  fields: list[str]) -> list[str]:
    """Find ops struct initialization and extract function pointer values.

    Looks for patterns like:
        static struct Qdisc_ops tbf_qdisc_ops = {
            .change = tbf_change,
            .init = tbf_init,
        };
    """
    functions = []
    try:
        with open(filepath) as f:
            content = f.read()
    except Exception:
        return functions

    # Find all struct initializations of this type
    # Pattern: struct <type> <name> [__read_mostly/__ro_after_init/etc] = { ... };
    pattern = rf"struct\s+{re.escape(struct_name)}\s+\w+[\s\w]*=\s*\{{([^}}]*)\}}"
    for m in re.finditer(pattern, content, re.DOTALL):
        init_block = m.group(1)
        # Extract .field = function_name patterns
        for field in fields:
            field_pattern = rf"\.{re.escape(field)}\s*=\s*(\w+)"
            for fm in re.finditer(field_pattern, init_block):
                func_name = fm.group(1)
                if func_name not in ("NULL", "0", "noop", "noop_dequeue"):
                    functions.append(func_name)

    return functions


def find_callers_in_file(filepath: str, target_func: str) -> list[str]:
    """Find functions that call target_func in a C file.

    Uses a robust approach: track function boundaries by brace depth,
    and detect function definitions by scanning for identifier(params) { patterns.
    """
    callers = []
    try:
        with open(filepath) as f:
            lines = f.readlines()
    except Exception:
        return callers

    current_func = None
    brace_depth = 0

    # Pre-scan: find all function definition start lines
    # A function definition is: <identifier>(<params>) { (possibly multi-line)
    # We look for lines that have a { at brace_depth==0 and the preceding
    # lines contain a function signature.
    func_starts = {}  # line_idx -> func_name
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Count braces
        for ch in stripped:
            if ch == '{':
                if brace_depth == 0:
                    # This { opens a function. Look back for the name.
                    # Scan backwards to find "identifier("
                    search_text = ""
                    for j in range(i, max(i - 5, -1), -1):
                        search_text = lines[j].strip() + " " + search_text
                    # Trim to text after the last '}' so that a single-line
                    # function on the previous line (e.g. `foo() {}`) doesn't
                    # pollute the search and cause the wrong name to be
                    # extracted for the current function.
                    last_close = search_text.rfind('}')
                    relevant = search_text[last_close + 1:] if last_close >= 0 else search_text
                    # Find the last identifier before (
                    m = re.search(r'(\w+)\s*\([^)]*\)\s*\{?\s*$',
                                  relevant.split('{')[0])
                    if m:
                        fname = m.group(1)
                        # Skip keywords
                        if fname not in ('if', 'for', 'while', 'switch',
                                         'do', 'else', 'return', 'sizeof',
                                         'typeof', '__attribute__'):
                            func_starts[i] = fname
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth < 0:
                    brace_depth = 0

    # Now re-scan with function boundaries
    brace_depth = 0
    current_func = None
    call_pattern = re.compile(rf"\b{re.escape(target_func)}\s*\(")

    for i, line in enumerate(lines):
        if i in func_starts:
            current_func = func_starts[i]

        if current_func and target_func in line:
            if call_pattern.search(line):
                if current_func != target_func and current_func not in callers:
                    callers.append(current_func)

        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            current_func = None
            brace_depth = 0

    return callers


def _resolve_ops_variable(src_dir: str, var_name: str, struct_type: str,
                           fields: list[str],
                           _cache: dict = {}) -> tuple[list[str], str]:
    """Resolve an ops struct variable to its handler functions.

    Given a variable name like 'tbf_qdisc_ops', find its definition anywhere
    in kernel source and extract the function pointers from its initializer.

    Returns: (list of handler functions, file where struct is defined)
    """
    cache_key = (src_dir, var_name, struct_type)
    if cache_key in _cache:
        return _cache[cache_key]

    # grep for the variable definition with struct assignment
    pattern = rf"{re.escape(var_name)}\s*=\s*\{{"
    matches = grep_source(src_dir, pattern, "*.c")

    for match in matches:
        funcs = extract_ops_struct_functions(
            match["file"], struct_type, fields
        )
        if funcs:
            result = (funcs, match["file"])
            _cache[cache_key] = result
            return result

    _cache[cache_key] = ([], "")
    return [], ""


# Pre-build a cache of all ops struct definitions in a directory
_ops_file_cache: dict[str, dict[str, list]] = {}


def _build_ops_cache(src_dir: str, struct_type: str,
                      fields: list[str]) -> dict[str, tuple[list[str], str]]:
    """Build a cache mapping ops variable names → (handler functions, file).

    Searches ALL files in src_dir for struct initializations of struct_type.
    Much faster than grepping per-variable.
    """
    cache_key = (src_dir, struct_type)
    if cache_key in _ops_file_cache:
        return _ops_file_cache[cache_key]

    result = {}
    # Find all struct <type> <name> [__attr] = { patterns
    # __read_mostly, __ro_after_init, etc. may appear between name and =
    pattern = rf"struct\s+{re.escape(struct_type)}\s+(\w+)\s+.*="
    matches = grep_source(src_dir, pattern, "*.c")
    # Also try without attributes
    pattern2 = rf"struct\s+{re.escape(struct_type)}\s+(\w+)\s*="
    matches.extend(grep_source(src_dir, pattern2, "*.c"))

    seen_files = set()
    for match in matches:
        if match["file"] in seen_files:
            continue
        seen_files.add(match["file"])

        # Extract ALL ops structs of this type from this file
        try:
            with open(match["file"]) as f:
                content = f.read()
        except Exception:
            continue

        full_pattern = rf"struct\s+{re.escape(struct_type)}\s+(\w+)[\s\w]*=\s*\{{([^}}]*)\}}"
        for m in re.finditer(full_pattern, content, re.DOTALL):
            var_name = m.group(1)
            init_block = m.group(2)
            funcs = []
            for field in fields:
                field_pat = rf"\.{re.escape(field)}\s*=\s*(\w+)"
                for fm in re.finditer(field_pat, init_block):
                    func_name = fm.group(1)
                    if func_name not in ("NULL", "0", "noop", "noop_dequeue"):
                        funcs.append(func_name)
            if funcs:
                result[var_name] = (funcs, match["file"])

    _ops_file_cache[cache_key] = result
    log.info(f"[ops_cache] {struct_type}: found {len(result)} struct instances "
             f"across {len(seen_files)} files")
    return result


def scan_registration_patterns(src_dir: str) -> dict[str, list[dict]]:
    """Scan kernel source for all known registration patterns.

    Returns: {pattern_name: [{"file": ..., "line": ..., "handlers": [...]}]}
    """
    all_registrations = {}

    for pattern_name, pattern_def in DISPATCH_PATTERNS.items():
        grep_pat = pattern_def["grep_pattern"]
        matches = grep_source(src_dir, grep_pat)

        registrations = []
        for match in matches:
            # Skip unregister/definition lines
            text = match["text"]
            if "unregister" in text or text.startswith("int ") or \
               text.startswith("void ") or "EXPORT_SYMBOL" in text:
                continue

            entry = {
                "file": match["file"],
                "line": match["line"],
                "handlers": [],
            }

            # Method 1: Extract handler from function call arguments
            if "handler_arg_indices" in pattern_def and \
               pattern_def.get("handler_arg_indices"):
                full_text = read_multiline_call(match["file"], match["line"])
                args = extract_function_args(full_text)
                for idx in pattern_def["handler_arg_indices"]:
                    if idx < len(args):
                        func = args[idx].strip().strip("&")
                        if func and func not in ("NULL", "0", "noop"):
                            entry["handlers"].append(func)

            # Method 2: Extract from ops struct
            if "ops_struct" in pattern_def:
                struct_type = pattern_def["ops_struct"]
                fields = pattern_def.get("ops_fields", [])

                # Build batch cache for this struct type (once per type)
                ops_cache = _build_ops_cache(src_dir, struct_type, fields)

                # Extract ops variable name from registration call
                full_text = read_multiline_call(match["file"], match["line"])
                args = extract_function_args(full_text)
                ops_var = None
                if args:
                    ops_var = args[0].strip().strip("&")

                if ops_var and ops_var not in ("NULL", "0"):
                    # Look up in batch cache
                    if ops_var in ops_cache:
                        funcs, found_file = ops_cache[ops_var]
                        entry["handlers"].extend(funcs)
                        entry["file"] = found_file
                    else:
                        # Fallback: try same file
                        funcs = extract_ops_struct_functions(
                            match["file"], struct_type, fields
                        )
                        entry["handlers"].extend(funcs)
                else:
                    # No variable name, try same file
                    funcs = extract_ops_struct_functions(
                        match["file"], struct_type, fields
                    )
                    entry["handlers"].extend(funcs)

            if entry["handlers"]:
                # Deduplicate
                entry["handlers"] = list(dict.fromkeys(entry["handlers"]))
                registrations.append(entry)

        if registrations:
            all_registrations[pattern_name] = registrations
            total = sum(len(r["handlers"]) for r in registrations)
            log.info(f"[{pattern_name}] Found {len(registrations)} registrations, "
                     f"{total} handler functions")

    return all_registrations


def build_handler_to_syscall_map(registrations: dict) -> dict[str, dict]:
    """Build handler_function → {syscalls, related} mapping from registrations.

    Returns: {
        "tc_modify_qdisc": {
            "syscalls": ["sendmsg$nl_route", "sendmsg$nl_route_sched"],
            "related": ["socket$nl_route"],
            "pattern": "rtnl_register",
            "file": "net/sched/sch_api.c",
        },
        ...
    }
    """
    handler_map = {}

    for pattern_name, reg_list in registrations.items():
        pattern_def = DISPATCH_PATTERNS[pattern_name]
        syscalls = pattern_def["syscalls"]
        related = pattern_def["related"]

        for reg in reg_list:
            for handler in reg["handlers"]:
                if handler not in handler_map:
                    handler_map[handler] = {
                        "syscalls": list(syscalls),
                        "related": list(related),
                        "pattern": pattern_name,
                        "file": reg["file"],
                    }
                else:
                    # Merge syscalls
                    for s in syscalls:
                        if s not in handler_map[handler]["syscalls"]:
                            handler_map[handler]["syscalls"].append(s)
                    for r in related:
                        if r not in handler_map[handler]["related"]:
                            handler_map[handler]["related"].append(r)

    return handler_map


def trace_target_to_handler(target_function: str, src_dir: str,
                             handler_map: dict,
                             max_depth: int = 6) -> Optional[dict]:
    """Trace from target_function backwards through caller chain to find
    a registered handler function.

    Returns the handler_map entry if found, with the call chain added.
    """
    visited = set()
    queue = [(target_function, [target_function])]

    while queue:
        func, chain = queue.pop(0)
        if func in visited:
            continue
        visited.add(func)

        if len(chain) > max_depth:
            continue

        # Check if this function is a registered handler
        if func in handler_map:
            result = dict(handler_map[func])
            result["call_chain"] = chain
            result["handler"] = func
            return result

        # Find callers of this function in kernel source
        matches = grep_source(src_dir, rf"\b{re.escape(func)}\s*\(", "*.c")

        callers_found = set()
        for match in matches:
            # Find the enclosing function
            callers = find_callers_in_file(match["file"], func)
            for caller in callers:
                if caller not in visited and caller not in callers_found:
                    callers_found.add(caller)
                    queue.append((caller, chain + [caller]))

        # Also check if the function itself is assigned to an ops struct field
        assign_matches = grep_source(
            src_dir, rf"\.\w+\s*=\s*{re.escape(func)}\b", "*.c"
        )
        for match in assign_matches:
            # Check which pattern this struct belongs to
            for pname, pdef in DISPATCH_PATTERNS.items():
                if "ops_struct" not in pdef:
                    continue
                struct_pat = pdef["ops_struct"]
                # Check if the file contains this struct type
                try:
                    with open(match["file"]) as f:
                        nearby = f.readlines()
                    # Look backwards from the assignment for struct type
                    for li in range(max(0, match["line"] - 20), match["line"]):
                        if struct_pat in nearby[li]:
                            result = {
                                "syscalls": list(pdef["syscalls"]),
                                "related": list(pdef["related"]),
                                "pattern": pname,
                                "file": match["file"],
                                "call_chain": chain + [f"[ops:{struct_pat}]"],
                                "handler": func,
                            }
                            return result
                except Exception:
                    pass

    return None


def augment_k2s(k2s_path: str, src_dir: str, target_function: str,
                target_file: Optional[str] = None) -> dict:
    """Main entry point: augment k2s with indirect dispatch resolution.

    Args:
        k2s_path: path to kernelCode2syscall.json
        src_dir: path to kernel source directory
        target_function: the fuzzing target function name
        target_file: optional, the source file containing target_function

    Returns: augmented k2s dict
    """
    # Load existing k2s
    try:
        with open(k2s_path) as f:
            k2s = json.load(f)
    except Exception:
        k2s = {}

    log.info(f"[V7] Resolving indirect dispatch for target: {target_function}")
    log.info(f"[V7] Existing k2s has {len(k2s)} handler functions")

    # Phase 1: Scan registration patterns
    registrations = scan_registration_patterns(src_dir)
    total_patterns = sum(len(v) for v in registrations.values())
    log.info(f"[V7] Found {total_patterns} registrations across "
             f"{len(registrations)} pattern types")

    # Phase 2: Build handler→syscall map
    handler_map = build_handler_to_syscall_map(registrations)
    log.info(f"[V7] Built handler map with {len(handler_map)} handler functions")

    # Phase 3: Trace target to handler
    trace_result = trace_target_to_handler(target_function, src_dir, handler_map)

    if trace_result:
        chain_str = " → ".join(trace_result["call_chain"])
        log.info(f"[V7] Found dispatch chain: {chain_str}")
        log.info(f"[V7] Handler: {trace_result['handler']} "
                 f"(pattern: {trace_result['pattern']})")
        log.info(f"[V7] Syscalls: {trace_result['syscalls']}")

        # Phase 4: Inject into k2s
        # Add all functions in the call chain to k2s
        for func in trace_result["call_chain"]:
            if func.startswith("["):  # skip markers like [ops:...]
                continue
            if func not in k2s:
                k2s[func] = {
                    "none": trace_result["syscalls"],
                }
                log.info(f"[V7] Added to k2s: {func} → {trace_result['syscalls']}")

        # Also add the handler itself
        handler = trace_result["handler"]
        if handler not in k2s:
            k2s[handler] = {"none": trace_result["syscalls"]}
            log.info(f"[V7] Added handler to k2s: {handler} → "
                     f"{trace_result['syscalls']}")
    else:
        log.warning(f"[V7] Could not trace {target_function} to any "
                    f"registered handler. Trying direct file scan...")

        # Fallback: if target_file is known, check all ops structs in it
        if target_file:
            _fallback_file_scan(k2s, src_dir, target_function, target_file,
                                handler_map)

    # Phase 5: Subsystem-based fallback for functions not reachable through
    # direct registration chains (e.g. packet-processing paths)
    if not trace_result:
        trace_result = _subsystem_fallback(target_function, src_dir, k2s)

    return k2s


# Subsystem → syscall mapping for functions that are called indirectly
# through packet processing or other non-registration paths
SUBSYSTEM_RULES = [
    # (path pattern, syscalls, related)
    ("net/xfrm/", ["sendmsg$nl_xfrm"], ["socket$nl_xfrm"]),
    ("net/sched/cls_", ["sendmsg$nl_route_sched"], ["socket$nl_route"]),
    ("net/sched/sch_", ["sendmsg$nl_route_sched"], ["socket$nl_route"]),
    ("net/sched/act_", ["sendmsg$nl_route_sched"], ["socket$nl_route"]),
    ("net/netfilter/nf_tables", ["sendmsg$nl_netfilter"], ["socket$nl_netfilter"]),
    ("net/netfilter/nft_", ["sendmsg$nl_netfilter"], ["socket$nl_netfilter"]),
    ("net/netfilter/xt_", ["setsockopt$IP_SET_OP_GET_BYNAME"], ["socket$inet"]),
    ("net/bluetooth/", ["socket$bt_hci", "socket$bt_l2cap", "socket$bt_sco"], []),
    ("net/llc/", ["sendmsg$llc"], ["socket$llc"]),
    ("net/can/", ["sendmsg$can_raw"], ["socket$can_raw"]),
    ("crypto/", ["sendmsg$alg"], ["socket$alg"]),
]


def _subsystem_fallback(target_function: str, src_dir: str,
                         k2s: dict) -> Optional[dict]:
    """When tracing fails, infer syscalls from the file path of the target."""
    # Find which file contains the target function
    matches = grep_source(src_dir, rf"\b{re.escape(target_function)}\s*\(", "*.c")
    if not matches:
        return None

    for match in matches:
        filepath = match["file"]
        # Make relative to src_dir
        rel_path = os.path.relpath(filepath, src_dir)

        for path_pattern, syscalls, related in SUBSYSTEM_RULES:
            if path_pattern in rel_path:
                for func_name in [target_function]:
                    if func_name not in k2s:
                        k2s[func_name] = {"none": syscalls}
                        log.info(f"[V7-subsystem] {func_name} in {rel_path} "
                                 f"→ {syscalls} (subsystem rule: {path_pattern})")
                return {
                    "syscalls": syscalls,
                    "related": related,
                    "pattern": f"subsystem:{path_pattern}",
                    "file": filepath,
                    "call_chain": [target_function, f"[subsystem:{path_pattern}]"],
                    "handler": target_function,
                }

    return None


def _fallback_file_scan(k2s: dict, src_dir: str, target_function: str,
                         target_file: str, handler_map: dict):
    """Fallback: scan the target file for any ops struct that might contain
    the target function or its callers."""
    filepath = os.path.join(src_dir, target_file)
    if not os.path.exists(filepath):
        # Try to find the file
        matches = grep_source(src_dir, rf"\b{re.escape(target_function)}\b", "*.c")
        if matches:
            filepath = matches[0]["file"]
        else:
            return

    for pname, pdef in DISPATCH_PATTERNS.items():
        if "ops_struct" not in pdef:
            continue
        struct_funcs = extract_ops_struct_functions(
            filepath, pdef["ops_struct"], pdef.get("ops_fields", [])
        )
        if struct_funcs:
            # Check if target_function is one of the ops functions or called by one
            if target_function in struct_funcs:
                k2s[target_function] = {"none": pdef["syscalls"]}
                log.info(f"[V7-fallback] {target_function} is directly in "
                         f"{pdef['ops_struct']} → {pdef['syscalls']}")
                return

            for sf in struct_funcs:
                callers = find_callers_in_file(filepath, target_function)
                if sf in callers:
                    k2s[target_function] = {"none": pdef["syscalls"]}
                    k2s[sf] = {"none": pdef["syscalls"]}
                    log.info(f"[V7-fallback] {target_function} called by "
                             f"{sf} in {pdef['ops_struct']} → {pdef['syscalls']}")
                    return


def augment_callfile(callfile_path: str, src_dir: str, target_function: str,
                      target_file: Optional[str] = None) -> bool:
    """Convenience function: directly augment inp_0.json callfile.

    Use this when you want to skip the full pipeline and directly inject
    the correct syscalls into the fuzzer input.

    Returns True if callfile was modified.
    """
    log.info(f"[V7] Augmenting callfile: {callfile_path}")

    # Scan and trace
    registrations = scan_registration_patterns(src_dir)
    handler_map = build_handler_to_syscall_map(registrations)
    trace_result = trace_target_to_handler(target_function, src_dir, handler_map)

    if not trace_result:
        log.warning(f"[V7] No dispatch chain found for {target_function}")
        return False

    # Load callfile
    try:
        with open(callfile_path) as f:
            callfile = json.load(f)
    except Exception:
        callfile = []

    # Check if syscalls already present
    existing_targets = {entry.get("Target", "") for entry in callfile}
    new_syscalls = trace_result["syscalls"]
    related = trace_result["related"]

    modified = False
    for syscall in new_syscalls:
        if syscall not in existing_targets:
            # Build Relate list from pattern definition + existing related
            relate_list = list(related)
            # Add other syscalls from this pattern as related
            for other in new_syscalls:
                if other != syscall and other not in relate_list:
                    relate_list.append(other)

            callfile.append({
                "Target": syscall,
                "Relate": relate_list,
            })
            log.info(f"[V7] Added to callfile: Target={syscall}, "
                     f"Relate={relate_list}")
            modified = True

    if modified:
        with open(callfile_path, "w") as f:
            json.dump(callfile, f, indent="\t")
        log.info(f"[V7] Callfile updated with {len(new_syscalls)} new targets")

    chain_str = " → ".join(trace_result["call_chain"])
    log.info(f"[V7] Dispatch chain: {chain_str}")

    return modified


# ── CLI interface ──
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(
        description="Resolve indirect dispatch patterns in kernel source")
    parser.add_argument("--src-dir", required=True,
                        help="Kernel source directory")
    parser.add_argument("--target", required=True,
                        help="Target function name")
    parser.add_argument("--target-file",
                        help="Source file containing target function")
    parser.add_argument("--k2s",
                        help="Path to kernelCode2syscall.json to augment")
    parser.add_argument("--callfile",
                        help="Path to inp_0.json to augment directly")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only scan registrations, don't trace")
    parser.add_argument("--output",
                        help="Output JSON path (default: stdout)")

    args = parser.parse_args()

    if args.scan_only:
        registrations = scan_registration_patterns(args.src_dir)
        handler_map = build_handler_to_syscall_map(registrations)
        print(f"\nTotal registered handlers: {len(handler_map)}")
        print(f"\nPatterns found:")
        for pname, regs in registrations.items():
            total_h = sum(len(r["handlers"]) for r in regs)
            print(f"  {pname}: {len(regs)} registrations, {total_h} handlers")

        # Check if target is in handler_map
        if args.target in handler_map:
            info = handler_map[args.target]
            print(f"\n{args.target} is DIRECTLY registered:")
            print(f"  Pattern: {info['pattern']}")
            print(f"  Syscalls: {info['syscalls']}")
        else:
            print(f"\n{args.target} is NOT directly registered. Tracing...")
            result = trace_target_to_handler(
                args.target, args.src_dir, handler_map)
            if result:
                chain = " → ".join(result["call_chain"])
                print(f"  Chain: {chain}")
                print(f"  Handler: {result['handler']}")
                print(f"  Pattern: {result['pattern']}")
                print(f"  Syscalls: {result['syscalls']}")
            else:
                print(f"  No dispatch chain found.")

    elif args.callfile:
        augment_callfile(args.callfile, args.src_dir, args.target,
                          args.target_file)

    elif args.k2s:
        result = augment_k2s(args.k2s, args.src_dir, args.target,
                              args.target_file)
        out_path = args.output or args.k2s
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Augmented k2s written to {out_path} ({len(result)} entries)")

    else:
        # Just trace and print
        registrations = scan_registration_patterns(args.src_dir)
        handler_map = build_handler_to_syscall_map(registrations)
        result = trace_target_to_handler(
            args.target, args.src_dir, handler_map)
        if not result:
            # Try subsystem fallback
            dummy_k2s = {}
            result = _subsystem_fallback(args.target, args.src_dir, dummy_k2s)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"No dispatch chain found for {args.target}")
