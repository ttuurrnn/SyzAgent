#!/usr/bin/env python3
"""
Pre-compute a compact seed plan from kernel source, .dist files, and syzlang.

Instead of stuffing raw kernel source (5000+ chars) and syzlang type defs
(3000+ chars) into the LLM prompt, this module extracts only the essential
information and produces a compact plan (~500 chars) that the LLM can act on.

The LLM then only needs to convert this plan into a Python script with
struct.pack() calls — no source-reading or analysis needed.
"""

import os
import re
import struct
import subprocess


# ── Netlink / TC constants ────────────────────────────────────────────

RTM_TYPES = {
    "RTM_NEWQDISC": 0x24, "RTM_DELQDISC": 0x25,
    "RTM_NEWTCLASS": 0x28, "RTM_DELTCLASS": 0x29,
    "RTM_NEWTFILTER": 0x2c, "RTM_DELTFILTER": 0x2d,
    "RTM_NEWLINK": 0x10,
    "RTM_NEWACTION": 0x30, "RTM_DELACTION": 0x31,
    "RTM_NEWCHAIN": 0x64, "RTM_DELCHAIN": 0x65,
    "RTM_NEWRULE": 0x20,
}

# NLM flags
NLM_F_REQUEST = 0x01
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200

# TC attribute indices (TCA_*)
TCA_INDICES = {
    "TCA_KIND": 1, "TCA_OPTIONS": 2, "TCA_RATE": 3,
    "TCA_STATS": 4, "TCA_XSTATS": 5, "TCA_STATS2": 7,
    "TCA_CHAIN": 11,
}


def extract_branch_conditions(source_text, target_function):
    """Extract branch conditions from kernel source that gate entry to target.

    Returns list of dicts with condition, required values, and explanation.
    """
    conditions = []
    if not source_text:
        return conditions

    # Pattern: if (expr) ... target_function
    # We look for if-statements in the caller that guard the call to target
    lines = source_text.split('\n')

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Find if-conditions
        m = re.match(r'if\s*\((.+?)\)\s*{?\s*$', stripped)
        if not m:
            m = re.match(r'if\s*\((.+?)\)\s*$', stripped)
        if not m:
            continue

        cond = m.group(1).strip()

        # Extract concrete constraints
        constraint = _parse_condition(cond)
        if constraint:
            conditions.append(constraint)

    return conditions


def _parse_condition(cond_str):
    """Parse a C condition into a concrete constraint dict."""
    # Pattern: tb[ATTR_NAME] — attribute must be present
    m = re.match(r'tb\[(\w+)\]', cond_str)
    if m:
        return {"type": "attr_required", "attr": m.group(1), "raw": cond_str}

    # Pattern: !tb[ATTR_NAME] — attribute must NOT be present
    m = re.match(r'!tb\[(\w+)\]', cond_str)
    if m:
        return {"type": "attr_absent", "attr": m.group(1), "raw": cond_str}

    # Pattern: var > N, var < N, var >= N, var <= N
    m = re.match(r'(\w+(?:->\w+)*)\s*(>|<|>=|<=|==|!=)\s*(\w+)', cond_str)
    if m:
        return {
            "type": "comparison",
            "var": m.group(1), "op": m.group(2), "value": m.group(3),
            "raw": cond_str,
        }

    # Pattern: !var — var must be zero/NULL
    m = re.match(r'^!(\w+(?:->\w+)*)$', cond_str)
    if m:
        return {"type": "zero_check", "var": m.group(1), "raw": cond_str}

    # Pattern: var — var must be non-zero/non-NULL
    m = re.match(r'^(\w+(?:->\w+)*)$', cond_str)
    if m:
        return {"type": "nonzero_check", "var": m.group(1), "raw": cond_str}

    # Compound: (expr) < THRESHOLD
    m = re.match(r'\((.+?)\)\s*(<|>|<=|>=)\s*(\w+)', cond_str)
    if m:
        return {
            "type": "compound_comparison",
            "expr": m.group(1), "op": m.group(2), "value": m.group(3),
            "raw": cond_str,
        }

    return {"type": "unknown", "raw": cond_str}


def extract_nla_policy(source_text, kind_name):
    """Extract NLA attribute definitions for a specific TC kind.

    Looks for patterns like:
        [TCA_TCINDEX_HASH] = { .type = NLA_U32 }

    Returns list of {name, index, nla_type, size}.
    """
    attrs = []
    if not source_text:
        return attrs

    # Find policy array entries
    for m in re.finditer(
        r'\[(\w+)\]\s*=\s*\{[^}]*\.type\s*=\s*(\w+)',
        source_text
    ):
        attr_name = m.group(1)
        nla_type = m.group(2)

        size_map = {
            "NLA_U8": 1, "NLA_U16": 2, "NLA_U32": 4, "NLA_U64": 8,
            "NLA_STRING": 0, "NLA_BINARY": 0, "NLA_NESTED": 0,
            "NLA_FLAG": 0, "NLA_S32": 4,
        }
        size = size_map.get(nla_type, 0)

        # Try to get enum index from name pattern
        # e.g., TCA_TCINDEX_HASH → look for enum definition
        attrs.append({
            "name": attr_name,
            "nla_type": nla_type,
            "size": size,
        })

    return attrs


def extract_kind_from_target(target_function, target_file):
    """Infer TC qdisc/filter kind from target function/file.

    e.g., cls_tcindex.c → tcindex, sch_tbf.c → tbf
    """
    basename = os.path.basename(target_file or "")

    # cls_X.c → filter kind X
    m = re.match(r'cls_(\w+)\.c', basename)
    if m and m.group(1) not in ("api", "route"):
        return m.group(1), "filter"

    # sch_X.c → qdisc kind X
    m = re.match(r'sch_(\w+)\.c', basename)
    if m and m.group(1) not in ("api", "generic"):
        return m.group(1), "qdisc"

    # act_X.c → action kind X
    m = re.match(r'act_(\w+)\.c', basename)
    if m and m.group(1) not in ("api",):
        return m.group(1), "action"

    return None, None


def _kind_from_dispatch_context(roadmap):
    prefixes = {
        "tcindex": ("tcindex", "filter"),
        "tbf": ("tbf", "qdisc"),
        "cls_u32": ("u32", "filter"),
        "u32": ("u32", "filter"),
        "fl_": ("flower", "filter"),
        "flower": ("flower", "filter"),
        "mall_": ("matchall", "filter"),
        "matchall": ("matchall", "filter"),
        "basic_": ("basic", "filter"),
        "bpf": ("bpf", "filter"),
        "pfifo": ("pfifo", "qdisc"),
        "bfifo": ("bfifo", "qdisc"),
        "htb": ("htb", "qdisc"),
        "sfq": ("sfq", "qdisc"),
    }
    tokens = []
    tokens.extend(str(fn) for fn in (roadmap or {}).get("actual_callers", []) or [])
    for caller in (roadmap or {}).get("cross_file_callers", []) or []:
        tokens.append(caller.get("function", "") if isinstance(caller, dict) else str(caller))
    for stone in (roadmap or {}).get("stepping_stones", []) or []:
        tokens.append(stone.get("function", ""))
    for tok in tokens:
        tok = tok.lower()
        for prefix, result in prefixes.items():
            if tok.startswith(prefix) or f"_{prefix}" in tok:
                return result
    return None, None


def determine_syscall_sequence(target_function, target_file, roadmap=None):
    """Determine the prerequisite syscall sequence to reach target.

    Returns list of steps: [{call, msg_type, kind, attrs, notes}]
    """
    kind, obj_type = extract_kind_from_target(target_function, target_file)
    ctx_kind, ctx_type = _kind_from_dispatch_context(roadmap)
    if ctx_kind:
        # Caller/registration chain is more reliable for helpers and generic
        # API files than the target's own source basename.
        kind, obj_type = ctx_kind, ctx_type
    steps = []

    if "net/sched" in (target_file or ""):
        # TC subsystem: always need a qdisc first
        if obj_type == "filter":
            # Need: 1) create interface, 2) add qdisc, 3) add filter
            steps.append({
                "step": 1,
                "call": "socket$nl_route(0x10, 0x3, 0x0) → r0",
                "note": "netlink route socket",
            })
            steps.append({
                "step": 2,
                "msg": "RTM_NEWQDISC",
                "kind": "htb",
                "handle": "0x10000",
                "parent": "0xffffffff",
                "note": "create root qdisc (htb supports filters)",
            })
            steps.append({
                "step": 3,
                "msg": "RTM_NEWTFILTER",
                "kind": kind or "tcindex",
                "parent": "0x10000",
                "note": f"create {kind} filter → triggers {target_function}",
            })
        elif obj_type == "qdisc":
            steps.append({
                "step": 1,
                "call": "socket$nl_route(0x10, 0x3, 0x0) → r0",
                "note": "netlink route socket",
            })
            steps.append({
                "step": 2,
                "msg": "RTM_NEWQDISC",
                "kind": kind or "unknown",
                "handle": "0x10000",
                "parent": "0xffffffff",
                "note": f"create {kind} qdisc → triggers {target_function}",
            })

    elif "net/netfilter" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "socket$nl_generic(0x10, 0x3, 0x10) → r0",
            "note": "netlink generic socket for nftables",
        })
        steps.append({
            "step": 2,
            "msg": "NFT_MSG_NEWTABLE",
            "note": "create nftables table",
        })
        steps.append({
            "step": 3,
            "msg": "NFT_MSG_NEWCHAIN",
            "note": "create chain in table",
        })
        steps.append({
            "step": 4,
            "msg": "NFT_MSG_NEWRULE",
            "note": f"create rule → triggers {target_function}",
        })

    elif "net/xfrm" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "socket$nl_xfrm(0x10, 0x3, 0x6) → r0",
            "note": "netlink xfrm socket",
        })
        steps.append({
            "step": 2,
            "msg": "XFRM_MSG_NEWSA",
            "note": "create security association",
        })
        steps.append({
            "step": 3,
            "msg": "XFRM_MSG_NEWPOLICY",
            "note": f"create policy → triggers {target_function}",
        })

    elif "net/bluetooth" in (target_file or "") or "net/sco" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "socket$bt_sco(0x1f, 0x5, 0x2) → r0",
            "note": "bluetooth SCO socket",
        })
        steps.append({
            "step": 2,
            "call": "connect$bt_sco(r0, ...)",
            "note": f"connect → triggers {target_function}",
        })

    elif "net/sctp" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "socket$inet_sctp(0x2, 0x1, 0x84) → r0",
            "note": "SCTP socket",
        })
        steps.append({
            "step": 2,
            "call": "sendmsg$inet_sctp(r0, ...)",
            "note": f"send → triggers {target_function}",
        })

    elif "net/llc" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "socket$llc(0x1a, 0x2, 0x0) → r0",
            "note": "LLC socket",
        })
        steps.append({
            "step": 2,
            "call": "sendmsg$llc(r0, ...)",
            "note": f"sendmsg → triggers {target_function}",
        })

    elif "mm/" in (target_file or ""):
        steps.append({
            "step": 1,
            "call": "mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x7, 0x22, -1, 0x0)",
            "note": "create memory mapping",
        })
        steps.append({
            "step": 2,
            "call": "mremap / move_pages / mbind",
            "note": f"memory operation → triggers {target_function}",
        })

    return steps


def build_compact_plan(roadmap, source_snippets, target_function, target_file,
                       semantic_context="", closest_program=None, closest_dist=None,
                       current_dist=None):
    """Build a compact seed plan for LLM consumption.

    Returns a string ~500 chars instead of ~12000 chars.
    """
    dist = current_dist or (roadmap or {}).get("current_dist_min", 0)

    sections = []

    # 1. Target + distance (always needed)
    sections.append(f"TARGET: {target_function} in {target_file}")
    sections.append(f"CURRENT DISTANCE: {dist}")

    # 2. Syscall sequence (pre-computed)
    steps = determine_syscall_sequence(target_function, target_file, roadmap)
    if steps:
        step_lines = []
        for s in steps:
            if "call" in s:
                step_lines.append(f"  {s['step']}. {s['call']}  # {s['note']}")
            elif "msg" in s:
                parts = [f"  {s['step']}. sendmsg {s['msg']}"]
                if s.get("kind"):
                    parts.append(f'kind="{s["kind"]}"')
                if s.get("handle"):
                    parts.append(f"handle={s['handle']}")
                if s.get("parent"):
                    parts.append(f"parent={s['parent']}")
                parts.append(f"# {s['note']}")
                step_lines.append(" ".join(parts))
        sections.append("SYSCALL SEQUENCE:\n" + "\n".join(step_lines))

    # 3. Branch conditions (extracted from source, not raw source)
    conditions = extract_branch_conditions(source_snippets or "", target_function)
    if conditions:
        cond_lines = []
        for c in conditions:
            if c["type"] == "attr_required":
                cond_lines.append(f"  - {c['attr']} must be set")
            elif c["type"] == "comparison":
                cond_lines.append(f"  - {c['var']} {c['op']} {c['value']}")
            elif c["type"] == "compound_comparison":
                cond_lines.append(f"  - ({c['expr']}) {c['op']} {c['value']}")
            elif c["type"] == "zero_check":
                cond_lines.append(f"  - {c['var']} must be 0/NULL")
            elif c["type"] == "nonzero_check":
                cond_lines.append(f"  - {c['var']} must be non-zero")
            else:
                cond_lines.append(f"  - {c['raw']}")
        if cond_lines:
            sections.append("CONDITIONS to satisfy:\n" + "\n".join(cond_lines))

    # 4. NLA attributes (extracted from source, not syzlang dump)
    nla_attrs = extract_nla_policy(source_snippets or "",
                                    extract_kind_from_target(target_function, target_file)[0] or "")
    if nla_attrs:
        attr_lines = [f"  - {a['name']}: {a['nla_type']} ({a['size']}B)" for a in nla_attrs]
        sections.append("NLA ATTRIBUTES:\n" + "\n".join(attr_lines))

    # 5. Call chain (from semantic context or roadmap, just function names)
    if roadmap:
        actual_callers = roadmap.get("actual_callers", [])
        cross_file = roadmap.get("cross_file_callers", [])
        stones = roadmap.get("stepping_stones", [])

        chain_parts = []
        if actual_callers:
            chain_parts.append("Direct callers: " + ", ".join(
                f"{c[0]}({c[1]})" if isinstance(c, (list, tuple)) else str(c)
                for c in actual_callers[:3]
            ))
        if cross_file:
            chain_parts.append("Cross-file callers: " + ", ".join(
                f"{c[0]}(dist={c[1]})" for c in cross_file[:3]
            ))
        if stones:
            closest = stones[0]
            chain_parts.append(f"Next barrier: {closest['function']} (dist={closest['distance']})")

        if chain_parts:
            sections.append("CALL CHAIN:\n  " + "\n  ".join(chain_parts))

    # 6. Closest program (keep as-is, LLM needs it for reference)
    if closest_program:
        # Truncate to first 3 lines
        prog_lines = closest_program.strip().split('\n')[:3]
        sections.append("CLOSEST PROGRAM (dist={}):\n{}".format(
            closest_dist, "\n".join(prog_lines)))

    return "\n\n".join(sections)


def build_compact_plan_file(roadmap, source_snippets, target_function, target_file,
                            output_path, **kwargs):
    """Build plan and write to file. Returns the path."""
    plan = build_compact_plan(roadmap, source_snippets, target_function, target_file,
                              **kwargs)
    with open(output_path, 'w') as f:
        f.write(plan)
    return output_path


# ── Self-test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick test with case 0
    plan = build_compact_plan(
        roadmap={
            "current_dist_min": 2010,
            "stepping_stones": [
                {"function": "tc_new_tfilter", "distance": 1010},
                {"function": "tcindex_change", "distance": 10},
            ],
            "actual_callers": [("tcindex_set_parms", "net/sched/cls_tcindex.c:281")],
            "cross_file_callers": [("tc_new_tfilter", 1010)],
        },
        source_snippets="""
if (tb[TCA_TCINDEX_HASH])
    cp->hash = nla_get_u32(tb[TCA_TCINDEX_HASH]);
if (tb[TCA_TCINDEX_MASK])
    cp->mask = nla_get_u16(tb[TCA_TCINDEX_MASK]);
if (tb[TCA_TCINDEX_SHIFT]) {
    cp->shift = nla_get_u32(tb[TCA_TCINDEX_SHIFT]);
    if (cp->shift > 16) {
if (!cp->hash) {
    if ((cp->mask >> cp->shift) < PERFECT_HASH_THRESHOLD)
if (p->perfect) {
    if (tcindex_alloc_perfect_hash(net, cp) < 0)
""",
        target_function="tcindex_alloc_perfect_hash",
        target_file="net/sched/cls_tcindex.c",
        current_dist=2010,
        closest_program="r0 = socket$nl_route(0x10, 0x3, 0x0)\nsendmsg$nl_route_sched(r0, ...)",
        closest_dist=2010,
    )
    print(plan)
    print(f"\n--- Plan length: {len(plan)} chars ---")
