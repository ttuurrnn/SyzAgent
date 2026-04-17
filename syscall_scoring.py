"""
SyzDirect Runner — syscall context scoring, narrowing, and heuristic guessing.

Provides context-aware scoring of syscall names against a target function,
callfile narrowing (biasing toward the relevant subsystem), and file-path
based heuristic syscall guessing.
"""

import os
import re

from paths import HUNT_MODES, _GENERIC_CONTEXT_TOKENS
from syscall_normalize import normalize_syscall_name, normalize_callfile_entries


# ──────────────────────────────────────────────────────────────────────────
# Context tokenization
# ──────────────────────────────────────────────────────────────────────────

def _tokenize_context(text):
    tokens = set()
    for token in re.split(r"[^a-zA-Z0-9]+", (text or "").lower()):
        if len(token) < 3 or token.isdigit() or token in _GENERIC_CONTEXT_TOKENS:
            continue
        tokens.add(token)
        if "_" in token:
            for part in token.split("_"):
                if len(part) >= 3 and part not in _GENERIC_CONTEXT_TOKENS:
                    tokens.add(part)
    return tokens


def collect_target_context(file_path, function_name=""):
    """Build a context dict with tokenized file/function info for scoring."""
    file_path = file_path or ""
    basename = os.path.splitext(os.path.basename(file_path))[0]
    path_tokens = _tokenize_context(file_path.replace("/", " "))
    func_tokens = _tokenize_context(function_name)
    strong_tokens = set(func_tokens)
    strong_tokens.update(t for t in _tokenize_context(basename) if t not in {"inode", "openat"})
    last_dirs = [p for p in file_path.lower().split("/") if p][-3:-1]
    strong_tokens.update(_tokenize_context(" ".join(last_dirs)))
    return {
        "file_path": file_path,
        "function": function_name,
        "path_tokens": path_tokens,
        "func_tokens": func_tokens,
        "strong_tokens": strong_tokens,
    }


# ──────────────────────────────────────────────────────────────────────────
# Subsystem-specific prep syscalls
# ──────────────────────────────────────────────────────────────────────────

def subsystem_prep_syscalls(file_path, function_name=""):
    """Return syscalls commonly needed as setup for the target subsystem."""
    context = f"{file_path} {function_name}".lower()
    seeds = []
    mappings = [
        (("drivers/net/netdevsim", "netdevsim", "nsim"), [
            "bpf$MAP_CREATE", "bpf$PROG_LOAD", "socket$nl_route",
            "sendmsg$nl_route", "socket$nl_generic",
        ]),
        (("kernel/bpf", " bpf", "bpf_"), [
            "bpf$MAP_CREATE", "bpf$PROG_LOAD", "close",
        ]),
        (("net/vmw_vsock", "vsock"), [
            "socket$vsock_stream", "bind$vsock_stream",
            "connect$vsock_stream", "listen",
        ]),
        (("net/sched", "tc_", "qdisc"), [
            "socket$nl_route", "sendmsg$nl_route", "sendmsg$nl_route_sched",
            "bind",
        ]),
        (("net/packet", "packet"), [
            "socket$packet", "bind", "setsockopt$packet_fanout",
        ]),
        (("io_uring", "io_uring"), [
            "io_uring_setup", "io_uring_register$IORING_REGISTER_FILES",
        ]),
        (("gfs2", "fs/gfs2"), [
            "mount", "openat", "close",
        ]),
        (("fs/", "super", "inode"), [
            "mount", "openat", "read", "close",
        ]),
    ]
    for hints, calls in mappings:
        if any(hint in context for hint in hints):
            seeds.extend(calls)
    return seeds


# ──────────────────────────────────────────────────────────────────────────
# Syscall scoring
# ──────────────────────────────────────────────────────────────────────────

def _score_syscall_name(name, context):
    """Score a syscall name against target context tokens."""
    lowered = (name or "").lower()
    score = 0
    for token in context["strong_tokens"]:
        if token in lowered:
            score += 4
    for token in context["func_tokens"]:
        if token in lowered:
            score += 3
    for token in context["path_tokens"]:
        if token in lowered:
            score += 1
    if any(key in lowered for key in ("bpf", "xdp")) and "bpf" in context["path_tokens"] | context["func_tokens"]:
        score += 4
    if "netdevsim" in lowered and "netdevsim" in context["path_tokens"] | context["strong_tokens"]:
        score += 6
    if "vsock" in lowered and "vsock" in context["path_tokens"] | context["func_tokens"]:
        score += 4
    if "nl_route" in lowered and "net" in context["file_path"]:
        score += 1
    return score


# ──────────────────────────────────────────────────────────────────────────
# Callfile narrowing
# ──────────────────────────────────────────────────────────────────────────

def narrow_callfile_entries(entries, context_file="", target_function="", hunt_mode="hybrid"):
    """Bias generated callfiles toward the target subsystem instead of broad fuzz noise."""
    if hunt_mode not in HUNT_MODES:
        hunt_mode = "hybrid"

    context = collect_target_context(context_file, target_function)
    entries = normalize_callfile_entries(entries, context_file)
    if not entries:
        return entries

    limits = {
        "repro": (2, 4),
        "hybrid": (3, 6),
        "harvest": (4, 8),
    }
    max_targets, max_related = limits[hunt_mode]

    scored = []
    for entry in entries:
        target = entry.get("Target", "")
        related = list(entry.get("Relate", []))
        prep = [
            normalize_syscall_name(name, context_file)
            for name in subsystem_prep_syscalls(context_file, target_function)
        ]
        prep = [name for name in prep if name and name != target]
        merged_related = []
        for candidate in prep + related:
            if candidate and candidate != target and candidate not in merged_related:
                merged_related.append(candidate)
        merged_related.sort(key=lambda name: _score_syscall_name(name, context), reverse=True)
        merged_related = merged_related[:max_related]
        target_score = _score_syscall_name(target, context) + max(
            (_score_syscall_name(name, context) for name in merged_related),
            default=0,
        )
        scored.append((target_score, {"Target": target, "Relate": merged_related}))

    scored.sort(key=lambda item: item[0], reverse=True)
    narrowed = [entry for _, entry in scored[:max_targets]]

    if hunt_mode == "repro":
        strong = [entry for entry in narrowed if _score_syscall_name(entry["Target"], context) > 0]
        if strong:
            narrowed = strong

    return narrowed


# ──────────────────────────────────────────────────────────────────────────
# Heuristic syscall guessing
# ──────────────────────────────────────────────────────────────────────────

def guess_syscalls(file_path):
    """Heuristic syscall mapping based on kernel source file path.
    Names match syzkaller sys/linux/gen/amd64.go."""
    p = file_path.lower()
    patterns = [
        ("net/sched",     {"Target": "sendmsg$nl_route_sched",
                           "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}),
        ("net/packet",    {"Target": "setsockopt$packet_fanout",
                           "Relate": ["socket$packet", "bind", "close"]}),
        ("net/vmw_vsock", {"Target": "connect$vsock_stream",
                           "Relate": ["socket$vsock_stream", "bind", "listen", "shutdown", "close"]}),
        ("net/",          {"Target": "sendmsg",
                           "Relate": ["socket", "bind", "connect", "close"]}),
        ("drivers/media", {"Target": "ioctl",
                           "Relate": ["openat", "close", "read", "write"]}),
        ("kernel/bpf",    {"Target": "bpf$PROG_LOAD",
                           "Relate": ["bpf", "close"]}),
        ("fs/",           {"Target": "openat",
                           "Relate": ["read", "write", "close", "ioctl"]}),
    ]
    for prefix, entry in patterns:
        if prefix in p:
            return [entry]
    return [{"Target": "ioctl", "Relate": ["openat", "close", "read", "write", "mmap"]}]
