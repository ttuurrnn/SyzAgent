"""
SyzDirect Runner — syscall name normalization.

Loads syzkaller call names from the generated amd64 syscall table and
provides best-effort normalization from heuristic/LLM-suggested names
to valid syzkaller names.
"""

import os
import re

from paths import FUZZER_DIR


# ──────────────────────────────────────────────────────────────────────────
# Syzkaller call name cache
# ──────────────────────────────────────────────────────────────────────────

_SYZCALL_NAME_CACHE = None


def load_syzkaller_call_names(fuzzer_dir=None):
    """Load syzkaller call names from the generated amd64 syscall table once."""
    global _SYZCALL_NAME_CACHE
    if _SYZCALL_NAME_CACHE is not None:
        return _SYZCALL_NAME_CACHE

    fuzzer_dir = fuzzer_dir or FUZZER_DIR
    amd64_gen = os.path.join(fuzzer_dir, "sys", "linux", "gen", "amd64.go")
    names = set()
    call_re = re.compile(r'Name:"([^"]+)"')
    if os.path.exists(amd64_gen):
        with open(amd64_gen, errors="replace") as f:
            for line in f:
                m = call_re.search(line)
                if m:
                    names.add(m.group(1))
    _SYZCALL_NAME_CACHE = names
    return names


# ──────────────────────────────────────────────────────────────────────────
# Single-name normalization
# ──────────────────────────────────────────────────────────────────────────

def normalize_syscall_name(name, context_file=""):
    """Best-effort normalization from heuristic names to actual syzkaller names."""
    if not name:
        return None

    call_names = load_syzkaller_call_names()
    if name in call_names:
        return name

    base = name.split("$", 1)[0]
    suffix = name.split("$", 1)[1] if "$" in name else ""

    preferred_aliases = {
        "connect$vsock": "connect$vsock_stream",
        "bind$vsock": "bind$vsock_stream",
        "accept4$vsock": "accept4$vsock_stream",
        "socket$vsock": "socket$vsock_stream",
        "connect$mptcp": "connect",
        "setsockopt$mptcp": "setsockopt",
    }
    if name in preferred_aliases and preferred_aliases[name] in call_names:
        return preferred_aliases[name]

    if base == "io_uring_register":
        preferred = "io_uring_register$IORING_REGISTER_EVENTFD" if "eventfd" in (context_file or "").lower() \
            else "io_uring_register$IORING_REGISTER_FILES"
        if preferred in call_names:
            return preferred

    if base in call_names:
        return base

    candidates = sorted(n for n in call_names if n.startswith(base + "$"))
    if not candidates:
        return None

    preferred_suffixes = {
        "connect": ["vsock_stream", "inet6", "inet"],
        "bind": ["vsock_stream", "inet6", "inet"],
        "accept4": ["vsock_stream", "inet6", "inet"],
        "socket": ["vsock_stream", "inet_mptcp", "inet6_mptcp", "inet", "inet6"],
        "io_uring_register": ["IORING_REGISTER_EVENTFD", "IORING_REGISTER_FILES"],
    }
    for suffix_hint in preferred_suffixes.get(base, []):
        for candidate in candidates:
            if candidate.endswith("$" + suffix_hint):
                return candidate

    if suffix:
        for candidate in candidates:
            if suffix in candidate:
                return candidate

    return candidates[0]


# ──────────────────────────────────────────────────────────────────────────
# Callfile-level normalization
# ──────────────────────────────────────────────────────────────────────────

def normalize_callfile_entries(entries, context_file=""):
    """Normalize a callfile to syzkaller-recognized syscall names."""
    normalized = []
    seen = set()

    for entry in entries:
        target = normalize_syscall_name(entry.get("Target", ""), context_file)
        if not target:
            continue

        related = []
        for name in entry.get("Relate", []):
            resolved = normalize_syscall_name(name, context_file)
            if resolved and resolved != target and resolved not in related:
                related.append(resolved)

        if "mptcp" in entry.get("Target", "").lower():
            for helper in ["socket$inet_mptcp", "socket$inet6_mptcp"]:
                if helper in load_syzkaller_call_names() and helper not in related and helper != target:
                    related.insert(0, helper)
        if "vsock" in entry.get("Target", "").lower() or "vsock" in " ".join(entry.get("Relate", [])).lower():
            helper = "socket$vsock_stream"
            if helper in load_syzkaller_call_names() and helper not in related and helper != target:
                related.insert(0, helper)

        key = (target, tuple(related))
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"Target": target, "Relate": related})

    return normalized
