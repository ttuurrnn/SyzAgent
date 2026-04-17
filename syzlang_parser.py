"""
SyzDirect Runner — Syzlang Description Parser.

Parses syzkaller's sys/linux/*.txt description files to extract:
  - resource declarations (resource X[Y])
  - syscall return types and input resource requirements
  - producer/consumer indices

Public API:
  get_db(syz_dir=None) -> SyzlangDB   # cached, call freely
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from paths import FUZZER_DIR, RESOURCE_ROOT

# Primary: the local fuzzer sys/linux (may only have gen/)
# Fallback: deps copy which has full .txt descriptions
_SYZ_DIR_PRIMARY = os.path.join(FUZZER_DIR, "sys", "linux")
_SYZ_DIR_DEPS = os.path.join(
    RESOURCE_ROOT, "..", "..", "deps", "SyzDirect",
    "source", "syzdirect", "syzdirect_fuzzer", "sys", "linux"
)

def _resolve_syz_dir():
    """Return the syzlang sys/linux directory that contains .txt files."""
    for candidate in (_SYZ_DIR_PRIMARY, _SYZ_DIR_DEPS):
        d = os.path.normpath(candidate)
        if os.path.isdir(d) and any(f.endswith(".txt") for f in os.listdir(d)):
            return d
    return _SYZ_DIR_PRIMARY

_SYZ_DIR_DEFAULT = _resolve_syz_dir()

# Module-level cache keyed by syz_dir path
_CACHE: Dict[str, "SyzlangDB"] = {}

# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ResourceDef:
    name: str
    parent: str          # the type inside [...], e.g. "sock_netlink"
    source_file: str


@dataclass
class SyscallDef:
    name: str
    returns: Optional[str]          # resource type returned, or None
    input_resources: List[str]      # resource types consumed as first fd param
    source_file: str


# ─────────────────────────────────────────────────────────────────────────────
# SyzlangDB
# ─────────────────────────────────────────────────────────────────────────────

class SyzlangDB:
    """Container for parsed syzlang resource and syscall information."""

    def __init__(self, syz_dir: str = ""):
        self.syz_dir: str = syz_dir
        self.resources: Dict[str, ResourceDef] = {}
        self.syscalls: Dict[str, SyscallDef] = {}
        # resource_type -> list of syscall names that CREATE this type
        self.producers: Dict[str, List[str]] = {}
        # resource_type -> list of syscall names that CONSUME this type (first fd param)
        self.consumers: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    def get_prerequisites(self, syscall_name: str, max_depth: int = 4) -> List[str]:
        """Return ordered list of prerequisite syscall names for syscall_name.

        BFS traversal of resource dependencies up to max_depth levels.
        Returns syscalls in topological order (outermost dependency first).

        Example:
            get_prerequisites("sendmsg$nl_route_sched")
            → ["socket$nl_route"]
            get_prerequisites("sendmsg$NFT_MSG_NEWRULE")
            → ["socket$nl_netfilter", "sendmsg$NFT_MSG_NEWTABLE", "sendmsg$NFT_MSG_NEWCHAIN"]
        """
        from collections import deque

        def _complexity(s):
            sd = self.syscalls.get(s)
            return len(sd.input_resources) if sd else 0

        def _find_best_producer(rtype):
            producers = self.producers.get(rtype, [])
            if not producers:
                rd = self.resources.get(rtype)
                if rd:
                    producers = self.producers.get(rd.parent, [])
            if not producers:
                return None
            return min(producers, key=_complexity)

        sc = self.syscalls.get(syscall_name)
        if not sc or not sc.input_resources:
            return []

        prereqs: List[str] = []
        seen: set = set()
        queue: deque = deque()

        # Seed the queue with direct dependencies
        for rtype in sc.input_resources:
            best = _find_best_producer(rtype)
            if best and best not in seen:
                seen.add(best)
                queue.append((best, 1))

        while queue:
            current, depth = queue.popleft()
            prereqs.append(current)

            if depth >= max_depth:
                continue

            current_sc = self.syscalls.get(current)
            if not current_sc:
                continue
            for rtype in current_sc.input_resources:
                best = _find_best_producer(rtype)
                if best and best not in seen:
                    seen.add(best)
                    queue.append((best, depth + 1))

        # Reverse so outermost dependencies come first
        prereqs.reverse()
        return prereqs

    # ------------------------------------------------------------------
    def format_for_prompt(self, syscall_name: str) -> str:
        """Return a human-readable dependency summary for LLM prompt injection."""
        sc = self.syscalls.get(syscall_name)
        if not sc:
            return ""

        lines = [f"SYZLANG RESOURCE DEPENDENCIES for {syscall_name}:"]

        if not sc.input_resources:
            lines.append("  (no resource prerequisites)")
            return "\n".join(lines)

        for rtype in sc.input_resources:
            rd = self.resources.get(rtype)
            parent_info = f" (specialization of {rd.parent})" if rd else ""
            lines.append(f"  Required input resource: {rtype}{parent_info}")

            producers = self.producers.get(rtype, [])
            if not producers and rd:
                producers = self.producers.get(rd.parent, [])

            if producers:
                lines.append(f"  Produced by:")
                for p in producers[:3]:
                    p_sc = self.syscalls.get(p)
                    ret_info = f" → {p_sc.returns}" if p_sc and p_sc.returns else ""
                    lines.append(f"    → {p}{ret_info}")
            else:
                lines.append(f"  (no known producer for {rtype})")

        prereqs = self.get_prerequisites(syscall_name)
        if prereqs:
            lines.append("  Prerequisite syscall chain (call in this order):")
            for i, p in enumerate(prereqs, 1):
                lines.append(f"    {i}. {p}")
            lines.append(f"    {len(prereqs) + 1}. {syscall_name}  ← target")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    def extract_type_context(self, syscall_name: str, max_chars: int = 3000) -> str:
        """Extract raw syzlang type definitions relevant to a syscall.

        Reads the .txt file where the syscall is defined, extracts its
        signature and transitively referenced type/union/struct definitions.
        Returns raw syzlang text that an LLM can read directly.
        """
        sc = self.syscalls.get(syscall_name)
        if not sc or not self.syz_dir:
            return ""

        filepath = os.path.join(self.syz_dir, sc.source_file)
        if not os.path.isfile(filepath):
            return ""

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError:
            return ""

        # --- Step 1: Find syscall signature line ---
        sig_line = ""
        for line in all_lines:
            if line.startswith(syscall_name + "("):
                sig_line = line.rstrip()
                break

        if not sig_line:
            return ""

        # --- Step 2: Extract type names referenced in signature ---
        _SYZLANG_KEYWORDS = {
            "ptr", "in", "out", "inout", "flags", "const", "len", "bytesize",
            "bitsize", "array", "string", "int8", "int16", "int32", "int64",
            "intptr", "void", "bool8", "bool16", "bool32", "bool64",
            "resource", "type", "optional", "vma", "proc", "text",
        }
        type_names = set()
        for token in re.findall(r'\b([a-zA-Z_]\w+)\b', sig_line):
            if token not in _SYZLANG_KEYWORDS and not token.startswith("0x"):
                type_names.add(token)
        type_names.discard(syscall_name)
        type_names.discard(syscall_name.split("$")[0])

        # --- Step 3: Extract type definition blocks from file ---
        def _extract_block(start_idx):
            block_lines = [all_lines[start_idx].rstrip()]
            line0 = all_lines[start_idx]
            if "[" in line0 and "]" not in line0:
                for j in range(start_idx + 1, min(start_idx + 60, len(all_lines))):
                    block_lines.append(all_lines[j].rstrip())
                    if all_lines[j].strip().startswith("]"):
                        break
            elif "{" in line0 and "}" not in line0:
                for j in range(start_idx + 1, min(start_idx + 60, len(all_lines))):
                    block_lines.append(all_lines[j].rstrip())
                    if all_lines[j].strip().startswith("}"):
                        break
            return "\n".join(block_lines)

        blocks = {}
        for depth in range(3):  # 3 rounds of transitive expansion
            new_names = set()
            for i, line in enumerate(all_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for tname in list(type_names):
                    if tname in blocks:
                        continue
                    if (stripped.startswith(tname + " [") or
                        stripped.startswith(tname + " {") or
                        stripped.startswith(tname + "\t") or
                        stripped.startswith(f"type {tname}")):
                        block = _extract_block(i)
                        blocks[tname] = block
                        for token in re.findall(r'\b([a-zA-Z_]\w+)\b', block):
                            if (token not in _SYZLANG_KEYWORDS and
                                token not in type_names and
                                token not in blocks and
                                not token.startswith("0x") and
                                len(token) > 3):
                                new_names.add(token)
                        break
            if not new_names:
                break
            type_names.update(new_names)

        if not blocks:
            return ""

        # --- Step 4: Assemble output ---
        parts = [sig_line, ""]
        for name, block in sorted(blocks.items(), key=lambda x: len(x[1]), reverse=True):
            parts.append(block)
            parts.append("")

        result = "\n".join(parts)
        if len(result) > max_chars:
            result = result[:max_chars] + "\n... (truncated)"
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

# Matches: resource sock_nl_route[sock_netlink]
#          resource fd_bpf_map[fd]: BPF_PSEUDO_MAP_FD
_RE_RESOURCE = re.compile(r'^resource\s+(\w+)\s*\[\s*(\w+)\s*\]')

# Matches syscall lines that end with a known identifier (return type candidate):
#   socket$nl_route(domain ..., ...) sock_nl_route
#   bpf$MAP_CREATE(...) fd_bpf_map
# We only trust the return type if it matches a known resource (checked post-parse).
_RE_SYSCALL_RET = re.compile(
    r'^(\w+(?:\$\w+)?)\s*\([^)]*\)\s+(\w+)\s*$'
)

# Matches the first parameter being a resource fd:
#   sendmsg$nl_route_sched(fd sock_nl_route, ...)
#   ioctl$KVM_RUN(fd fd_kvm_vcpu, ...)
_RE_FIRST_PARAM_RESOURCE = re.compile(
    r'^(\w+(?:\$\w+)?)\s*\(\s*(\w+)\s+(\w+)'
)


def _parse_file(filepath: str, db: SyzlangDB) -> None:
    """Parse a single syzlang .txt file into db."""
    fname = os.path.basename(filepath)
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return

    for line in lines:
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue

        # Resource declaration
        m = _RE_RESOURCE.match(line)
        if m:
            name, parent = m.group(1), m.group(2)
            if name not in db.resources:
                db.resources[name] = ResourceDef(
                    name=name, parent=parent, source_file=fname
                )
            continue

        # Syscall with explicit return type on same line
        m = _RE_SYSCALL_RET.match(line)
        if m:
            sc_name, ret_type = m.group(1), m.group(2)
            # We don't know yet if ret_type is a resource — defer validation
            if sc_name not in db.syscalls:
                db.syscalls[sc_name] = SyscallDef(
                    name=sc_name,
                    returns=ret_type,
                    input_resources=[],
                    source_file=fname,
                )
            else:
                # Update return type if not already set
                if db.syscalls[sc_name].returns is None:
                    db.syscalls[sc_name].returns = ret_type
            continue

        # Syscall with resource as first parameter
        m = _RE_FIRST_PARAM_RESOURCE.match(line)
        if m:
            sc_name, param_name, param_type = m.group(1), m.group(2), m.group(3)
            # param_name is typically "fd" — only record if likely a resource fd
            if param_name in ("fd", "sock", "file"):
                if sc_name not in db.syscalls:
                    db.syscalls[sc_name] = SyscallDef(
                        name=sc_name,
                        returns=None,
                        input_resources=[param_type],
                        source_file=fname,
                    )
                elif param_type not in db.syscalls[sc_name].input_resources:
                    db.syscalls[sc_name].input_resources.append(param_type)


def _build_indices(db: SyzlangDB) -> None:
    """Build producers/consumers indices after parsing all files.

    Also prunes return types that aren't real resources (e.g. syscall names
    that happened to match the regex).
    """
    for sc_name, sc in db.syscalls.items():
        # Validate return type against known resources
        if sc.returns and sc.returns not in db.resources:
            sc.returns = None

        # Validate input_resources
        sc.input_resources = [
            r for r in sc.input_resources if r in db.resources
        ]

        # Build producers index
        if sc.returns:
            db.producers.setdefault(sc.returns, [])
            if sc_name not in db.producers[sc.returns]:
                db.producers[sc.returns].append(sc_name)

        # Build consumers index
        for rtype in sc.input_resources:
            db.consumers.setdefault(rtype, [])
            if sc_name not in db.consumers[rtype]:
                db.consumers[rtype].append(sc_name)


def parse_syzlang_dir(syz_dir: Optional[str] = None) -> SyzlangDB:
    """Parse all *.txt files in syz_dir and return a SyzlangDB.

    First call takes ~1-2 seconds for ~100 files. Use get_db() for caching.
    """
    syz_dir = syz_dir or _SYZ_DIR_DEFAULT
    db = SyzlangDB(syz_dir=syz_dir or _SYZ_DIR_DEFAULT)

    if not os.path.isdir(syz_dir):
        return db

    for fname in sorted(os.listdir(syz_dir)):
        if not fname.endswith(".txt"):
            continue
        _parse_file(os.path.join(syz_dir, fname), db)

    _build_indices(db)
    return db


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_db(syz_dir: Optional[str] = None) -> SyzlangDB:
    """Return a cached SyzlangDB for syz_dir (parses on first call)."""
    key = syz_dir or _SYZ_DIR_DEFAULT
    if key not in _CACHE:
        _CACHE[key] = parse_syzlang_dir(syz_dir)
    return _CACHE[key]
