"""
SyzDirect Runner — LLM-driven syscall analysis and distance roadmap.

Handles all LLM interactions: CVE-based syscall suggestion, distance
roadmap extraction from .dist files, kernel source reading for
stepping-stone functions, and LLM-driven callfile enhancement when
the fuzzer's distance stagnates.
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import re

from syscall_normalize import load_syzkaller_call_names, normalize_syscall_name
from syzlang_parser import get_db as _get_syzlang_db


def _edit_distance(a, b):
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _fuzzy_kind_match(target_kind, all_kinds):
    """Find a kind in all_kinds within edit distance 2 of target_kind."""
    for k in all_kinds:
        if _edit_distance(k, target_kind) <= 2:
            return target_kind  # target_kind is the canonical name
    return None


# ──────────────────────────────────────────────────────────────────────────
# LLM backend — ollama (local) with opencode fallback
# ──────────────────────────────────────────────────────────────────────────

_OLLAMA_MODEL = os.environ.get("SYZDIRECT_LLM_MODEL", "qwen2.5-coder:14b")
_OLLAMA_URL = os.environ.get("SYZDIRECT_OLLAMA_URL", "http://localhost:11434")


def _call_llm(prompt, timeout=180):
    """Call LLM via claude CLI (primary) or ollama (fallback). Returns response text or None."""
    import urllib.request
    import urllib.error

    # Try claude CLI first (highest quality)
    claude_bin = shutil.which("claude")
    if claude_bin:
        try:
            proc = subprocess.Popen(
                [claude_bin, "--print", "--model", "sonnet"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(input=prompt, timeout=timeout)
            except subprocess.TimeoutExpired:
                import signal
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=5)
                print(f"  [LLM] claude timed out after {timeout}s")
                stdout = None
                stderr = None
            if stdout and stdout.strip():
                text = stdout.strip()
                print(f"  [LLM] claude responded ({len(text)} chars)")
                return text
            elif proc.returncode != 0:
                print(f"  [LLM] claude failed (rc={proc.returncode}): {(stderr or '')[:200]}")
        except (FileNotFoundError, OSError) as e:
            print(f"  [LLM] claude error: {e}")

    # Fallback to ollama (local)
    try:
        req_data = json.dumps({
            "model": _OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_URL}/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
            text = result.get("response", "")
            if text:
                print(f"  [LLM] ollama responded ({len(text)} chars)")
                return text
    except urllib.error.URLError as e:
        print(f"  [LLM] ollama unavailable: {e}")
    except Exception as e:
        print(f"  [LLM] ollama error: {e}")

    return None


# ──────────────────────────────────────────────────────────────────────────
# LLM-based CVE analysis
# ──────────────────────────────────────────────────────────────────────────

def llm_analyze_cve(cve_id, kernel_commit, target_function, file_path):
    """Ask LLM for syzkaller syscall suggestions. Returns dict or None."""
    prompt = (
        "You are a Linux kernel security researcher.\n"
        f"CVE: {cve_id}\nKernel commit: {kernel_commit}\n"
        f"Target function: {target_function}\nFile: {file_path}\n\n"
        "Suggest the most relevant syzkaller syscalls to reach this function.\n"
        "Return ONLY valid JSON:\n"
        '{"syscalls": [{"Target": "name$variant", "Relate": ["setup1", "setup2"]}]}\n'
        "Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, "
        "bpf$PROG_LOAD, connect$vsock_stream). 1-3 Target entries, 3-6 Relate each."
    )
    try:
        text = _call_llm(prompt, timeout=120)
        if text:
            start, end = text.find("{"), text.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
    except json.JSONDecodeError as e:
        print(f"  [LLM] JSON parse error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# Distance roadmap extraction
# ──────────────────────────────────────────────────────────────────────────

# Function name prefixes that are noise (tracepoints, debug helpers)
_NOISE_PREFIXES = (
    "__traceiter_", "__trace_", "trace_", "perf_trace_",
    "decompress_", "early_", "__pfx_",
)

_TC_KIND_PREFIXES = {
    "tcindex": "tcindex",
    "tbf": "tbf",
    "pfifo": "pfifo",
    "bfifo": "bfifo",
    "htb": "htb",
    "hfsc": "hfsc",
    "sfq": "sfq",
    "fq_codel": "fq_codel",
    "codel": "codel",
    "netem": "netem",
    "cbq": "cbq",
    "qfq": "qfq",
    "cls_u32": "u32",
    "u32": "u32",
    "fl_": "flower",
    "flower": "flower",
    "mall_": "matchall",
    "matchall": "matchall",
    "basic_": "basic",
    "bpf": "bpf",
    "route4_": "route4",
    "fw_": "fw",
}

_TC_FILTER_KINDS = {
    "tcindex", "u32", "flower", "matchall", "basic", "bpf", "route4", "fw",
}
_TC_QDISC_KINDS = {
    "tbf", "pfifo", "bfifo", "htb", "hfsc", "sfq", "fq_codel", "codel",
    "netem", "cbq", "qfq", "prio", "ingress", "clsact",
}


def _tc_kind_from_token(token):
    token = (token or "").lower()
    for prefix, kind in _TC_KIND_PREFIXES.items():
        if token.startswith(prefix) or f"_{prefix}" in token:
            return kind
    return None


def _add_kind_score(scores, kind, weight, reason):
    if not kind:
        return
    current = scores.setdefault(kind, {"score": 0, "reasons": []})
    current["score"] += weight
    current["reasons"].append(reason)


def _infer_type_from_kind_candidates(kind_candidates):
    if not kind_candidates:
        return None
    top_kind = kind_candidates[0][0]
    if top_kind in _TC_FILTER_KINDS:
        return "filter"
    if top_kind in _TC_QDISC_KINDS:
        return "qdisc"
    return None


def _build_target_seed_profile(roadmap, target_function, target_file, source_snippets=""):
    """Infer a reusable seed profile from structural signals, not case ids."""
    if "net/sched" not in (target_file or ""):
        return {
            "target_type": "unknown",
            "target_kind": None,
            "kind_candidates": [],
            "prefer_multi_stage": False,
            "avoid_ops": set(),
            "prefer_explicit_handle": False,
            "snippet_type": None,
        }

    target_type = _detect_tc_target_type(target_file)
    snippet_type = _detect_tc_target_type_from_snippets(source_snippets)
    if snippet_type and snippet_type != target_type:
        target_type = snippet_type

    scores = {}
    basename = os.path.basename(target_file or "")
    m = re.match(r'cls_(\w+)\.c', basename)
    if m and m.group(1) not in {"api", "route"}:
        _add_kind_score(scores, _tc_kind_from_token(os.path.splitext(basename)[0]), 5, "target_file")
    m = re.match(r'sch_(\w+)\.c', basename)
    if m and m.group(1) not in {"api", "generic"}:
        _add_kind_score(scores, _tc_kind_from_token(os.path.splitext(basename)[0]), 4, "target_file")

    for fn in [target_function]:
        _add_kind_score(scores, _tc_kind_from_token(fn), 5, "target_function")

    for fn in (roadmap or {}).get("actual_callers", []) or []:
        _add_kind_score(scores, _tc_kind_from_token(str(fn)), 8, "actual_caller")

    for caller in (roadmap or {}).get("cross_file_callers", []) or []:
        fn = caller.get("function") if isinstance(caller, dict) else str(caller)
        _add_kind_score(scores, _tc_kind_from_token(fn), 5, "cross_file_caller")

    for stone in (roadmap or {}).get("stepping_stones", []) or []:
        weight = 6 if stone.get("is_caller") else 3
        _add_kind_score(scores, _tc_kind_from_token(stone.get("function", "")), weight, "roadmap")

    # Semantic context and injected caller snippets often contain the true
    # dispatch function for generic files such as cls_api.c.
    for tok in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', source_snippets or ""):
        _add_kind_score(scores, _tc_kind_from_token(tok), 1, "source_snippet")

    kind_candidates = sorted(
        ((kind, data["score"], data["reasons"]) for kind, data in scores.items()),
        key=lambda item: (-item[1], item[0]),
    )

    if target_type == "unknown":
        inferred = _infer_type_from_kind_candidates(kind_candidates)
        if inferred:
            target_type = inferred

    terms = [target_function.lower()]
    terms.extend(str(fn).lower() for fn in (roadmap or {}).get("actual_callers", []) or [])
    terms.extend((s.get("function", "") or "").lower() for s in (roadmap or {}).get("stepping_stones", [])[:5])
    prefer_multi_stage = any(
        any(tok in term for tok in ("change", "update", "replace", "modify", "alloc", "set_parms"))
        for term in terms
    )
    if target_type == "qdisc" and kind_candidates and kind_candidates[0][0] == "tbf":
        prefer_multi_stage = True

    return {
        "target_type": target_type,
        "target_kind": kind_candidates[0][0] if kind_candidates else None,
        "kind_candidates": kind_candidates,
        "prefer_multi_stage": prefer_multi_stage,
        "avoid_ops": {0x29, 0x2d},
        "prefer_explicit_handle": target_type in {"filter", "action"},
        "snippet_type": snippet_type,
    }


def _parse_detail_corpus(detail_corpus_path):
    """Parse detailCorpus.txt (JSON format) into list of (program_text, distance).

    detailCorpus.txt contains concatenated JSON objects:
      {"Uptime": "0s", "Prog": "socket$nl_route(...)\\n", "Dist": 1030}
      {"Uptime": "0s", "Prog": "close(...)\\n", "Dist": 4010}
    """
    results = []
    if not detail_corpus_path or not os.path.exists(detail_corpus_path):
        return results
    try:
        with open(detail_corpus_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        # Split on }{ boundaries (concatenated JSON objects)
        import re as _re
        # Find each JSON object
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(content):
            # Skip whitespace
            while pos < len(content) and content[pos] in ' \t\n\r':
                pos += 1
            if pos >= len(content):
                break
            try:
                obj, end_pos = decoder.raw_decode(content, pos)
                prog = obj.get("Prog", "").strip()
                dist = obj.get("Dist")
                if prog and dist is not None and isinstance(dist, (int, float)) and dist > 0:
                    results.append((prog, int(dist)))
                pos = end_pos
            except (json.JSONDecodeError, ValueError):
                pos += 1
    except OSError:
        pass
    return results


def extract_closest_program(workdir, syz_db_path, detail_corpus_path=None):
    """Extract the program that achieved the minimum distance from corpus.db.

    Parses detailCorpus.txt to find the program with the lowest distance.
    Returns the program text directly from detailCorpus (no unpack needed
    since detailCorpus already contains program text).

    Returns: (program_text, distance) or (None, None) if extraction fails.
    """
    entries = _parse_detail_corpus(detail_corpus_path)
    if entries:
        entries.sort(key=lambda x: x[1])
        return entries[0]  # (prog_text, dist)

    # Fallback: unpack corpus.db and return first program
    corpus_db = os.path.join(workdir, "corpus.db")
    if not os.path.exists(corpus_db):
        return None, None

    syz_db = syz_db_path if (syz_db_path and os.path.exists(syz_db_path)) else shutil.which("syz-db")
    if not syz_db:
        return None, None

    unpack_dir = tempfile.mkdtemp(prefix="syz_corpus_")
    try:
        result = subprocess.run(
            [syz_db, "unpack", corpus_db, unpack_dir],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None, None
        prog_files = os.listdir(unpack_dir)
        if not prog_files:
            return None, None
        with open(os.path.join(unpack_dir, prog_files[0])) as f:
            return f.read().strip(), None
    except Exception:
        return None, None
    finally:
        shutil.rmtree(unpack_dir, ignore_errors=True)


def _program_shape_score(program_text, profile):
    if not profile:
        return 0, []
    analysis = _analyze_seed_program(program_text)
    score = 0
    reasons = []
    if analysis["has_route_socket"]:
        score += 1
        reasons.append("route_socket")
    if analysis["sendmsg_sched_count"]:
        score += 2
        reasons.append("sched_sendmsg")
    messages = analysis["messages"]
    nl_types = [m["nl_type"] for m in messages]
    all_kinds = [kind for m in messages for kind in m["kinds"]]
    target_type = profile.get("target_type")
    if target_type == "filter" and 0x24 in nl_types and 0x2C in nl_types:
        score += 3
        reasons.append("qdisc_then_filter")
    elif target_type == "qdisc" and 0x24 in nl_types:
        score += 3
        reasons.append("qdisc_msg")
    elif target_type == "action" and 0x24 in nl_types and 0x2C in nl_types:
        score += 2
        reasons.append("action_prereq_shape")

    for idx, (kind, weight, _why) in enumerate(profile.get("kind_candidates", [])[:5]):
        if kind in all_kinds:
            score += max(1, min(4, int(weight)))
            reasons.append(f"kind={kind}")
            break
        if _fuzzy_kind_match(kind, all_kinds):
            score += 1
            reasons.append(f"kind~{kind}")
            break
        # Do not let weak lower-ranked candidates dominate exact shape.
        if idx >= 2:
            break

    if profile.get("kind_candidates") and messages and not any(r.startswith("kind") for r in reasons):
        return 0, ["kind_mismatch"]

    if profile.get("prefer_multi_stage"):
        if target_type == "qdisc" and len([m for m in messages if m["nl_type"] in {0x24, 0x25}]) >= 2:
            score += 3
            reasons.append("multi_stage_qdisc")
        elif target_type in {"filter", "action"} and len([m for m in messages if m["nl_type"] == 0x2C]) >= 1 and 0x24 in nl_types:
            score += 2
            reasons.append("stateful_filter_setup")
    return score, reasons


def extract_closest_programs(workdir, syz_db_path, detail_corpus_path=None,
                             max_programs=20, dist_threshold=None,
                             target_profile=None, min_shape_score=0):
    """Extract the N closest programs from detailCorpus.txt ordered by distance.

    Returns list of (program_text, distance) tuples, sorted by distance ascending.
    If dist_threshold is set, only returns programs with dist <= threshold.
    """
    entries = _parse_detail_corpus(detail_corpus_path)
    if not entries:
        return []

    if dist_threshold is not None:
        entries = [(p, d) for p, d in entries if d <= dist_threshold]

    # Deduplicate by program text
    seen = set()
    unique = []
    for prog, dist in entries:
        if prog not in seen:
            seen.add(prog)
            unique.append((prog, dist))
    entries = unique

    if target_profile:
        shaped = []
        for prog, dist in entries:
            shape_score, shape_reasons = _program_shape_score(prog, target_profile)
            if shape_score >= min_shape_score:
                shaped.append((prog, dist, shape_score, shape_reasons))
        shaped.sort(key=lambda x: (x[1], -x[2]))
        return [(prog, dist) for prog, dist, _score, _reasons in shaped[:max_programs]]

    entries.sort(key=lambda x: x[1])
    return entries[:max_programs]


def pack_programs_to_corpus(programs_text_list, syz_db_path, output_path):
    """Pack a list of program text strings into a corpus.db file.

    Args:
        programs_text_list: list of syzkaller program text strings
        syz_db_path: path to syz-db binary
        output_path: path for the output corpus.db

    Returns: output_path on success, None on failure.
    """
    if not programs_text_list or not syz_db_path:
        return None

    pack_dir = tempfile.mkdtemp(prefix="syz_pack_")
    try:
        for i, prog in enumerate(programs_text_list):
            with open(os.path.join(pack_dir, f"prog_{i:04d}"), "w") as f:
                f.write(prog)

        result = subprocess.run(
            [syz_db_path, "pack", pack_dir, output_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and os.path.exists(output_path):
            return output_path
        return None
    except Exception:
        return None
    finally:
        shutil.rmtree(pack_dir, ignore_errors=True)


def _dist_files_for_target(dist_dir, target_file):
    """Return the set of dist file names relevant to target_file.

    Strategy (ordered by priority):
    1. The dist file that directly corresponds to target_file
       (e.g. "net/sched/sch_fifo.c" → "net-sched-sch_fifo.dist")
    2. All dist files in the same subsystem directory
       (same prefix up to the last path component, e.g. "net-sched-*")

    This avoids reading thousands of unrelated dist files (e.g. InfiniBand
    when the target is in net/sched) and prevents bogus stepping stones.

    Returns a set of basenames (may be empty, caller falls back to all files).
    """
    if not target_file:
        return set()
    # Strip leading slash and normalise
    tf = target_file.lstrip("/")
    # Remove .c extension
    if tf.endswith(".c"):
        tf = tf[:-2]
    # Convert path separators to dashes
    stem = tf.replace("/", "-")
    primary = stem + ".dist"

    # Subsystem prefix: everything up to (not including) the last component
    # e.g. "net-sched-sch_fifo" → prefix "net-sched-"
    last_dash = stem.rfind("-")
    if last_dash > 0:
        prefix = stem[:last_dash + 1]  # e.g. "net-sched-"
    else:
        prefix = stem  # single-component path, just use the stem itself

    result = set()
    try:
        for fname in os.listdir(dist_dir):
            if not fname.endswith(".dist"):
                continue
            if fname == primary or fname.startswith(prefix):
                result.add(fname)
    except OSError:
        pass
    return result


def extract_distance_roadmap(dist_dir, target_function, current_dist_min,
                             k2s_path=None, max_stones=12, src_dir=None,
                             target_file=None):
    """Build a stepping-stone roadmap from .dist files.

    Returns a dict with target info and a list of intermediate functions
    sorted by distance (ascending, closest to target first).

    Args:
        target_file: Source file path of the target (e.g. "net/sched/sch_fifo.c").
            When provided, only the dist file for that source file plus files in
            the same subsystem directory are read.  This prevents unrelated
            subsystems (e.g. InfiniBand when targeting net/sched) from
            polluting the roadmap with bogus stepping stones.
    """
    if not os.path.isdir(dist_dir):
        return None

    # Determine which dist files to read.
    # If target_file is given, restrict to the target's own dist file and
    # same-subsystem files.  Fall back to all files only when no match found.
    candidate_files = _dist_files_for_target(dist_dir, target_file)
    all_fnames = [f for f in os.listdir(dist_dir) if f.endswith(".dist")]
    if candidate_files:
        fnames_to_read = [f for f in all_fnames if f in candidate_files]
        if not fnames_to_read:
            # Derived name didn't match anything — fall back to all files
            fnames_to_read = all_fnames
    else:
        fnames_to_read = all_fnames

    # Parse selected .dist files: collect min distance per function
    func_min_dist = {}
    for fname in fnames_to_read:
        fpath = os.path.join(dist_dir, fname)
        try:
            with open(fpath) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    fn, _blk, dist_s = parts[0], parts[1], parts[2]
                    dist = int(dist_s)
                    if fn not in func_min_dist or dist < func_min_dist[fn]:
                        func_min_dist[fn] = dist
        except (OSError, ValueError):
            continue

    # Filter to stepping stones: 0 < dist <= current_dist_min
    # Using <= instead of < so that functions at the SAME distance as
    # current best (i.e., the actual callers of the target) are included.
    # This is critical for cross-file call chains where the caller lives
    # in a different .dist file (e.g., tbf_change calls fifo_set_limit).
    stones = []
    for fn, d in func_min_dist.items():
        if 0 < d <= current_dist_min and fn != target_function:
            stones.append({"function": fn, "distance": d})

    # Filter out noise
    stones = [s for s in stones if not any(
        s["function"].startswith(p) for p in _NOISE_PREFIXES
    )]

    # Find actual callers of the target function in kernel source.
    # Functions that directly call the target are the most important
    # stepping stones, regardless of which .dist file they live in.
    actual_callers = set()
    # Determine source directory
    _src_candidates = []
    if src_dir:
        _src_candidates.append(src_dir)
    _src_candidates.append(os.path.join(os.path.dirname(dist_dir), "..", "srcs",
                                         os.path.basename(os.path.dirname(dist_dir))))
    _src_candidates.append(os.path.join(os.path.dirname(os.path.dirname(dist_dir)), "srcs",
                                         os.path.basename(os.path.dirname(dist_dir))))
    for _try_src in _src_candidates:
        if os.path.isdir(_try_src):
            try:
                result = subprocess.run(
                    ["grep", "-rn", f"\\b{target_function}\\b", "--include=*.c",
                     _try_src],
                    capture_output=True, text=True, timeout=15,
                )
                if result.stdout:
                    for line in result.stdout.strip().split("\n"):
                        # Lines calling the function (not defining it)
                        # Heuristic: contains target_function( and is not a definition
                        if f"{target_function}(" in line and not line.strip().startswith(("//", "*", "/*")):
                            # Extract the containing function name from the file
                            # by finding what function scope this line is in
                            parts = line.split(":")
                            if len(parts) >= 3:
                                filepath = parts[0]
                                lineno = int(parts[1])
                                # Read surrounding lines to find enclosing function
                                try:
                                    with open(filepath) as _f:
                                        all_lines = _f.readlines()
                                    # Scan backwards for function definition
                                    import re
                                    for back in range(lineno - 2, max(0, lineno - 120), -1):
                                        l = all_lines[back]
                                        # Match C function definitions, handling
                                        # qualifiers like static/inline/etc:
                                        #   static int foo(
                                        #   void *bar(
                                        #   static noinline int baz(
                                        m = re.match(
                                            r'^(?:static\s+|inline\s+|noinline\s+|__always_inline\s+)*'
                                            r'(?:\w+\s+\**)*?(\w+)\s*\(',
                                            l,
                                        )
                                        if m:
                                            caller_fn = m.group(1)
                                            _skip = ('if', 'while', 'for', 'switch',
                                                     'return', 'sizeof', 'typeof',
                                                     'EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL')
                                            if caller_fn in _skip or caller_fn == target_function:
                                                break
                                            if caller_fn in func_min_dist:
                                                actual_callers.add(caller_fn)
                                            else:
                                                # Intermediate static function not in .dist;
                                                # record it anyway as it's still a caller
                                                actual_callers.add(caller_fn)
                                            break
                                except (OSError, ValueError):
                                    pass
            except (subprocess.TimeoutExpired, OSError):
                pass
            break  # found src dir

    # Sort: prioritize actual callers > same-prefix functions > by distance
    target_prefix = target_function.split("_")[0] if "_" in target_function else ""

    def _stone_sort_key(s):
        fn = s["function"]
        is_caller = 0 if fn in actual_callers else 1
        related = 0 if (target_prefix and target_prefix in fn) else 1
        return (is_caller, related, s["distance"])
    stones.sort(key=_stone_sort_key)

    if actual_callers:
        # Tag caller stones
        for s in stones:
            if s["function"] in actual_callers:
                s["is_caller"] = True

    # Sample: keep closest stones + evenly spaced rest
    if len(stones) > max_stones:
        top = stones[:4]
        rest = stones[4:]
        step = len(rest) / (max_stones - 4)
        sampled = [rest[int(i * step)] for i in range(max_stones - 4)]
        stones = top + sampled

    # Annotate with reachable syscalls from k2s
    if k2s_path and os.path.exists(k2s_path):
        try:
            with open(k2s_path) as f:
                k2s = json.load(f)
            for stone in stones:
                raw = k2s.get(stone["function"], [])
                if isinstance(raw, dict):
                    syscalls = list({s for bb_syscalls in raw.values() for s in bb_syscalls})
                else:
                    syscalls = list(raw)
                stone["reachable_via"] = syscalls[:5] if syscalls else []
        except (OSError, json.JSONDecodeError):
            pass

    # Identify likely direct callers: functions whose min dist is close to
    # current_dist_min (within one callgraph hop = 1000) and that appear in
    # a DIFFERENT .dist file than the target.  These are cross-file callers
    # that the stepping stone sort might deprioritize.
    target_dist_file = None
    for fname in os.listdir(dist_dir):
        if not fname.endswith(".dist"):
            continue
        fpath = os.path.join(dist_dir, fname)
        try:
            with open(fpath) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == target_function:
                        target_dist_file = fname
                        break
        except OSError:
            continue
        if target_dist_file:
            break

    cross_file_callers = []
    if target_dist_file:
        for fname in os.listdir(dist_dir):
            if not fname.endswith(".dist") or fname == target_dist_file:
                continue
            # Restrict to same-subsystem files when target_file was provided.
            # This prevents unrelated subsystems (e.g. InfiniBand when target
            # is in net/sched) from injecting bogus cross-file callers.
            if candidate_files and fname not in candidate_files:
                continue
            fpath = os.path.join(dist_dir, fname)
            try:
                file_funcs = {}
                with open(fpath) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        fn, d = parts[0], int(parts[2])
                        if fn not in file_funcs or d < file_funcs[fn]:
                            file_funcs[fn] = d
                # A cross-file caller has dist close to target's dist
                # (within ~1 hop = typically 10-1000)
                for fn, d in file_funcs.items():
                    if 0 < d <= current_dist_min and fn != target_function:
                        cross_file_callers.append({
                            "function": fn, "distance": d,
                            "dist_file": fname,
                        })
            except (OSError, ValueError):
                continue
        # Sort by distance, keep closest
        cross_file_callers.sort(key=lambda x: x["distance"])
        cross_file_callers = cross_file_callers[:5]

    # Ensure cross-file callers are in stones (they may have been filtered)
    stone_names = {s["function"] for s in stones}
    for caller in cross_file_callers:
        if caller["function"] not in stone_names:
            stones.insert(0, {
                "function": caller["function"],
                "distance": caller["distance"],
            })

    return {
        "target_function": target_function,
        "current_dist_min": current_dist_min,
        "stepping_stones": stones,
        "cross_file_callers": cross_file_callers,
        "actual_callers": sorted(actual_callers) if actual_callers else [],
        "total_functions_in_range": len([
            fn for fn, d in func_min_dist.items()
            if 0 < d <= current_dist_min
        ]),
    }


# ──────────────────────────────────────────────────────────────────────────
# Kernel source reading for stepping stones
# ──────────────────────────────────────────────────────────────────────────

def reverse_trace_bottleneck(src_dir, bottleneck_func, k2s_path=None, max_depth=2):
    """Trace callers of the bottleneck function to find syscall entry points.

    Searches kernel source for functions that call bottleneck_func,
    then traces their callers (up to max_depth levels), and maps
    to syscalls via k2s if available.

    Returns a text summary like:
      "To reach bottleneck_func:
       ← called by caller_A (in net/foo.c:123)
         ← called by caller_B (in net/foo.c:456)
           ← reachable via: socket$inet_tcp, setsockopt$..."
    """
    if not os.path.isdir(src_dir):
        return ""

    k2s = {}
    if k2s_path and os.path.exists(k2s_path):
        try:
            with open(k2s_path) as f:
                k2s = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass

    def _find_callers(func_name):
        """Find functions that call func_name in the kernel source."""
        try:
            result = subprocess.run(
                ["grep", "-rn", f"\\b{func_name}\\s*(", "--include=*.c", src_dir],
                capture_output=True, text=True, timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []

        callers = []
        seen = set()
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            # Skip the function's own definition
            if f"{func_name}(" in line and (
                line.strip().startswith("static") or
                line.strip().startswith("int") or
                line.strip().startswith("void") or
                line.strip().startswith("struct") or
                line.strip().startswith("long") or
                line.strip().startswith("unsigned") or
                line.strip().startswith("bool") or
                line.strip().startswith("ssize_t") or
                line.strip().startswith("__")
            ):
                # Likely a definition, try to extract the defining function name
                # but we want callers, not definitions — skip lines that look
                # like function signatures (return_type func_name(...)
                parts = line.split(":")
                if len(parts) >= 3:
                    code = ":".join(parts[2:]).strip()
                    # If the function name IS at the start, it's a definition
                    tokens = code.split()
                    if len(tokens) >= 2 and func_name in tokens[1]:
                        continue

            # Extract caller file:line
            parts = line.split(":")
            if len(parts) < 3:
                continue
            filepath = parts[0]
            try:
                lineno = int(parts[1])
            except ValueError:
                continue

            # Try to find the enclosing function name
            try:
                with open(filepath) as f:
                    lines = f.readlines()
                # Search backward for function definition
                for i in range(lineno - 1, max(0, lineno - 50), -1):
                    l = lines[i]
                    # Simple heuristic: line starting with non-space, contains '('
                    if l and not l[0].isspace() and '(' in l and '{' in l:
                        caller_name = l.split('(')[0].split()[-1] if l.split('(')[0].split() else None
                        if caller_name and caller_name != func_name and caller_name not in seen:
                            seen.add(caller_name)
                            rel_path = os.path.relpath(filepath, src_dir)
                            callers.append({
                                "function": caller_name,
                                "file": rel_path,
                                "line": lineno,
                            })
                        break
            except OSError:
                continue

            if len(callers) >= 5:
                break
        return callers

    lines = [f"Reverse trace for bottleneck: {bottleneck_func}"]
    current_funcs = [bottleneck_func]

    for depth in range(max_depth):
        next_funcs = []
        for func in current_funcs:
            callers = _find_callers(func)
            for caller in callers:
                prefix = "  " * (depth + 1)
                raw = k2s.get(caller["function"], [])
                if isinstance(raw, dict):
                    syscalls = list({s for bb_syscalls in raw.values() for s in bb_syscalls})
                else:
                    syscalls = list(raw)
                line = f"{prefix}← {caller['function']} ({caller['file']}:{caller['line']})"
                if syscalls:
                    line += f"  [reachable via: {', '.join(syscalls[:5])}]"
                lines.append(line)
                next_funcs.append(caller["function"])
        current_funcs = next_funcs[:3]  # limit branching

    return "\n".join(lines) if len(lines) > 1 else ""


_DEFINITION_PREFIXES = (
    "static", "int", "void", "struct", "long", "unsigned", "bool",
    "ssize_t", "__", "noinline", "inline", "const", "char", "u8", "u16",
    "u32", "u64", "s32", "s64", "size_t",
)

_CONDITION_RE = re.compile(r'^\s*(if|switch|while|for)\s*\(')


def _extract_caller_conditions(src_dir, func_name, max_callers=3, look_back=30):
    """Find callers of func_name and extract pre-call condition blocks.

    For each caller site, scans up to look_back lines before the call and
    extracts if/switch/while/for blocks that guard the call.

    Returns:
        list of {"caller_file": str, "caller_line": int, "conditions": [str]}
    """
    if not os.path.isdir(src_dir):
        return []

    try:
        result = subprocess.run(
            ["grep", "-rn", f"\\b{func_name}\\s*(", "--include=*.c", src_dir],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    caller_results = []
    seen_files = set()

    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        filepath = parts[0]
        try:
            lineno = int(parts[1])
        except ValueError:
            continue

        # Skip definition lines
        code = ":".join(parts[2:]).strip()
        if code.startswith(_DEFINITION_PREFIXES):
            tokens = code.split()
            if len(tokens) >= 2 and func_name in tokens[1]:
                continue

        if filepath in seen_files:
            continue
        seen_files.add(filepath)

        try:
            with open(filepath) as f:
                file_lines = f.readlines()
        except OSError:
            continue

        rel_path = os.path.relpath(filepath, src_dir)
        conditions = []
        seen_conds = set()

        # Scan backwards from call site
        scan_start = max(0, lineno - look_back - 1)
        for i in range(lineno - 2, scan_start, -1):
            raw = file_lines[i]
            if not _CONDITION_RE.match(raw):
                continue
            # Collect condition block (until braces balance or max 10 lines)
            block_lines = [raw.rstrip()]
            depth = raw.count("{") - raw.count("}")
            j = i + 1
            while depth > 0 and j < lineno - 1 and (j - i) < 10:
                block_lines.append(file_lines[j].rstrip())
                depth += file_lines[j].count("{") - file_lines[j].count("}")
                j += 1
            block_text = "\n".join(block_lines)
            if block_text not in seen_conds:
                seen_conds.add(block_text)
                conditions.append(block_text)

        if conditions:
            caller_results.append({
                "caller_file": rel_path,
                "caller_line": lineno,
                "conditions": conditions,
            })

        if len(caller_results) >= max_callers:
            break

    return caller_results


def read_stepping_stone_sources(src_dir, roadmap, max_funcs=5, max_lines=40,
                                 include_caller_conditions=True):
    """Read kernel source snippets for stepping-stone functions.

    Returns a string with annotated source excerpts, optionally including
    condition blocks from callers immediately before each call site.
    """
    if not roadmap or not roadmap.get("stepping_stones"):
        return ""

    stones = roadmap["stepping_stones"][:max_funcs]
    snippets = []

    for stone in stones:
        fn = stone["function"]
        dist = stone["distance"]
        try:
            result = subprocess.run(
                ["grep", "-rn", f"^[a-zA-Z_].*\\b{fn}\\b", "--include=*.c",
                 "-l", src_dir],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not result.stdout.strip():
            continue

        src_file = result.stdout.strip().split("\n")[0]
        try:
            result2 = subprocess.run(
                ["grep", "-n", f"\\b{fn}\\b", src_file],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not result2.stdout.strip():
            continue

        first_line = result2.stdout.strip().split("\n")[0]
        try:
            lineno = int(first_line.split(":")[0])
        except ValueError:
            continue

        try:
            with open(src_file) as f:
                lines = f.readlines()
            start = max(0, lineno - 3)
            end = min(len(lines), lineno + max_lines)
            rel_path = os.path.relpath(src_file, src_dir)
            snippet = f"// {rel_path}:{lineno} (distance={dist})\n"
            snippet += "".join(lines[start:end])

            # Append caller condition blocks
            if include_caller_conditions:
                caller_conds = _extract_caller_conditions(
                    src_dir, fn, max_callers=3, look_back=30
                )
                cond_parts = []
                for cc in caller_conds:
                    if cc["conditions"]:
                        header = f"  // caller: {cc['caller_file']}:{cc['caller_line']}"
                        cond_parts.append(
                            header + "\n" + "\n".join(cc["conditions"])
                        )
                if cond_parts:
                    snippet += "\n// CONDITIONS BEFORE CALL:\n" + "\n---\n".join(cond_parts)

            snippets.append(snippet)
        except OSError:
            continue

    return "\n---\n".join(snippets)


# ──────────────────────────────────────────────────────────────────────────
# LLM-driven callfile enhancement for distance stagnation
# ──────────────────────────────────────────────────────────────────────────

def llm_enhance_callfile_for_distance(current_callfile, roadmap,
                                       target_function, target_file,
                                       source_snippets="",
                                       closest_program=None, closest_dist=None,
                                       reverse_trace=""):
    """Ask the LLM to suggest better syscalls based on distance roadmap."""
    if not roadmap:
        return None

    current_dist = roadmap["current_dist_min"]

    # ── Build compact plan ──────────────────────────────────────────────
    try:
        from seed_planner import build_compact_plan
        compact_plan = build_compact_plan(
            roadmap=roadmap,
            source_snippets=source_snippets,
            target_function=target_function,
            target_file=target_file,
            closest_program=closest_program,
            closest_dist=closest_dist,
            current_dist=current_dist,
        )
    except Exception as e:
        print(f"  [LLM-dist] seed_planner failed ({e}), falling back")
        compact_plan = f"TARGET: {target_function} in {target_file}\nCURRENT DISTANCE: {current_dist}"

    prompt = f"""You are a Linux kernel security researcher helping a distance-guided fuzzer.

{compact_plan}

CURRENT CALLFILE (syscalls being fuzzed):
{json.dumps(current_callfile, indent=2)}

Suggest better syscalls to reach {target_function}. Follow the SYSCALL SEQUENCE above.

Return ONLY valid JSON:
{{"syscalls": [{{"Target": "name$variant", "Relate": ["setup1", "setup2", ...]}}], "reasoning": "brief explanation"}}

Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, bpf$PROG_LOAD).
Provide 1-4 Target entries with 3-6 Relate syscalls each."""

    try:
        text = _call_llm(prompt, timeout=180)
        if not text:
            return None
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(text[start:end])
            reasoning = result.pop("reasoning", "")
            if reasoning:
                print(f"  [LLM-dist] Reasoning: {reasoning}")
            syscalls = result.get("syscalls", [])
            if syscalls:
                validated = []
                for entry in syscalls:
                    target = entry.get("Target", "")
                    normalized = normalize_syscall_name(target, target_file)
                    if normalized:
                        entry["Target"] = normalized
                    relates = []
                    for r_name in entry.get("Relate", []):
                        nr = normalize_syscall_name(r_name, target_file)
                        if nr:
                            relates.append(nr)
                    entry["Relate"] = relates or entry.get("Relate", [])
                    validated.append(entry)
                validated = _validate_r4_entries(validated, current_callfile, roadmap)
                return validated
    except json.JSONDecodeError as e:
        print(f"  [LLM-dist] JSON parse error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# Python-based TC netlink seed generator (reliable fallback)
# ──────────────────────────────────────────────────────────────────────────

def _nlattr_u32(attr_type, value):
    return struct.pack("<HHI", 8, attr_type, value)


def _nlattr_u16(attr_type, value):
    return struct.pack("<HHH", 6, attr_type, value) + b"\x00\x00"


def _nlattr_bytes(attr_type, data):
    payload = data
    nla_len = 4 + len(payload)
    padded = payload + (b"\x00" * ((4 - (len(payload) % 4)) % 4))
    return struct.pack("<HH", nla_len, attr_type) + padded


def _prio_qdisc_options():
    """Build TCA_OPTIONS for prio qdisc (required or prio_tune returns -EINVAL).

    struct tc_prio_qopt { int bands; __u8 priomap[TC_PRIO_MAX+1]; }
    3 bands, standard priomap.
    """
    prio_qopt = struct.pack('<I', 3) + bytes([1,2,2,2,1,2,0,0,1,1,1,1,1,1,1,1])
    return _nlattr_bytes(2, prio_qopt)


def _tbf_qdisc_options(limit=0x10000, rate_bps=0x00100000, burst=0x4000):
    """Build minimal valid TCA_OPTIONS for a TBF qdisc."""
    rate_spec = struct.pack('<BBHhHI', 0, 1, 0, 0, 0, rate_bps)
    peak_spec = struct.pack('<BBHhHI', 0, 0, 0, 0, 0, 0)
    tbf_qopt = rate_spec + peak_spec + struct.pack('<III', limit, burst, 0)
    tca_parms = _nlattr_bytes(1, tbf_qopt)
    tca_burst = _nlattr_u32(6, burst)
    return _nlattr_bytes(2, tca_parms + tca_burst)


def _build_netlink_tc_seed(kind, msg_type, ifindex=1, parent=0xffff0000,
                           handle=0, info=0, extra_attrs=b"", flags=None):
    """Build a valid RTM_NEWQDISC or RTM_NEWTFILTER netlink message bytes.

    kind: TC kind string (e.g. "tcindex", "pfifo", "tbf")
    msg_type: 0x24=RTM_NEWQDISC, 0x2c=RTM_NEWTFILTER, 0x25=RTM_CHANGEQDISC
    Returns hex string suitable for ANYBLOB.
    """
    kind_bytes = kind.encode() + b'\x00'
    tca_kind = _nlattr_bytes(1, kind_bytes)  # TCA_KIND

    # Auto-add required TCA_OPTIONS for qdiscs that need them
    if msg_type == 0x24 and kind == "prio" and not extra_attrs:
        extra_attrs = _prio_qdisc_options()
    if msg_type == 0x24 and kind == "tbf" and not extra_attrs:
        extra_attrs = _tbf_qdisc_options()

    # tcmsg: family(1) + pad(3) + ifindex(4le) + handle(4le) + parent(4le) + info(4le)
    tcmsg = struct.pack('<BBBBIIII', 0, 0, 0, 0, ifindex, handle, parent, info)

    # nlmsghdr: len(4le) + type(2le) + flags(2le) + seq(4le) + pid(4le)
    if flags is None:
        flags = 0x0405  # NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    body = tcmsg + tca_kind + extra_attrs
    total_len = 16 + len(body)
    nlmsghdr = struct.pack('<IHHII', total_len, msg_type, flags, 1, 0)

    return (nlmsghdr + body).hex()


def _build_tcindex_filter_seed(ifindex=1, parent=0x00010000, prio=1,
                               protocol=3, handle=1, hash_size=16,
                               mask=15, shift=0, fall_through=1,
                               classid=None, msg_type=0x2c):
    """Build RTM_NEWTFILTER message that carries tcindex options.

    This favors the perfect-hash path: hash > (mask >> shift).
    """
    info = ((prio & 0xffff) << 16) | (protocol & 0xffff)
    tcindex_opts = b"".join([
        _nlattr_u32(1, hash_size),        # TCA_TCINDEX_HASH
        _nlattr_u16(2, mask),             # TCA_TCINDEX_MASK
        _nlattr_u32(3, shift),            # TCA_TCINDEX_SHIFT
        _nlattr_u32(4, fall_through),     # TCA_TCINDEX_FALL_THROUGH
    ])
    if classid is not None:
        tcindex_opts += _nlattr_u32(5, classid)  # TCA_TCINDEX_CLASSID
    extra_attrs = _nlattr_bytes(2, tcindex_opts)  # TCA_OPTIONS
    return _build_netlink_tc_seed(
        "tcindex", msg_type, ifindex=ifindex, parent=parent,
        handle=handle, info=info, extra_attrs=extra_attrs,
    )


def _infer_tc_kind_from_roadmap(roadmap, target_function):
    """Try to infer TC classifier/qdisc kind from stepping stone function names."""
    stones = roadmap.get("stepping_stones", []) if roadmap else []
    candidates = [s["function"] for s in stones] + [target_function]

    # Map known function prefixes → TC kind strings
    _KIND_MAP = {
        "tcindex": "tcindex",
        "pfifo":   "pfifo",
        "tbf":     "tbf",
        "htb":     "htb",
        "hfsc":    "hfsc",
        "sfq":     "sfq",
        "fq_codel": "fq_codel",
        "codel":   "codel",
        "netem":   "netem",
        "cbq":     "cbq",
        "qfq":     "qfq",
        "cls_u32": "u32",
        "u32":     "u32",
        "flower":  "flower",
        "matchall": "matchall",
        "bpf":     "bpf",
    }
    for fn in candidates:
        for prefix, kind in _KIND_MAP.items():
            if fn.startswith(prefix):
                return kind
    return None


def _detect_tc_target_type(target_file):
    """Detect TC target type from source file path.

    Returns one of: "filter", "qdisc", "action", or "unknown".
    - cls_*.c  → filter  (needs parent qdisc before RTM_NEWTFILTER)
    - act_*.c  → action  (needs qdisc + filter chain before action)
    - sch_*.c  → qdisc   (RTM_NEWQDISC is the entry point itself)
    - *_api.c  → "unknown" (common code, any kind works)
    """
    basename = os.path.basename(target_file)
    # Common/API files should not force a specific kind
    if basename.endswith("_api.c"):
        return "unknown"
    if basename.startswith("cls_"):
        return "filter"
    if basename.startswith("act_"):
        return "action"
    if basename.startswith("sch_"):
        return "qdisc"
    return "unknown"


def _detect_tc_target_type_from_snippets(source_snippets):
    counts = {"filter": 0, "action": 0, "qdisc": 0}
    for line in (source_snippets or "").splitlines():
        line = line.strip()
        if line.startswith("// "):
            path = line[3:].split(":", 1)[0]
        else:
            path = line
        inferred = _detect_tc_target_type(path)
        if inferred in counts:
            counts[inferred] += 1
        kind = _tc_kind_from_token(line)
        if kind in _TC_FILTER_KINDS:
            counts["filter"] += 1
        elif kind in _TC_QDISC_KINDS:
            counts["qdisc"] += 1
    best_type = max(counts, key=counts.get)
    return best_type if counts[best_type] > 0 else None


def _callfile_targets_and_related(current_callfile):
    targets = set()
    related = set()
    for entry in current_callfile or []:
        target = entry.get("Target", "")
        if target:
            targets.add(target.lower())
            targets.add(target.split("$", 1)[0].lower())
        for name in entry.get("Relate", []) or []:
            if name:
                related.add(name.lower())
                related.add(name.split("$", 1)[0].lower())
    return targets, related


def _roadmap_allowed_calls(roadmap):
    allowed = set()
    for stone in (roadmap or {}).get("stepping_stones", []):
        for call in stone.get("reachable_via", []) or []:
            if call:
                allowed.add(call.lower())
                allowed.add(call.split("$", 1)[0].lower())
    return allowed


def _validate_r4_entries(entries, current_callfile, roadmap):
    """Validate LLM-suggested R4 entries.

    For entries whose Target already exists in the callfile or roadmap,
    keep them as-is.  For *novel* targets (LLM suggesting a completely
    new syscall family), accept them but keep their Relate list as
    provided — the LLM's subsystem reasoning is the best signal we have
    for non-TC targets where roadmap reachable_via is sparse.
    """
    current_targets, current_related = _callfile_targets_and_related(current_callfile)
    roadmap_calls = _roadmap_allowed_calls(roadmap)
    known = current_targets | current_related | roadmap_calls
    validated = []
    for entry in entries or []:
        target = (entry.get("Target") or "").strip()
        if not target:
            continue
        relates = []
        for relate in entry.get("Relate", []) or []:
            r = (relate or "").strip()
            if r and r != target:
                relates.append(r)
        validated.append({"Target": target, "Relate": relates})
    return validated


def _validate_seed_programs(programs, target_file, current_callfile, source_snippets=""):
    """Filter seed programs using structural checks.

    For TC targets (net/sched/*), apply the original TC-specific checks
    (requires socket$nl_route, sendmsg counts, etc.).
    For non-TC targets, accept any non-empty program that contains at
    least one syscall.
    """
    if not programs:
        return []

    is_tc = "net/sched" in (target_file or "")

    if is_tc:
        current_targets, _ = _callfile_targets_and_related(current_callfile)
        target_type = _detect_tc_target_type(target_file)
        snippet_type = _detect_tc_target_type_from_snippets(source_snippets)
        if snippet_type and snippet_type != target_type:
            target_type = snippet_type

    validated = []
    for prog in programs:
        text = (prog.get("text") or "").strip()
        if not text:
            continue

        if is_tc:
            text_l = text.lower()
            if "socket$nl_route" not in text_l:
                continue
            sendmsg_count = text_l.count("sendmsg$nl_route_sched")
            if target_type in {"filter", "action"} and sendmsg_count < 2:
                continue
            if target_type == "qdisc" and sendmsg_count < 1:
                continue
            if current_targets and not any(name in text_l for name in current_targets):
                if "sendmsg$nl_route_sched" not in text_l:
                    continue
        else:
            # Generic: accept any program with at least one syscall-like call
            if "(" not in text:
                continue

        validated.append(prog)
    return validated


def _decode_tc_anyblob(hex_bytes):
    try:
        blob = bytes.fromhex(hex_bytes)
    except ValueError:
        return None
    if len(blob) < 36:
        return None
    try:
        nl_len, nl_type, flags, seq, pid = struct.unpack_from("<IHHII", blob, 0)
        family, _p1, _p2, _p3, ifindex, handle, parent, info = struct.unpack_from("<BBBBIIII", blob, 16)
    except struct.error:
        return None
    msg = {
        "nl_type": nl_type,
        "flags": flags,
        "ifindex": ifindex,
        "handle": handle,
        "parent": parent,
        "info": info,
        "kinds": [],
        "has_options": False,
        "option_attrs": 0,
    }
    off = 36
    while off + 4 <= len(blob):
        try:
            nla_len, nla_type = struct.unpack_from("<HH", blob, off)
        except struct.error:
            break
        if nla_len < 4 or off + nla_len > len(blob):
            break
        data = blob[off + 4:off + nla_len]
        if nla_type == 1:
            kind = data.rstrip(b"\x00").decode("ascii", "ignore")
            if kind:
                msg["kinds"].append(kind)
        elif nla_type == 2:
            msg["has_options"] = True
            sub = 0
            while sub + 4 <= len(data):
                try:
                    slen, _stype = struct.unpack_from("<HH", data, sub)
                except struct.error:
                    break
                if slen < 4 or sub + slen > len(data):
                    break
                msg["option_attrs"] += 1
                sub += ((slen + 3) // 4) * 4
        off += ((nla_len + 3) // 4) * 4
    return msg


def _analyze_seed_program(program_text):
    text = (program_text or "").strip()
    text_l = text.lower()
    blobs = re.findall(r'anyblob="([0-9a-f]+)"', text_l)
    messages = []
    for blob in blobs:
        decoded = _decode_tc_anyblob(blob)
        if decoded:
            messages.append(decoded)
    for marker, nl_type, prefix in (
        ("@newqdisc", 0x24, "q_"),
        ("@newtfilter", 0x2C, "f_"),
    ):
        start = 0
        while True:
            idx = text_l.find(marker, start)
            if idx < 0:
                break
            segment = text_l[idx:idx + 500]
            kinds = []
            for member in re.findall(r'@([qf]_[a-z0-9_]+)', segment):
                if not member.startswith(prefix):
                    continue
                kind = member[2:]
                if kind == "route":
                    kind = "route4"
                kinds.append(kind)
            messages.append({
                "nl_type": nl_type,
                "flags": 0,
                "ifindex": 0,
                "handle": 0,
                "parent": 0,
                "info": 0,
                "kinds": kinds,
                "has_options": bool(kinds),
                "option_attrs": 1 if kinds else 0,
            })
            start = idx + len(marker)
    return {
        "has_route_socket": "socket$nl_route" in text_l,
        "sendmsg_sched_count": text_l.count("sendmsg$nl_route_sched"),
        "messages": messages,
    }


def _seed_requirements(roadmap, target_function, target_file, source_snippets=""):
    return _build_target_seed_profile(roadmap, target_function, target_file, source_snippets)


def _kind_candidate_match(kind_candidates, all_kinds):
    for idx, item in enumerate(kind_candidates or []):
        kind = item[0]
        weight = item[1] if len(item) > 1 else 1
        if kind in all_kinds:
            return kind, weight, False
        if _fuzzy_kind_match(kind, all_kinds):
            return kind, max(1, weight // 2), True
        if idx >= 2:
            break
    return None, 0, False


def _format_seed_messages(messages):
    parts = []
    for idx, msg in enumerate(messages):
        parts.append(
            f"m{idx}:type=0x{msg['nl_type']:02x}"
            f"/kinds={msg['kinds'] or ['-']}"
            f"/handle=0x{msg['handle']:08x}"
            f"/parent=0x{msg['parent']:08x}"
            f"/opts={msg['option_attrs']}"
        )
    return "; ".join(parts) if parts else "no_decoded_messages"


def _score_seed_program(prog, requirements):
    text = (prog.get("text") or "").strip()
    if not text:
        return None
    analysis = _analyze_seed_program(text)
    score = 0
    reasons = []

    # For non-TC targets, use generic scoring
    target_type = requirements.get("target_type")
    if target_type == "unknown":
        # Generic: score based on program complexity
        score = 1
        reasons.append("generic_program")
        line_count = len(text.strip().splitlines())
        if line_count >= 3:
            score += 1
            reasons.append("multi_step")
        return {
            "program": prog,
            "score": score,
            "reasons": reasons,
            "analysis": analysis,
        }

    if not analysis["has_route_socket"]:
        return None
    score += 1
    reasons.append("route_socket")

    messages = analysis["messages"]
    target_type = requirements.get("target_type")
    kind_candidates = requirements.get("kind_candidates", [])
    nl_types = [m["nl_type"] for m in messages]
    all_kinds = [kind for m in messages for kind in m["kinds"]]

    if any(m["nl_type"] in requirements.get("avoid_ops", set()) and m["nl_type"] not in {0x24, 0x2c}
           for m in messages):
        return None

    if target_type == "filter":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return None
        score += 3
        reasons.append("qdisc_then_filter_shape")
    elif target_type == "action":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return None
        score += 2
        reasons.append("action_prereqs")
    elif target_type == "qdisc":
        if 0x24 not in nl_types:
            return None
        score += 2
        reasons.append("qdisc_entry")

    matched_kind, kind_weight, fuzzy_kind = _kind_candidate_match(kind_candidates, all_kinds)
    if kind_candidates:
        if not matched_kind:
            return None
        score += max(1, min(4, int(kind_weight)))
        reasons.append(f"kind{'~' if fuzzy_kind else '='}{matched_kind}")

    if target_type == "filter":
        first_qdisc = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x24), None)
        first_filter = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x2C), None)
        if first_qdisc is None or first_filter is None or first_filter <= first_qdisc:
            return None
        qdisc_msg = messages[first_qdisc]
        filter_msg = messages[first_filter]
        if matched_kind and matched_kind in qdisc_msg["kinds"]:
            return None
        reasons.append("filter_after_qdisc")
        score += 2
        if matched_kind:
            kind_filters = [m for m in messages if m["nl_type"] == 0x2C and matched_kind in m["kinds"]]
            if not kind_filters:
                return None
            if any(m["has_options"] for m in kind_filters):
                score += 1
                reasons.append("filter_options")
            if any(m["option_attrs"] >= 2 for m in kind_filters):
                score += 1
                reasons.append("rich_options")
        if requirements.get("prefer_explicit_handle") and filter_msg["handle"] != 0:
            score += 1
            reasons.append("explicit_filter_handle")
        if qdisc_msg["handle"] != 0 and filter_msg["parent"] == qdisc_msg["handle"]:
            score += 2
            reasons.append("parent_matches_qdisc_handle")
        elif filter_msg["parent"] == 0xFFFF0000:
            score -= 1
            reasons.append("root_parent_only")

    if requirements.get("prefer_multi_stage"):
        if target_type in {"filter", "action"}:
            filter_msgs = [m for m in messages if m["nl_type"] == 0x2C]
            if len(filter_msgs) >= 2:
                score += 2
                reasons.append("multi_stage_filter_update")
                if matched_kind:
                    kind_filters = [m for m in filter_msgs if matched_kind in m["kinds"]]
                    if len(kind_filters) >= 2:
                        score += 1
                        reasons.append("repeated_target_filter_kind")
        elif target_type == "qdisc":
            qdisc_ops = [m for m in messages if m["nl_type"] in {0x24, 0x25}]
            if len(qdisc_ops) >= 2:
                score += 2
                reasons.append("multi_stage_qdisc")
                if matched_kind:
                    kind_qdiscs = [m for m in qdisc_ops if matched_kind in m["kinds"]]
                    if len(kind_qdiscs) >= 2:
                        score += 1
                        reasons.append("repeated_target_qdisc_kind")

    return {
        "program": prog,
        "score": score,
        "reasons": reasons,
        "analysis": analysis,
    }


def _reject_reason_for_seed(prog, requirements):
    text = (prog.get("text") or "").strip()
    if not text:
        return "empty_program"

    target_type = requirements.get("target_type")
    if target_type == "unknown":
        return "filtered_by_score"

    analysis = _analyze_seed_program(text)
    if not analysis["has_route_socket"]:
        return "missing_route_socket"

    messages = analysis["messages"]
    kind_candidates = requirements.get("kind_candidates", [])
    nl_types = [m["nl_type"] for m in messages]
    all_kinds = [kind for m in messages for kind in m["kinds"]]

    if any(m["nl_type"] in requirements.get("avoid_ops", set()) and m["nl_type"] not in {0x24, 0x2c}
           for m in messages):
        return "contains_weak_get_or_delete_ops"

    if target_type == "filter":
        if 0x2C not in nl_types:
            return "missing_rtm_newtfilter"
        if 0x24 not in nl_types:
            return "missing_parent_qdisc"
        first_qdisc = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x24), None)
        first_filter = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x2C), None)
        if first_qdisc is None or first_filter is None or first_filter <= first_qdisc:
            return "filter_not_after_qdisc"
        qdisc_msg = messages[first_qdisc]
        matched_kind, _weight, _fuzzy = _kind_candidate_match(kind_candidates, all_kinds)
        if matched_kind and matched_kind in qdisc_msg["kinds"]:
            return "target_kind_used_as_qdisc"
        if kind_candidates and not matched_kind:
            # Fuzzy match: fix LLM typos (edit distance ≤ 2)
            return "target_kind_missing"
        kind_filters = [m for m in messages if m["nl_type"] == 0x2C and (not matched_kind or matched_kind in m["kinds"])]
        if not kind_filters:
            return "target_filter_message_missing"
        if not any(m["has_options"] for m in kind_filters):
            return "missing_tca_options"
    elif target_type == "action":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return "missing_action_prereqs"
    elif target_type == "qdisc":
        if 0x24 not in nl_types:
            return "missing_rtm_newqdisc"
    elif kind_candidates and not _kind_candidate_match(kind_candidates, all_kinds)[0]:
        return "target_kind_missing"

    return "filtered_by_score"


def _select_seed_programs(programs, roadmap, target_function, target_file, source_snippets="", limit=4):
    requirements = _seed_requirements(roadmap, target_function, target_file, source_snippets)
    scored = []
    seen_text = set()
    rejected = []
    examined = []
    for prog in programs or []:
        text = (prog.get("text") or "").strip()
        if not text or text in seen_text:
            continue
        seen_text.add(text)
        analysis = _analyze_seed_program(text)
        scored_item = _score_seed_program(prog, requirements)
        if scored_item:
            scored.append(scored_item)
            examined.append({
                "name": prog.get("name", "prog"),
                "decision": "selected_candidate",
                "score": scored_item["score"],
                "reasons": scored_item["reasons"],
                "analysis": analysis,
            })
        else:
            reject_reason = _reject_reason_for_seed(prog, requirements)
            rejected.append({
                "name": prog.get("name", "prog"),
                "reason": reject_reason,
            })
            examined.append({
                "name": prog.get("name", "prog"),
                "decision": "rejected_candidate",
                "reason": reject_reason,
                "analysis": analysis,
            })
    scored.sort(key=lambda item: (-item["score"], item["program"].get("name", "")))
    return scored[:limit], rejected, requirements, examined


# ──────────────────────────────────────────────────────────────────────────
# Subsystem-specific seed builders
# ──────────────────────────────────────────────────────────────────────────

def _build_xfrm_newsa(spi=0x1000, proto=0x32,   # proto=50=ESP
                      family=0x2,                # AF_INET
                      mode=0,                    # XFRM_MODE_TRANSPORT
                      reqid=1):
    """Build XFRM_MSG_NEWSA netlink message bytes (minimal ESP SA).

    xfrm_selector  : 16+16+2+2+2+2+2+1+1+1+1+4+4 = 56 bytes
    xfrm_id        : 16+4+1+pad3                  = 24 bytes
    xfrm_address_t : 16 bytes (saddr)
    xfrm_lifetime_cfg : 8*8                       = 64 bytes  (all XFRM_INF)
    xfrm_lifetime_cur : 4*8                       = 32 bytes  (zeros)
    xfrm_stats     : 3*4                          = 12 bytes
    seq+reqid      : 4+4                          =  8 bytes
    family+mode+rw+flags+pad : 2+1+1+1+1+2       =  8 bytes
    Total xfrm_usersa_info                        = 224 bytes
    """
    INF = 0xFFFFFFFFFFFFFFFF
    # xfrm_selector (56 bytes): daddr(16) saddr(16) dport(2) dport_mask(2)
    #   sport(2) sport_mask(2) family(2) prefixlen_d(1) prefixlen_s(1)
    #   proto(1) pad(1) ifindex(4) user(4)
    sel = struct.pack('<16s16sHHHHHBBBBiI',
                      b'\x7f\x00\x00\x01' + b'\x00'*12,  # daddr = 127.0.0.1
                      b'\x7f\x00\x00\x01' + b'\x00'*12,  # saddr = 127.0.0.1
                      0, 0xffff, 0, 0xffff,               # ports/masks
                      family, 32, 32, proto, 0, 0, 0)     # family=AF_INET, /32
    # xfrm_id (24 bytes): daddr(16) spi(4be) proto(1) pad(3)
    xid = struct.pack('>16sI', b'\x7f\x00\x00\x01' + b'\x00'*12, spi)
    xid += struct.pack('<B3x', proto)  # proto + 3-byte pad
    # saddr (16 bytes)
    saddr = b'\x7f\x00\x00\x01' + b'\x00'*12
    # xfrm_lifetime_cfg (64 bytes): 8 x u64 all INF
    lft = struct.pack('<8Q', INF, INF, INF, INF, INF, INF, INF, INF)
    # xfrm_lifetime_cur (32 bytes): zeros
    curlft = b'\x00' * 32
    # xfrm_stats (12 bytes): zeros
    stats = b'\x00' * 12
    # tail: seq(4) reqid(4) family(2) mode(1) replay_window(1) flags(1) pad(3)
    tail = struct.pack('<IIHBBBxxx', 0, reqid, family, mode, 32, 0)

    body = sel + xid + saddr + lft + curlft + stats + tail
    # nlattr XFRMA_ALG_AUTH_TRUNC — skip for minimal; just bare usersa_info
    total = 16 + len(body)
    # XFRM_MSG_NEWSA=0x10, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL = 0x0600|0x0400|0x0200 = 0x0601
    nlhdr = struct.pack('<IHHII', total, 0x10, 0x0601, 1, 0)
    return (nlhdr + body).hex()


def _build_xfrm_newpolicy(family=0x2, direction=0):  # 0=XFRM_POLICY_IN
    """Build XFRM_MSG_NEWPOLICY netlink message bytes.

    xfrm_userpolicy_info:
      xfrm_selector(56) + xfrm_lifetime_cfg(64) + xfrm_lifetime_cur(32)
      + priority(4) + index(4) + dir(1) + action(1) + flags(1) + share(1) = 164 bytes
    """
    INF = 0xFFFFFFFFFFFFFFFF
    sel = struct.pack('<16s16sHHHHHBBBBiI',
                      b'\x7f\x00\x00\x01' + b'\x00'*12,
                      b'\x7f\x00\x00\x01' + b'\x00'*12,
                      0, 0xffff, 0, 0xffff,
                      family, 32, 32, 0, 0, 0, 0)
    lft    = struct.pack('<8Q', INF, INF, INF, INF, INF, INF, INF, INF)
    curlft = b'\x00' * 32
    tail   = struct.pack('<IIBBBBxx', 0, 0, direction, 0, 0, 0)  # prio,idx,dir,action,flags,share
    body   = sel + lft + curlft + tail
    total  = 16 + len(body)
    nlhdr  = struct.pack('<IHHII', total, 0x14, 0x0601, 2, 0)  # XFRM_MSG_NEWPOLICY=0x14
    return (nlhdr + body).hex()


def _xfrm_sendmsg(hex_bytes, slot=0):
    """Wrap xfrm netlink bytes into sendmsg$nl_xfrm syzkaller call."""
    msg_len = len(hex_bytes) // 2
    hdr = 0x7f0000005000 + slot * 0x3000
    iov = 0x7f0000004040 + slot * 0x3000
    buf = 0x7f0000004080 + slot * 0x3000
    return (
        f'sendmsg$nl_xfrm(r0, &(0x{hdr:x})={{0x0, 0x0, '
        f'&(0x{iov:x})=[{{&(0x{buf:x})=ANY=[@ANYBLOB="{hex_bytes}"], '
        f'0x{msg_len:x}}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)\n'
    )


def _build_bpf_prog_hex(prog_type=1):
    """Return hex of a minimal valid BPF program (MOV r0=0; EXIT).

    BPF instruction: u8 code, u8 regs(dst:4|src:4), s16 off, s32 imm  = 8 bytes
    BPF_MOV64_IMM(BPF_REG_0, 0): code=0xb7, regs=0x00, off=0, imm=0
    BPF_EXIT_INSN():              code=0x95, regs=0x00, off=0, imm=0
    """
    insns = struct.pack('<BBhI', 0xb7, 0x00, 0, 0)   # MOV64 r0=0
    insns += struct.pack('<BBhI', 0x95, 0x00, 0, 0)  # EXIT
    return insns.hex()


def _generate_generic_seed_programs(roadmap, target_function, target_file, source_snippets=""):
    """Generate deterministic seed programs for non-TC targets based on subsystem heuristics."""
    programs = []
    tf = (target_file or "").lower()

    if "net/bluetooth" in tf:
        # Bluetooth subsystem: socket + bind + connect
        for proto, sock_type, variant in [
            ("0x1f", "0x5", "bt_sco"),    # SCO
            ("0x1f", "0x1", "bt_l2cap"),  # L2CAP
            ("0x1f", "0x2", "bt_hci"),    # HCI
        ]:
            programs.append({
                "name": f"bt_{variant}_setup",
                "text": (
                    f"r0 = socket${variant}({proto}, {sock_type}, 0x0)\n"
                    f"bind${variant}(r0, &(0x7f0000000000)={{{proto}}}, 0x1e)\n"
                    f"connect${variant}(r0, &(0x7f0000001000)={{{proto}}}, 0x1e)\n"
                    f"setsockopt${variant}(r0, 0x112, 0x1, &(0x7f0000002000)=0x1, 0x4)\n"
                ),
            })

    elif "mm/" in tf:
        # Memory management subsystem: mmap + mremap + madvise
        programs.append({
            "name": "mm_mmap_mremap",
            "text": (
                "r0 = mmap(&(0x7f0000ff0000/0x4000)=nil, 0x4000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n"
                "mremap(r0, 0x4000, 0x8000, 0x3, &(0x7f0000fe0000/0x8000)=nil)\n"
            ),
        })
        programs.append({
            "name": "mm_mmap_madvise",
            "text": (
                "r0 = mmap(&(0x7f0000ff0000/0x4000)=nil, 0x4000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n"
                "madvise(r0, 0x4000, 0x4)\n"
                "munmap(r0, 0x4000)\n"
            ),
        })

    elif "net/ipv4" in tf or "net/ipv6" in tf or "net/tcp" in tf:
        # TCP/IP subsystem
        programs.append({
            "name": "tcp_socket_ops",
            "text": (
                "r0 = socket$inet_tcp(0x2, 0x1, 0x0)\n"
                "bind$inet(r0, &(0x7f0000000000)={0x2, 0x0, @local}, 0x10)\n"
                "listen(r0, 0x5)\n"
                "setsockopt$inet_tcp_int(r0, 0x6, 0x1, &(0x7f0000001000)=0x1, 0x4)\n"
            ),
        })
        programs.append({
            "name": "udp_socket_ops",
            "text": (
                "r0 = socket$inet_udp(0x2, 0x2, 0x0)\n"
                "bind$inet(r0, &(0x7f0000000000)={0x2, 0x0, @local}, 0x10)\n"
                "sendto$inet(r0, &(0x7f0000001000)=\"aabb\", 0x2, 0x0, "
                "&(0x7f0000002000)={0x2, 0x0, @remote}, 0x10)\n"
            ),
        })

    elif "net/netfilter" in tf or "net/netlink" in tf:
        programs.append({
            "name": "netlink_route",
            "text": (
                "r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                "sendmsg$nl_route(r0, &(0x7f0000001000)={0x0, 0x0, "
                "&(0x7f0000000040)=[{&(0x7f0000000080)=\"140000001000050100000000000000000000000000000000\", 0x2c}], "
                "0x1, 0x0, 0x0, 0x0}, 0x0)\n"
            ),
        })

    elif "net/sctp" in tf:
        # SCTP: socket pair + listen + connect triggers sctp_sf_do_prm_asoc
        # via SCTP_CMD_NEW_ASOC in the state machine
        programs.append({
            "name": "sctp_connect_assoc",
            "text": (
                "r0 = socket$inet_sctp(0x2, 0x1, 0x84)\n"
                "bind$inet(r0, &(0x7f0000000000)={0x2, 0x10e1, @local}, 0x10)\n"
                "listen(r0, 0x5)\n"
                "r1 = socket$inet_sctp(0x2, 0x1, 0x84)\n"
                "bind$inet(r1, &(0x7f0000001000)={0x2, 0x10e2, @local}, 0x10)\n"
                "connect$inet(r1, &(0x7f0000002000)={0x2, 0x10e1, @local}, 0x10)\n"
                "close(r1)\n"
                "close(r0)\n"
            ),
        })
        programs.append({
            "name": "sctp_sendmsg_assoc",
            "text": (
                "r0 = socket$inet_sctp(0x2, 0x1, 0x84)\n"
                "bind$inet(r0, &(0x7f0000000000)={0x2, 0x10e3, @local}, 0x10)\n"
                "setsockopt$inet_sctp_SCTP_SOCKOPT_BINDX_ADD(r0, 0x84, 0x64, "
                "&(0x7f0000001000)=[{0x2, 0x10e3, @local}], 0x10)\n"
                "connect$inet_sctp(r0, &(0x7f0000002000)={0x2, 0x10e4, @local}, 0x10)\n"
                "sendmsg$inet_sctp(r0, &(0x7f0000003000)={0x0, 0x0, "
                "&(0x7f0000004000)=[{&(0x7f0000005000)=\"aabbccdd\", 0x4}], 0x1}, 0x0)\n"
            ),
        })

    elif "net/xfrm" in tf:
        # XFRM: Add ESP SA + inbound policy → triggers xfrm_state_find
        # during IPsec packet processing (kernel path: xfrm_input → xfrm_state_find)
        try:
            hex_sa     = _build_xfrm_newsa(spi=0x1001, proto=0x32, family=0x2)
            hex_policy = _build_xfrm_newpolicy(family=0x2, direction=1)  # XFRM_POLICY_IN
            # Also an outbound policy to trigger state lookup on output
            hex_out    = _build_xfrm_newpolicy(family=0x2, direction=0)  # XFRM_POLICY_OUT
            programs.append({
                "name": "xfrm_esp_sa_inbound",
                "text": (
                    "r0 = socket$nl_xfrm(0x10, 0x3, 0x6)\n"
                    + _xfrm_sendmsg(hex_sa, 0)
                    + _xfrm_sendmsg(hex_policy, 1)
                    # Send raw packet to trigger xfrm_state_find via xfrm_input
                    + "r1 = socket$inet_udp(0x2, 0x2, 0x0)\n"
                    "bind$inet(r1, &(0x7f0000008000)={0x2, 0x1234, @local}, 0x10)\n"
                    "sendto$inet(r1, &(0x7f0000009000)=\"aabb\", 0x2, 0x0, "
                    "&(0x7f000000a000)={0x2, 0x1234, @local}, 0x10)\n"
                ),
            })
            programs.append({
                "name": "xfrm_esp_sa_outbound",
                "text": (
                    "r0 = socket$nl_xfrm(0x10, 0x3, 0x6)\n"
                    + _xfrm_sendmsg(hex_sa, 0)
                    + _xfrm_sendmsg(hex_out, 1)
                    + "r1 = socket$inet_tcp(0x2, 0x1, 0x0)\n"
                    "connect$inet(r1, &(0x7f0000008000)={0x2, 0x50, @remote}, 0x10)\n"
                ),
            })
        except Exception:
            pass

    elif "net/packet" in tf:
        # AF_PACKET raw socket: bind to interface + send raw frame
        programs.append({
            "name": "packet_raw_send",
            "text": (
                # ETH_P_ALL=0x300 (htons(0x0003)), SOCK_RAW=3
                "r0 = socket$packet(0x11, 0x3, 0x300)\n"
                "bind$packet(r0, &(0x7f0000000000)={0x11, 0x300, 0x1, 0x6, 0x1, "
                "0x0, @broadcast}, 0x14)\n"
                "sendto$packet(r0, &(0x7f0000001000)=ANY=[@ANYBLOB="
                "\"ffffffffffff0011223344550800\"], 0xe, 0x0, 0x0, 0x0)\n"
            ),
        })
        programs.append({
            "name": "packet_dgram_send",
            "text": (
                # SOCK_DGRAM=2, ETH_P_IP=0x800 (htons=0x0008)
                "r0 = socket$packet(0x11, 0x2, 0x8)\n"
                "bind$packet(r0, &(0x7f0000000000)={0x11, 0x8, 0x1, 0x1, 0x0, "
                "0x0, @local}, 0x14)\n"
                "sendto$packet(r0, &(0x7f0000001000)=ANY, 0x14, 0x0, 0x0, 0x0)\n"
            ),
        })

    elif "net/llc" in tf:
        # LLC UI socket: init_net socket + bind + connect + sendmsg
        programs.append({
            "name": "llc_ui_sendmsg",
            "text": (
                "r0 = syz_init_net_socket$llc(0x1a, 0x5, 0x0)\n"
                "bind$llc(r0, &(0x7f0000000000)={0x1a, @local, 0x2, 0x0}, 0x10)\n"
                "connect$llc(r0, &(0x7f0000001000)={0x1a, @remote, 0x2, 0x1}, 0x10)\n"
                "sendmsg$llc(r0, &(0x7f0000002000)={0x0, 0x0, "
                "&(0x7f0000003000)=[{&(0x7f0000004000)=\"aabbccdd\", 0x4}], 0x1}, 0x0)\n"
            ),
        })
        programs.append({
            "name": "llc_ui_sendmsg_dgram",
            "text": (
                "r0 = syz_init_net_socket$llc(0x1a, 0x2, 0x0)\n"  # SOCK_DGRAM
                "bind$llc(r0, &(0x7f0000000000)={0x1a, @local, 0x4, 0x0}, 0x10)\n"
                "sendto$llc(r0, &(0x7f0000001000)=\"aabb\", 0x2, 0x0, "
                "&(0x7f0000002000)={0x1a, @remote, 0x4, 0x1}, 0x10)\n"
            ),
        })

    elif "net/vmw_vsock" in tf or "vsock" in tf:
        # VSock stream: server + client connect + close (triggers virtio_transport_close)
        programs.append({
            "name": "vsock_stream_connect_close",
            "text": (
                # AF_VSOCK=40(0x28), SOCK_STREAM=1, CID_HOST=2
                "r0 = socket$vsock_stream(0x28, 0x1, 0x0)\n"
                "bind$vsock(r0, &(0x7f0000000000)={0x28, 0x3, 0x100}, 0xc)\n"
                "listen(r0, 0x1)\n"
                "r1 = socket$vsock_stream(0x28, 0x1, 0x0)\n"
                "connect$vsock_stream(r1, &(0x7f0000001000)={0x28, 0x3, 0x100}, 0xc)\n"
                "shutdown(r1, 0x2)\n"
                "close(r1)\n"
                "close(r0)\n"
            ),
        })
        programs.append({
            "name": "vsock_stream_concurrent_close",
            "text": (
                # Race: two sockets connecting/closing concurrently
                "r0 = socket$vsock_stream(0x28, 0x1, 0x0)\n"
                "r1 = socket$vsock_stream(0x28, 0x1, 0x0)\n"
                "bind$vsock(r0, &(0x7f0000000000)={0x28, 0x3, 0x101}, 0xc)\n"
                "connect$vsock_stream(r1, &(0x7f0000001000)={0x28, 0x3, 0x101}, 0xc)\n"
                "close(r0)\n"
                "close(r1)\n"
            ),
        })

    elif "kernel/bpf" in tf:
        # BPF verifier: load minimal valid programs of various types
        bpf_hex = _build_bpf_prog_hex()
        # BPF_PROG_TYPE_SOCKET_FILTER=1, BPF_PROG_TYPE_SCHED_CLS=3,
        # BPF_PROG_TYPE_TRACEPOINT=5, BPF_PROG_TYPE_XDP=6
        for prog_type, type_name in [(1, "socket_filter"), (3, "sched_cls"), (5, "tracepoint")]:
            programs.append({
                "name": f"bpf_prog_load_{type_name}",
                "text": (
                    f"r0 = bpf$PROG_LOAD(0x5, &(0x7f0000000000)="
                    f"{{0x{prog_type:x}, 0x2, 0x0, "
                    f"&(0x7f0000001000)=ANY=[@ANYBLOB=\"{bpf_hex}\"], "
                    f"&(0x7f0000002000)='GPL\\x00', 0x0, 0x0, 0x0, 0x0, 0x0, "
                    f"0x10, 0x0, @fallback, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, 0x90)\n"
                ),
            })
        # BPF map + prog combination to trigger verifier more deeply
        programs.append({
            "name": "bpf_map_then_prog",
            "text": (
                "r0 = bpf$MAP_CREATE(0x0, &(0x7f0000000000)="
                "{0x1, 0x4, 0x4, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x48)\n"
                "r1 = bpf$PROG_LOAD(0x5, &(0x7f0000001000)="
                "{0x1, 0x2, 0x0, "
                f"&(0x7f0000002000)=ANY=[@ANYBLOB=\"{bpf_hex}\"], "
                "&(0x7f0000003000)='GPL\\x00', 0x0, 0x0, 0x0, 0x0, 0x0, "
                "0x10, 0x0, @fallback, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)\n"
                "close(r0)\n"
                "close(r1)\n"
            ),
        })

    elif "drivers/" in tf:
        # Device driver: open + ioctl
        programs.append({
            "name": "dev_open_ioctl",
            "text": (
                "r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/dev/null\\x00', 0x2, 0x0)\n"
                "ioctl(r0, 0x1, 0x0)\n"
                "close(r0)\n"
            ),
        })

    return programs


def _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets=""):
    """Generate TC seed programs with generic prerequisite sequences."""
    if "net/sched" not in target_file:
        return []

    profile = _build_target_seed_profile(roadmap, target_function, target_file, source_snippets)
    kind = profile.get("target_kind")
    if not kind:
        return []

    # ── Generic prerequisite sequences ───────────────────────────────
    target_type = profile.get("target_type")

    def _make_msg(hex_bytes, slot=0):
        msg_len = len(hex_bytes) // 2
        hdr  = 0x7f0000001000 + slot * 0x2000
        iov  = 0x7f0000000040 + slot * 0x2000
        buf  = 0x7f0000000080 + slot * 0x2000
        return (
            f'sendmsg$nl_route_sched(r0, &(0x{hdr:x})={{0x0, 0x0, '
            f'&(0x{iov:x})=[{{&(0x{buf:x})=ANY=[@ANYBLOB="{hex_bytes}"],'
            f' 0x{msg_len:x}}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)\n'
        )

    try:
        if target_type == "filter":
            hex_prio   = _build_netlink_tc_seed("prio", 0x24, handle=0x00010000)
            hex_pfifo  = _build_netlink_tc_seed("pfifo", 0x24, handle=0x00010000)
            hex_filter = _build_netlink_tc_seed(kind, 0x2c)     # RTM_NEWTFILTER kind
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_prio, 0) + _make_msg(hex_filter, 1))
            prog2 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_pfifo, 0) + _make_msg(hex_filter, 1))
            return [
                {"name": f"prio_then_{kind}_filter", "text": prog1},
                {"name": f"pfifo_then_{kind}_filter", "text": prog2},
            ]

        elif target_type == "action":
            hex_pfifo  = _build_netlink_tc_seed("pfifo", 0x24)
            hex_filter = _build_netlink_tc_seed(kind, 0x2c)
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_pfifo, 0) + _make_msg(hex_filter, 1))
            return [{"name": f"pfifo_then_{kind}_action", "text": prog1}]

        else:
            hex_new    = _build_netlink_tc_seed(kind, 0x24, flags=0x0405)
            hex_change = _build_netlink_tc_seed(kind, 0x24, handle=0, flags=0x0005)
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_new, 0))
            prog2 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_new, 0) + _make_msg(hex_change, 1))
            return [
                {"name": f"new_{kind}_qdisc",          "text": prog1},
                {"name": f"new_then_change_{kind}_qdisc", "text": prog2},
            ]
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────
# LLM-driven seed program synthesis
# ──────────────────────────────────────────────────────────────────────────

def llm_generate_seed_program(roadmap, source_snippets, target_function, target_file,
                               current_callfile, syz_db_path=None, output_dir=None,
                               closest_program=None, closest_dist=None,
                               reverse_trace="", syz_resource_chain="",
                               agent_context=""):
    """Ask the LLM to generate syzkaller seed programs based on the distance roadmap.

    Generates concrete syzkaller program text that exercises kernel paths leading
    to target_function, then packs them into a corpus.db using syz-db pack.

    Args:
        roadmap: distance roadmap dict from extract_distance_roadmap().
        source_snippets: kernel source snippets string.
        target_function: name of target kernel function.
        target_file: kernel source file path (e.g. net/sched/sch_fifo.c).
        current_callfile: current callfile entries list.
        syz_db_path: path to syz-db binary (searches PATH if None/missing).
        output_dir: directory to write corpus.db (default: /tmp).

    Returns:
        Absolute path to the generated corpus.db, or None if failed.
    """
    if not roadmap:
        return None

    # ── Find syz-db ──────────────────────────────────────────────────────
    syz_db = syz_db_path if (syz_db_path and os.path.exists(syz_db_path)) else None
    if not syz_db:
        syz_db = shutil.which("syz-db")
    if not syz_db or not os.path.exists(syz_db):
        print("  [LLM-seed] syz-db not found, cannot pack corpus")
        return None

    # ── Build compact plan ─────────────────────────────────────────────
    current_dist = roadmap.get("current_dist_min", 0)

    try:
        from seed_planner import build_compact_plan
        compact_plan = build_compact_plan(
            roadmap=roadmap,
            source_snippets=source_snippets,
            target_function=target_function,
            target_file=target_file,
            closest_program=closest_program,
            closest_dist=closest_dist,
            current_dist=current_dist,
        )
    except Exception as e:
        print(f"  [LLM-seed] seed_planner failed ({e}), falling back to minimal plan")
        compact_plan = f"TARGET: {target_function} in {target_file}\nCURRENT DISTANCE: {current_dist}"

    prompt = f"""You are a Linux kernel fuzzing expert. Generate syzkaller seed programs.

{compact_plan}
{agent_context}

Before generating programs, classify the target using the taxonomy above and choose exactly one blocking layer.
Then generate 2 syzkaller programs that trigger the kernel path to {target_function}.
Follow the SYSCALL SEQUENCE above. Each program should be a complete sequence and should attack only the selected blocking layer.

Use syzkaller syntax. Each syscall on its own line:
  r0 = socket$nl_route(0x10, 0x3, 0x0)
  sendmsg$nl_route_sched(r0, &(0x7f0000001000)={{0x0, 0x0, &(0x7f0000000040)=[{{&(0x7f0000000080)=ANY=[@ANYBLOB="HEXBYTES"], LEN}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)

Use $variant names (e.g. socket$inet_tcp, ioctl$KVM_RUN).
Use different memory addresses for each argument (increment by 0x1000).

Return ONLY JSON (no markdown):
{{"classified_layers": {{"syscall_family": "...", "resource_chain": "...", "payload_grammar": "...", "subsystem_state": "...", "dispatch_selector": "..."}}, "blocking_layer": "...", "selected_strategy": "...", "programs": [{{"name": "short_name", "text": "complete program text"}}], "reasoning": "one sentence"}}"""

    print(f"  [LLM-seed] Compact plan: {len(compact_plan)} chars")
    try:
        text = _call_llm(prompt, timeout=120)
        if not text:
            print("  [LLM-seed] No response from LLM")
            return None
        start, end = text.find("{"), text.rfind("}") + 1
        if start < 0 or end <= start:
            print("  [LLM-seed] No JSON found in LLM response")
            return None
        result = json.loads(text[start:end])
    except json.JSONDecodeError as e:
        print(f"  [LLM-seed] JSON parse error: {e}")
        return None

    blocking_layer = result.get("blocking_layer", "")
    selected_strategy = result.get("selected_strategy", "")
    classified_layers = result.get("classified_layers", {})
    if blocking_layer or selected_strategy:
        print(f"  [LLM-seed] Blocking layer: {blocking_layer or 'unknown'}")
        print(f"  [LLM-seed] Strategy: {selected_strategy or 'unknown'}")
    if classified_layers:
        print(f"  [LLM-seed] Classified layers: {classified_layers}")

    reasoning = result.get("reasoning", "")
    if reasoning:
        print(f"  [LLM-seed] Reasoning: {reasoning}")

    programs = result.get("programs", [])
    deterministic = []
    if "net/sched" in (target_file or ""):
        deterministic = _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)
    else:
        deterministic = _generate_generic_seed_programs(roadmap, target_function, target_file, source_snippets)

    merged_candidates = []
    if deterministic or programs:
        seen_text = set()
        for prog in deterministic + programs:
            prog_text = (prog.get("text") or "").strip()
            if not prog_text or prog_text in seen_text:
                continue
            seen_text.add(prog_text)
            merged_candidates.append(prog)

    programs = _validate_seed_programs(merged_candidates, target_file, current_callfile, source_snippets)
    selected, rejected, requirements, examined = _select_seed_programs(
        programs, roadmap, target_function, target_file, source_snippets
    )
    print(f"  [LLM-seed] Target metadata: function={target_function} file={target_file}")
    print(
        "  [LLM-seed] Seed selection basis:"
        f" target_type={requirements.get('target_type')}"
        f" target_kind={requirements.get('target_kind')}"
        f" kind_candidates={[(k, s) for k, s, _ in requirements.get('kind_candidates', [])[:4]]}"
        f" prefer_multi_stage={requirements.get('prefer_multi_stage')}"
        f" snippet_type={requirements.get('snippet_type')}"
    )
    if examined:
        print("  [LLM-seed] Raw candidate analysis:")
        for item in examined[:12]:
            analysis = item.get("analysis", {})
            msg_summary = _format_seed_messages(analysis.get("messages", []))
            if item["decision"] == "selected_candidate":
                print(
                    f"    - {item['name']}  decision=selected_candidate"
                    f" score={item['score']}"
                    f" reasons={','.join(item['reasons'])}"
                    f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                )
            else:
                print(
                    f"    - {item['name']}  decision=rejected_candidate"
                    f" reject={item['reason']}"
                    f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                )
            print(f"      {msg_summary}")
    if rejected:
        print("  [LLM-seed] Rejected candidate seeds:")
        for item in rejected[:8]:
            print(f"    - {item['name']}  reject={item['reason']}")
    if selected:
        print("  [LLM-seed] Selected candidate seeds:")
        programs = []
        for item in selected:
            prog = item["program"]
            programs.append(prog)
            print(f"    - {prog.get('name', 'prog')}  score={item['score']}  reasons={','.join(item['reasons'])}")

    if not programs:
        print("  [LLM-seed] LLM returned no programs, trying Python fallback")
        if "net/sched" in (target_file or ""):
            programs = deterministic or _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)
        else:
            programs = deterministic or _generate_generic_seed_programs(roadmap, target_function, target_file, source_snippets)
        programs = _validate_seed_programs(programs, target_file, current_callfile, source_snippets)
        selected, rejected, requirements, examined = _select_seed_programs(
            programs, roadmap, target_function, target_file, source_snippets
        )
        print(
            "  [LLM-seed] Fallback seed selection basis:"
            f" target_type={requirements.get('target_type')}"
            f" target_kind={requirements.get('target_kind')}"
            f" kind_candidates={[(k, s) for k, s, _ in requirements.get('kind_candidates', [])[:4]]}"
            f" prefer_multi_stage={requirements.get('prefer_multi_stage')}"
            f" snippet_type={requirements.get('snippet_type')}"
        )
        if examined:
            print("  [LLM-seed] Fallback raw candidate analysis:")
            for item in examined[:12]:
                analysis = item.get("analysis", {})
                msg_summary = _format_seed_messages(analysis.get("messages", []))
                if item["decision"] == "selected_candidate":
                    print(
                        f"    - {item['name']}  decision=selected_candidate"
                        f" score={item['score']}"
                        f" reasons={','.join(item['reasons'])}"
                        f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                    )
                else:
                    print(
                        f"    - {item['name']}  decision=rejected_candidate"
                        f" reject={item['reason']}"
                        f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                    )
                print(f"      {msg_summary}")
        if rejected:
            print("  [LLM-seed] Fallback rejected candidate seeds:")
            for item in rejected[:8]:
                print(f"    - {item['name']}  reject={item['reason']}")
        if selected:
            print("  [LLM-seed] Fallback selected candidate seeds:")
            programs = []
            for item in selected:
                prog = item["program"]
                programs.append(prog)
                print(f"    - {prog.get('name', 'prog')}  score={item['score']}  reasons={','.join(item['reasons'])}")
        if not programs:
            return None

    # ── Write programs to temp dir, pack with syz-db ─────────────────────
    prog_dir = tempfile.mkdtemp(prefix="syz_seed_")
    try:
        written = 0
        for i, prog in enumerate(programs):
            prog_text = (prog.get("text") or "").strip()
            prog_name = (prog.get("name") or f"prog{i}").replace("/", "_")
            if not prog_text:
                continue
            prog_file = os.path.join(prog_dir, f"{i:04d}_{prog_name}")
            with open(prog_file, "w") as f:
                f.write(prog_text + "\n")
            print(f"  [LLM-seed] Program {i + 1}: {prog_name}")
            written += 1

        if written == 0:
            print("  [LLM-seed] No valid programs to pack")
            return None

        dest_dir = output_dir or tempfile.gettempdir()
        os.makedirs(dest_dir, exist_ok=True)
        corpus_db = os.path.join(dest_dir, f"llm_seed_{target_function}.db")

        pack = subprocess.run(
            [syz_db, "pack", prog_dir, corpus_db],
            capture_output=True, text=True, timeout=30,
        )
        if pack.returncode != 0:
            print(f"  [LLM-seed] syz-db pack failed: {pack.stderr[:300]}")
            return None

        # Verify: unpack and count valid programs
        verify_dir = tempfile.mkdtemp(prefix="syz_verify_")
        try:
            subprocess.run([syz_db, "unpack", corpus_db, verify_dir],
                           capture_output=True, timeout=10)
            valid_count = len(os.listdir(verify_dir))
        except Exception:
            valid_count = written  # assume ok if verify fails
        finally:
            shutil.rmtree(verify_dir, ignore_errors=True)

        if valid_count == 0:
            print(f"  [LLM-seed] All {written} program(s) rejected by syz-db, trying Python fallback")
            if "net/sched" in (target_file or ""):
                fallback = _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)
            else:
                fallback = _generate_generic_seed_programs(roadmap, target_function, target_file, source_snippets)
            fallback = _validate_seed_programs(fallback, target_file, current_callfile, source_snippets)
            selected, rejected, _requirements, _examined = _select_seed_programs(
                fallback, roadmap, target_function, target_file, source_snippets
            )
            if rejected:
                print("  [LLM-seed] Repack fallback rejected candidate seeds:")
                for item in rejected[:8]:
                    print(f"    - {item['name']}  reject={item['reason']}")
            if selected:
                fallback = [item["program"] for item in selected]
            if fallback:
                programs = fallback
                # re-write and re-pack with fallback programs
                for i, prog in enumerate(programs):
                    prog_text = (prog.get("text") or "").strip()
                    prog_name = (prog.get("name") or f"prog{i}").replace("/", "_")
                    if not prog_text:
                        continue
                    with open(os.path.join(prog_dir, f"{i:04d}_{prog_name}"), "w") as f:
                        f.write(prog_text + "\n")
                    print(f"  [LLM-seed] Fallback program {i + 1}: {prog_name}")
                pack2 = subprocess.run(
                    [syz_db, "pack", prog_dir, corpus_db],
                    capture_output=True, text=True, timeout=30,
                )
                if pack2.returncode != 0:
                    return None
                verify_dir2 = tempfile.mkdtemp(prefix="syz_verify2_")
                try:
                    subprocess.run([syz_db, "unpack", corpus_db, verify_dir2],
                                   capture_output=True, timeout=10)
                    valid_count = len(os.listdir(verify_dir2))
                finally:
                    shutil.rmtree(verify_dir2, ignore_errors=True)
                if valid_count == 0:
                    return None
            else:
                return None

        print(f"  [LLM-seed] Packed {valid_count}/{written} valid program(s) → {corpus_db}")
        return corpus_db
    finally:
        shutil.rmtree(prog_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────
# LLM Code-Gen Seed Generator (V4)
# ──────────────────────────────────────────────────────────────────────────

def llm_generate_seed_via_codegen(roadmap, source_snippets, target_function, target_file,
                                   current_callfile, syz_db_path=None, output_dir=None,
                                   closest_program=None, closest_dist=None,
                                   reverse_trace="", syz_resource_chain="",
                                   current_dist=None, semantic_context="",
                                   agent_context=""):
    """Generate syzkaller seeds by having LLM write a Python script, then executing it.

    Instead of asking the LLM to produce hex bytes directly (which it gets wrong),
    we ask it to write a Python script that uses struct.pack() to build correct
    binary payloads and outputs syzkaller program text to stdout.

    On script execution failure, retries once with the error message fed back to LLM.

    Returns:
        Absolute path to generated corpus.db, or None if failed.
    """
    if not roadmap:
        return None

    # ── Find syz-db ──────────────────────────────────────────────────────
    syz_db = syz_db_path if (syz_db_path and os.path.exists(syz_db_path)) else None
    if not syz_db:
        syz_db = shutil.which("syz-db")
    if not syz_db or not os.path.exists(syz_db):
        print("  [codegen] syz-db not found, cannot pack corpus")
        return None

    dist = current_dist or roadmap.get("current_dist_min", 0)

    # ── Build compact plan via seed_planner (replaces raw source + syzlang) ──
    try:
        from seed_planner import build_compact_plan
        compact_plan = build_compact_plan(
            roadmap=roadmap,
            source_snippets=source_snippets,
            target_function=target_function,
            target_file=target_file,
            semantic_context=semantic_context,
            closest_program=closest_program,
            closest_dist=closest_dist,
            current_dist=dist,
        )
    except Exception as e:
        print(f"  [codegen] seed_planner failed ({e}), falling back to minimal plan")
        compact_plan = f"TARGET: {target_function} in {target_file}\nCURRENT DISTANCE: {dist}"

    close_distance_hint = ""
    if dist and dist < 100:
        close_distance_hint = f"\nCRITICAL: Distance is only {dist}. Your payload must satisfy the exact branch condition blocking entry."

    # ── Build codegen prompt (compact) ───────────────────────────────────
    prompt = f"""You are a Linux kernel fuzzing expert. Write a Python 3 script that generates syzkaller seed programs.

{compact_plan}
{agent_context}
{close_distance_hint}

Before writing the script, use the taxonomy above internally:
- classify the syscall family, resource chain, payload grammar, subsystem state, and dispatch selector
- choose exactly one blocking layer
- make the generated programs attack only that layer

Write a Python script that:
1. Uses struct.pack() to build binary payloads (netlink messages, ioctl args, setsockopt buffers, etc.)
2. Computes all lengths, offsets, and padding correctly in code (do NOT hardcode hex strings)
3. Prints complete syzkaller program text to stdout
4. Separates multiple programs with a line containing only "---"

Syzkaller program format example:
  r0 = socket$nl_route(0x10, 0x3, 0x0)
  sendmsg$nl_route_sched(r0, &(0x7f0000001000)={{{{0x0, 0x0, &(0x7f0000000040)=[{{{{&(0x7f0000000080)=ANY=[@ANYBLOB="HEXBYTES"], 0xLEN}}}}], 0x1, 0x0, 0x0, 0x0}}}}, 0x0)

Where HEXBYTES is the lowercase hex encoding of the binary payload, and 0xLEN is its byte length.
Use different memory addresses for each sendmsg call (increment base by 0x2000).

The script must be self-contained. Only use Python stdlib (struct, socket, etc.).
Generate 2-4 programs following the SYSCALL SEQUENCE above.
Put MULTIPLE sendmsg calls in a SINGLE program when stateful setup is needed.

Output ONLY the Python script. No markdown fences, no explanation."""

    print(f"  [codegen] Querying LLM for Python seed generator script...")
    print(f"  [codegen] Compact plan: {len(compact_plan)} chars (was ~12000+)")
    script_text = _call_llm(prompt, timeout=120)
    if not script_text:
        print("  [codegen] No response from LLM")
        return None

    # Strip markdown fences if present
    script_text = _strip_markdown_fences(script_text)

    # ── Execute script (with retry on failure) ───────────────────────────
    programs_text = _execute_codegen_script(script_text)
    if programs_text is None:
        # Retry: feed error back to LLM
        print("  [codegen] First attempt failed, retrying with error feedback...")
        programs_text = _retry_codegen_script(script_text, prompt)

    if not programs_text or not programs_text.strip():
        print("  [codegen] Script produced no output")
        return None

    # ── Parse programs from stdout ───────────────────────────────────────
    raw_programs = [p.strip() for p in programs_text.split("---") if p.strip()]
    if not raw_programs:
        # Try treating whole output as single program
        raw_programs = [programs_text.strip()]

    programs = []
    for i, prog_text in enumerate(raw_programs):
        # Basic validation: must contain at least one syscall-like line
        if not any(c in prog_text for c in ("socket", "open", "ioctl", "sendmsg",
                                              "setsockopt", "mmap", "connect", "write")):
            print(f"  [codegen] Program {i} has no recognizable syscalls, skipping")
            continue
        programs.append({"name": f"codegen_{i}", "text": prog_text})

    print(f"  [codegen] Parsed {len(programs)} programs from script output")
    if not programs:
        return None

    # ── Pack into corpus.db ──────────────────────────────────────────────
    prog_dir = tempfile.mkdtemp(prefix="syz_codegen_")
    try:
        written = 0
        for i, prog in enumerate(programs):
            prog_text = prog["text"].strip()
            if not prog_text:
                continue
            with open(os.path.join(prog_dir, f"{i:04d}_{prog['name']}"), "w") as f:
                f.write(prog_text + "\n")
            written += 1

        if written == 0:
            return None

        dest_dir = output_dir or tempfile.gettempdir()
        os.makedirs(dest_dir, exist_ok=True)
        corpus_db = os.path.join(dest_dir, f"codegen_seed_{target_function}.db")

        pack = subprocess.run(
            [syz_db, "pack", prog_dir, corpus_db],
            capture_output=True, text=True, timeout=30,
        )
        if pack.returncode != 0:
            print(f"  [codegen] syz-db pack failed: {pack.stderr[:300]}")
            return None

        # Verify
        verify_dir = tempfile.mkdtemp(prefix="syz_codegen_verify_")
        try:
            subprocess.run([syz_db, "unpack", corpus_db, verify_dir],
                           capture_output=True, timeout=10)
            valid_count = len(os.listdir(verify_dir))
        except Exception:
            valid_count = written
        finally:
            shutil.rmtree(verify_dir, ignore_errors=True)

        if valid_count == 0:
            print(f"  [codegen] All programs rejected by syz-db")
            return None

        print(f"  [codegen] Packed {valid_count}/{written} program(s) → {corpus_db}")
        return corpus_db
    finally:
        shutil.rmtree(prog_dir, ignore_errors=True)


def _strip_markdown_fences(text):
    """Remove ```python ... ``` fences from LLM output."""
    lines = text.split("\n")
    out = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        out.append(line)
    return "\n".join(out)


def _execute_codegen_script(script_text):
    """Execute a Python script in a sandbox and return its stdout, or None on failure."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="codegen_",
                                      delete=False) as f:
        f.write(script_text)
        script_path = f.name
    try:
        r = subprocess.run(
            ["python3", script_path],
            capture_output=True, text=True, timeout=15,
            cwd="/tmp",
        )
        if r.returncode != 0:
            print(f"  [codegen] Script failed (rc={r.returncode}): {r.stderr[:500]}")
            return None
        return r.stdout
    except subprocess.TimeoutExpired:
        print("  [codegen] Script timed out (15s)")
        return None
    finally:
        os.unlink(script_path)


def _retry_codegen_script(failed_script, original_prompt):
    """Retry by sending the error back to LLM for a fixed script."""
    # Re-run to capture the error
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="codegen_retry_",
                                      delete=False) as f:
        f.write(failed_script)
        script_path = f.name
    try:
        r = subprocess.run(
            ["python3", script_path],
            capture_output=True, text=True, timeout=15,
            cwd="/tmp",
        )
        error_msg = r.stderr[:1000] if r.stderr else "Script produced no output"
    except subprocess.TimeoutExpired:
        error_msg = "Script timed out after 15 seconds"
    finally:
        os.unlink(script_path)

    retry_prompt = f"""Your previous Python script had an error:

ERROR:
{error_msg}

ORIGINAL SCRIPT:
{failed_script[:3000]}

Fix the script. Output ONLY the corrected Python script, no markdown fences."""

    print(f"  [codegen] Asking LLM to fix script...")
    fixed_script = _call_llm(retry_prompt, timeout=300)
    if not fixed_script:
        return None
    fixed_script = _strip_markdown_fences(fixed_script)
    return _execute_codegen_script(fixed_script)
