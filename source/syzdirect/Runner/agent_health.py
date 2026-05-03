"""
SyzDirect Runner — fuzzing health assessment.

Standalone function that scores a fuzzing round using metrics, logs,
and crash data. Extracted from AgentLoop._assess_health() to enable
unit testing and reuse.
"""

import json
import os


def _load_detail_corpus(detail_corpus_path):
    """Parse syz-manager's concatenated JSON objects from detailCorpus.txt."""
    if not detail_corpus_path or not os.path.exists(detail_corpus_path):
        return []
    try:
        with open(detail_corpus_path) as f:
            text = f.read()
    except OSError:
        return []

    decoder = json.JSONDecoder()
    pos = 0
    objs = []
    length = len(text)
    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        objs.append(obj)
        pos = end
    return objs


def _relevant_dist_from_corpus(detail_corpus_path, relevant_call_names, repeat_threshold=1):
    """Compute the best distance among programs that mention target-related calls.

    repeat_threshold narrows the frontier for stateful targets by requiring
    the program to exercise relevant calls multiple times before we treat its
    distance as a meaningful target-progress signal.
    """
    names = {name.lower() for name in (relevant_call_names or []) if name}
    if not names:
        return None, 0
    best = None
    matched = 0
    for item in _load_detail_corpus(detail_corpus_path):
        prog = str(item.get("Prog", "")).lower()
        if not prog:
            continue
        hits = sum(prog.count(name) for name in names)
        if hits <= 0:
            continue
        if repeat_threshold > 1 and hits < repeat_threshold:
            continue
        matched += 1
        dist = item.get("Dist")
        # 4294967295 (UINT_MAX) is a sentinel meaning "no BB on target path
        # was hit" — treat it as missing, not as a real distance value.
        if isinstance(dist, int) and dist != 4294967295 and (best is None or dist < best):
            best = dist
    return best, matched


def assess_round_health(metrics_jsonl, manager_log, crash_summary=None,
                        best_dist_min_ever=None, stall_timeout=0,
                        detail_corpus_path=None, relevant_call_names=None,
                        relevant_repeat_threshold=1):
    """Score a fuzzing round and determine its health status.

    Args:
        metrics_jsonl: Path to metrics JSONL file from syz-manager.
        manager_log: Path to syz-manager log file.
        crash_summary: Dict with crash counts from crash_triage.
        best_dist_min_ever: Previous best minimum distance (cross-round).
        stall_timeout: Stall timeout in seconds (0 = disabled).
        detail_corpus_path: Optional detailCorpus.txt path for target-aware distance.
        relevant_call_names: Lower-cased syscall names considered target-relevant.

    Returns:
        Dict with status, score, reason, and detailed metrics.
        status is one of: "healthy", "stagnant", "boot_failed", "fatal"
    """
    metrics = []
    if metrics_jsonl and os.path.exists(metrics_jsonl):
        with open(metrics_jsonl) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        metrics.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    log_text = ""
    if manager_log and os.path.exists(manager_log):
        with open(manager_log) as f:
            log_text = f.read().lower()

    qemu_eof = "failed to create instance: failed to read from qemu: eof" in log_text
    # Distinguish distance stall from coverage stall — they need different triage
    dist_stall_terminated = "dist_stall_timeout:" in log_text
    coverage_stall_terminated = "stall_timeout:" in log_text and not dist_stall_terminated
    stall_terminated = dist_stall_terminated or coverage_stall_terminated

    if not metrics:
        if qemu_eof:
            return {"status": "boot_failed", "score": -9.0,
                    "reason": "qemu EOF during guest boot", "metrics": []}
        return {"status": "stagnant", "score": -5.0,
                "reason": "no metrics collected", "metrics": []}

    first, last = metrics[0], metrics[-1]

    exec_delta = max(0, last.get("exec_total", 0) - first.get("exec_total", 0))
    cover_delta = max(0, last.get("corpus_cover", 0) - first.get("corpus_cover", 0))
    crash_delta = max(0, last.get("crashes", 0) - first.get("crashes", 0))
    elapsed = max(1, last.get("timestamp", 0) - first.get("timestamp", 0))

    avg_exec = exec_delta / elapsed
    avg_cover = cover_delta / elapsed

    score = 0.0
    score += min(avg_exec / 5.0, 5.0)
    score += min(avg_cover, 3.0)
    score -= min((crash_delta / elapsed) * 30.0, 5.0)

    fatal = "all target calls are disabled" in log_text
    unknown_input_calls = log_text.count("unknown input call")
    machine_check_failed = "machine check failed" in log_text
    target_focus = 0.0
    crash_counts = (crash_summary or {}).get("counts", {})
    target_focus += crash_counts.get("target_related", 0) * 3.0
    target_focus += crash_counts.get("incidental", 0) * 0.5
    target_focus -= crash_counts.get("infra", 0) * 1.5
    target_focus -= unknown_input_calls * 0.25

    # ── Distance tracking ────────────────────────────────────────────
    # Filter out initial metrics where dist_min=0 before fuzzing starts.
    # Warmup phase: dist_min=0 AND (exec_total<10 OR corpus_cover==0).
    # corpus_cover==0 means the kernel hasn't reported real coverage yet
    # (e.g. exec=17 but no BBs covered → still initializing).
    dist_vals = [m["dist_min"] for m in metrics
                 if "dist_min" in m
                 and m.get("dist_min") != 4294967295  # UINT_MAX sentinel = no BB hit
                 and not (m.get("dist_min", 0) == 0
                          and (m.get("exec_total", 0) < 10
                               or m.get("corpus_cover", 0) == 0))]
    dist_min_first = dist_vals[0] if dist_vals else None
    dist_min_last = dist_vals[-1] if dist_vals else None
    dist_min_best = min(dist_vals) if dist_vals else None
    relevant_dist_min_best, relevant_prog_count = _relevant_dist_from_corpus(
        detail_corpus_path, relevant_call_names, repeat_threshold=relevant_repeat_threshold,
    )
    effective_dist_best = relevant_dist_min_best if relevant_dist_min_best is not None else dist_min_best

    # ── Null-coverage detection ──────────────────────────────────────────
    # syz-manager initialises dist_min=0 and only updates it when a corpus
    # program reaches a measured BB.  If all corpus programs have UINT_MAX
    # distance (no BB on the target path was ever hit), dist_min stays at 0
    # even after millions of executions — a "false zero" that makes the agent
    # think the target was reached and suppresses stagnation detection.
    #
    # We detect this by cross-checking the detailCorpus: when
    #   relevant_prog_count > 0  (target-relevant programs DO exist)
    #   relevant_dist_min_best is None  (every one of them is UINT_MAX)
    #   dist_min_best == 0              (metrics show the false zero)
    # we override effective_dist_best with a large sentinel so that
    # stagnation logic fires correctly.
    null_coverage = (
        relevant_prog_count > 0
        and relevant_dist_min_best is None
        and dist_min_best == 0
    )
    if null_coverage:
        # Use a large value — clearly not "target reached", but allows
        # stagnation detection and feeds the R4 roadmap as current_dist.
        effective_dist_best = 2_000_000_000

    dist_stagnant = False
    # If dist_stall_timeout fired, the fuzzer already proved distance is stuck —
    # trust that verdict even if first→last shows improvement within the round
    # (e.g. 2030→2010 improved but then stuck at 2010 for 300s).
    if dist_stall_terminated and effective_dist_best is not None and effective_dist_best > 0:
        dist_stagnant = True
    elif null_coverage and exec_delta > 100:
        # All corpus programs miss every target-adjacent BB → treat as stagnant.
        dist_stagnant = True
    elif effective_dist_best is not None and effective_dist_best > 0:
        if best_dist_min_ever is not None:
            dist_stagnant = effective_dist_best >= best_dist_min_ever
        elif len(dist_vals) > 5:
            dist_stagnant = dist_min_last >= dist_min_first

    # ── Status determination ─────────────────────────────────────────
    status = "healthy"
    reason = "fuzzing is progressing"

    if fatal:
        status = "fatal"
        reason = "all target calls are disabled"
        score -= 10.0
    elif machine_check_failed:
        status = "stagnant"
        reason = "machine check failed before stable coverage"
    elif exec_delta == 0:
        status = "stagnant"
        reason = "execution count did not increase"
    elif dist_stall_terminated:
        status = "stagnant"
        reason = f"distance stagnant at {effective_dist_best} (dist_stall_timeout fired)"
    elif coverage_stall_terminated:
        status = "stagnant"
        reason = f"coverage stalled for stall_timeout ({stall_timeout}s), terminated early"
    elif dist_stagnant and exec_delta > 500:
        status = "stagnant"
        if null_coverage:
            reason = (f"null coverage: {relevant_prog_count} relevant programs all have "
                      f"UINT_MAX distance — no target BB reached (syz-manager false-zero)")
        else:
            basis = "relevant distance" if relevant_dist_min_best is not None else "distance"
            reason = f"{basis} stagnant at {effective_dist_best} (not getting closer to target)"
    elif cover_delta == 0 and exec_delta > 100:
        status = "stagnant"
        reason = "coverage stalled despite executions"

    return {
        "status": status, "score": score, "reason": reason,
        "exec_delta": exec_delta, "cover_delta": cover_delta,
        "crash_delta": crash_delta, "elapsed": elapsed,
        "total_exec": last.get("exec_total", 0),
        "total_cover": last.get("corpus_cover", 0),
        "total_crashes": last.get("crashes", 0),
        "fatal": fatal, "metrics": metrics,
        "stall_terminated": stall_terminated,
        "dist_stall_terminated": dist_stall_terminated,
        "unknown_input_calls": unknown_input_calls,
        "machine_check_failed": machine_check_failed,
        "qemu_eof": qemu_eof,
        "target_focus": target_focus,
        "crash_counts": crash_counts,
        "dist_min_first": dist_min_first,
        "dist_min_last": dist_min_last,
        "dist_min_best": dist_min_best,
        "relevant_dist_min_best": relevant_dist_min_best,
        "relevant_prog_count": relevant_prog_count,
        "null_coverage": null_coverage,
        "effective_dist_min_best": effective_dist_best,
        "distance_basis": "relevant" if relevant_dist_min_best is not None else "raw",
        "dist_stagnant": dist_stagnant,
    }
