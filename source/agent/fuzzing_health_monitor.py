#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class WindowSummary:
    decision: str
    status: str
    score: float
    reason: str
    window_seconds: int
    exec_delta: int
    cover_delta: int
    crash_delta: int
    distance_delta: float | None
    total_exec: int
    total_cover: int
    total_crashes: int
    all_target_calls_disabled: bool
    repeated_fatal_count: int
    manager_alive: bool
    avg_exec_per_sec: float
    avg_cover_per_sec: float
    avg_crash_per_sec: float
    recent_log_excerpt: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a continuous fuzzing window and decide whether to continue")
    parser.add_argument("--metrics", required=True, help="metrics.jsonl path")
    parser.add_argument("--manager-log", required=True, help="manager.log path")
    parser.add_argument("--window-seconds", type=int, required=True, help="window size in seconds")
    parser.add_argument("--output", required=True, help="output JSON path")
    parser.add_argument("--llm-hook-cmd", help="optional shell command that receives summary path as its only argument")
    parser.add_argument("--manager-alive", action="store_true", help="whether the manager process was alive at sample time")
    return parser.parse_args()


def load_metrics(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            entries.append(item)
    return entries


def parse_log_time(prefix: str) -> int | None:
    try:
        dt = datetime.strptime(prefix, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    return int(dt.timestamp())


def load_recent_log_lines(path: Path, window_seconds: int) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    timestamps: list[tuple[int | None, str]] = []
    for line in lines:
        prefix = line[:19]
        timestamps.append((parse_log_time(prefix), line))
    recent_epoch = max((ts for ts, _ in timestamps if ts is not None), default=None)
    if recent_epoch is None:
        return lines[-200:]
    cutoff = recent_epoch - window_seconds
    return [line for ts, line in timestamps if ts is None or ts >= cutoff]


def recent_window_metrics(entries: list[dict[str, Any]], window_seconds: int) -> list[dict[str, Any]]:
    if not entries:
        return []
    latest_ts = max(int(item.get("timestamp", 0)) for item in entries)
    cutoff = latest_ts - window_seconds
    return [item for item in entries if int(item.get("timestamp", 0)) >= cutoff]


def metric_delta(window: list[dict[str, Any]], key: str) -> int:
    if not window:
        return 0
    first = int(window[0].get(key, 0))
    last = int(window[-1].get(key, 0))
    return max(0, last - first)


def elapsed_seconds(window: list[dict[str, Any]], fallback: int) -> int:
    if len(window) < 2:
        return max(1, fallback)
    start = int(window[0].get("timestamp", 0))
    end = int(window[-1].get("timestamp", 0))
    return max(1, end - start)


def maybe_distance_delta(window: list[dict[str, Any]]) -> float | None:
    if not window:
        return None
    values: list[float] = []
    for item in window:
        if "distance_min" not in item:
            return None
        try:
            values.append(float(item["distance_min"]))
        except (TypeError, ValueError):
            return None
    if len(values) < 2:
        return None
    return values[-1] - values[0]


def apply_llm_hook(summary: WindowSummary, llm_hook_cmd: str) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="fuzz_health_") as tmpdir:
        summary_path = Path(tmpdir) / "summary.json"
        summary_path.write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")
        command = f"{llm_hook_cmd} {shlex.quote(str(summary_path))}"
        try:
            result = subprocess.run(
                ["bash", "-lc", command],
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return summary.decision, "LLM hook timed out"
        if result.returncode != 0:
            return summary.decision, f"LLM hook failed: {result.stderr.strip() or result.stdout.strip()}"
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return summary.decision, "LLM hook returned non-JSON output"
        decision = payload.get("decision")
        reason = payload.get("reason")
        if decision not in {
            "continue",
            "stop",
            "intervene_r1",
            "intervene_r2",
            "intervene_r3",
            "intervene_mixed",
        }:
            return summary.decision, "LLM hook returned invalid decision"
        return decision, reason or summary.reason


def main() -> int:
    args = parse_args()
    metrics = load_metrics(Path(args.metrics))
    window = recent_window_metrics(metrics, args.window_seconds)
    recent_lines = load_recent_log_lines(Path(args.manager_log), args.window_seconds)
    joined = "\n".join(recent_lines).lower()

    exec_delta = metric_delta(window, "exec_total")
    cover_delta = metric_delta(window, "corpus_cover")
    crash_delta = metric_delta(window, "crashes")
    elapsed = elapsed_seconds(window, args.window_seconds)
    distance_delta = maybe_distance_delta(window)
    total_exec = int(metrics[-1].get("exec_total", 0)) if metrics else 0
    total_cover = int(metrics[-1].get("corpus_cover", 0)) if metrics else 0
    total_crashes = int(metrics[-1].get("crashes", 0)) if metrics else 0
    fatal_count = joined.count("all target calls are disabled")
    all_target_calls_disabled = fatal_count > 0
    recent_log_excerpt = recent_lines[-40:]

    avg_exec_per_sec = exec_delta / elapsed
    avg_cover_per_sec = cover_delta / elapsed
    avg_crash_per_sec = crash_delta / elapsed

    score = 0.0
    score += min(avg_exec_per_sec / 5.0, 5.0)
    score += min(avg_cover_per_sec, 3.0)
    score -= min(avg_crash_per_sec * 30.0, 5.0)
    if distance_delta is not None:
        score += 2.0 if distance_delta < 0 else -1.0
    if all_target_calls_disabled:
        score -= 10.0

    status = "healthy"
    decision = "continue"
    reason = "fuzzing is progressing"

    if all_target_calls_disabled:
        status = "fatal"
        decision = "stop"
        reason = "runtime reported that all target calls are disabled"
    elif total_exec == 0 or exec_delta == 0:
        status = "stagnant"
        reason = "execution count did not increase during the scoring window"
    elif distance_delta is not None and distance_delta >= 0:
        status = "stagnant"
        reason = "distance did not decrease during the scoring window"
    elif cover_delta == 0 and crash_delta > 0:
        status = "stagnant"
        reason = "coverage stalled while crashes kept increasing"

    summary = WindowSummary(
        decision=decision,
        status=status,
        score=score,
        reason=reason,
        window_seconds=args.window_seconds,
        exec_delta=exec_delta,
        cover_delta=cover_delta,
        crash_delta=crash_delta,
        distance_delta=distance_delta,
        total_exec=total_exec,
        total_cover=total_cover,
        total_crashes=total_crashes,
        all_target_calls_disabled=all_target_calls_disabled,
        repeated_fatal_count=fatal_count,
        manager_alive=args.manager_alive,
        avg_exec_per_sec=avg_exec_per_sec,
        avg_cover_per_sec=avg_cover_per_sec,
        avg_crash_per_sec=avg_crash_per_sec,
        recent_log_excerpt=recent_log_excerpt,
    )

    if summary.status == "stagnant" and args.llm_hook_cmd:
        decision, reason = apply_llm_hook(summary, args.llm_hook_cmd)
        summary.decision = decision
        summary.reason = reason

    Path(args.output).write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
