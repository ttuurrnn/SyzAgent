#!/usr/bin/env python3
"""Summarize flat syz-manager smoke runs.

The regular CVE summarizer expects SyzDirect agent_round_* directories.  Smoke
runs launched directly with syz-manager use a flatter layout:

  runtime/name_smoke_YYYYMMDD/
    logs/manager.log
    workdir/crashes/<hash>/{description,report0}

This script produces a compact JSON or Markdown snapshot and filters known
infrastructure noise before calling a crash a candidate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import re
from pathlib import Path


STATUS_RE = re.compile(
    r"VMs\s+(?P<vms>\d+),\s+executed\s+(?P<executed>\d+),\s+cover\s+(?P<cover>\d+),"
    r"\s+signal\s+(?P<signal>\d+/\d+),\s+crashes\s+(?P<crashes>\d+),"
    r"\s+repro\s+(?P<repro>\d+),\s+dist\s+(?P<dist>\S+)"
)

INFRA_PATTERNS = (
    "memory cgroup out of memory",
    "bug: max_lockdep_keys too low",
    "at do_notify_parent",
    "warning: kernel/signal.c",
    "no output from test machine",
    "syzfatal:",
    "panic: all target calls are disabled",
)

REAL_CRASH_RE = re.compile(
    r"kasan|ubsan|use-after-free|out-of-bounds|null-ptr-deref|"
    r"stack-out-of-bounds|slab-out-of-bounds|invalid-free|double-free|kernel bug at",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime-root",
        default=str(Path.home() / "syzdirect-runtime" / "cve"),
        help="runtime directory containing *_smoke_* runs",
    )
    parser.add_argument("--pattern", default="*_smoke_*", help="glob under runtime root")
    parser.add_argument("--output", default="", help="optional output path")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    return parser.parse_args()


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def last_status(log_path: Path) -> dict:
    status = {}
    last_status_idx = -1
    shutdown_idx = -1
    for idx, line in enumerate(read_text(log_path).splitlines()):
        if "shutting down" in line.lower():
            shutdown_idx = idx
        match = STATUS_RE.search(line)
        if not match:
            continue
        last_status_idx = idx
        status = {
            "line": line,
            "vms": int(match.group("vms")),
            "executed": int(match.group("executed")),
            "cover": int(match.group("cover")),
            "signal": match.group("signal"),
            "crashes": int(match.group("crashes")),
            "repro": int(match.group("repro")),
            "dist": match.group("dist"),
        }
    if status:
        status["shutting_down"] = shutdown_idx > last_status_idx
    return status


def classify_crash(crash_dir: Path) -> dict:
    description = read_text(crash_dir / "description").strip().splitlines()
    title = description[0] if description else "unknown crash"
    report = read_text(crash_dir / "report0")
    text = f"{title}\n{report}".lower()
    infra = any(pattern in text for pattern in INFRA_PATTERNS)
    real_signature = bool(REAL_CRASH_RE.search(title) or REAL_CRASH_RE.search(report))
    if infra:
        bucket = "infra"
    elif real_signature:
        bucket = "candidate"
    else:
        bucket = "unknown"
    return {
        "id": crash_dir.name,
        "title": title,
        "bucket": bucket,
        "path": str(crash_dir),
    }


def summarize_run(run_dir: Path) -> dict:
    crashes = []
    crash_root = run_dir / "workdir" / "crashes"
    if crash_root.is_dir():
        for crash_dir in sorted(crash_root.iterdir()):
            if crash_dir.is_dir() and ((crash_dir / "description").exists() or (crash_dir / "report0").exists()):
                crashes.append(classify_crash(crash_dir))
    status = last_status(run_dir / "logs" / "manager.log")
    counts = {
        "total": len(crashes),
        "candidate": sum(1 for item in crashes if item["bucket"] == "candidate"),
        "infra": sum(1 for item in crashes if item["bucket"] == "infra"),
        "unknown": sum(1 for item in crashes if item["bucket"] == "unknown"),
    }
    live_manager = is_live_manager(run_dir)
    return {
        "name": run_dir.name,
        "path": str(run_dir),
        "status": status,
        "crash_counts": counts,
        "crashes": crashes,
        "running": live_manager,
        "live_manager": live_manager,
    }


def is_live_manager(run_dir: Path) -> bool:
    try:
        proc = subprocess.run(
            ["ps", "-eo", "comm,args"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
    config_path = str(run_dir / "config.json")
    return any(
        line.startswith("syz-manager ") and config_path in line
        for line in proc.stdout.splitlines()
    )


def render_markdown(rows: list[dict]) -> str:
    lines = [
        "# Smoke Run Summary",
        "",
        "| run | vms | executed | cover | crashes | candidates | infra | status |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        status = row.get("status") or {}
        counts = row["crash_counts"]
        state = "running" if row["running"] else "stopped/no-vm"
        lines.append(
            "| {name} | {vms} | {executed} | {cover} | {crashes} | {candidate} | {infra} | {state} |".format(
                name=row["name"],
                vms=status.get("vms", 0),
                executed=status.get("executed", 0),
                cover=status.get("cover", 0),
                crashes=counts["total"],
                candidate=counts["candidate"],
                infra=counts["infra"],
                state=state,
            )
        )
    lines.append("")
    candidate_rows = [
        (row, crash)
        for row in rows
        for crash in row["crashes"]
        if crash["bucket"] == "candidate"
    ]
    if candidate_rows:
        lines.append("## Candidate Crashes")
        lines.append("")
        for row, crash in candidate_rows:
            lines.append(f"- `{row['name']}`: {crash['title']} ({crash['path']})")
    else:
        lines.append("No candidate crashes after infra-noise filtering.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    root = Path(args.runtime_root)
    rows = [summarize_run(path) for path in sorted(root.glob(args.pattern)) if path.is_dir()]
    if args.format == "json":
        output = json.dumps(rows, indent=2)
    else:
        output = render_markdown(rows)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
