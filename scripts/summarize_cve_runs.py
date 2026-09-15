#!/usr/bin/env python3
"""
Summarize SyzDirect recent-CVE run directories.

Expected runtime layout:
  $SYZDIRECT_RUNTIME/<cve_name>/
    fuzzres/case_0/xidx_0/agent_round_1/
      logs_x0/metrics.jsonl
      logs_x0/manager.log
      crash_summary.json
    fuzzres/case_0/xidx_1/agent_round_1/
      ...

The script emits a compact JSON summary plus a human-readable table that helps
answer:
  - why older runs failed
  - which new CVEs look promising
  - where distance stagnated / crashes appeared
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_DIR = REPO_ROOT / "source" / "syzdirect" / "Runner"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from agent_health import assess_round_health  # pylint: disable=import-error
from crash_triage import INFRA_MARKERS  # pylint: disable=import-error

GENERIC_BASE_CALLS = {
    "socket", "bind", "write", "read", "close", "open", "openat",
    "sendmsg", "sendto", "recvmsg", "recvfrom", "connect", "accept",
    "accept4", "listen", "ioctl", "setsockopt", "getsockopt",
}


@dataclass
class RoundSummary:
    round_num: int
    xidx: str
    status: str
    reason: str
    best_distance: int | None
    total_crashes: int
    target_related_crashes: int
    incidental_unknown_crashes: int
    infra_crashes: int
    null_coverage: bool

    def as_dict(self) -> dict:
        return {
            "round": self.round_num,
            "xidx": self.xidx,
            "status": self.status,
            "reason": self.reason,
            "best_distance": self.best_distance,
            "total_crashes": self.total_crashes,
            "target_related_crashes": self.target_related_crashes,
            "incidental_unknown_crashes": self.incidental_unknown_crashes,
            "infra_crashes": self.infra_crashes,
            "null_coverage": self.null_coverage,
        }


def parse_args():
    parser = argparse.ArgumentParser(description="Summarize recent SyzDirect CVE runs")
    parser.add_argument(
        "--runtime-root",
        default=os.environ.get("SYZDIRECT_RUNTIME", str(Path.home() / "syzdirect-runtime" / "cve")),
        help="Root directory containing one subdirectory per CVE run",
    )
    parser.add_argument("--cve", nargs="*", default=None, help="Optional CVE ids to filter")
    parser.add_argument(
        "--output",
        default="",
        help="Optional JSON output path",
    )
    return parser.parse_args()


def normalize_cve_dir_name(cve_id: str) -> str:
    return cve_id.lower().replace("-", "_")


def load_json_if_exists(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def load_relevant_call_names(case_dir: Path) -> list[str]:
    callfile = case_dir / "fuzzinps" / "case_0" / "inp_0.json"
    if not callfile.exists():
        return []
    try:
        data = json.loads(callfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    names = []
    flat_names = []
    has_variant = False
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            target = str(entry.get("Target", "")).strip().lower()
            if target:
                flat_names.append(target)
                if "$" in target:
                    has_variant = True
            for rel in entry.get("Relate", []) or []:
                rel_name = str(rel).strip().lower()
                if rel_name:
                    flat_names.append(rel_name)
                    if "$" in rel_name:
                        has_variant = True
    for lowered in flat_names:
        base = lowered.split("$", 1)[0]
        if "$" not in lowered and has_variant and base in GENERIC_BASE_CALLS:
            continue
        names.append(lowered)
        if ("$" not in lowered or base not in GENERIC_BASE_CALLS) and base and base not in names:
            names.append(base)
    deduped = []
    seen = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def collect_round_dirs(case_dir: Path) -> list[tuple[str, Path]]:
    rounds = []
    fuzzres_root = case_dir / "fuzzres"
    if fuzzres_root.is_dir():
        for xidx_dir in sorted(fuzzres_root.glob("case_*/xidx_*")):
            if not xidx_dir.is_dir():
                continue
            xidx = xidx_dir.name
            for round_dir in sorted(xidx_dir.glob("agent_round_*")):
                if round_dir.is_dir():
                    rounds.append((xidx, round_dir))
    if rounds:
        return rounds

    # Fallback for older flat layouts.
    for child in sorted(case_dir.iterdir() if case_dir.exists() else []):
        if child.is_dir() and child.name.startswith("agent_round_"):
            rounds.append(("xidx_0", child))
    return rounds


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def _read_manifest_text(manifest: dict) -> str:
    parts = [str(manifest.get("description", ""))]
    paths = manifest.get("paths") or {}
    for key in ("report", "log"):
        path = paths.get(key)
        if not path:
            continue
        try:
            parts.append(Path(path).read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(parts).lower()


def _is_infra_crash(manifest: dict) -> bool:
    text = _read_manifest_text(manifest)
    return any(marker in text for marker in INFRA_MARKERS)


def sanitized_crash_counts(crash_summary: dict) -> dict:
    """Re-count crashes, demoting known infra noise in older summaries.

    Older agent runs wrote crash_summary.json before the infra filters covered
    memcg OOM, do_notify_parent, and MAX_LOCKDEP_KEYS reports. Re-reading the
    manifest paths here keeps historical summaries from showing false
    target_hit results.
    """
    manifests = crash_summary.get("crashes")
    if not isinstance(manifests, list):
        return crash_summary.get("counts", {})

    counts = {
        "total": 0,
        "target_related": 0,
        "incidental": 0,
        "infra": 0,
        "known": 0,
        "incidental_unknown": 0,
    }
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        counts["total"] += 1
        bucket = str(manifest.get("bucket", "incidental"))
        if _is_infra_crash(manifest):
            bucket = "infra"
        if bucket == "target_related":
            counts["target_related"] += 1
        elif bucket == "infra":
            counts["infra"] += 1
        else:
            counts["incidental"] += 1
            if not manifest.get("known_rule"):
                counts["incidental_unknown"] += 1
        if manifest.get("known_rule"):
            counts["known"] += 1
    return counts


def summarize_round(xidx: str, round_dir: Path, best_dist_min_ever: int | None,
                    relevant_call_names: list[str]) -> tuple[RoundSummary, int | None]:
    round_num = int(round_dir.name.rsplit("_", 1)[-1])
    metrics_path = first_existing([
        round_dir / "logs_x0" / "metrics.jsonl",
        round_dir / "logs_x1" / "metrics.jsonl",
    ])
    manager_log = first_existing([
        round_dir / "logs_x0" / "manager.log",
        round_dir / "logs_x1" / "manager.log",
    ])
    detail_corpus = first_existing([
        round_dir / "workdir_x0" / "detailCorpus.txt",
        round_dir / "workdir_x1" / "detailCorpus.txt",
    ])
    crash_summary = load_json_if_exists(round_dir / "crash_summary.json")
    sanitized_summary = dict(crash_summary)
    if crash_summary:
        sanitized_summary["counts"] = sanitized_crash_counts(crash_summary)

    health = assess_round_health(
        str(metrics_path) if metrics_path else "",
        str(manager_log) if manager_log else "",
        crash_summary=sanitized_summary or None,
        best_dist_min_ever=best_dist_min_ever,
        detail_corpus_path=str(detail_corpus) if detail_corpus else None,
        relevant_call_names=relevant_call_names,
    )
    best = health.get("effective_dist_min_best")
    if isinstance(best, int) and best > 0:
        next_best = best if best_dist_min_ever is None else min(best_dist_min_ever, best)
    else:
        next_best = best_dist_min_ever

    counts = sanitized_summary.get("counts", {})
    summary = RoundSummary(
        round_num=round_num,
        xidx=xidx,
        status=health.get("status", "unknown"),
        reason=health.get("reason", ""),
        best_distance=best if isinstance(best, int) else None,
        total_crashes=int(counts.get("total", 0)),
        target_related_crashes=int(counts.get("target_related", 0)),
        incidental_unknown_crashes=int(counts.get("incidental_unknown", 0)),
        infra_crashes=int(counts.get("infra", 0)),
        null_coverage=bool(health.get("null_coverage", False)),
    )
    return summary, next_best


def classify_case(rounds: list[RoundSummary]) -> tuple[str, str]:
    if not rounds:
        return "not_started", "no agent rounds found"
    if any(r.target_related_crashes > 0 for r in rounds):
        return "target_hit", "target-related crash observed"
    if any(r.best_distance == 0 for r in rounds if r.best_distance is not None):
        return "distance_zero", "distance reached zero"
    if any(r.total_crashes > 0 for r in rounds):
        return "incidental_crash", "crashes found but none target-related"
    last = rounds[-1]
    if last.null_coverage:
        return "null_coverage", "relevant programs never hit target-adjacent BBs"
    if "distance stagnant" in last.reason.lower():
        return "distance_stall", last.reason
    if "coverage stalled" in last.reason.lower():
        return "coverage_stall", last.reason
    return last.status, last.reason


def summarize_case(case_dir: Path) -> dict:
    best_dist_by_xidx: dict[str, int | None] = {}
    round_summaries = []
    relevant_call_names = load_relevant_call_names(case_dir)
    for xidx, round_dir in collect_round_dirs(case_dir):
        summary, best_dist_by_xidx[xidx] = summarize_round(
            xidx, round_dir, best_dist_by_xidx.get(xidx), relevant_call_names
        )
        round_summaries.append(summary)

    classification, reason = classify_case(round_summaries)
    best_distance = None
    vals = [r.best_distance for r in round_summaries if isinstance(r.best_distance, int)]
    if vals:
        best_distance = min(vals)

    xidx_summary = {}
    for xidx in sorted({r.xidx for r in round_summaries}):
        xrounds = [r for r in round_summaries if r.xidx == xidx]
        xvals = [r.best_distance for r in xrounds if isinstance(r.best_distance, int)]
        xclass, xreason = classify_case(xrounds)
        xidx_summary[xidx] = {
            "classification": xclass,
            "reason": xreason,
            "round_count": len(xrounds),
            "best_distance": min(xvals) if xvals else None,
            "target_related_crashes": sum(r.target_related_crashes for r in xrounds),
            "total_crashes": sum(r.total_crashes for r in xrounds),
        }

    return {
        "cve": case_dir.name.replace("_", "-").upper(),
        "workdir": str(case_dir),
        "classification": classification,
        "reason": reason,
        "best_distance": best_distance,
        "relevant_call_names": relevant_call_names,
        "round_count": len(round_summaries),
        "total_crashes": sum(r.total_crashes for r in round_summaries),
        "target_related_crashes": sum(r.target_related_crashes for r in round_summaries),
        "xidx": xidx_summary,
        "rounds": [r.as_dict() for r in round_summaries],
    }


def print_table(rows: list[dict]):
    print("[summarize_cve_runs]")
    if not rows:
        print("no runs found")
        return
    for row in rows:
        print(
            f"{row['cve']}: class={row['classification']} rounds={row['round_count']} "
            f"best_dist={row['best_distance']} target_crash={row['target_related_crashes']} "
            f"total_crash={row['total_crashes']}"
        )
        print(f"  reason: {row['reason']}")


def main():
    args = parse_args()
    runtime_root = Path(args.runtime_root).resolve()
    if not runtime_root.exists():
        raise SystemExit(f"runtime root not found: {runtime_root}")

    selected = None
    if args.cve:
        selected = {normalize_cve_dir_name(cve) for cve in args.cve}

    rows = []
    for child in sorted(runtime_root.iterdir()):
        if not child.is_dir():
            continue
        if selected and child.name not in selected:
            continue
        rows.append(summarize_case(child))

    rows.sort(key=lambda row: (
        row["classification"] not in {"target_hit", "distance_zero"},
        row["best_distance"] is None,
        row["best_distance"] if row["best_distance"] is not None else 10**18,
        row["cve"],
    ))

    print_table(rows)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"[summarize_cve_runs] wrote {out}")


if __name__ == "__main__":
    main()
