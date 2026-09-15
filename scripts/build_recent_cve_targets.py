#!/usr/bin/env python3
"""
Build a recent Linux-kernel CVE target list from a local linux/security/vulns.git clone.

The script reads CVE JSON records under:
  cve/published/<year>/CVE-YYYY-NNNN.json

It emits a SyzAgent-friendly shortlist compatible with targets/recent_cves_2026.json.
This avoids hard-coding CVE entries and lets us refresh the latest 6-month window once
the official repository is available locally.
"""

from __future__ import annotations

import argparse
import calendar
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import date, datetime
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_prebuilt_targets():
    import sys

    sys.path.insert(0, str(REPO_ROOT / "source" / "syzdirect" / "Runner"))
    from case_registry import PREBUILT_TARGETS  # pylint: disable=import-error

    return PREBUILT_TARGETS


PREBUILT_TARGETS = _load_prebuilt_targets()

BUG_KIND_PATTERNS = {
    "UAF": [
        r"use-after-free",
        r"\buaf\b",
    ],
    "OOB": [
        r"out-of-bounds",
        r"slab-out-of-bounds",
        r"buffer overflow",
        r"stack overflow",
        r"\boob\b",
    ],
    "RACE": [
        r"\brace\b",
        r"toctou",
    ],
    "NPD": [
        r"null pointer dereference",
        r"null deref",
        r"null-ptr-deref",
        r"\bnpd\b",
    ],
    "LEAK": [
        r"information leak",
        r"memory leak",
        r"\bleak\b",
    ],
}

INTERESTING_FILE_PREFIXES = (
    "net/",
    "kernel/bpf/",
    "io_uring/",
    "fs/",
    "drivers/",
    "mm/",
    "security/",
)


@dataclass
class ParsedCVE:
    cve: str
    published: date
    file_path: str
    function: str
    subject: str
    kinds: list[str]
    fix_commit: str
    checkout_commit: str
    prebuilt_idx: int | None
    callfile_template: str | None
    rationale: str
    score: int

    def as_selected(self) -> dict:
        item = {
            "cve": self.cve,
            "date": self.published.isoformat(),
            "kind": self.kinds,
            "file": self.file_path,
            "function": self.function or "",
            "fix_commit": self.fix_commit,
            "checkout_commit": self.checkout_commit,
            "subject": self.subject,
            "prebuilt_idx": self.prebuilt_idx,
        }
        if self.callfile_template:
            item["callfile_template"] = self.callfile_template
        if self.rationale:
            item["rationale"] = self.rationale
        return item


def parse_args():
    parser = argparse.ArgumentParser(description="Build recent SyzAgent CVE shortlist")
    parser.add_argument("--vulns-repo", required=True, help="Path to linux/security/vulns.git clone")
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "targets" / "recent_cves_2026.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--as-of",
        default=str(date.today()),
        help="Window end date (YYYY-MM-DD). Default: today",
    )
    parser.add_argument(
        "--months",
        type=int,
        default=6,
        help="Look-back window in calendar months (default: 6)",
    )
    parser.add_argument(
        "--selected-count",
        type=int,
        default=8,
        help="Number of top-ranked entries to place in selected[]",
    )
    parser.add_argument(
        "--min-shortlist",
        type=int,
        default=40,
        help="Warn if shortlist has fewer than this many entries",
    )
    parser.add_argument(
        "--shortlist-count",
        type=int,
        default=50,
        help="Number of top-ranked entries to retain in shortlist[]",
    )
    parser.add_argument(
        "--max-per-file",
        type=int,
        default=2,
        help="Preferred maximum number of shortlist entries per source file",
    )
    parser.add_argument(
        "--max-per-prebuilt",
        type=int,
        default=8,
        help="Preferred maximum number of shortlist entries per PREBUILT target index",
    )
    return parser.parse_args()


def parse_iso_date(text: str) -> date | None:
    if not text:
        return None
    text = text.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    if "T" in text:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
        except ValueError:
            return None
    return None


def subtract_calendar_months(value: date, months: int) -> date:
    if months < 0:
        raise ValueError("months must be non-negative")
    year = value.year
    month = value.month - months
    while month <= 0:
        month += 12
        year -= 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def extract_cve_id(record: dict) -> str:
    metadata = record.get("cveMetadata", {})
    return normalize_text(metadata.get("cveID") or metadata.get("cveId"))


@lru_cache(maxsize=None)
def git_path_date(vulns_repo: Path, rel_path: str, added_only: bool) -> date | None:
    args = ["git", "-C", str(vulns_repo), "log"]
    if added_only:
        args.append("--diff-filter=A")
    args.extend(["--format=%cs", "--", rel_path])
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    return parse_iso_date(lines[0])


@lru_cache(maxsize=None)
def git_added_dates(vulns_repo: Path, rel_dirs: tuple[str, ...]) -> dict[str, date]:
    if not rel_dirs:
        return {}
    args = [
        "git",
        "-C",
        str(vulns_repo),
        "log",
        "--diff-filter=A",
        "--format=__DATE__%cs",
        "--name-only",
        "--",
        *rel_dirs,
    ]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return {}

    current_date = None
    result = {}
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("__DATE__"):
            current_date = parse_iso_date(line.removeprefix("__DATE__"))
            continue
        if current_date is not None and line.endswith(".json") and line not in result:
            result[line] = current_date
    return result


def extract_published_date(
    vulns_repo: Path,
    json_path: Path,
    record: dict,
    added_dates: dict[str, date] | None = None,
) -> date | None:
    metadata = record.get("cveMetadata", {})
    for key in ("datePublished", "dateReserved", "dateUpdated"):
        published = parse_iso_date(metadata.get(key, ""))
        if published is not None:
            return published

    rel_path = json_path.resolve().relative_to(vulns_repo.resolve()).as_posix()
    if added_dates is not None:
        published = added_dates.get(rel_path)
        if published is not None:
            return published
    published = git_path_date(vulns_repo.resolve(), rel_path, added_only=True)
    if published is not None:
        return published
    return git_path_date(vulns_repo.resolve(), rel_path, added_only=False)


def normalize_text(value) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def derive_subject(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    title = normalize_text(cna.get("title"))
    if title:
        return title
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        value = normalize_text(desc.get("value"))
        if value:
            return value.splitlines()[0][:240]
    return ""


def extract_description_text(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    parts = []
    for desc in cna.get("descriptions", []):
        value = normalize_text(desc.get("value"))
        if value:
            parts.append(value)
    for problem in cna.get("problemTypes", []):
        for desc in problem.get("descriptions", []):
            value = normalize_text(desc.get("description"))
            if value:
                parts.append(value)
    return "\n".join(parts)


def classify_kinds(subject: str, description: str) -> list[str]:
    text = f"{subject}\n{description}".lower()
    kinds = []
    for label, patterns in BUG_KIND_PATTERNS.items():
        if any(re.search(pattern, text) for pattern in patterns):
            kinds.append(label)
    return kinds or ["UNKNOWN"]


def extract_program_files(record: dict) -> list[str]:
    cna = record.get("containers", {}).get("cna", {})
    files = []
    for affected in cna.get("affected", []):
        for path in affected.get("programFiles", []) or []:
            norm = normalize_text(path)
            if norm and norm not in files:
                files.append(norm)
    return files


def extract_fix_commit(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    urls = []
    for ref in cna.get("references", []):
        url = normalize_text(ref.get("url"))
        if url:
            urls.append(url)
    commit_re = re.compile(r"(?:id=|/c/|/commit/)([0-9a-f]{12,40})")
    matches = []
    for url in urls:
        match = commit_re.search(url)
        if match:
            matches.append(match.group(1))
    if matches:
        # Prefer the last reference: Linux CVE records عادة list stable backports
        # first and the original/mainline fix last, which is the better default
        # for pre-fix reproduction and source reuse.
        return matches[-1]
    return "auto-resolve"


def derive_checkout_commit(fix_commit: str) -> str:
    if fix_commit and fix_commit != "auto-resolve":
        return f"{fix_commit}~1"
    return "auto-resolve"


def extract_function(subject: str, description: str) -> str:
    text = f"{subject}\n{description}"
    patterns = [
        r"\bin ([A-Za-z_]\w+)\(\)",
        r"\bfix [^.\n]* in ([A-Za-z_]\w+)\(\)",
        r"`([A-Za-z_]\w+)`",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            name = match.group(1)
            if name not in {"Linux", "kernel"}:
                return name
    return ""


def map_prebuilt(file_path: str) -> tuple[int | None, str | None]:
    if not file_path:
        return None, None
    for target in PREBUILT_TARGETS:
        if target.get("func_path") == file_path:
            syscall = target.get("syscalls", [{}])[0].get("Target")
            return target["idx"], syscall
    for target in PREBUILT_TARGETS:
        tpath = target.get("func_path", "")
        if tpath and (
            file_path.startswith(str(Path(tpath).parent).rstrip("/") + "/")
            or tpath.startswith(str(Path(file_path).parent).rstrip("/") + "/")
        ):
            syscall = target.get("syscalls", [{}])[0].get("Target")
            return target["idx"], syscall
    return None, None


def build_rationale(file_path: str, prebuilt_idx: int | None, kinds: list[str]) -> str:
    reasons = []
    if prebuilt_idx is not None:
        reasons.append(f"Matches or neighbors PREBUILT_TARGETS[{prebuilt_idx}]")
    if file_path.startswith("net/"):
        reasons.append("Net subsystem is typically syscall reachable")
    if file_path.startswith("kernel/bpf/"):
        reasons.append("BPF verifier path is directly reachable from bpf syscalls")
    if file_path.startswith("io_uring/"):
        reasons.append("io_uring path is reachable from io_uring setup and net ops")
    if any(kind in {"UAF", "OOB", "RACE", "NPD"} for kind in kinds):
        reasons.append("Bug class is historically productive for directed fuzzing")
    return ". ".join(reasons)


def score_entry(file_path: str, prebuilt_idx: int | None, kinds: list[str], function: str) -> int:
    score = 0
    if prebuilt_idx is not None:
        score += 40
    if file_path.startswith("net/"):
        score += 25
    elif file_path.startswith("kernel/bpf/"):
        score += 20
    elif file_path.startswith("io_uring/"):
        score += 18
    elif file_path.startswith("fs/"):
        score += 12
    weight = {"UAF": 20, "OOB": 18, "RACE": 16, "NPD": 14, "LEAK": 8, "UNKNOWN": 0}
    score += max(weight.get(kind, 0) for kind in kinds)
    if function:
        score += 5
    return score


def choose_best_file(files: Iterable[str]) -> str:
    candidates = [path for path in files if path.startswith(INTERESTING_FILE_PREFIXES)]
    if not candidates:
        candidates = list(files)
    if not candidates:
        return ""
    candidates.sort(key=lambda path: (not path.startswith("net/"), len(path), path))
    return candidates[0]


def load_record(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_recent_records(vulns_repo: Path, window_start: date, window_end: date) -> Iterable[ParsedCVE]:
    base = vulns_repo / "cve" / "published"
    years = tuple(
        f"cve/published/{year}"
        for year in range(window_start.year, window_end.year + 1)
        if (base / str(year)).is_dir()
    )
    added_dates = git_added_dates(vulns_repo.resolve(), years)
    for year_dir in sorted(base.glob("*")):
        if not year_dir.is_dir():
            continue
        try:
            year = int(year_dir.name)
        except ValueError:
            continue
        if year < window_start.year or year > window_end.year:
            continue
        for json_path in sorted(year_dir.glob("CVE-*.json")):
            record = load_record(json_path)
            cve_id = extract_cve_id(record)
            published = extract_published_date(vulns_repo, json_path, record, added_dates)
            if not cve_id or not published:
                continue
            if published < window_start or published > window_end:
                continue

            subject = derive_subject(record)
            description = extract_description_text(record)
            file_path = choose_best_file(extract_program_files(record))
            if not file_path:
                continue

            kinds = classify_kinds(subject, description)
            function = extract_function(subject, description)
            fix_commit = extract_fix_commit(record)
            prebuilt_idx, callfile_template = map_prebuilt(file_path)
            rationale = build_rationale(file_path, prebuilt_idx, kinds)
            score = score_entry(file_path, prebuilt_idx, kinds, function)

            yield ParsedCVE(
                cve=cve_id,
                published=published,
                file_path=file_path,
                function=function,
                subject=subject,
                kinds=kinds,
                fix_commit=fix_commit,
                checkout_commit=derive_checkout_commit(fix_commit),
                prebuilt_idx=prebuilt_idx,
                callfile_template=callfile_template,
                rationale=rationale,
                score=score,
            )


def render_output(
    entries: list[ParsedCVE],
    window_start: date,
    window_end: date,
    selected_count: int,
    candidate_count: int | None = None,
) -> dict:
    selected = [entry.as_selected() for entry in entries[:selected_count]]
    shortlist = [entry.as_selected() for entry in entries]
    return {
        "_comment": (
            f"Recent (<=6 months from {window_end.isoformat()}) Linux kernel CVEs curated "
            "for SyzAgent directed fuzzing. Generated from a local linux/security/vulns.git clone."
        ),
        "_source": (
            f"linux/security/vulns.git local clone, filtered "
            f"{window_start.isoformat()}..{window_end.isoformat()}"
        ),
        "_candidate_count": candidate_count if candidate_count is not None else len(entries),
        "_shortlist_count": len(shortlist),
        "_selection_policy": {
            "selected_count": selected_count,
        },
        "selected": selected,
        "shortlist": shortlist,
    }


def select_diverse_entries(
    entries: list[ParsedCVE],
    shortlist_count: int,
    max_per_file: int,
    max_per_prebuilt: int,
) -> list[ParsedCVE]:
    chosen = []
    seen = set()
    file_counts: Counter[str] = Counter()
    prebuilt_counts: Counter[int] = Counter()

    def can_take(entry: ParsedCVE) -> bool:
        if file_counts[entry.file_path] >= max_per_file:
            return False
        if entry.prebuilt_idx is not None and prebuilt_counts[entry.prebuilt_idx] >= max_per_prebuilt:
            return False
        return True

    def record(entry: ParsedCVE):
        chosen.append(entry)
        seen.add(entry.cve)
        file_counts[entry.file_path] += 1
        if entry.prebuilt_idx is not None:
            prebuilt_counts[entry.prebuilt_idx] += 1

    for entry in entries:
        if len(chosen) >= shortlist_count:
            break
        if can_take(entry):
            record(entry)

    if len(chosen) < shortlist_count:
        for entry in entries:
            if len(chosen) >= shortlist_count:
                break
            if entry.cve in seen:
                continue
            record(entry)

    return chosen


def main():
    args = parse_args()
    vulns_repo = Path(args.vulns_repo).resolve()
    if not (vulns_repo / "cve" / "published").is_dir():
        raise SystemExit(f"missing cve/published under {vulns_repo}")

    window_end = parse_iso_date(args.as_of)
    if window_end is None:
        raise SystemExit(f"invalid --as-of date: {args.as_of}")
    window_start = subtract_calendar_months(window_end, args.months)

    entries = list(iter_recent_records(vulns_repo, window_start, window_end))
    entries.sort(key=lambda item: (-item.score, -item.published.toordinal(), item.cve))
    candidate_count = len(entries)
    shortlist_entries = select_diverse_entries(
        entries,
        args.shortlist_count,
        args.max_per_file,
        args.max_per_prebuilt,
    )
    payload = render_output(
        shortlist_entries,
        window_start,
        window_end,
        args.selected_count,
        candidate_count=candidate_count,
    )
    payload["_selection_policy"].update(
        {
            "shortlist_count": args.shortlist_count,
            "max_per_file": args.max_per_file,
            "max_per_prebuilt": args.max_per_prebuilt,
        }
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(
        f"[build_recent_cve_targets] ranked {len(entries)} candidate entries "
        f"({len(payload['selected'])} selected, kept {len(shortlist_entries)}) to {out_path}"
    )
    if len(entries) < args.min_shortlist:
        print(
            f"[build_recent_cve_targets] warning: shortlist has only {len(entries)} entries; "
            f"target was >= {args.min_shortlist}"
        )


if __name__ == "__main__":
    main()
