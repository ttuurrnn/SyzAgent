#!/usr/bin/env python3
"""
Lookup helper for curated CVE metadata.

Reads targets/recent_cves_2026.json and prints the matching entry as JSON so
shell launchers can avoid network-based CVE resolution when the curated file
already provides fix_commit/function/file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = REPO_ROOT / "targets" / "recent_cves_2026.json"


def parse_args():
    parser = argparse.ArgumentParser(description="Lookup a curated CVE entry")
    parser.add_argument("--cve", required=True, help="CVE ID to find")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="Curated CVE JSON path")
    return parser.parse_args()


def load_matches(path: Path, cve_id: str) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    wanted = cve_id.strip().upper()
    matches = []
    for group in ("selected", "shortlist"):
        items = data.get(group, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("cve", "")).strip().upper() == wanted:
                matches.append(item)
    return matches


def choose_best_match(matches: list[dict]) -> dict | None:
    if not matches:
        return None
    # Prefer entries that include all launch-critical fields.
    matches = sorted(
        matches,
        key=lambda item: (
            not bool(item.get("checkout_commit")),
            not bool(item.get("fix_commit")),
            not bool(item.get("function")),
            not bool(item.get("file")),
        ),
    )
    return matches[0]


def main() -> int:
    args = parse_args()
    match = choose_best_match(load_matches(Path(args.input), args.cve))
    if match is None:
        return 1
    print(json.dumps(match))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
