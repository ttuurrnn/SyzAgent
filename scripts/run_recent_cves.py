#!/usr/bin/env python3
"""
Batch runner for curated recent CVE targets.

Reads targets/recent_cves_2026.json-style files and either:
  - prints the launch plan (default)
  - executes scripts/launch_cve_run.sh sequentially

This bridges the curated recent-CVE list into the existing directed-fuzz
runner without hand-writing per-CVE shell commands.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = REPO_ROOT / "targets" / "recent_cves_2026.json"
LAUNCH_SCRIPT = REPO_ROOT / "scripts" / "launch_cve_run.sh"


@dataclass
class LaunchItem:
    cve: str
    function: str
    file_path: str
    fix_commit: str
    checkout_commit: str
    prebuilt_idx: int | None
    payload: dict
    run_tag: str = ""

    @classmethod
    def from_dict(cls, payload: dict) -> "LaunchItem":
        return cls(
            cve=str(payload.get("cve", "")).strip(),
            function=str(payload.get("function", "") or "").strip(),
            file_path=str(payload.get("file", "") or "").strip(),
            fix_commit=str(payload.get("fix_commit", "") or "").strip(),
            checkout_commit=str(payload.get("checkout_commit", "") or "").strip(),
            prebuilt_idx=payload.get("prebuilt_idx"),
            payload=payload,
        )

    def env_overrides(self, *, from_stage: str, verify_patch: bool) -> dict[str, str]:
        env = {}
        if from_stage:
            env["FROM_STAGE"] = from_stage
        if self.run_tag:
            env["RUN_TAG"] = self.run_tag
        if getattr(self, "linux_template", ""):
            env["SYZDIRECT_LINUX_TEMPLATE"] = self.linux_template
        if self.function:
            env["FUNC_OVERRIDE"] = self.function
        if self.file_path:
            env["FILE_OVERRIDE"] = self.file_path
        if verify_patch:
            env["VERIFY_PATCH"] = "1"
            if self.fix_commit and self.fix_commit != "auto-resolve":
                env["COMMIT_OVERRIDE"] = self.fix_commit
        elif self.checkout_commit and self.checkout_commit != "auto-resolve":
            env["COMMIT_OVERRIDE"] = self.checkout_commit
        return env


def parse_args():
    parser = argparse.ArgumentParser(description="Batch-launch curated recent CVEs")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="Path to curated CVE JSON")
    parser.add_argument(
        "--group",
        choices=["selected", "shortlist"],
        default="selected",
        help="Which group from the JSON file to use",
    )
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of entries to use (0=all)")
    parser.add_argument("--cve", nargs="*", default=None, help="Specific CVE IDs to run")
    parser.add_argument("--hours", type=int, default=1, help="Hours per fuzz round")
    parser.add_argument("--jobs", type=int, default=8, help="CPU count passed to launch_cve_run.sh")
    parser.add_argument("--agent-rounds", type=int, default=10, help="Agent rounds passed to launch_cve_run.sh")
    parser.add_argument(
        "--from-stage",
        default="",
        help="Optional SyzDirect stage to resume from (source/bitcode/analyze/target/distance/fuzz)",
    )
    parser.add_argument(
        "--verify-patch",
        action="store_true",
        help="Run in patch verification mode using fix_commit when present",
    )
    parser.add_argument(
        "--only-prebuilt",
        action="store_true",
        help="Keep only entries mapped to an existing PREBUILT_TARGETS index",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the launch commands. Default is dry-run.",
    )
    parser.add_argument(
        "--run-tag",
        default="",
        help="Optional suffix to isolate workdirs for a fresh batch run",
    )
    parser.add_argument(
        "--linux-template",
        default="",
        help="Optional local linux git clone to reuse instead of cloning from GitHub",
    )
    return parser.parse_args()


def load_items(path: Path, group: str) -> list[LaunchItem]:
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_items = data.get(group, [])
    if not isinstance(raw_items, list):
        raise SystemExit(f"{path} group '{group}' is not a list")
    items = [LaunchItem.from_dict(item) for item in raw_items if isinstance(item, dict)]
    items = [item for item in items if item.cve]
    return items


def select_items(items: list[LaunchItem], args) -> list[LaunchItem]:
    selected = items
    if args.cve:
        wanted = {item.upper() for item in args.cve}
        selected = [item for item in selected if item.cve.upper() in wanted]
    if args.only_prebuilt:
        selected = [item for item in selected if item.prebuilt_idx is not None]
    if args.limit > 0:
        selected = selected[:args.limit]
    if args.run_tag:
        for item in selected:
            item.run_tag = args.run_tag
    if args.linux_template:
        for item in selected:
            item.linux_template = args.linux_template
    return selected


def render_env_prefix(env: dict[str, str]) -> str:
    if not env:
        return ""
    return " ".join(f"{key}={value}" for key, value in env.items())


def build_command(item: LaunchItem, args) -> tuple[list[str], dict[str, str]]:
    env = item.env_overrides(from_stage=args.from_stage, verify_patch=args.verify_patch)
    cmd = [
        str(LAUNCH_SCRIPT),
        item.cve,
        str(args.hours),
        str(args.jobs),
        str(args.agent_rounds),
    ]
    return cmd, env


def run_plan(items: list[LaunchItem], args) -> int:
    print(f"[run_recent_cves] input={args.input} group={args.group} count={len(items)} execute={args.execute}")
    if not items:
        print("[run_recent_cves] no matching CVE entries")
        return 0

    for index, item in enumerate(items, start=1):
        cmd, env = build_command(item, args)
        env_prefix = render_env_prefix(env)
        summary = f"{index:02d}. {item.cve}"
        if item.function:
            summary += f" func={item.function}"
        if item.file_path:
            summary += f" file={item.file_path}"
        if item.prebuilt_idx is not None:
            summary += f" prebuilt={item.prebuilt_idx}"
        print(summary)
        print(f"    {env_prefix + ' ' if env_prefix else ''}{' '.join(cmd)}")

        if not args.execute:
            continue

        child_env = os.environ.copy()
        child_env.update(env)
        result = subprocess.run(cmd, cwd=str(REPO_ROOT), env=child_env, check=False)
        if result.returncode != 0:
            print(f"[run_recent_cves] stopped at {item.cve} (rc={result.returncode})")
            return result.returncode

    return 0


def main():
    args = parse_args()
    items = load_items(Path(args.input), args.group)
    items = select_items(items, args)
    raise SystemExit(run_plan(items, args))


if __name__ == "__main__":
    main()
