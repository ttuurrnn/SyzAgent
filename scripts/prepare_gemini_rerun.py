#!/usr/bin/env python3
"""
Prepare an existing recent-CVE runtime for a Gemini-backed rerun.

What it does:
  1. load the current workdir callfile
  2. normalize syscall names against the local syzkaller DB
  3. drop unsupported names and duplicate/generic noise where possible
  4. optionally write the sanitized callfile back
  5. print or execute the `launch_cve_run.sh` command with Gemini env

This is intended for already-prepared runtimes such as:
  <runtime-root>/cve_2026_23277
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_DIR = REPO_ROOT / "source" / "syzdirect" / "Runner"
import sys

if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from syscall_normalize import normalize_callfile_entries  # pylint: disable=import-error


GENERIC_EXACT_CALLS = {
    "socket", "bind", "write", "read", "close", "open", "openat",
    "sendmsg", "sendto", "recvmsg", "recvfrom", "connect", "accept",
    "accept4", "listen", "ioctl", "setsockopt", "getsockopt",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Prepare Gemini rerun for existing recent-CVE runtimes")
    parser.add_argument(
        "--runtime-root",
        default=os.environ.get("SYZDIRECT_RUNTIME", str(Path.home() / "syzdirect_runtime" / "cve")),
        help="Root directory containing cve_<id> workdirs",
    )
    parser.add_argument("--cve", nargs="+", required=True, help="CVE IDs to prepare")
    parser.add_argument("--hours", type=int, default=1, help="Hours per round for relaunch")
    parser.add_argument("--jobs", type=int, default=8, help="CPU count for relaunch")
    parser.add_argument("--agent-rounds", type=int, default=10, help="Agent rounds for relaunch")
    parser.add_argument("--gemini-model", default="gemini-2.5-pro", help="Gemini model name")
    parser.add_argument("--from-stage", default="fuzz", help="Pipeline stage to resume from")
    parser.add_argument(
        "--plan-dir",
        default=str(REPO_ROOT / ".runtime" / "gemini_rerun_plans"),
        help="Directory to write sanitized callfile copies and launch scripts",
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not modify files or launch")
    parser.add_argument("--execute", action="store_true", help="Actually launch rerun commands")
    return parser.parse_args()


def normalize_cve_dir_name(cve_id: str) -> str:
    return cve_id.lower().replace("-", "_")


def callfile_path(runtime_root: Path, cve_id: str) -> Path:
    return runtime_root / normalize_cve_dir_name(cve_id) / "fuzzinps" / "case_0" / "inp_0.json"


def sanitize_entries(entries: list[dict]) -> list[dict]:
    normalized = normalize_callfile_entries(entries)
    has_variant = any(
        "$" in value
        for entry in normalized
        for value in [entry.get("Target", "")] + list(entry.get("Relate", []) or [])
    )
    cleaned = []
    for entry in normalized:
        target = entry.get("Target", "")
        related = []
        for name in entry.get("Relate", []) or []:
            lowered = name.lower()
            if has_variant and "$" not in lowered and lowered in GENERIC_EXACT_CALLS:
                continue
            if lowered == target.lower():
                continue
            if name not in related:
                related.append(name)
        cleaned.append({"Target": target, "Relate": related})
    return cleaned


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, payload):
    path.write_text(json.dumps(payload, indent="\t"), encoding="utf-8")


def prepare_one(runtime_root: Path, cve_id: str, dry_run: bool) -> tuple[Path, bool, list[dict]]:
    path = callfile_path(runtime_root, cve_id)
    if not path.exists():
        raise FileNotFoundError(f"callfile not found: {path}")
    original = load_json(path)
    if not isinstance(original, list):
        raise ValueError(f"callfile must be a JSON list: {path}")
    sanitized = sanitize_entries(original)
    changed = sanitized != original
    if changed and not dry_run:
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
        save_json(path, sanitized)
    return path, changed, sanitized


def build_launch_command(cve_id: str, args) -> tuple[list[str], dict[str, str]]:
    env = {
        "SYZDIRECT_LLM_BACKEND": "gemini",
        "SYZDIRECT_GEMINI_MODEL": args.gemini_model,
        "FROM_STAGE": args.from_stage,
    }
    cmd = [
        str(REPO_ROOT / "scripts" / "launch_cve_run.sh"),
        cve_id,
        str(args.hours),
        str(args.jobs),
        str(args.agent_rounds),
    ]
    return cmd, env


def write_plan_artifacts(plan_dir: Path, cve_id: str, callfile_path_src: Path,
                         sanitized_entries: list[dict], cmd: list[str], env: dict[str, str]):
    target_dir = plan_dir / normalize_cve_dir_name(cve_id)
    target_dir.mkdir(parents=True, exist_ok=True)

    callfile_copy = target_dir / "inp_0.sanitized.json"
    save_json(callfile_copy, sanitized_entries)

    command_text = " ".join(f"{key}={value}" for key, value in env.items())
    command_text = f"{command_text} {' '.join(cmd)}".strip()
    (target_dir / "rerun.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n" + command_text + "\n",
        encoding="utf-8",
    )
    os.chmod(target_dir / "rerun.sh", 0o755)

    manifest = {
        "cve": cve_id,
        "source_callfile": str(callfile_path_src),
        "sanitized_callfile": str(callfile_copy),
        "env": env,
        "command": cmd,
    }
    (target_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return target_dir


def main():
    args = parse_args()
    runtime_root = Path(args.runtime_root).resolve()
    plan_dir = Path(args.plan_dir).resolve()
    for cve_id in args.cve:
        path, changed, sanitized = prepare_one(runtime_root, cve_id, dry_run=args.dry_run)
        cmd, env = build_launch_command(cve_id, args)
        artifact_dir = write_plan_artifacts(plan_dir, cve_id, path, sanitized, cmd, env)
        env_text = " ".join(f"{key}={value}" for key, value in env.items())
        print(f"[prepare_gemini_rerun] {cve_id} callfile={path} changed={changed} plan={artifact_dir}")
        print(f"  {env_text} {' '.join(cmd)}")
        if args.execute:
            child_env = os.environ.copy()
            child_env.update(env)
            subprocess.run(cmd, cwd=str(REPO_ROOT), env=child_env, check=False)


if __name__ == "__main__":
    main()
