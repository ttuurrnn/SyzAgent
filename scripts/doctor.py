#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_COMMANDS = (
    "python3",
    "git",
    "go",
    "make",
    "gcc",
    "bc",
    "flex",
    "bison",
    "qemu-system-x86_64",
    "qemu-img",
    "debootstrap",
    "ssh-keygen",
)


def fmt(status: str, message: str) -> str:
    return f"[{status}] {message}"


def passwordless_sudo() -> bool:
    if not shutil.which("sudo"):
        return False
    result = subprocess.run(
        ["sudo", "-n", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    deps_root = repo_root / "deps"
    syzdirect_root = deps_root / "SyzDirect"
    runtime_root = repo_root / ".runtime"

    missing = []
    print(fmt("INFO", f"repo root: {repo_root}"))
    print(fmt("INFO", f"default SyzDirect root: {syzdirect_root}"))
    print(fmt("INFO", f"default runtime root: {runtime_root}"))

    for command in REQUIRED_COMMANDS:
        path = shutil.which(command)
        if path:
            print(fmt("PASS", f"{command}: {path}"))
        else:
            print(fmt("FAIL", f"{command}: missing"))
            missing.append(command)

    if syzdirect_root.exists():
        print(fmt("PASS", f"SyzDirect checkout present: {syzdirect_root}"))
    else:
        print(fmt("INFO", "SyzDirect checkout missing; it will be bootstrapped automatically on first run"))

    kvm = Path("/dev/kvm")
    if not kvm.exists():
        print(fmt("WARN", "/dev/kvm is missing; runs will fall back to TCG and be much slower"))
    elif os.access(kvm, os.R_OK | os.W_OK):
        print(fmt("PASS", "/dev/kvm is accessible"))
    else:
        print(fmt("WARN", "/dev/kvm exists but is not accessible from the current shell"))

    if shutil.which("sudo"):
        if passwordless_sudo():
            print(fmt("PASS", "passwordless sudo is available"))
        else:
            print(fmt("INFO", "sudo is available but may prompt during image creation"))
    else:
        print(fmt("WARN", "sudo is missing; image creation will not work"))

    if missing:
        print()
        print(fmt("INFO", "install host dependencies with:"))
        print("  bash scripts/bootstrap_host.sh --yes")
        return 1

    print()
    print(fmt("INFO", "quick start:"))
    print("  bash scripts/run_case.sh 54")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
