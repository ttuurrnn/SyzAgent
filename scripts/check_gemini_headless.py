#!/usr/bin/env python3
"""
Quick headless-health probe for the local Gemini CLI integration.

This distinguishes between:
  - working headless auth
  - interactive browser auth prompt
  - missing CLI
  - timeout / unknown failure

The goal is to fail fast before launching a long fuzzing run.
"""

from __future__ import annotations

import argparse
import os
import selectors
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CMD = str(REPO_ROOT / "scripts" / "gemini_cli.sh")
AUTH_PROMPT = "Opening authentication page in your browser."


@dataclass
class ProbeResult:
    status: str
    message: str
    output: str
    returncode: int | None = None


def parse_args():
    parser = argparse.ArgumentParser(description="Probe Gemini CLI headless availability")
    parser.add_argument("--cmd", default=DEFAULT_CMD, help="Gemini CLI wrapper/command")
    parser.add_argument("--prompt", default="Reply with OK only", help="Short prompt used for probing")
    parser.add_argument("--timeout", type=float, default=12.0, help="Timeout in seconds")
    return parser.parse_args()


def classify_probe(output: str, returncode: int | None, timed_out: bool) -> ProbeResult:
    text = (output or "").strip()
    if AUTH_PROMPT in text:
        return ProbeResult(
            status="interactive_auth_required",
            message="Gemini CLI requested browser authentication in headless mode.",
            output=text,
            returncode=returncode,
        )
    if timed_out:
        return ProbeResult(
            status="timeout",
            message="Gemini CLI did not finish the headless probe before timeout.",
            output=text,
            returncode=returncode,
        )
    if returncode == 127:
        return ProbeResult(
            status="missing_cli",
            message="Gemini CLI command was not found.",
            output=text,
            returncode=returncode,
        )
    if returncode == 0 and text:
        return ProbeResult(
            status="ok",
            message="Gemini CLI returned a headless response.",
            output=text,
            returncode=returncode,
        )
    return ProbeResult(
        status="error",
        message="Gemini CLI headless probe failed.",
        output=text,
        returncode=returncode,
    )


def run_probe(cmd: str, prompt: str, timeout: float) -> ProbeResult:
    env = os.environ.copy()
    env.setdefault("GEMINI_CLI_TRUST_WORKSPACE", "true")
    args = [
        cmd,
        "-p",
        prompt,
        "--output-format",
        "text",
        "--skip-trust",
    ]

    try:
        proc = subprocess.Popen(
            args,
            cwd=str(REPO_ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
    except FileNotFoundError:
        return ProbeResult(
            status="missing_cli",
            message="Gemini CLI command was not found.",
            output="",
            returncode=127,
        )

    selector = selectors.DefaultSelector()
    assert proc.stdout is not None
    os.set_blocking(proc.stdout.fileno(), False)
    selector.register(proc.stdout, selectors.EVENT_READ)

    chunks: list[str] = []
    deadline = time.monotonic() + timeout
    timed_out = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            proc.kill()
            break

        events = selector.select(timeout=remaining)
        if not events:
            if proc.poll() is not None:
                break
            continue

        for key, _mask in events:
            try:
                data = os.read(key.fileobj.fileno(), 4096).decode("utf-8", errors="replace")
            except BlockingIOError:
                data = ""
            if not data:
                continue
            chunks.append(data)
            joined = "".join(chunks)
            if AUTH_PROMPT in joined:
                proc.kill()
                proc.wait(timeout=5)
                return classify_probe(joined, proc.returncode, timed_out=False)

        if proc.poll() is not None:
            break

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        timed_out = True

    output = "".join(chunks)
    return classify_probe(output, proc.returncode, timed_out)


def main() -> int:
    args = parse_args()
    result = run_probe(args.cmd, args.prompt, args.timeout)
    print(f"[check_gemini_headless] status={result.status}")
    print(f"[check_gemini_headless] {result.message}")
    if result.returncode is not None:
        print(f"[check_gemini_headless] returncode={result.returncode}")
    if result.output:
        print(result.output)
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
