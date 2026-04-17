#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ALLOWED_DECISIONS = {
    "continue",
    "stop",
    "intervene_r1",
    "intervene_r2",
    "intervene_r3",
    "intervene_mixed",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Use opencode to decide fuzzing watcher actions")
    parser.add_argument("summary_json", help="path to watcher summary JSON")
    return parser.parse_args()


def load_summary(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("summary JSON must be an object")
    return payload


def build_prompt(summary: dict[str, Any]) -> str:
    excerpt = "\n".join(summary.get("recent_log_excerpt", [])[-20:])
    return f"""You are deciding whether a long-running directed fuzzing session should continue, stop, or intervene.

Return ONLY strict JSON with this schema:
{{"decision":"continue|stop|intervene_r1|intervene_r2|intervene_r3|intervene_mixed","reason":"short reason"}}

Decision guidance:
- continue: fuzzing still looks healthy enough to keep running unchanged
- stop: continuing is not worthwhile or a fatal runtime blocker is present
- intervene_r1: missing dependent/precursor syscalls
- intervene_r2: object or parameter synthesis issues dominate
- intervene_r3: related/context syscall setup is insufficient
- intervene_mixed: both context expansion and object synthesis are needed

Important:
- If "all target calls are disabled" appears, return stop
- Prefer continue unless there is clear evidence of stagnation or misconfiguration
- The reason must be short and concrete
- Output JSON only, no markdown

Watcher summary:
{json.dumps(summary, indent=2)}

Recent log excerpt:
{excerpt}
"""


def extract_text_from_json_events(stdout: str) -> str:
    chunks: list[str] = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for key in ("text", "content", "message", "output", "response"):
            value = event.get(key)
            if isinstance(value, str):
                chunks.append(value)
        data = event.get("data")
        if isinstance(data, dict):
            for key in ("text", "content", "message", "output_text"):
                value = data.get(key)
                if isinstance(value, str):
                    chunks.append(value)
            parts = data.get("parts")
            if isinstance(parts, list):
                for part in parts:
                    if isinstance(part, dict):
                        text = part.get("text")
                        if isinstance(text, str):
                            chunks.append(text)
    return "\n".join(chunks).strip()


def extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("opencode output did not contain a JSON object")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("opencode output JSON was not an object")
    return payload


def call_opencode(prompt: str) -> dict[str, Any]:
    cmd = ["opencode", "run", "--format", "json"]
    model = os.environ.get("OPENCODE_MODEL")
    agent = os.environ.get("OPENCODE_AGENT")
    variant = os.environ.get("OPENCODE_VARIANT")
    workdir = os.environ.get("OPENCODE_DIR") or os.getcwd()
    timeout_seconds = int(os.environ.get("OPENCODE_TIMEOUT_SECONDS", "120"))

    if model:
        cmd += ["--model", model]
    if agent:
        cmd += ["--agent", agent]
    if variant:
        cmd += ["--variant", variant]
    cmd += ["--dir", workdir, prompt]

    try:
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"opencode run timed out after {timeout_seconds}s") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "opencode run failed")

    text = extract_text_from_json_events(result.stdout)
    if not text:
        text = result.stdout
    payload = extract_json_object(text)
    return payload


def validate_decision(payload: dict[str, Any]) -> dict[str, str]:
    decision = payload.get("decision")
    reason = payload.get("reason")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"invalid decision: {decision}")
    if not isinstance(reason, str) or not reason.strip():
        reason = "decision returned by opencode"
    return {"decision": decision, "reason": reason.strip()}


def main() -> int:
    args = parse_args()
    summary = load_summary(Path(args.summary_json))
    prompt = build_prompt(summary)
    payload = call_opencode(prompt)
    validated = validate_decision(payload)
    print(json.dumps(validated))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
