from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional


@dataclass
class TargetSpec:
    target_id: str
    kernel_commit: str
    file_path: str
    function: Optional[str] = None
    line: Optional[int] = None
    target_type: str = "bug_repro"
    description: Optional[str] = None
    notes: Optional[str] = None
    syzbot_bug_id: Optional[str] = None
    fix_commit: Optional[str] = None
    cause_commit: Optional[str] = None
    patch_commit: Optional[str] = None
    patch_type: Optional[str] = None
    entry_syscalls: list[str] = field(default_factory=list)
    related_syscalls: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TargetSpec":
        allowed = set(cls.__dataclass_fields__)
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ValueError(f"unknown target spec field(s): {', '.join(unknown)}")

        required = ("target_id", "kernel_commit", "file_path")
        missing = [name for name in required if not isinstance(data.get(name), str) or not data.get(name)]
        if missing:
            raise ValueError(f"missing required target spec field(s): {', '.join(missing)}")

        line = data.get("line")
        if line is not None and not isinstance(line, int):
            raise ValueError("target spec field 'line' must be an integer when present")

        for key in ("entry_syscalls", "related_syscalls", "sequence"):
            value = data.get(key, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"target spec field '{key}' must be a list of strings")

        for key in (
            "function",
            "target_type",
            "description",
            "notes",
            "syzbot_bug_id",
            "fix_commit",
            "cause_commit",
            "patch_commit",
            "patch_type",
        ):
            value = data.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"target spec field '{key}' must be a string when present")

        return cls(**dict(data))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_target_spec(path: str | Path) -> TargetSpec:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("target spec JSON must be an object")
    return TargetSpec.from_mapping(payload)
