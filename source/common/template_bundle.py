from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable


def template_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        templates = data.get("templates")
        if isinstance(templates, list):
            return [item for item in templates if isinstance(item, dict)]
        enhanced = data.get("enhanced_templates")
        if isinstance(enhanced, list):
            return [item for item in enhanced if isinstance(item, dict)]
    return []


def infer_target_id(templates: Iterable[dict[str, Any]], default: str = "unknown") -> str:
    for template in templates:
        target_id = template.get("target_id")
        if isinstance(target_id, str) and target_id:
            return target_id
    return default


def normalize_template_bundle(data: Any, *, default_target_id: str = "unknown") -> dict[str, Any]:
    templates = template_list(data)
    bundle: dict[str, Any] = {
        "format_version": 1,
        "target_id": infer_target_id(templates, default=default_target_id),
        "template_count": len(templates),
        "templates": templates,
    }
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "enhanced_templates":
                continue
            if key == "templates":
                bundle["templates"] = templates
                continue
            bundle[key] = value
        bundle["template_count"] = len(templates)
        bundle["target_id"] = bundle.get("target_id") or infer_target_id(templates, default=default_target_id)
    return bundle


def load_template_bundle(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return normalize_template_bundle(payload)


def sanitize_json_numbers(data: Any) -> Any:
    if isinstance(data, float):
        return data if math.isfinite(data) else None
    if isinstance(data, list):
        return [sanitize_json_numbers(item) for item in data]
    if isinstance(data, dict):
        return {key: sanitize_json_numbers(value) for key, value in data.items()}
    return data


def save_template_bundle(path: str | Path, data: Any, *, default_target_id: str = "unknown") -> dict[str, Any]:
    bundle = normalize_template_bundle(data, default_target_id=default_target_id)
    Path(path).write_text(json.dumps(sanitize_json_numbers(bundle), indent=2, allow_nan=False), encoding="utf-8")
    return bundle
