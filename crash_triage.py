"""
SyzDirect Runner — crash classification and known-crash matching.

Provides functions to classify fuzzer crashes into buckets (target-related,
incidental, infrastructure) and match against known crash signatures.
"""

import json
import os


# ──────────────────────────────────────────────────────────────────────────
# Known crash database
# ──────────────────────────────────────────────────────────────────────────

def load_known_crash_db(*paths):
    """Load known crash signature rules from one or more JSON files."""
    rules = []
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("rules", [])
        if isinstance(data, list):
            rules.extend(x for x in data if isinstance(x, dict))
    return rules


def match_known_crash(description, report_text, rules):
    """Check if a crash matches any known signature rule."""
    haystack = f"{description}\n{report_text}".lower()
    for rule in rules:
        matches = [s.lower() for s in rule.get("match_any", []) if s]
        if matches and any(m in haystack for m in matches):
            return rule
    return None


# ──────────────────────────────────────────────────────────────────────────
# Crash classification
# ──────────────────────────────────────────────────────────────────────────

INFRA_MARKERS = (
    "no output from test machine",
    "lost connection to test machine",
    "machine check failed",
    "rcu detected stall",
    "task hung",
    "soft lockup",
    "syzfatal:",
    "executor failed",
    "loop exited with status",
    "too many open files",
    "socketpair failed",
    "syz_usbip_server_init",
    "child failed",
)


def _read_text_if_exists(path):
    if not os.path.exists(path):
        return ""
    with open(path, errors="replace") as f:
        return f.read()


def target_relevance(text, target_info, target_context, target_call_names):
    """Check if crash text is related to the fuzzing target."""
    import re
    lowered = (text or "").lower()
    if target_info.get("function", "").lower() in lowered:
        return True
    for token in target_context.get("strong_tokens", set()):
        if len(token) < 5:
            # Short tokens need word-boundary matching to avoid false positives
            # e.g. "add" matching "addition" in unrelated crash reports
            if re.search(r'\b' + re.escape(token) + r'\b', lowered):
                return True
        elif token in lowered:
            return True
    for call_name in target_call_names:
        if len(call_name) >= 4 and call_name in lowered:
            return True
    return False


def classify_crash_dir(crash_dir, known_rules, target_info, target_context, target_call_names):
    """Classify a single crash directory into a bucket.

    Returns a dict with crash_id, description, bucket, known_rule info, etc.
    """
    description = _read_text_if_exists(os.path.join(crash_dir, "description")).strip()
    report_text = _read_text_if_exists(os.path.join(crash_dir, "report0"))
    log_text = _read_text_if_exists(os.path.join(crash_dir, "log0"))
    primary_text = "\n".join([description, report_text]).lower()
    combined = "\n".join([description, report_text, log_text]).lower()

    is_infra = any(marker in combined for marker in INFRA_MARKERS)
    known_rule = match_known_crash(description, report_text, known_rules)
    is_target_related = (not is_infra) and target_relevance(
        primary_text, target_info, target_context, target_call_names
    )

    if is_infra:
        bucket = "infra"
    elif is_target_related:
        bucket = "target_related"
    else:
        bucket = "incidental"

    return {
        "crash_id": os.path.basename(crash_dir),
        "description": description or "unknown crash",
        "bucket": bucket,
        "known_rule": known_rule.get("id") if known_rule else None,
        "known_notes": known_rule.get("notes") if known_rule else None,
        "target_related": is_target_related,
        "paths": {
            "dir": crash_dir,
            "report": os.path.join(crash_dir, "report0"),
            "log": os.path.join(crash_dir, "log0"),
        },
    }


def collect_crashes(round_dir, round_num, hunt_mode, known_rules,
                    target_info, target_context, target_call_names):
    """Walk a round directory, classify all crashes, and write a summary.

    Returns a crash summary dict with counts and crash manifests.
    """
    bucket_root = os.path.join(round_dir, "crash_buckets")
    os.makedirs(bucket_root, exist_ok=True)

    manifests = []
    seen_ids = set()
    for dirpath, _, filenames in os.walk(round_dir):
        if os.path.basename(os.path.dirname(dirpath)) != "crashes":
            continue
        crash_id = os.path.basename(dirpath)
        if crash_id in seen_ids:
            continue
        if "description" not in filenames and "report0" not in filenames:
            continue
        seen_ids.add(crash_id)
        manifest = classify_crash_dir(
            dirpath, known_rules, target_info, target_context, target_call_names
        )
        manifests.append(manifest)

        bucket_dir = os.path.join(bucket_root, manifest["bucket"])
        os.makedirs(bucket_dir, exist_ok=True)
        link_path = os.path.join(bucket_dir, crash_id)
        if not os.path.exists(link_path):
            os.symlink(dirpath, link_path)

        if manifest["known_rule"]:
            known_dir = os.path.join(bucket_root, "known")
            os.makedirs(known_dir, exist_ok=True)
            known_link = os.path.join(known_dir, crash_id)
            if not os.path.exists(known_link):
                os.symlink(dirpath, known_link)

    counts = {
        "total": len(manifests),
        "target_related": sum(1 for m in manifests if m["bucket"] == "target_related"),
        "incidental": sum(1 for m in manifests if m["bucket"] == "incidental"),
        "infra": sum(1 for m in manifests if m["bucket"] == "infra"),
        "known": sum(1 for m in manifests if m["known_rule"]),
        "incidental_unknown": sum(
            1 for m in manifests
            if m["bucket"] == "incidental" and not m["known_rule"]
        ),
    }

    summary = {
        "round": round_num,
        "hunt_mode": hunt_mode,
        "counts": counts,
        "crashes": manifests,
    }
    with open(os.path.join(round_dir, "crash_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    return summary
