"""
SyzDirect Runner — interface_generator retry/quarantine logic.

Handles automatic retries of interface_generator when it crashes on
problematic bitcode files, quarantining bad modules between attempts.
"""

import os
import re
import shutil

from paths import Q, sh


def _analysis_skip_manifest(bc_dir):
    return os.path.join(bc_dir, ".analysis_skip.txt")


def _analysis_quarantine_dir(bc_dir):
    parent = os.path.dirname(bc_dir.rstrip(os.sep))
    base = os.path.basename(bc_dir.rstrip(os.sep))
    return os.path.join(parent, f".{base}_analysis_quarantine")


def _normalize_analysis_relpath(rel):
    prefix = ".analysis_quarantine" + os.sep
    while rel.startswith(prefix):
        rel = rel[len(prefix):]
    return rel


def load_analysis_skiplist(bc_dir):
    manifest = _analysis_skip_manifest(bc_dir)
    if not os.path.exists(manifest):
        return []
    with open(manifest) as f:
        return [line.strip() for line in f if line.strip()]


def save_analysis_skiplist(bc_dir, entries):
    manifest = _analysis_skip_manifest(bc_dir)
    with open(manifest, "w") as f:
        for entry in sorted(set(entries)):
            f.write(f"{entry}\n")


def quarantine_analysis_files(bc_dir, rel_paths):
    if not rel_paths:
        return []
    quarantine_root = _analysis_quarantine_dir(bc_dir)
    moved = []
    for rel in sorted(set(_normalize_analysis_relpath(rel) for rel in rel_paths)):
        src = os.path.join(bc_dir, rel)
        if not os.path.exists(src):
            continue
        dst = os.path.join(quarantine_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        moved.append(rel)
    if moved:
        print(f"  Quarantined {len(moved)} problematic bitcode file(s).")
    return moved


def parse_interface_generator_failures(log_path, bc_dir):
    if not os.path.exists(log_path):
        return []

    bad = []
    seen = set()
    progress_re = re.compile(r"\[[^\]]+\]\s+\[\d+\s*/\s*\d+\]\s+\[(.+?\.llbc)\]")
    load_err_re = re.compile(r"error loading file '(.+?\.llbc)'")

    with open(log_path, errors="replace") as f:
        lines = f.readlines()

    last_module = None
    for line in lines:
        m = progress_re.search(line)
        if m:
            last_module = m.group(1)
        m = load_err_re.search(line)
        if m:
            path = m.group(1)
            rel = os.path.relpath(path, bc_dir) if os.path.isabs(path) else path
            rel = _normalize_analysis_relpath(rel)
            if rel not in seen:
                bad.append(rel)
                seen.add(rel)

    if last_module:
        rel = os.path.relpath(last_module, bc_dir) if os.path.isabs(last_module) else last_module
        rel = _normalize_analysis_relpath(rel)
        if rel not in seen:
            bad.append(rel)

    return [rel for rel in bad if not rel.startswith("..")]


def run_interface_generator_with_retries(bc_dir, iface_dir, output_sig,
                                          interface_generator_path, max_attempts=6):
    """Run interface_generator with automatic retry on crash.

    Args:
        bc_dir: Path to bitcode directory.
        iface_dir: Output directory for interface results.
        output_sig: Path to expected output signature file.
        interface_generator_path: Path to the interface_generator binary.
        max_attempts: Maximum number of retry attempts.

    Returns:
        True if output_sig was produced, False otherwise.
    """
    skiplist = load_analysis_skiplist(bc_dir)
    quarantine_analysis_files(bc_dir, skiplist)

    for attempt in range(1, max_attempts + 1):
        print(f"  interface_generator attempt {attempt}/{max_attempts}")
        sh(f"cd {Q(iface_dir)} && "
           f"{Q(interface_generator_path)} --verbose-level=4 {Q(bc_dir)} 2>&1 | tee log",
           check=False, big=True)

        if os.path.exists(output_sig):
            return True

        new_bad = parse_interface_generator_failures(os.path.join(iface_dir, "log"), bc_dir)
        new_bad = [rel for rel in new_bad if rel not in skiplist]
        if not new_bad:
            return False

        print("  interface_generator identified problematic modules:")
        for rel in new_bad:
            print(f"    - {rel}")
        skiplist.extend(new_bad)
        save_analysis_skiplist(bc_dir, skiplist)
        quarantine_analysis_files(bc_dir, new_bad)

    return False
