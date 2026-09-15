#!/usr/bin/env python3
"""Launch a short post-mount probe from an existing filesystem smoke run."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_ROOT = Path(
    os.environ.get("SYZDIRECT_RUNTIME", PROJECT_ROOT / ".runtime" / "cve")
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_run", help="source smoke run name under runtime root")
    parser.add_argument(
        "dest_run",
        nargs="?",
        help="destination run name; defaults to SOURCE with _smoke_ replaced by _postmount_smoke_",
    )
    parser.add_argument("--runtime-root", default=str(DEFAULT_RUNTIME_ROOT))
    parser.add_argument("--repo", default=str(PROJECT_ROOT))
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--uptime", default=1, type=int, help="syz-manager uptime in hours")
    parser.add_argument("--procs", default=2, type=int)
    parser.add_argument("--kernel", help="override config.vm.kernel")
    parser.add_argument("--kernel-obj", help="override config.kernel_obj")
    parser.add_argument(
        "--only-target",
        help="keep only one Target entry in the copied callfile, e.g. syz_mount_image$hpfs",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="synthesize a callfile entry for this Target; can be repeated",
    )
    parser.add_argument(
        "--relate",
        action="append",
        default=[],
        help="Relate syscall used with every synthesized --target entry; can be repeated",
    )
    parser.add_argument(
        "--target-relate",
        action="append",
        default=[],
        metavar="TARGET:RELATE[,RELATE...]",
        help="synthesize one target-specific callfile entry; can be repeated",
    )
    parser.add_argument(
        "--seed-pattern",
        action="append",
        default=None,
        help="glob for manual seed files copied into the destination corpus; can be repeated",
    )
    parser.add_argument(
        "--seed-dir",
        help="manual seed directory; defaults to RUNTIME_ROOT/manual_seeds/SOURCE_RUN",
    )
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="build destination corpus only from matching manual seeds",
    )
    parser.add_argument(
        "--enable-callfile-syscalls",
        action="store_true",
        help="write config.enable_syscalls from Target/Relate calls plus copied seed calls",
    )
    parser.add_argument(
        "--enable-syscall",
        action="append",
        default=[],
        help="extra syscall to include in config.enable_syscalls; can be repeated",
    )
    parser.add_argument(
        "--allow-syscall-variants",
        action="append",
        default=[],
        metavar="BASE",
        help=(
            "when deriving disable_syscalls, keep BASE$* variants enabled; "
            "by default bare enabled syscalls only keep the bare syscall"
        ),
    )
    parser.add_argument(
        "--disable-syscall",
        action="append",
        default=[],
        help="extra disable_syscalls pattern to write to config; can be repeated",
    )
    parser.add_argument(
        "--preserve-corpus",
        action="store_true",
        help="keep corpus entries even if disable_syscalls rejects them",
    )
    parser.add_argument("--force", action="store_true", help="replace an existing destination run")
    return parser.parse_args()


def default_dest(source_run: str) -> str:
    if "_smoke_" in source_run:
        return source_run.replace("_smoke_", "_postmount_smoke_", 1)
    return source_run + "_postmount_smoke"


def merge_corpus(
    syzdb: Path,
    src_db: Path,
    dst_db: Path,
    seed_dir: Path,
    seed_patterns: list[str],
    seed_only: bool,
) -> int:
    seed_files: list[Path] = []
    if seed_dir.is_dir():
        seen: set[Path] = set()
        for seed_pattern in seed_patterns:
            for seed in sorted(seed_dir.glob(seed_pattern)):
                if seed in seen:
                    continue
                seen.add(seed)
                seed_files.append(seed)
    if (seed_only or not src_db.exists()) and not seed_files:
        return 0

    with tempfile.TemporaryDirectory(prefix="postmount_probe_") as tmp_name:
        tmp = Path(tmp_name)
        if src_db.exists() and not seed_only:
            subprocess.run([str(syzdb), "unpack", str(src_db), str(tmp)], check=True)
        for seed in seed_files:
            shutil.copy2(seed, tmp / seed.name)
        subprocess.run([str(syzdb), "-os", "linux", "-arch", "amd64", "pack", str(tmp), str(dst_db)], check=True)
    return len(seed_files)


def selected_seed_files(seed_dir: Path, seed_patterns: list[str]) -> list[Path]:
    seed_files: list[Path] = []
    if not seed_dir.is_dir():
        return seed_files
    seen: set[Path] = set()
    for seed_pattern in seed_patterns:
        for seed in sorted(seed_dir.glob(seed_pattern)):
            if seed in seen:
                continue
            seen.add(seed)
            seed_files.append(seed)
    return seed_files


def write_callfile(
    src_callfile: Path,
    dst_callfile: Path,
    only_target: str | None,
    targets: list[str],
    relates: list[str],
    target_relates: list[str],
) -> None:
    if target_relates:
        entries = []
        for item in target_relates:
            if ":" not in item:
                raise ValueError(f"bad --target-relate entry, expected TARGET:RELATE[,RELATE...]: {item}")
            target, raw_relates = item.split(":", 1)
            target = target.strip()
            if not target:
                raise ValueError(f"empty target in --target-relate entry: {item}")
            entry_relates = [rel.strip() for rel in raw_relates.split(",") if rel.strip()]
            entries.append({"Target": target, "Relate": entry_relates})
        for target in targets:
            entries.append({"Target": target, "Relate": relates})
        dst_callfile.write_text(json.dumps(entries, indent=2) + "\n")
        return

    if targets:
        dst_callfile.write_text(
            json.dumps(
                [{"Target": target, "Relate": relates} for target in targets],
                indent=2,
            )
            + "\n"
        )
        return

    if not only_target:
        shutil.copy2(src_callfile, dst_callfile)
        return

    data = json.loads(src_callfile.read_text())
    filtered = []
    for entry in data:
        if not isinstance(entry, dict) or entry.get("Target") != only_target:
            continue
        item = dict(entry)
        relate = item.get("Relate")
        if isinstance(relate, list):
            item["Relate"] = [
                call for call in relate
                if not (isinstance(call, str) and call.startswith("syz_mount_image$") and call != only_target)
            ]
        filtered.append(item)
    if not filtered:
        raise ValueError(f"target not found in callfile: {only_target}")
    dst_callfile.write_text(json.dumps(filtered, indent=2) + "\n")


def collect_callfile_syscalls(callfile: Path) -> set[str]:
    calls: set[str] = set()
    data = json.loads(callfile.read_text())
    for entry in data:
        if not isinstance(entry, dict):
            continue
        target = entry.get("Target")
        if isinstance(target, str) and target:
            calls.add(target)
        relate = entry.get("Relate")
        if isinstance(relate, list):
            calls.update(call for call in relate if isinstance(call, str) and call)
    return calls


def collect_seed_syscalls(seed_files: list[Path], allowed_mount_images: set[str] | None = None) -> set[str]:
    call_re = re.compile(r"^\s*(?:r\d+\s*=\s*)?([A-Za-z0-9_$]+)\(")
    calls: set[str] = set()
    for seed in seed_files:
        for line in seed.read_text(errors="replace").splitlines():
            match = call_re.match(line)
            if match:
                call = match.group(1)
                if (
                    allowed_mount_images is not None
                    and call.startswith("syz_mount_image$")
                    and call not in allowed_mount_images
                ):
                    continue
                calls.add(call)
    return calls


def syscall_variant_bases(repo: Path) -> set[str]:
    """Return bases that have BASE$variant syzkaller descriptions."""
    bases: set[str] = set()
    sys_dir = repo / "deps/SyzDirect/source/syzdirect/syzdirect_fuzzer/sys/linux"
    line_re = re.compile(r"^([A-Za-z0-9_]+)\$[A-Za-z0-9_]+\(")
    if not sys_dir.is_dir():
        return bases
    for path in sys_dir.glob("*.txt"):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            match = line_re.match(line)
            if match:
                bases.add(match.group(1))
    return bases


def disable_bare_syscall_variants(
    enabled_syscalls: set[str],
    variant_bases: set[str],
    allowed_variant_bases: set[str],
) -> list[str]:
    """Disable BASE$* when BASE is enabled only to reach the generic syscall."""
    disabled = []
    for call in sorted(enabled_syscalls):
        if "$" in call or call.startswith("syz_"):
            continue
        if call in allowed_variant_bases:
            continue
        if call in variant_bases:
            disabled.append(f"{call}$*")
    return disabled


def write_config(
    src_config: Path,
    dst_config: Path,
    workdir: Path,
    port: int,
    procs: int,
    enable_syscalls: list[str] | None,
    disable_syscalls: list[str] | None,
    preserve_corpus: bool,
    kernel: str | None,
    kernel_obj: str | None,
) -> None:
    cfg = json.loads(src_config.read_text())
    cfg["workdir"] = str(workdir)
    cfg["http"] = f"0.0.0.0:{port}"
    cfg["procs"] = procs
    cfg.setdefault("vm", {})["count"] = 1
    if kernel:
        cfg["vm"]["kernel"] = kernel
    if kernel_obj:
        cfg["kernel_obj"] = kernel_obj
    if enable_syscalls:
        cfg["enable_syscalls"] = sorted(set(enable_syscalls))
    if disable_syscalls:
        cfg["disable_syscalls"] = sorted(set(disable_syscalls))
        if not preserve_corpus:
            cfg["preserve_corpus"] = False
    dst_config.write_text(json.dumps(cfg, indent=2) + "\n")


def launch(manager: Path, dst: Path, uptime: int) -> int:
    log_path = dst / "logs" / "manager.log"
    log = log_path.open("ab")
    proc = subprocess.Popen(
        [
            str(manager),
            f"-config={dst / 'config.json'}",
            f"-callfile={dst / 'inp_0.json'}",
            f"-uptime={uptime}",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    (dst / "logs" / "launcher.pid").write_text(str(proc.pid) + "\n")
    log.close()
    return proc.pid


def main() -> int:
    args = parse_args()
    runtime_root = Path(args.runtime_root)
    repo = Path(args.repo)
    manager = repo / "deps/SyzDirect/source/syzdirect/syzdirect_fuzzer/bin/syz-manager"
    syzdb = repo / "deps/SyzDirect/source/syzdirect/syzdirect_fuzzer/bin/syz-db"

    src = runtime_root / args.source_run
    dest_name = args.dest_run or default_dest(args.source_run)
    dst = runtime_root / dest_name
    seed_dir = Path(args.seed_dir) if args.seed_dir else runtime_root / "manual_seeds" / args.source_run

    required = [manager, syzdb, src / "config.json", src / "inp_0.json"]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("missing required paths:", *missing, sep="\n  ", file=sys.stderr)
        return 2
    if dst.exists():
        if not args.force:
            print(f"destination exists, use --force to replace: {dst}", file=sys.stderr)
            return 2
        shutil.rmtree(dst)

    (dst / "logs").mkdir(parents=True)
    (dst / "workdir").mkdir()
    write_callfile(
        src / "inp_0.json",
        dst / "inp_0.json",
        args.only_target,
        args.target,
        args.relate,
        args.target_relate,
    )
    seed_patterns = args.seed_pattern or ["*.syz"]
    seed_files = selected_seed_files(seed_dir, seed_patterns)
    seed_count = merge_corpus(
        syzdb,
        src / "workdir" / "corpus.db",
        dst / "workdir" / "corpus.db",
        seed_dir,
        seed_patterns,
        args.seed_only,
    )
    enable_syscalls = None
    disable_syscalls = list(args.disable_syscall)
    if args.enable_callfile_syscalls:
        base_resource_calls = {
            "close",
            "getegid",
            "geteuid",
            "getgid",
            "getpid",
            "gettid",
            "getuid",
            "mmap",
            "munmap",
        }
        callfile_calls = collect_callfile_syscalls(dst / "inp_0.json")
        allowed_mount_images = {
            call for call in callfile_calls if call.startswith("syz_mount_image$")
        }
        enable_syscalls = sorted(
            base_resource_calls
            | callfile_calls
            | collect_seed_syscalls(seed_files, allowed_mount_images)
            | set(args.enable_syscall)
        )
        disable_syscalls.extend(
            disable_bare_syscall_variants(
                set(enable_syscalls),
                syscall_variant_bases(repo),
                set(args.allow_syscall_variants),
            )
        )
    elif args.enable_syscall:
        enable_syscalls = sorted(set(args.enable_syscall))
    write_config(
        src / "config.json",
        dst / "config.json",
        dst / "workdir",
        args.port,
        args.procs,
        enable_syscalls,
        disable_syscalls,
        args.preserve_corpus,
        args.kernel,
        args.kernel_obj,
    )
    pid = launch(manager, dst, args.uptime)

    focus = f" enable_syscalls={len(enable_syscalls)}" if enable_syscalls else ""
    print(f"launched {dest_name} pid={pid} port={args.port} uptime={args.uptime}h seeds={seed_count}{focus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
