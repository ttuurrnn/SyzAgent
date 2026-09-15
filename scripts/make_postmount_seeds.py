#!/usr/bin/env python3
"""Build post-mount filesystem seeds from smoke-run detail corpora.

The smoke campaigns are good at finding mount-image inputs, but their corpus can
remain sparse after the mount succeeds. This script reuses existing corpus
programs that call syz_mount_image$fs, captures its fd return value when needed,
then adds fd-based filesystem operations. It emits read/write metadata,
read-only traversal, and mount-lifecycle seeds so inherently read-only
filesystems and cleanup paths still get exercised.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_ROOT = Path(
    os.environ.get("SYZDIRECT_RUNTIME", PROJECT_ROOT / ".runtime" / "cve")
)
DEFAULT_OUTPUT_BASE = DEFAULT_RUNTIME_ROOT / "manual_seeds"
DEFAULT_IMAGEGEN_TEST_DIR = (
    PROJECT_ROOT
    / "deps"
    / "SyzDirect"
    / "source"
    / "syzdirect"
    / "syzdirect_fuzzer"
    / "sys"
    / "linux"
    / "test"
)


MOUNT_LINE_RE = re.compile(
    r"^\s*(?:(?P<reg>r\d+)\s*=\s*)?(?P<call>syz_mount_image\$[A-Za-z0-9_]+)\("
)
REG_RE = re.compile(r"\br(\d+)\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "runs",
        nargs="*",
        help="smoke/continuation run names or directories; defaults to non-postmount runs matching --run-pattern",
    )
    parser.add_argument(
        "--runtime-root",
        default=str(DEFAULT_RUNTIME_ROOT),
        help="runtime root containing smoke run directories",
    )
    parser.add_argument(
        "--output-base",
        default=str(DEFAULT_OUTPUT_BASE),
        help="directory where per-run seed directories will be written",
    )
    parser.add_argument(
        "--max-per-target",
        type=int,
        default=2,
        help="maximum seed programs generated per target mount-image call",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="remove old generated postmount seed files for the selected runs",
    )
    parser.add_argument(
        "--imagegen-test-dir",
        default=str(DEFAULT_IMAGEGEN_TEST_DIR),
        help="optional syzkaller sys/linux/test directory with syz_mount_image_* seeds",
    )
    parser.add_argument(
        "--run-pattern",
        default="*_smoke_*",
        help="glob used to discover runs when no positional run is provided",
    )
    parser.add_argument(
        "--imagegen-first",
        action="store_true",
        help="try syz-imagegen test seeds before detailCorpus programs",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="extra syz_mount_image$fs target to synthesize seeds for; can be repeated",
    )
    return parser.parse_args()


def iter_detail_objects(path: Path):
    text = path.read_text(errors="replace")
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, next_idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        idx = next_idx
        if isinstance(obj, dict):
            yield obj


def resolve_runs(runtime_root: Path, runs: list[str], run_pattern: str) -> list[Path]:
    if runs:
        out = []
        for item in runs:
            path = Path(item)
            if not path.is_absolute():
                path = runtime_root / item
            out.append(path)
        return out
    return sorted(
        path
        for path in runtime_root.glob(run_pattern)
        if path.is_dir() and "_postmount_smoke_" not in path.name
    )


def load_targets(run_dir: Path) -> list[str]:
    callfile = run_dir / "inp_0.json"
    if not callfile.exists():
        return []
    data = json.loads(callfile.read_text())
    targets: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        target = entry.get("Target")
        if isinstance(target, str) and target.startswith("syz_mount_image$"):
            if target not in targets:
                targets.append(target)
    return targets


def iter_imagegen_programs(imagegen_test_dir: Path, target: str):
    if not imagegen_test_dir.is_dir() or "$" not in target:
        return
    suffix = target.split("$", 1)[1]
    for path in sorted(imagegen_test_dir.glob(f"syz_mount_image_{suffix}_*")):
        if path.suffix == ".img":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if target in text:
            yield text


def max_register(program: str) -> int:
    regs = [int(item) for item in REG_RE.findall(program)]
    return max(regs, default=-1)


def postmount_ops(mount_reg: str, temp_reg: str) -> str:
    return "\n".join(
        [
            f"fstatfs({mount_reg}, &(0x7f0000010000))",
            f"getdents64({mount_reg}, &(0x7f0000011000), 0x1000)",
            f"mkdirat({mount_reg}, &(0x7f0000013000)='./pm0\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000013000)='./pm0\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f0000014000)='postmount\\x00', 0x9)",
            f"fchmod({temp_reg}, 0x1ff)",
            f"fchown({temp_reg}, 0x0, 0x0)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000015000)='user.syz\\x00', "
                f"&(0x7f0000015040)='seed\\x00', 0x4, 0x0)"
            ),
            f"fgetxattr({temp_reg}, &(0x7f0000015000)='user.syz\\x00', &(0x7f0000015100), 0x100)",
            f"flistxattr({temp_reg}, &(0x7f0000015300), 0x100)",
            f"fremovexattr({temp_reg}, &(0x7f0000015000)='user.syz\\x00')",
            f"fsync({temp_reg})",
            f"close({temp_reg})",
        ]
    )


def hex_blob(byte: str, size: int) -> str:
    return '"' + (byte * size) + '"'


def ea_stress_postmount_ops(mount_reg: str, temp_reg: str) -> str:
    val_32 = hex_blob("41", 0x20)
    val_32b = hex_blob("42", 0x20)
    val_big = hex_blob("43", 0x180)
    return "\n".join(
        [
            f"fstatfs({mount_reg}, &(0x7f0000040000))",
            f"mkdirat({mount_reg}, &(0x7f0000041000)='./pm_ea\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000041000)='./pm_ea\\x00', 0x42, 0x1ff)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000042000)='user.syz0\\x00', "
                f"&(0x7f0000042100)={val_32}, 0x20, 0x1)"
            ),
            (
                f"fsetxattr({temp_reg}, &(0x7f0000042000)='user.syz0\\x00', "
                f"&(0x7f0000042300)={val_32b}, 0x20, 0x2)"
            ),
            f"fgetxattr({temp_reg}, &(0x7f0000042000)='user.syz0\\x00', &(0x7f0000042500), 0x1)",
            f"fgetxattr({temp_reg}, &(0x7f0000042000)='user.syz0\\x00', &(0x7f0000042600), 0x200)",
            f"flistxattr({temp_reg}, &(0x7f0000043000), 0x1)",
            f"flistxattr({temp_reg}, &(0x7f0000043200), 0x400)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000044000)='user.syz1\\x00', "
                f"&(0x7f0000044100)={val_big}, 0x180, 0x0)"
            ),
            f"fgetxattr({temp_reg}, &(0x7f0000044000)='user.syz1\\x00', &(0x7f0000045000), 0x20)",
            f"fgetxattr({temp_reg}, &(0x7f0000044000)='user.syz1\\x00', &(0x7f0000045400), 0x200)",
            f"fremovexattr({temp_reg}, &(0x7f0000042000)='user.syz0\\x00')",
            f"fsync({temp_reg})",
            f"close({temp_reg})",
        ]
    )


def file_growth_postmount_ops(mount_reg: str, temp_reg: str) -> str:
    val_32 = hex_blob("44", 0x20)
    val_512 = hex_blob("45", 0x200)
    return "\n".join(
        [
            f"fstatfs({mount_reg}, &(0x7f0000050000))",
            f"mkdirat({mount_reg}, &(0x7f0000051000)='./pm_grow\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000051000)='./pm_grow\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f0000052000)={val_32}, 0x20)",
            f"pwrite64({temp_reg}, &(0x7f0000053000)={val_512}, 0x200, 0x1000)",
            f"pwrite64({temp_reg}, &(0x7f0000054000)={val_512}, 0x200, 0x10000)",
            f"ftruncate({temp_reg}, 0x20000)",
            f"lseek({temp_reg}, 0x0, 0x0)",
            f"read({temp_reg}, &(0x7f0000055000), 0x200)",
            f"fsync({temp_reg})",
            f"close({temp_reg})",
        ]
    )


def target_last_postmount_ops(profile: str, mount_reg: str, temp_reg: str) -> str:
    val_32 = hex_blob("46", 0x20)
    val_256 = hex_blob("47", 0x100)
    setups = {
        "openat_last": [
            f"openat({mount_reg}, &(0x7f0000060000)='./file0/file0\\x00', 0x0, 0x0)",
        ],
        "getdents64_last": [
            f"getdents64({mount_reg}, &(0x7f0000060800), 0x1000)",
        ],
        "statx_last": [
            f"statx({mount_reg}, &(0x7f0000060a00)='./file0/file1\\x00', 0x0, 0x7ff, &(0x7f0000060c00))",
        ],
        "readlinkat_last": [
            f"readlinkat({mount_reg}, &(0x7f0000060e00)='./file0/file1\\x00', &(0x7f0000061000), 0x200)",
        ],
        "read_last": [
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000061200)='./file0/file0\\x00', 0x0, 0x0)",
            f"read({temp_reg}, &(0x7f0000061400), 0x400)",
        ],
        "fsetxattr_last": [
            f"mkdirat({mount_reg}, &(0x7f0000061000)='./pm_last_ea\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000061000)='./pm_last_ea\\x00', 0x42, 0x1ff)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000062000)='user.last\\x00', "
                f"&(0x7f0000062100)={val_32}, 0x20, 0x0)"
            ),
        ],
        "fgetxattr_last": [
            f"mkdirat({mount_reg}, &(0x7f0000063000)='./pm_last_get\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000063000)='./pm_last_get\\x00', 0x42, 0x1ff)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000064000)='user.last\\x00', "
                f"&(0x7f0000064100)={val_32}, 0x20, 0x0)"
            ),
            f"fgetxattr({temp_reg}, &(0x7f0000064000)='user.last\\x00', &(0x7f0000064200), 0x100)",
        ],
        "flistxattr_last": [
            f"mkdirat({mount_reg}, &(0x7f0000065000)='./pm_last_list\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000065000)='./pm_last_list\\x00', 0x42, 0x1ff)",
            (
                f"fsetxattr({temp_reg}, &(0x7f0000066000)='user.last\\x00', "
                f"&(0x7f0000066100)={val_32}, 0x20, 0x0)"
            ),
            f"flistxattr({temp_reg}, &(0x7f0000066200), 0x200)",
        ],
        "pwrite64_last": [
            f"mkdirat({mount_reg}, &(0x7f0000067000)='./pm_last_write\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000067000)='./pm_last_write\\x00', 0x42, 0x1ff)",
            f"pwrite64({temp_reg}, &(0x7f0000068000)={val_256}, 0x100, 0x4000)",
        ],
        "ftruncate_last": [
            f"mkdirat({mount_reg}, &(0x7f0000069000)='./pm_last_trunc\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000069000)='./pm_last_trunc\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f000006a000)={val_256}, 0x100)",
            f"ftruncate({temp_reg}, 0x4000)",
        ],
        "fsync_last": [
            f"mkdirat({mount_reg}, &(0x7f000006b000)='./pm_last_sync\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f000006b000)='./pm_last_sync\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f000006c000)={val_256}, 0x100)",
            f"fsync({temp_reg})",
        ],
        "mkdirat_last": [
            f"mkdirat({mount_reg}, &(0x7f000006d000)='./pm_last_dir\\x00', 0x1ff)",
        ],
        "mknodat_last": [
            f"mknodat({mount_reg}, &(0x7f000006d800)='./pm_last_node\\x00', 0x81ff, 0x0)",
        ],
        "linkat_last": [
            f"{temp_reg} = openat({mount_reg}, &(0x7f000006e800)='./pm_last_link_src\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f000006ea00)={val_32}, 0x20)",
            f"close({temp_reg})",
            (
                f"linkat({mount_reg}, &(0x7f000006e800)='./pm_last_link_src\\x00', "
                f"{mount_reg}, &(0x7f000006ec00)='./pm_last_link_dst\\x00', 0x0)"
            ),
        ],
        "symlinkat_last": [
            (
                f"symlinkat(&(0x7f000006f000)='./pm_last_link_src\\x00', "
                f"{mount_reg}, &(0x7f000006f200)='./pm_last_symlink\\x00')"
            ),
        ],
        "renameat2_last": [
            f"{temp_reg} = openat({mount_reg}, &(0x7f000006f800)='./pm_last_rename_src\\x00', 0x42, 0x1ff)",
            f"write({temp_reg}, &(0x7f000006fa00)={val_32}, 0x20)",
            f"close({temp_reg})",
            (
                f"renameat2({mount_reg}, &(0x7f000006f800)='./pm_last_rename_src\\x00', "
                f"{mount_reg}, &(0x7f000006fc00)='./pm_last_rename_dst\\x00', 0x0)"
            ),
        ],
        "unlinkat_last": [
            f"mkdirat({mount_reg}, &(0x7f000006e000)='./pm_last_unlink\\x00', 0x1ff)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f000006e000)='./pm_last_unlink\\x00', 0x42, 0x1ff)",
            f"close({temp_reg})",
            f"unlinkat({mount_reg}, &(0x7f000006e000)='./pm_last_unlink\\x00', 0x0)",
        ],
    }
    if profile not in setups:
        raise ValueError(f"unknown target-last profile: {profile}")
    return "\n".join(setups[profile])


def readonly_postmount_ops(mount_reg: str, temp_reg: str) -> str:
    return "\n".join(
        [
            f"fstatfs({mount_reg}, &(0x7f0000020000))",
            f"getdents64({mount_reg}, &(0x7f0000021000), 0x1000)",
            f"statx({mount_reg}, &(0x7f0000023000)='.\\x00', 0x0, 0x7ff, &(0x7f0000024000))",
            f"readlinkat({mount_reg}, &(0x7f0000023000)='.\\x00', &(0x7f0000025000), 0x100)",
            f"{temp_reg} = openat({mount_reg}, &(0x7f0000023000)='.\\x00', 0x0, 0x0)",
            f"lseek({temp_reg}, 0x0, 0x0)",
            f"read({temp_reg}, &(0x7f0000026000), 0x200)",
            f"pread64({temp_reg}, &(0x7f0000027000), 0x200, 0x0)",
            f"close({temp_reg})",
        ]
    )


def lifecycle_postmount_ops(mount_reg: str, _temp_reg: str) -> str:
    return "\n".join(
        [
            f"fstatfs({mount_reg}, &(0x7f0000030000))",
            f"getdents64({mount_reg}, &(0x7f0000031000), 0x1000)",
            f"syncfs({mount_reg})",
            f"close({mount_reg})",
            "umount2(&(0x7f0000033000)='./file0\\x00', 0x0)",
            "umount2(&(0x7f0000033100)='./file1\\x00', 0x2)",
        ]
    )


def ops_for_profile(profile: str, mount_reg: str, temp_reg: str) -> str:
    if profile == "rw":
        return postmount_ops(mount_reg, temp_reg)
    if profile == "ea":
        return ea_stress_postmount_ops(mount_reg, temp_reg)
    if profile == "growth":
        return file_growth_postmount_ops(mount_reg, temp_reg)
    if profile.endswith("_last"):
        return target_last_postmount_ops(profile, mount_reg, temp_reg)
    if profile == "ro":
        return readonly_postmount_ops(mount_reg, temp_reg)
    if profile == "life":
        return lifecycle_postmount_ops(mount_reg, temp_reg)
    raise ValueError(f"unknown postmount profile: {profile}")


def build_seed(program: str, target: str, profile: str) -> str | None:
    # Keep seeds strict-target friendly: smoke corpora often mix several
    # syz_mount_image$fs calls in one program, but later strict runs enable only
    # the chosen filesystem. Isolate the target mount line and append the
    # post-mount operation sequence to that returned fd.
    for raw_line in program.splitlines():
        line = raw_line.strip()
        match = MOUNT_LINE_RE.match(line)
        if not match or match.group("call") != target:
            continue
        mount_reg = match.group("reg")
        if not mount_reg:
            mount_reg = f"r{max_register(line) + 1}"
            line = f"{mount_reg} = {line}"
        temp_reg = f"r{max_register(line) + 1}"
        return line.rstrip() + "\n" + ops_for_profile(profile, mount_reg, temp_reg) + "\n"
    return None


def seed_name(target: str, profile: str, index: int) -> str:
    suffix = target.split("$", 1)[1]
    return f"{suffix}_postmount_{profile}_{index:02d}.syz"


def generate_for_run(
    run_dir: Path,
    output_base: Path,
    max_per_target: int,
    overwrite: bool,
    imagegen_test_dir: Path,
    imagegen_first: bool,
    extra_targets: list[str],
) -> dict:
    detail = run_dir / "workdir" / "detailCorpus.txt"
    targets = load_targets(run_dir)
    for target in extra_targets:
        if target not in targets:
            targets.append(target)
    stats = {
        "run": run_dir.name,
        "targets": len(targets),
        "generated": 0,
        "missing": [],
        "skipped": "",
    }
    if not targets:
        stats["skipped"] = "no mount-image targets in inp_0.json"
        return stats

    out_dir = output_base / run_dir.name
    out_dir.mkdir(parents=True, exist_ok=True)
    if overwrite:
        for old in out_dir.glob("*_postmount_*.syz"):
            old.unlink()

    profiles = (
        "rw",
        "ea",
        "growth",
        "openat_last",
        "getdents64_last",
        "statx_last",
        "readlinkat_last",
        "read_last",
        "fsetxattr_last",
        "fgetxattr_last",
        "flistxattr_last",
        "pwrite64_last",
        "ftruncate_last",
        "fsync_last",
        "mkdirat_last",
        "mknodat_last",
        "linkat_last",
        "symlinkat_last",
        "renameat2_last",
        "unlinkat_last",
        "ro",
        "life",
    )
    seen: dict[tuple[str, str], set[str]] = {(target, profile): set() for target in targets for profile in profiles}
    counts = {(target, profile): 0 for target in targets for profile in profiles}

    def programs():
        if imagegen_first:
            for target in targets:
                yield target, iter_imagegen_programs(imagegen_test_dir, target)
        if detail.exists():
            yield None, (str(obj.get("Prog", "")) for obj in iter_detail_objects(detail))
        if not imagegen_first:
            for target in targets:
                yield target, iter_imagegen_programs(imagegen_test_dir, target)

    for source_target, program_iter in programs():
        for program in program_iter:
            if not program:
                continue
            candidate_targets = [source_target] if source_target else targets
            for target in candidate_targets:
                if target not in program:
                    continue
                for profile in profiles:
                    key = (target, profile)
                    if counts[key] >= max_per_target:
                        continue
                    seed = build_seed(program, target, profile)
                    if seed is None or seed in seen[key]:
                        continue
                    seen[key].add(seed)
                    path = out_dir / seed_name(target, profile, counts[key])
                    path.write_text(seed, encoding="utf-8")
                    counts[key] += 1
                    stats["generated"] += 1
            if all(count >= max_per_target for count in counts.values()):
                break
        if all(count >= max_per_target for count in counts.values()):
            break

    stats["missing"] = [
        f"{target}:{profile}" for (target, profile), count in counts.items() if count == 0
    ]
    return stats


def main() -> int:
    args = parse_args()
    runtime_root = Path(args.runtime_root)
    output_base = Path(args.output_base)
    rows = [
        generate_for_run(
            run,
            output_base,
            args.max_per_target,
            args.overwrite,
            Path(args.imagegen_test_dir),
            args.imagegen_first,
            args.target,
        )
        for run in resolve_runs(runtime_root, args.runs, args.run_pattern)
    ]
    for row in rows:
        line = f"{row['run']}: generated={row['generated']} targets={row['targets']}"
        if row["missing"]:
            line += " missing=" + ",".join(row["missing"])
        if row["skipped"]:
            line += f" skipped={row['skipped']}"
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
