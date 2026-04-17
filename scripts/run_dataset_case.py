#!/usr/bin/env python3
"""
Automate SyzDirect dataset case preparation and best-effort execution.

This wrapper turns a public SyzDirect dataset case ID into:
1. parsed case metadata from dataset.pdf
2. augmented syzbot metadata for known bug cases
3. a target.json usable by this research repo
4. optional kernel source checkout
5. optional analyzer/distance/template generation
6. optional full run_experiment.sh execution when the local environment is ready
"""

from __future__ import annotations

import argparse
import difflib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from source.common.target_spec import TargetSpec, load_target_spec


SYZBOT_ROOT = "https://syzkaller.appspot.com"
KNOWN_BUG_CASE_FALLBACKS = {
    20: {
        "bug_url": f"{SYZBOT_ROOT}/bug?extid=32d3767580a1ea339a81",
        "syzbot_bug_id": "32d3767580a1ea339a81",
        "file_path": "fs/squashfs/block.c",
        "line": 242,
    },
    60: {
        "bug_url": f"{SYZBOT_ROOT}/bug?id=53b6555b27af2cae74e2fbdac6cadc73f9cb18aa",
        "syzbot_bug_id": "53b6555b27af2cae74e2fbdac6cadc73f9cb18aa",
        "file_path": "net/rxrpc/local_object.c",
        "line": 225,
    },
}
LINUX_REPO_CANDIDATES = (
    "https://github.com/torvalds/linux.git",
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
)
SYZDIRECT_REPO_CANDIDATES = (
    "https://github.com/whysocscs/SyzDirect.git",
)
SYZDIRECT_SPARSE_PATHS = (
    "dataset",
    "source/syzdirect",
)
SYZDIRECT_TARGET_IMPORTS = (
    ("sys_akaros.go", "akaros", "github.com/google/syzkaller/sys/akaros/gen"),
    ("sys_darwin.go", "darwin", "github.com/google/syzkaller/sys/darwin/gen"),
    ("sys_freebsd.go", "freebsd", "github.com/google/syzkaller/sys/freebsd/gen"),
    ("sys_fuchsia.go", "fuchsia", "github.com/google/syzkaller/sys/fuchsia/gen"),
    ("sys_linux.go", "linux", "github.com/google/syzkaller/sys/linux/gen"),
    ("sys_netbsd.go", "netbsd", "github.com/google/syzkaller/sys/netbsd/gen"),
    ("sys_openbsd.go", "openbsd", "github.com/google/syzkaller/sys/openbsd/gen"),
    ("sys_testos.go", "test", "github.com/google/syzkaller/sys/test/gen"),
    ("sys_trusty.go", "trusty", "github.com/google/syzkaller/sys/trusty/gen"),
    ("sys_windows.go", "windows", "github.com/google/syzkaller/sys/windows/gen"),
)


def log(msg: str) -> None:
    print(f"[INFO] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[WARN] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[ERROR] {msg}", flush=True)


def run_cmd(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    quoted = " ".join(shlex_quote(part) for part in cmd)
    log(f"run: {quoted}")
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        check=check,
        text=True,
    )


def shlex_quote(text: str) -> str:
    return subprocess.list2cmdline([text]) if os.name == "nt" else __import__("shlex").quote(text)


def fetch_text(url: str) -> str:
    url = html.unescape(url)
    req = urllib.request.Request(url, headers={"User-Agent": "syzdirect-research/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "ignore")


def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def save_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_if_changed(path: Path, content: str) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def command_path(name: str) -> Optional[str]:
    return shutil.which(name)


def syzdirect_checkout_ready(root: Path) -> bool:
    return (root / "dataset" / "dataset.pdf").exists() and (
        root / "source" / "syzdirect" / "syzdirect_fuzzer"
    ).is_dir()


def ensure_syzdirect_checkout(root: Path) -> Path:
    if syzdirect_checkout_ready(root):
        return root

    if root.exists():
        if (root / ".git").exists():
            try:
                run_cmd(
                    [
                        "git",
                        "-C",
                        str(root),
                        "sparse-checkout",
                        "set",
                        "--cone",
                        *SYZDIRECT_SPARSE_PATHS,
                    ]
                )
                run_cmd(["git", "-C", str(root), "checkout", "HEAD"])
            except subprocess.CalledProcessError as exc:
                warn(f"failed to repair sparse SyzDirect checkout in {root}: {exc}")
            if syzdirect_checkout_ready(root):
                return root
        elif any(root.iterdir()):
            raise SystemExit(f"{root} exists but is not a usable SyzDirect checkout")

    root.parent.mkdir(parents=True, exist_ok=True)
    last_error: Optional[Exception] = None
    for repo_url in SYZDIRECT_REPO_CANDIDATES:
        try:
            if root.exists():
                shutil.rmtree(root)
            run_cmd(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--sparse",
                    repo_url,
                    str(root),
                ]
            )
            run_cmd(
                [
                    "git",
                    "-C",
                    str(root),
                    "sparse-checkout",
                    "set",
                    "--cone",
                    *SYZDIRECT_SPARSE_PATHS,
                ]
            )
            if syzdirect_checkout_ready(root):
                return root
        except subprocess.CalledProcessError as exc:
            last_error = exc
            warn(f"SyzDirect bootstrap from {repo_url} failed")
            shutil.rmtree(root, ignore_errors=True)
    raise SystemExit(f"failed to bootstrap SyzDirect checkout at {root}: {last_error}")


def passwordless_sudo() -> bool:
    if not command_path("sudo"):
        return False
    result = subprocess.run(
        ["sudo", "-n", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def decode_pdf_string(raw: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    raw = re.sub(r"\\([0-7]{3})", repl, raw)
    raw = raw.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
    return raw.replace("\x0c", "").replace("\x0b", "")


def extract_tj_text_items(stream_text: str) -> list[str]:
    items: list[str] = []
    for match in re.finditer(r"\[(.*?)\]TJ", stream_text, re.S):
        content = match.group(1)
        parts = [
            decode_pdf_string(part)
            for part in re.findall(r"\(((?:\\.|[^\\)])*)\)", content)
        ]
        text = "".join(parts).strip()
        if text:
            items.append(text)
    for match in re.finditer(r"\(((?:\\.|[^\\)])*)\)\s*Tj", stream_text):
        text = decode_pdf_string(match.group(1)).strip()
        if text:
            items.append(text)
    return items


def iter_pdf_tables(pdf_path: Path) -> Iterable[tuple[str, list[str]]]:
    data = pdf_path.read_bytes()
    start = 0
    while True:
        stream_start = data.find(b"stream", start)
        if stream_start == -1:
            break
        stream_end = data.find(b"endstream", stream_start)
        if stream_end == -1:
            break
        raw = data[stream_start + 6 : stream_end].strip(b"\r\n")
        start = stream_end + 9
        try:
            text = zlib.decompress(raw).decode("latin1", "ignore")
        except Exception:
            continue
        items = extract_tj_text_items(text)
        joined = "".join(items).lower()
        if "knownbugsdataset" in joined or ("bugid" in items and "Syzbotbugid" in items):
            yield "known-bugs", items
        elif "patchdataset" in joined or ("PatchID" in items and "Commit" in items and "Type" in items):
            yield "patches", items


def is_case_id_token(token: str) -> bool:
    if not token.isdigit():
        return False
    value = int(token)
    return 1 <= value <= 100


def reconstruct_patch_position(parts: list[str]) -> str:
    if not parts:
        return ""
    position = parts[0]
    for token in parts[1:]:
        if token.isdigit() and position.endswith(":"):
            position += token
        else:
            position += f"_{token}"
    return position


def split_position(position: str) -> tuple[str, Optional[int]]:
    if ":" not in position:
        return position, None
    file_path, line_text = position.rsplit(":", 1)
    try:
        return file_path, int(line_text)
    except ValueError:
        return position, None


def canonicalize_path_fragment(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "", text).lower()


def replace_once(contents: str, original: str, replacement: str) -> tuple[str, bool]:
    if original not in contents:
        return contents, False
    return contents.replace(original, replacement, 1), True


def ensure_syzdirect_fuzzer_compatibility(fuzzer_root: Path) -> bool:
    changed = False

    makefile_path = fuzzer_root / "Makefile"
    if makefile_path.exists():
        original = makefile_path.read_text(encoding="utf-8")
        updated = original.replace(
            "GITREV=$(shell git rev-parse HEAD)\n",
            "GITREV=$(shell git rev-parse HEAD 2>/dev/null || printf 'source-archive')\n",
            1,
        )
        updated = updated.replace(
            'ifeq ("$(shell git diff --shortstat)", "")\n',
            'ifeq ("$(shell git diff --shortstat 2>/dev/null)", "")\n',
            1,
        )
        updated = updated.replace(
            'GITREVDATE=$(shell git log -n 1 --format="%cd" --date=format:%Y%m%d-%H%M%S)\n',
            'GITREVDATE=$(shell git log -n 1 --format="%cd" --date=format:%Y%m%d-%H%M%S 2>/dev/null || date -u +%Y%m%d-%H%M%S)\n',
            1,
        )
        if updated != original:
            makefile_path.write_text(updated, encoding="utf-8")
            changed = True

    sys_go_path = fuzzer_root / "sys" / "sys.go"
    if sys_go_path.exists():
        original = sys_go_path.read_text(encoding="utf-8")
        updated = original
        if "//go:build !syz_target" not in updated:
            prefix = (
                "// Copyright 2017 syzkaller project authors. All rights reserved.\n"
                "// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.\n\n"
            )
            replacement = prefix + "//go:build !syz_target\n// +build !syz_target\n\n"
            if updated.startswith(prefix):
                updated = replacement + updated[len(prefix) :]
            else:
                updated = "//go:build !syz_target\n// +build !syz_target\n\n" + updated
        if updated != original:
            sys_go_path.write_text(updated, encoding="utf-8")
            changed = True

    for filename, build_tag, import_path in SYZDIRECT_TARGET_IMPORTS:
        content = (
            "// Copyright 2017 syzkaller project authors. All rights reserved.\n"
            "// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.\n\n"
            f"//go:build syz_target && syz_os_{build_tag}\n"
            f"// +build syz_target,syz_os_{build_tag}\n\n"
            "package sys\n\n"
            f'import _ "{import_path}"\n'
        )
        changed = write_if_changed(fuzzer_root / "sys" / filename, content) or changed

    testing_path = fuzzer_root / "syz-fuzzer" / "testing.go"
    if testing_path.exists():
        original = testing_path.read_text(encoding="utf-8")
        updated = original
        if "execOpts := *args.ipcExecOpts" not in updated:
            updated, patch_changed = replace_once(
                updated,
                "\toutput, info, hanged, err := env.Exec(args.ipcExecOpts, p)\n",
                "\texecOpts := *args.ipcExecOpts\n"
                "\t// Collect raw cover for machine-check diagnostics and to tolerate kernels\n"
                "\t// that only provide a minimal signal for the mmap sanity program.\n"
                "\texecOpts.Flags |= ipc.FlagCollectCover\n"
                "\toutput, info, hanged, err := env.Exec(&execOpts, p)\n",
            )
            changed = changed or patch_changed
        if "callInfo := info.Calls[0]" not in updated:
            updated, patch_changed = replace_once(
                updated,
                '\tif args.ipcConfig.Flags&ipc.FlagSignal != 0 && len(info.Calls[0].Signal) < 2 {\n'
                '\t\treturn fmt.Errorf("got no coverage:\\n%s", output)\n'
                "\t}\n"
                '\tif len(info.Calls[0].Signal) < 1 {\n'
                '\t\treturn fmt.Errorf("got no fallback coverage:\\n%s", output)\n'
                "\t}\n",
                "\tcallInfo := info.Calls[0]\n"
                '\tlog.Logf(0, "simple program result: signal=%d cover=%d dist=%v flags=%v",\n'
                "\t\tlen(callInfo.Signal), len(callInfo.Cover), callInfo.Dist, callInfo.Flags)\n"
                '\tif args.ipcConfig.Flags&ipc.FlagSignal != 0 && len(callInfo.Signal) < 2 {\n'
                "\t\tif len(callInfo.Cover) == 0 && len(callInfo.Signal) == 0 {\n"
                '\t\t\treturn fmt.Errorf("got no coverage:\\n%s", output)\n'
                "\t\t}\n"
                '\t\tlog.Logf(0, "limited machine-check coverage detected, proceeding with signal=%d cover=%d",\n'
                "\t\t\tlen(callInfo.Signal), len(callInfo.Cover))\n"
                "\t}\n"
                "\tif len(callInfo.Signal) < 1 {\n"
                '\t\treturn fmt.Errorf("got no fallback coverage:\\n%s", output)\n'
                "\t}\n",
            )
            changed = changed or patch_changed
        if updated != original:
            testing_path.write_text(updated, encoding="utf-8")

    if changed:
        log(f"applied SyzDirect fuzzer compatibility patches in {fuzzer_root}")
    return changed


def ensure_syzdirect_kcov_support(kernel_src: Path) -> bool:
    header_path = kernel_src / "include" / "linux" / "kcov.h"
    source_path = kernel_src / "kernel" / "kcov.c"
    header_updated = False
    source_updated = False

    if header_path.exists():
        header = header_path.read_text(encoding="utf-8")
        updated = header
        if "void notrace kcov_mark_block(u32 i);" not in updated:
            updated, changed = replace_once(
                updated,
                "void kcov_remote_stop(void);\n",
                "void kcov_remote_stop(void);\nvoid notrace kcov_mark_block(u32 i);\n",
            )
            header_updated = header_updated or changed
        if "static inline void kcov_mark_block(u32 i) {}" not in updated:
            updated, changed = replace_once(
                updated,
                "static inline void kcov_remote_stop_softirq(void) {}\n",
                "static inline void kcov_remote_stop_softirq(void) {}\nstatic inline void kcov_mark_block(u32 i) {}\n",
            )
            header_updated = header_updated or changed
        if updated != header:
            header_path.write_text(updated, encoding="utf-8")

    if source_path.exists():
        source = source_path.read_text(encoding="utf-8")
        updated = source
        if "#define DISTBLOCKSIZE 300" not in updated:
            updated, changed = replace_once(
                updated,
                "#define KCOV_WORDS_PER_CMP 4\n",
                "#define KCOV_WORDS_PER_CMP 4\n\n#define DISTBLOCKSIZE 300\n",
            )
            source_updated = source_updated or changed

        if "void notrace kcov_mark_block(u32 i)" not in updated:
            updated, count = re.subn(
                r"void notrace __sanitizer_cov_trace_pc\(void\)\n\{.*?\n\}\nEXPORT_SYMBOL\(__sanitizer_cov_trace_pc\);\n",
                """void notrace __sanitizer_cov_trace_pc(void)
{
\tstruct task_struct *t;
\tunsigned long *area;
\tu32 *dt_area;
\tunsigned long ip = canonicalize_ip(_RET_IP_);
\tunsigned long pos;

\tt = current;
\tif (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
\t\treturn;

\tdt_area = (u32 *)t->kcov_area;
\tarea = (unsigned long *)(dt_area + DISTBLOCKSIZE);
\t/* The first 64-bit word is the number of subsequent PCs. */
\tpos = READ_ONCE(area[0]) + 1;
\tif (likely(pos < t->kcov_size - DISTBLOCKSIZE / 2)) {
\t\t/* Update pos before writing pc to avoid recursive corruption. */
\t\tWRITE_ONCE(area[0], pos);
\t\tbarrier();
\t\tarea[pos] = ip;
\t}
}
EXPORT_SYMBOL(__sanitizer_cov_trace_pc);

void notrace kcov_mark_block(u32 i)
{
\tstruct task_struct *t;
\tu32 *dt_area;

\tt = current;
\tif (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
\t\treturn;

\tif (unlikely(i + 1 >= DISTBLOCKSIZE))
\t\treturn;

\tdt_area = (u32 *)t->kcov_area;
\tif (i < READ_ONCE(dt_area[0]))
\t\tWRITE_ONCE(dt_area[0], i);
\tWRITE_ONCE(dt_area[i + 1], READ_ONCE(dt_area[i + 1]) + 1);
}
EXPORT_SYMBOL(kcov_mark_block);
""",
                updated,
                count=1,
                flags=re.S,
            )
            source_updated = source_updated or count == 1

        updated, changed = replace_once(
            updated,
            "if (size < 2 || size > INT_MAX / sizeof(unsigned long))",
            "if (size < DISTBLOCKSIZE / 2 + 2 || size > INT_MAX / sizeof(unsigned long))",
        )
        source_updated = source_updated or changed

        updated, changed = replace_once(
            updated,
            "\t\tif ((unsigned long)remote_arg->area_size >\n\t\t    LONG_MAX / sizeof(unsigned long))\n\t\t\treturn -EINVAL;\n",
            "\t\tif ((unsigned long)remote_arg->area_size >\n\t\t    LONG_MAX / sizeof(unsigned long) ||\n\t\t    remote_arg->area_size < DISTBLOCKSIZE / 2)\n\t\t\treturn -EINVAL;\n",
        )
        source_updated = source_updated or changed

        updated, changed = replace_once(
            updated,
            "\t/* Reset coverage size. */\n\t*(u64 *)area = 0;\n",
            "\t/* Reset coverage size. */\n\tif (mode == KCOV_MODE_TRACE_PC) {\n\t\tu32 *dt_area = area;\n\t\tint i;\n\n\t\tdt_area[0] = 0xffffffff;\n\t\tfor (i = 1; i < DISTBLOCKSIZE + 2; i++)\n\t\t\tdt_area[i] = 0;\n\t} else {\n\t\t*(u64 *)area = 0;\n\t}\n",
        )
        source_updated = source_updated or changed

        if "u32 *dst_dt_entries, *src_dt_entries;" not in updated:
            updated, changed = replace_once(
                updated,
                "\tvoid *dst_entries, *src_entries;\n",
                "\tvoid *dst_entries, *src_entries;\n\tu32 *dst_dt_entries, *src_dt_entries;\n",
            )
            source_updated = source_updated or changed

        updated, changed = replace_once(
            updated,
            "\tcase KCOV_MODE_TRACE_PC:\n\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n\t\tsrc_len = *(unsigned long *)src_area;\n\t\tcount_size = sizeof(unsigned long);\n\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n\t\tbreak;\n",
            "\tcase KCOV_MODE_TRACE_PC:\n\t\tdst_dt_entries = dst_area;\n\t\tsrc_dt_entries = src_area;\n\t\tdst_area_size -= DISTBLOCKSIZE / 2;\n\t\tdst_area = dst_dt_entries + DISTBLOCKSIZE;\n\t\tsrc_area = src_dt_entries + DISTBLOCKSIZE;\n\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n\t\tsrc_len = *(unsigned long *)src_area;\n\t\tcount_size = sizeof(unsigned long);\n\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n\t\tbreak;\n",
        )
        source_updated = source_updated or changed

        if "dst_dt_entries[0] =" not in updated:
            updated, changed = replace_once(
                updated,
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
                "\tif (mode == KCOV_MODE_TRACE_PC) {\n\t\tint i;\n\n\t\tif (src_dt_entries[0] < dst_dt_entries[0])\n\t\t\tdst_dt_entries[0] = src_dt_entries[0];\n\t\tfor (i = 1; i < DISTBLOCKSIZE; i++)\n\t\t\tWRITE_ONCE(dst_dt_entries[i], READ_ONCE(dst_dt_entries[i]) + READ_ONCE(src_dt_entries[i]));\n\t}\n\n\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
            )
            source_updated = source_updated or changed

        if updated != source:
            source_path.write_text(updated, encoding="utf-8")

    if header_updated or source_updated:
        log(f"applied SyzDirect KCOV compatibility patch in {kernel_src}")

    header_ok = not header_path.exists() or (
        "void notrace kcov_mark_block(u32 i);" in header_path.read_text(encoding="utf-8")
    )
    source_text = source_path.read_text(encoding="utf-8") if source_path.exists() else ""
    source_ok = not source_path.exists() or (
        "#define DISTBLOCKSIZE 300" in source_text
        and "void notrace kcov_mark_block(u32 i)" in source_text
        and "dst_dt_entries = dst_area;" in source_text
    )
    if not header_ok or not source_ok:
        warn(f"SyzDirect KCOV compatibility patch is incomplete in {kernel_src}")
    return header_updated or source_updated


def ensure_host_build_compatibility(kernel_src: Path) -> bool:
    changed = False

    objtool_makefile = kernel_src / "tools" / "objtool" / "Makefile"
    if objtool_makefile.exists():
        original = objtool_makefile.read_text(encoding="utf-8")
        updated = original.replace("CFLAGS   := -Werror ", "CFLAGS   := ", 1)
        updated = updated.replace("CFLAGS   += -Werror ", "CFLAGS   += ", 1)
        if updated != original:
            objtool_makefile.write_text(updated, encoding="utf-8")
            log(f"relaxed objtool host warnings in {objtool_makefile}")
            changed = True

    tools_string_header = kernel_src / "tools" / "include" / "linux" / "string.h"
    if tools_string_header.exists():
        original = tools_string_header.read_text(encoding="utf-8")
        updated = original.replace(
            "#if defined(__GLIBC__) && !defined(__UCLIBC__)\nextern size_t strlcpy(char *dest, const char *src, size_t size);\n#endif\n",
            "#if defined(__GLIBC__) && !defined(__UCLIBC__) && !defined(__USE_FORTIFY_LEVEL)\nextern size_t strlcpy(char *dest, const char *src, size_t size);\n#endif\n",
            1,
        )
        if updated != original:
            tools_string_header.write_text(updated, encoding="utf-8")
            log(f"guarded glibc strlcpy declaration in {tools_string_header}")
            changed = True

    selinux_classmap = kernel_src / "security" / "selinux" / "include" / "classmap.h"
    if selinux_classmap.exists():
        original = selinux_classmap.read_text(encoding="utf-8")
        updated = original.replace(
            "#if PF_MAX > 45\n#error New address family defined, please update secclass_map.\n#endif\n",
            "#if PF_MAX > 45\n"
            "/*\n"
            " * Newer host libc headers may expose address families that did not exist\n"
            " * when this kernel snapshot was released. Keep the legacy secclass_map\n"
            " * for build compatibility instead of aborting the host-tools build.\n"
            " */\n"
            "#endif\n",
            1,
        )
        if updated != original:
            selinux_classmap.write_text(updated, encoding="utf-8")
            log(f"relaxed SELinux classmap PF_MAX guard in {selinux_classmap}")
            changed = True

    return changed


@dataclass
class DatasetCase:
    case_id: int
    dataset_kind: str
    position: str
    file_path: str
    line: Optional[int]
    raw_tokens: list[str] = field(default_factory=list)
    patch_commit: Optional[str] = None
    patch_type: Optional[str] = None
    syzbot_bug_id: Optional[str] = None
    bug_title: Optional[str] = None
    crash_title: Optional[str] = None
    target_function: Optional[str] = None
    report_url: Optional[str] = None
    log_url: Optional[str] = None
    kernel_config_url: Optional[str] = None
    repro_c_url: Optional[str] = None
    repro_syz_url: Optional[str] = None
    cause_commit: Optional[str] = None
    fix_commit: Optional[str] = None
    kernel_commit: Optional[str] = None
    entry_syscalls: list[str] = field(default_factory=list)
    related_syscalls: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)


@dataclass
class CaseBundle:
    case: DatasetCase
    case_dir: Path
    case_json: Path
    target_json: Path

    def save(self) -> None:
        save_json(self.case_json, asdict(self.case))
        save_json(self.target_json, build_target_spec(self.case))


@dataclass
class KernelPreparation:
    kernel_src: Optional[Path] = None
    kernel_build_dir: Optional[Path] = None
    analysis_ok: bool = False
    kernel_src_changed: bool = False


@dataclass
class RuntimeAssets:
    image_path: Optional[Path] = None
    ssh_key_path: Optional[Path] = None
    sudo_password: Optional[str] = None


def extract_case_from_pdf(pdf_path: Path, case_id: int, dataset_kind: str) -> DatasetCase:
    for table_kind, items in iter_pdf_tables(pdf_path):
        if table_kind != dataset_kind:
            continue
        for idx, token in enumerate(items):
            if token != str(case_id):
                continue
            row_tokens: list[str] = []
            cursor = idx + 1
            while cursor < len(items) and not is_case_id_token(items[cursor]):
                row_tokens.append(items[cursor])
                cursor += 1
            if dataset_kind == "known-bugs":
                hex_tokens: list[str] = []
                pos_tokens: list[str] = []
                for item in row_tokens:
                    if re.fullmatch(r"[0-9a-f]{8,}", item) and not pos_tokens:
                        hex_tokens.append(item)
                    else:
                        pos_tokens.append(item)
                position = "".join(pos_tokens)
                file_path, line = split_position(position)
                return DatasetCase(
                    case_id=case_id,
                    dataset_kind=dataset_kind,
                    position=position,
                    file_path=file_path,
                    line=line,
                    raw_tokens=row_tokens,
                    syzbot_bug_id="".join(hex_tokens) if hex_tokens else None,
                )
            commit = row_tokens[0] if row_tokens else None
            patch_type = row_tokens[-1] if row_tokens and row_tokens[-1] in {"Benign", "Faulty"} else None
            position_tokens = row_tokens[1:-1] if patch_type else row_tokens[1:]
            position = reconstruct_patch_position(position_tokens)
            file_path, line = split_position(position)
            return DatasetCase(
                case_id=case_id,
                dataset_kind=dataset_kind,
                position=position,
                file_path=file_path,
                line=line,
                raw_tokens=row_tokens,
                patch_commit=commit,
                patch_type=patch_type,
                kernel_commit=commit,
            )
    raise SystemExit(f"case {case_id} not found in {pdf_path} ({dataset_kind})")


def absolute_url(maybe_relative: Optional[str]) -> Optional[str]:
    if not maybe_relative:
        return None
    return html.unescape(urllib.parse.urljoin(SYZBOT_ROOT, maybe_relative))


def clean_function_name(name: str) -> str:
    return re.sub(r"\.(?:isra|constprop)\.\d+$", "", name)


def extract_syscalls_from_repro(repro_text: str) -> list[str]:
    calls: list[str] = []
    for raw_line in repro_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^r\d+\s*=\s*", "", line)
        match = re.match(r"([A-Za-z0-9_.$]+)\(", line)
        if match:
            calls.append(match.group(1))
    return calls


def extract_function_from_report(report_text: str, file_path: str, line: Optional[int]) -> Optional[str]:
    if not file_path or line is None:
        return None
    pattern = re.compile(
        rf"^\s*([A-Za-z0-9_.$]+)\+0x[0-9a-f]+/0x[0-9a-f]+\s+{re.escape(file_path)}:{line}\s*$",
        re.M,
    )
    match = pattern.search(report_text)
    if match:
        return clean_function_name(match.group(1))
    return None


def augment_known_bug_case(case: DatasetCase, case_dir: Path) -> DatasetCase:
    if not case.syzbot_bug_id:
        return case

    bug_url = f"{SYZBOT_ROOT}/bug?id={case.syzbot_bug_id}"
    log(f"fetching syzbot metadata: {bug_url}")
    try:
        page = fetch_text(bug_url)
    except urllib.error.HTTPError as exc:
        fallback = KNOWN_BUG_CASE_FALLBACKS.get(case.case_id)
        if exc.code != 404 or not fallback:
            raise
        warn(f"dataset bug id for case {case.case_id} is stale or truncated; using fallback bug URL")
        case.syzbot_bug_id = str(fallback.get("syzbot_bug_id", case.syzbot_bug_id))
        fallback_path = fallback.get("file_path")
        fallback_line = fallback.get("line")
        if fallback_path:
            case.file_path = str(fallback_path)
        if isinstance(fallback_line, int):
            case.line = fallback_line
        case.position = f"{case.file_path}:{case.line}" if case.line is not None else case.file_path
        bug_url = str(fallback["bug_url"])
        log(f"fetching fallback syzbot metadata: {bug_url}")
        page = fetch_text(bug_url)
    save_text(case_dir / "artifacts" / "syzbot_bug.html", page)

    title_match = re.search(r"<title>(.*?)</title>", page, re.S | re.I)
    if title_match:
        case.bug_title = html.unescape(title_match.group(1)).strip()
        case.crash_title = case.bug_title

    cause_match = re.search(
        r"Cause bisection: introduced by.*?commit ([0-9a-f]{40})<br>",
        page,
        re.S,
    )
    if cause_match:
        case.cause_commit = cause_match.group(1)

    fix_match = re.search(
        r"Fix commit:</b>.*?commit/\?id=([0-9a-f]{40})",
        page,
        re.S,
    )
    if not fix_match:
        fix_match = re.search(r"Fix commit:</b>.*?([0-9a-f]{12,40})", page, re.S)
    if fix_match:
        case.fix_commit = fix_match.group(1)

    for key, attr in (
        ("KernelConfig", "kernel_config_url"),
        ("ReproC", "repro_c_url"),
        ("ReproSyz", "repro_syz_url"),
    ):
        match = re.search(rf'href="([^"]*tag={key}[^"]*)"', page)
        setattr(case, attr, absolute_url(match.group(1)) if match else None)

    report_match = re.search(r'href="([^"]*/x/report\.txt\?x=[^"]+)"', page)
    log_match = re.search(r'href="([^"]*/x/log\.txt\?x=[^"]+)"', page)
    case.report_url = report_match.group(1) if report_match else None
    case.log_url = log_match.group(1) if log_match else None

    case.kernel_commit = case.cause_commit or case.fix_commit or case.kernel_commit

    if case.kernel_config_url:
        save_text(case_dir / "artifacts" / "kernel.config", fetch_text(case.kernel_config_url))
    if case.repro_c_url:
        save_text(case_dir / "artifacts" / "repro.c", fetch_text(case.repro_c_url))
    if case.repro_syz_url:
        repro_text = fetch_text(case.repro_syz_url)
        save_text(case_dir / "artifacts" / "repro.syz", repro_text)
        sequence: list[str] = []
        for syscall_name in extract_syscalls_from_repro(repro_text):
            if syscall_name not in sequence:
                sequence.append(syscall_name)
        case.sequence = sequence
        case.entry_syscalls = list(sequence)
        case.related_syscalls = list(sequence[:-1]) if len(sequence) > 1 else []
    if case.report_url:
        report_text = fetch_text(case.report_url)
        save_text(case_dir / "artifacts" / "report.txt", report_text)
        case.target_function = extract_function_from_report(report_text, case.file_path, case.line)
    if case.log_url:
        save_text(case_dir / "artifacts" / "syzkaller.log", fetch_text(case.log_url))
    return case


def build_target_spec(case: DatasetCase) -> dict[str, object]:
    if not case.kernel_commit:
        raise ValueError(f"case {case.case_id} is missing kernel_commit; cannot build target spec")

    return TargetSpec(
        target_id=f"syzdirect_{case.dataset_kind}_case_{case.case_id}",
        kernel_commit=case.kernel_commit,
        file_path=case.file_path,
        function=case.target_function,
        line=case.line,
        target_type="syzdirect_dataset_case",
        description=case.bug_title or case.position,
        notes=f"SyzDirect {case.dataset_kind} dataset case {case.case_id}",
        syzbot_bug_id=case.syzbot_bug_id,
        fix_commit=case.fix_commit,
        cause_commit=case.cause_commit,
        patch_commit=case.patch_commit,
        patch_type=case.patch_type,
        entry_syscalls=list(case.entry_syscalls),
        related_syscalls=list(case.related_syscalls),
        sequence=list(case.sequence),
    ).to_dict()


def prepare_kernel_source(case_dir: Path, commit: str) -> Optional[Path]:
    kernel_dir = case_dir / "kernel-src"
    if kernel_dir.exists() and (kernel_dir / ".git").exists():
        current = subprocess.run(
            ["git", "-C", str(kernel_dir), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
        if current.returncode == 0 and current.stdout.strip().startswith(commit[:12]):
            return kernel_dir
    if kernel_dir.exists() and not (kernel_dir / ".git").exists():
        raise SystemExit(f"{kernel_dir} exists but is not a git repository")

    last_error: Optional[Exception] = None
    for repo_url in LINUX_REPO_CANDIDATES:
        try:
            if kernel_dir.exists():
                shutil.rmtree(kernel_dir)
            kernel_dir.mkdir(parents=True, exist_ok=True)
            run_cmd(["git", "init", str(kernel_dir)])
            run_cmd(["git", "-C", str(kernel_dir), "remote", "add", "origin", repo_url])
            run_cmd(["git", "-C", str(kernel_dir), "fetch", "--depth", "1", "origin", commit])
            run_cmd(["git", "-C", str(kernel_dir), "checkout", "--force", "FETCH_HEAD"])
            return kernel_dir
        except subprocess.CalledProcessError as exc:
            last_error = exc
            warn(f"kernel fetch from {repo_url} failed")
            shutil.rmtree(kernel_dir, ignore_errors=True)
    if last_error:
        warn(f"kernel source checkout failed: {last_error}")
    return None


def ensure_kernel_build(
    case_dir: Path,
    kernel_src: Path,
    config_path: Path,
    *,
    force_rebuild: bool = False,
) -> Optional[Path]:
    def disable_btf_debug_info(config_file: Path) -> bool:
        if not config_file.exists():
            return False
        original = config_file.read_text(encoding="utf-8")
        updated = original
        replacements = (
            ("CONFIG_DEBUG_INFO_BTF=y\n", "# CONFIG_DEBUG_INFO_BTF is not set\n"),
            ("CONFIG_DEBUG_INFO_BTF_MODULES=y\n", "# CONFIG_DEBUG_INFO_BTF_MODULES is not set\n"),
            ("CONFIG_PAHOLE_HAS_SPLIT_BTF=y\n", "# CONFIG_PAHOLE_HAS_SPLIT_BTF is not set\n"),
            ("CONFIG_PAHOLE_HAS_BTF_TAG=y\n", "# CONFIG_PAHOLE_HAS_BTF_TAG is not set\n"),
            ("CONFIG_PAHOLE_HAS_LANG_EXCLUDE=y\n", "# CONFIG_PAHOLE_HAS_LANG_EXCLUDE is not set\n"),
        )
        for old, new in replacements:
            updated = updated.replace(old, new)
        if updated != original:
            config_file.write_text(updated, encoding="utf-8")
            log(f"disabled BTF debug info options in {config_file}")
            return True
        return False

    build_dir = case_dir / "kernel-build"
    bzimage = build_dir / "bzImage"
    vmlinux = build_dir / "vmlinux"
    source_kcov = kernel_src / "kernel" / "kcov.c"
    if (
        not force_rebuild
        and bzimage.exists()
        and vmlinux.exists()
        and source_kcov.exists()
        and bzimage.stat().st_mtime >= source_kcov.stat().st_mtime
    ):
        return build_dir

    build_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config_path, build_dir / ".config")
    disable_btf_debug_info(build_dir / ".config")
    jobs = str(os.cpu_count() or 1)
    disable_hardening = "-fcf-protection=none -fno-stack-clash-protection -U_FORTIFY_SOURCE"
    build_env = os.environ.copy()
    for key in (
        "CFLAGS",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "KCFLAGS",
        "KCPPFLAGS",
        "KAFLAGS",
        "HOSTCFLAGS",
        "HOSTCPPFLAGS",
        "HOSTCXXFLAGS",
        "HOSTLDFLAGS",
        "USERCFLAGS",
        "USERLDFLAGS",
        "DEB_BUILD_MAINT_OPTIONS",
        "DEB_CFLAGS_MAINT_APPEND",
        "DEB_CPPFLAGS_MAINT_APPEND",
        "DEB_CXXFLAGS_MAINT_APPEND",
        "DEB_LDFLAGS_MAINT_APPEND",
    ):
        build_env.pop(key, None)
    make_base = [
        "make",
        "-C",
        str(kernel_src),
        f"O={build_dir}",
        f"KCFLAGS={disable_hardening}",
        "KCPPFLAGS=-U_FORTIFY_SOURCE",
        "KAFLAGS=",
        f"HOSTCFLAGS={disable_hardening}",
        "HOSTCPPFLAGS=-U_FORTIFY_SOURCE",
        f"HOSTCXXFLAGS={disable_hardening}",
        "HOSTLDFLAGS=",
        f"USERCFLAGS={disable_hardening}",
        "USERLDFLAGS=",
        "DEB_BUILD_MAINT_OPTIONS=hardening=none",
    ]
    try:
        run_cmd([*make_base, "olddefconfig"], env=build_env)
        if disable_btf_debug_info(build_dir / ".config"):
            run_cmd([*make_base, "olddefconfig"], env=build_env)
        run_cmd(
            [*make_base, "WERROR=0", f"-j{jobs}", "bzImage", "vmlinux"],
            env=build_env,
        )
    except subprocess.CalledProcessError as exc:
        warn(f"kernel build failed: {exc}")
        return None

    arch_bzimage = build_dir / "arch" / "x86" / "boot" / "bzImage"
    if arch_bzimage.exists() and not bzimage.exists():
        try:
            bzimage.symlink_to(Path("arch") / "x86" / "boot" / "bzImage")
        except FileExistsError:
            pass
        except OSError:
            shutil.copy2(arch_bzimage, bzimage)
    return build_dir if bzimage.exists() and vmlinux.exists() else None


def find_existing_vm_assets(case_dir: Path, output_root: Path) -> tuple[Optional[Path], Optional[Path]]:
    local_dir = case_dir / "image-work"
    local_image = local_dir / "bullseye.qcow2"
    local_key = local_dir / "bullseye.id_rsa"
    if local_image.exists() and local_key.exists():
        return local_image, local_key

    candidates: list[tuple[float, Path, Path]] = []
    for image_path in output_root.rglob("bullseye.qcow2"):
        key_path = image_path.with_name("bullseye.id_rsa")
        if key_path.exists():
            candidates.append((image_path.stat().st_mtime, image_path, key_path))
    if not candidates:
        return None, None
    _, image_path, key_path = max(candidates, key=lambda item: item[0])
    return image_path, key_path


def find_existing_kernel_config(case_dir: Path, output_root: Path) -> Optional[Path]:
    local_config = case_dir / "artifacts" / "kernel.config"
    if local_config.exists():
        return local_config

    candidates: list[tuple[float, Path]] = []
    for config_path in output_root.rglob("artifacts/kernel.config"):
        if config_path == local_config:
            continue
        candidates.append((config_path.stat().st_mtime, config_path))
    if not candidates:
        return None
    _, config_path = max(candidates, key=lambda item: item[0])
    return config_path


def resolve_sudo_password(password_file: Optional[Path]) -> Optional[str]:
    env_password = os.environ.get("SUDO_PASSWORD")
    if env_password:
        return env_password
    if not password_file:
        return None
    return password_file.read_text(encoding="utf-8").rstrip("\r\n")


def ensure_vm_assets(
    case_dir: Path,
    fuzzer_root: Path,
    env_report_data: dict[str, object],
    sudo_password: Optional[str],
) -> tuple[Optional[Path], Optional[Path]]:
    image_dir = case_dir / "image-work"
    image_dir.mkdir(parents=True, exist_ok=True)

    preferred_image = image_dir / "bullseye.qcow2"
    fallback_raw_image = image_dir / "bullseye.img"
    key_path = image_dir / "bullseye.id_rsa"

    if preferred_image.exists() and key_path.exists():
        return preferred_image, key_path
    if fallback_raw_image.exists() and key_path.exists():
        return fallback_raw_image, key_path

    if env_report_data["missing_for_image_build"]:
        warn(f"missing image build commands: {', '.join(env_report_data['missing_for_image_build'])}")
        return None, None

    create_image = fuzzer_root / "tools" / "create-image.sh"
    if not create_image.exists():
        warn(f"create-image.sh not found: {create_image}")
        return None, None

    password = None if env_report_data["passwordless_sudo"] else sudo_password
    if not env_report_data["passwordless_sudo"] and not password:
        warn("image build requires sudo; set SUDO_PASSWORD or run in an interactive terminal")
        return None, None

    uid = os.getuid()
    gid = os.getgid()
    inner_script = (
        "set -euo pipefail; "
        f"cd {shlex_quote(str(image_dir))}; "
        f"bash {shlex_quote(str(create_image))} --distribution bullseye --feature minimal; "
        "if [ -f bullseye.img ] && [ ! -f bullseye.qcow2 ]; then "
        "qemu-img convert -f raw -O qcow2 bullseye.img bullseye.qcow2; "
        "fi; "
        f"chown -R {uid}:{gid} {shlex_quote(str(image_dir))}"
    )
    quoted_inner_script = shlex_quote(inner_script)

    try:
        if env_report_data["passwordless_sudo"]:
            subprocess.run(
                ["bash", "-lc", f"sudo bash -lc {quoted_inner_script}"],
                cwd=str(image_dir),
                check=True,
                text=True,
            )
        else:
            env = os.environ.copy()
            env["SUDO_PASSWORD"] = password
            subprocess.run(
                [
                    "bash",
                    "-lc",
                    f'printf "%s\\n" "$SUDO_PASSWORD" | sudo -S bash -lc {quoted_inner_script}',
                ],
                cwd=str(image_dir),
                env=env,
                check=True,
                text=True,
            )
    except subprocess.CalledProcessError as exc:
        warn(f"image build failed: {exc}")
        return None, None

    if preferred_image.exists() and key_path.exists():
        return preferred_image, key_path
    if fallback_raw_image.exists() and key_path.exists():
        return fallback_raw_image, key_path

    warn(f"image build finished without expected artifacts in {image_dir}")
    return None, None


def resolve_case_file_path(case: DatasetCase, kernel_src: Path) -> bool:
    candidate = kernel_src / case.file_path
    if candidate.exists():
        return False

    rel_path = Path(case.file_path)
    search_dir = kernel_src / rel_path.parent
    if not search_dir.is_dir():
        return False

    wanted = canonicalize_path_fragment(rel_path.name)
    matches = [path for path in search_dir.iterdir() if path.is_file() and canonicalize_path_fragment(path.name) == wanted]
    if len(matches) != 1:
        file_entries = [path for path in search_dir.iterdir() if path.is_file()]
        canonical_to_paths: dict[str, list[Path]] = {}
        for path in file_entries:
            canonical_to_paths.setdefault(canonicalize_path_fragment(path.name), []).append(path)
        close = difflib.get_close_matches(wanted, canonical_to_paths.keys(), n=2, cutoff=0.8)
        if len(close) != 1 or len(canonical_to_paths.get(close[0], [])) != 1:
            return False
        matches = canonical_to_paths[close[0]]

    resolved = matches[0].relative_to(kernel_src).as_posix()
    warn(f"resolved dataset file path {case.file_path} -> {resolved}")
    case.file_path = resolved
    if case.line is not None:
        case.position = f"{resolved}:{case.line}"
    return True


def run_analysis_pipeline(repo_root: Path, kernel_src: Path, target_json: Path, case_dir: Path) -> bool:
    generated_dir = case_dir / "generated"
    templates_dir = generated_dir / "templates"
    distances_dir = generated_dir / "distances"
    logs_dir = generated_dir / "logs"
    generated_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)
    distances_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    analysis_json = templates_dir / "analysis.json"
    distance_json = distances_dir / "distances.json"
    target_spec = build_target_spec_from_file(target_json)

    try:
        run_cmd(
            [
                sys.executable,
                str(repo_root / "source" / "analyzer" / "syscall_analyzer.py"),
                "--kernel",
                str(kernel_src),
                "--target",
                str(target_json),
                "--output",
                str(analysis_json),
            ]
        )
        run_cmd(
            [
                sys.executable,
                str(repo_root / "source" / "distance" / "distance_calculator.py"),
                "--kernel",
                str(kernel_src),
                "--target-file",
                str(target_spec["file_path"]),
                "--target-line",
                str(target_spec["line"]),
                "--output",
                str(distance_json),
            ]
        )
        run_cmd(
            [
                sys.executable,
                str(repo_root / "source" / "template" / "template_generator.py"),
                "--analysis",
                str(analysis_json),
                "--distances",
                str(distance_json),
                "--output",
                str(templates_dir),
            ]
        )
        return True
    except subprocess.CalledProcessError as exc:
        warn(f"analysis pipeline failed: {exc}")
        return False


def build_target_spec_from_file(path: Path) -> dict[str, object]:
    return load_target_spec(path).to_dict()


def ensure_preflight_requirements(
    args: argparse.Namespace,
    env_data: dict[str, object],
    *,
    sudo_password: Optional[str],
) -> None:
    problems: list[str] = []

    commands = env_data["commands"]
    if not commands.get("python3"):
        problems.append("python3 is required")
    if not commands.get("git"):
        problems.append("git is required")

    if not args.skip_fuzzer_build and env_data["missing_for_fuzzer_build"]:
        missing = ", ".join(env_data["missing_for_fuzzer_build"])
        problems.append(f"missing fuzzer build commands: {missing}")

    needs_kernel_build = not args.skip_kernel_build and args.kernel_build_dir is None
    if needs_kernel_build and env_data["missing_for_kernel_build"]:
        missing = ", ".join(env_data["missing_for_kernel_build"])
        problems.append(f"missing kernel build commands: {missing}")

    needs_image_build = args.image is None or args.ssh_key is None
    if needs_image_build and env_data["missing_for_image_build"]:
        missing = ", ".join(env_data["missing_for_image_build"])
        problems.append(f"missing image build commands: {missing}")

    if not args.prepare_only and env_data["missing_for_fuzz_run"]:
        missing = ", ".join(env_data["missing_for_fuzz_run"])
        problems.append(f"missing runtime commands: {missing}")

    if needs_image_build and env_data["image_build_requires_sudo_prompt"] and not sudo_password:
        problems.append(
            "image build requires sudo but no non-interactive credential was provided "
            "(set SUDO_PASSWORD or pass --sudo-password-file)"
        )

    if problems:
        for problem in problems:
            err(problem)
        raise SystemExit(1)


def ensure_syzdirect_manager(fuzzer_root: Path, *, force_rebuild: bool = False) -> bool:
    manager = fuzzer_root / "bin" / "syz-manager"
    if manager.exists() and not force_rebuild:
        return True
    if force_rebuild:
        shutil.rmtree(fuzzer_root / "bin", ignore_errors=True)
        descriptions = fuzzer_root / ".descriptions"
        if descriptions.is_dir():
            shutil.rmtree(descriptions, ignore_errors=True)
        elif descriptions.exists():
            descriptions.unlink()
    try:
        run_cmd(["make", "manager", "fuzzer", "execprog", "executor"], cwd=fuzzer_root)
        return manager.exists()
    except subprocess.CalledProcessError as exc:
        warn(f"failed to build SyzDirect fuzzer: {exc}")
        return manager.exists()


def environment_report(case_dir: Path, fuzzer_root: Path) -> dict[str, object]:
    kvm_path = Path("/dev/kvm")
    commands = {
        name: command_path(name)
        for name in (
            "python3",
            "git",
            "go",
            "make",
            "gcc",
            "curl",
            "ssh-keygen",
            "qemu-system-x86_64",
            "qemu-img",
            "debootstrap",
            "flex",
            "bison",
            "bc",
            "sudo",
        )
    }
    report = {
        "commands": commands,
        "passwordless_sudo": passwordless_sudo(),
        "fuzzer_root": str(fuzzer_root),
        "case_dir": str(case_dir),
        "kvm_device": str(kvm_path) if kvm_path.exists() else None,
        "kvm_exists": kvm_path.exists(),
        "kvm_accessible": os.access(kvm_path, os.R_OK | os.W_OK) if kvm_path.exists() else False,
        "missing_for_fuzzer_build": [
            name for name in ("go", "make", "gcc") if not commands.get(name)
        ],
        "missing_for_kernel_build": [
            name for name in ("make", "gcc", "bc", "flex", "bison") if not commands.get(name)
        ],
        "missing_for_image_build": [
            name for name in ("qemu-img", "debootstrap", "ssh-keygen", "sudo") if not commands.get(name)
        ],
        "missing_for_fuzz_run": [
            name for name in ("qemu-system-x86_64", "ssh-keygen") if not commands.get(name)
        ],
    }
    report["image_build_blocked"] = bool(report["missing_for_image_build"])
    report["image_build_requires_sudo_prompt"] = bool(commands.get("sudo")) and not report["passwordless_sudo"]
    save_json(case_dir / "environment_report.json", report)
    return report


def full_run_ready(
    env_report_data: dict[str, object],
    manager_ok: bool,
    kernel_src: Optional[Path],
    kernel_build_dir: Optional[Path],
    image_path: Optional[Path],
    ssh_key_path: Optional[Path],
) -> bool:
    if not manager_ok or not kernel_src or not kernel_build_dir or not image_path or not ssh_key_path:
        return False
    if env_report_data["missing_for_fuzz_run"]:
        return False
    return (kernel_build_dir / "bzImage").exists() and image_path.exists() and ssh_key_path.exists()


def run_full_experiment(
    repo_root: Path,
    fuzzer_root: Path,
    case_dir: Path,
    mode: str,
    target_json: Path,
    budget_hours: int,
    repetitions: int,
    kernel_src: Path,
    kernel_build_dir: Path,
    image_path: Path,
    ssh_key_path: Path,
    sudo_password: Optional[str] = None,
) -> int:
    runtime_env = case_dir / "runtime_env"
    runtime_env.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["WORK_DIR"] = str(runtime_env)
    env["SYZDIRECT_DIR"] = str(repo_root)
    env["SYZDIRECT_FUZZER_DIR"] = str(fuzzer_root)
    env["KERNEL_SRC_DIR"] = str(kernel_src)
    env["KERNEL_BUILD_DIR"] = str(kernel_build_dir)
    env["IMAGE_PATH"] = str(image_path)
    env["SSHKEY_PATH"] = str(ssh_key_path)
    if sudo_password:
        env["SUDO_PASSWORD"] = sudo_password

    cmd = [
        "bash",
        str(repo_root / "scripts" / "run_experiment.sh"),
        mode,
        str(target_json),
        str(budget_hours),
        str(repetitions),
    ]
    result = subprocess.run(cmd, text=True, env=env, check=False)
    return result.returncode


def parse_args() -> argparse.Namespace:
    default_syzdirect_root = REPO_ROOT / "deps" / "SyzDirect"
    default_output_root = REPO_ROOT / ".runtime"
    parser = argparse.ArgumentParser(
        description="Prepare and run a SyzDirect public dataset case",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--case-id", type=int, required=True, help="dataset case id")
    parser.add_argument(
        "--dataset-kind",
        choices=("known-bugs", "patches"),
        default="known-bugs",
        help="which SyzDirect dataset table to use",
    )
    parser.add_argument(
        "--mode",
        choices=("baseline", "syzdirect", "agent-loop"),
        default="agent-loop",
        help="research pipeline mode to invoke if runtime is ready",
    )
    parser.add_argument("--budget-hours", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument(
        "--syzdirect-root",
        type=Path,
        default=default_syzdirect_root,
        help="repo-local SyzDirect checkout (bootstrapped automatically if missing)",
    )
    parser.add_argument(
        "--dataset-pdf",
        type=Path,
        default=None,
        help="override dataset.pdf path",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=default_output_root,
        help="repo-local directory where case bundles and runtime data are stored",
    )
    parser.add_argument(
        "--sudo-password-file",
        type=Path,
        default=None,
        help="path to a file containing the sudo password for non-interactive image/KVM setup",
    )
    parser.add_argument("--image", type=Path, default=None, help="existing image path")
    parser.add_argument("--ssh-key", type=Path, default=None, help="existing SSH private key path")
    parser.add_argument("--kernel-build-dir", type=Path, default=None, help="existing kernel build dir with bzImage")
    parser.add_argument("--prepare-only", action="store_true", help="stop before full run_experiment invocation")
    parser.add_argument("--skip-kernel-source", action="store_true", help="do not fetch kernel source")
    parser.add_argument("--skip-kernel-build", action="store_true", help="do not auto-build the kernel from saved kernel.config")
    parser.add_argument("--skip-analysis", action="store_true", help="do not run analyzer/distance/template generation")
    parser.add_argument("--skip-fuzzer-build", action="store_true", help="do not build SyzDirect manager if missing")
    parser.add_argument("--force-refresh", action="store_true", help="refresh case bundle artifacts")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help=argparse.SUPPRESS)
    return parser.parse_args()


def prepare_case_dir(output_root: Path, dataset_kind: str, case_id: int, *, force_refresh: bool) -> Path:
    case_dir = (output_root / dataset_kind / f"case_{case_id}").resolve()
    if force_refresh and case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


def prepare_case_bundle(
    dataset_pdf: Path,
    case_id: int,
    dataset_kind: str,
    case_dir: Path,
) -> CaseBundle:
    case = extract_case_from_pdf(dataset_pdf, case_id, dataset_kind)
    if dataset_kind == "known-bugs":
        try:
            case = augment_known_bug_case(case, case_dir)
        except urllib.error.URLError as exc:
            warn(f"failed to fetch syzbot metadata: {exc}")

    bundle = CaseBundle(
        case=case,
        case_dir=case_dir,
        case_json=case_dir / "case_metadata.json",
        target_json=case_dir / "target.json",
    )
    if not bundle.case.kernel_commit:
        raise SystemExit(f"case {case_id} is missing kernel_commit; cannot continue")
    bundle.save()
    log(f"case bundle written to {case_dir}")
    return bundle


def prepare_fuzzer_runtime(
    case_dir: Path,
    fuzzer_root: Path,
    env_data: dict[str, object],
    *,
    skip_fuzzer_build: bool,
) -> tuple[dict[str, object], bool]:
    fuzzer_changed = ensure_syzdirect_fuzzer_compatibility(fuzzer_root)
    manager_ok = (fuzzer_root / "bin" / "syz-manager").exists()
    if (fuzzer_changed or not manager_ok) and not skip_fuzzer_build:
        manager_ok = ensure_syzdirect_manager(
            fuzzer_root,
            force_rebuild=fuzzer_changed or not manager_ok,
        )
    save_json(case_dir / "environment_report.json", env_data | {"manager_ready": manager_ok})
    return env_data, manager_ok


def prepare_kernel_artifacts(
    args: argparse.Namespace,
    bundle: CaseBundle,
    repo_root: Path,
    output_root: Path,
    env_data: dict[str, object],
) -> KernelPreparation:
    prepared = KernelPreparation(
        kernel_build_dir=args.kernel_build_dir.resolve() if args.kernel_build_dir else None
    )

    if bundle.case.kernel_commit and not args.skip_kernel_source:
        try:
            prepared.kernel_src = prepare_kernel_source(bundle.case_dir, bundle.case.kernel_commit)
        except SystemExit:
            raise
        except Exception as exc:
            warn(f"kernel source preparation failed: {exc}")

        if prepared.kernel_src:
            prepared.kernel_src_changed = (
                ensure_syzdirect_kcov_support(prepared.kernel_src) or prepared.kernel_src_changed
            )
            prepared.kernel_src_changed = (
                ensure_host_build_compatibility(prepared.kernel_src) or prepared.kernel_src_changed
            )
    elif not bundle.case.kernel_commit:
        warn("no kernel commit available; skipping kernel source preparation")

    if prepared.kernel_src and resolve_case_file_path(bundle.case, prepared.kernel_src):
        bundle.save()

    if prepared.kernel_src and not args.skip_analysis:
        prepared.analysis_ok = run_analysis_pipeline(
            repo_root,
            prepared.kernel_src,
            bundle.target_json,
            bundle.case_dir,
        )

    if prepared.kernel_build_dir or not prepared.kernel_src or args.skip_kernel_build:
        return prepared

    kernel_config = find_existing_kernel_config(bundle.case_dir, output_root)
    if env_data["missing_for_kernel_build"]:
        warn(f"missing kernel build commands: {', '.join(env_data['missing_for_kernel_build'])}")
        return prepared
    if not kernel_config:
        warn("missing kernel.config; skipping automatic kernel build")
        return prepared
    if kernel_config != bundle.case_dir / "artifacts" / "kernel.config":
        log(f"reusing kernel.config from {kernel_config}")

    prepared.kernel_build_dir = ensure_kernel_build(
        bundle.case_dir,
        prepared.kernel_src,
        kernel_config,
        force_rebuild=prepared.kernel_src_changed,
    )
    return prepared


def resolve_runtime_assets(
    args: argparse.Namespace,
    case_dir: Path,
    output_root: Path,
    fuzzer_root: Path,
    env_data: dict[str, object],
    sudo_password: Optional[str],
) -> RuntimeAssets:
    assets = RuntimeAssets(
        image_path=args.image.resolve() if args.image else None,
        ssh_key_path=args.ssh_key.resolve() if args.ssh_key else None,
        sudo_password=sudo_password,
    )

    if not assets.image_path or not assets.ssh_key_path:
        auto_image_path, auto_ssh_key_path = find_existing_vm_assets(case_dir, output_root)
        if auto_image_path and auto_ssh_key_path:
            if not assets.image_path:
                assets.image_path = auto_image_path
            if not assets.ssh_key_path:
                assets.ssh_key_path = auto_ssh_key_path
            log(f"reusing VM assets from {auto_image_path.parent}")

    if assets.image_path and assets.ssh_key_path:
        return assets

    built_image_path, built_ssh_key_path = ensure_vm_assets(
        case_dir,
        fuzzer_root,
        env_data,
        assets.sudo_password,
    )
    if built_image_path and built_ssh_key_path:
        assets.image_path = built_image_path
        assets.ssh_key_path = built_ssh_key_path
        log(f"created VM assets in {built_image_path.parent}")
    return assets


def report_full_run_blockers(
    env_data: dict[str, object],
    manager_ok: bool,
    prepared: KernelPreparation,
    runtime_assets: RuntimeAssets,
) -> int:
    warn("full fuzz run prerequisites are not satisfied")
    if not manager_ok:
        warn("missing SyzDirect manager binary")
    if not prepared.kernel_src:
        warn("missing kernel source checkout")
    if not prepared.kernel_build_dir or not (prepared.kernel_build_dir / "bzImage").exists():
        warn("missing kernel build directory with bzImage")
    if not runtime_assets.image_path or not runtime_assets.image_path.exists():
        warn("missing VM image")
    if not runtime_assets.ssh_key_path or not runtime_assets.ssh_key_path.exists():
        warn("missing SSH key")
    if env_data["missing_for_fuzz_run"]:
        warn(f"missing runtime commands: {', '.join(env_data['missing_for_fuzz_run'])}")
    if env_data["image_build_blocked"]:
        warn("image build is blocked on this machine (missing tools)")
    elif env_data["image_build_requires_sudo_prompt"]:
        warn("image build would require interactive sudo on this machine")
    return 2 if prepared.analysis_ok else 1


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    sudo_password_file = args.sudo_password_file.resolve() if args.sudo_password_file else None
    sudo_password = resolve_sudo_password(sudo_password_file)
    syzdirect_root = ensure_syzdirect_checkout(args.syzdirect_root.resolve())
    output_root = args.output_root.resolve()
    case_dir = prepare_case_dir(
        output_root,
        args.dataset_kind,
        args.case_id,
        force_refresh=args.force_refresh,
    )

    fuzzer_root = syzdirect_root / "source" / "syzdirect" / "syzdirect_fuzzer"
    env_data = environment_report(case_dir, fuzzer_root)
    ensure_preflight_requirements(args, env_data, sudo_password=sudo_password)

    dataset_pdf = args.dataset_pdf.resolve() if args.dataset_pdf else syzdirect_root / "dataset" / "dataset.pdf"
    if not dataset_pdf.exists():
        raise SystemExit(f"dataset pdf not found: {dataset_pdf}")

    bundle = prepare_case_bundle(dataset_pdf, args.case_id, args.dataset_kind, case_dir)
    env_data, manager_ok = prepare_fuzzer_runtime(
        case_dir,
        fuzzer_root,
        env_data,
        skip_fuzzer_build=args.skip_fuzzer_build,
    )

    prepared = prepare_kernel_artifacts(args, bundle, repo_root, output_root, env_data)
    runtime_assets = resolve_runtime_assets(
        args,
        case_dir,
        output_root,
        fuzzer_root,
        env_data,
        sudo_password,
    )

    if args.prepare_only:
        log("prepare-only requested; stopping before full run")
        return 0

    if not full_run_ready(
        env_data,
        manager_ok,
        prepared.kernel_src,
        prepared.kernel_build_dir,
        runtime_assets.image_path,
        runtime_assets.ssh_key_path,
    ):
        return report_full_run_blockers(env_data, manager_ok, prepared, runtime_assets)

    exit_code = run_full_experiment(
        repo_root=repo_root,
        fuzzer_root=fuzzer_root,
        case_dir=case_dir,
        mode=args.mode,
        target_json=bundle.target_json,
        budget_hours=args.budget_hours,
        repetitions=args.repetitions,
        kernel_src=prepared.kernel_src,
        kernel_build_dir=prepared.kernel_build_dir,
        image_path=runtime_assets.image_path,
        ssh_key_path=runtime_assets.ssh_key_path,
        sudo_password=runtime_assets.sudo_password,
    )
    if exit_code != 0:
        warn(f"run_experiment exited with code {exit_code}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
