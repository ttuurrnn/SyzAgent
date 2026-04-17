"""
SyzDirect Runner — unified kernel build utilities.

Consolidates build compatibility fixes, KCOV patching, config overrides,
and emit-script generation previously duplicated across run_hunt.py and
Compilation.py.
"""

import os
import re
import subprocess

from paths import BOOT_SAFE_X86_OVERRIDES


# ──────────────────────────────────────────────────────────────────────────
# Clang version detection
# ──────────────────────────────────────────────────────────────────────────

def get_clang_version(clang_path):
    """Return (major, minor, patch) tuple of the given clang, or None."""
    try:
        proc = subprocess.run(
            [clang_path, "--version"],
            check=False, capture_output=True, text=True,
        )
    except OSError:
        return None
    m = re.search(r"clang version (\d+)\.(\d+)\.(\d+)", proc.stdout)
    return tuple(int(x) for x in m.groups()) if m else None


# ──────────────────────────────────────────────────────────────────────────
# Build compatibility relaxations
# ──────────────────────────────────────────────────────────────────────────

def _patch_file(path, replacements, label=""):
    """Apply text replacements to a file. Returns True if changed."""
    if not os.path.exists(path):
        return False
    with open(path) as f:
        txt = f.read()
    updated = txt
    for old, new in replacements.items():
        updated = updated.replace(old, new)
    if updated != txt:
        with open(path, "w") as f:
            f.write(updated)
        if label:
            print(f"  [compat] {label}: {path}")
        return True
    return False


def _replace_once(contents, original, replacement):
    """Replace the first occurrence of original in contents."""
    if original not in contents:
        return contents, False
    return contents.replace(original, replacement, 1), True


def relax_kernel_build(src_dir, clang_path):
    """Apply all clang/kernel build compatibility relaxations to a source tree."""
    _patch_file(
        os.path.join(src_dir, "tools", "include", "linux", "string.h"),
        {
            "extern size_t strlcpy(char *dest, const char *src, size_t size);":
                "#pragma GCC diagnostic push\n"
                "#pragma GCC diagnostic ignored \"-Wredundant-decls\"\n"
                "extern size_t strlcpy(char *dest, const char *src, size_t size);\n"
                "#pragma GCC diagnostic pop",
        },
        "Relaxed host strlcpy declaration",
    )

    ver = get_clang_version(clang_path)
    if ver is None or ver >= (15, 0, 0):
        return

    # 1) min-tool-version.sh: lower required clang from 15 to 13
    _patch_file(
        os.path.join(src_dir, "scripts", "min-tool-version.sh"),
        {"echo 15.0.0": "echo 13.0.0"},
        "Relaxed min clang version",
    )

    # 2) arch/x86/Makefile: wrap clang-only flags in cc-option
    _patch_file(
        os.path.join(src_dir, "arch", "x86", "Makefile"),
        {
            "KBUILD_CFLAGS += -mno-fp-ret-in-387":
                "KBUILD_CFLAGS += $(call cc-option,-mno-fp-ret-in-387)",
            "KBUILD_CFLAGS += -mskip-rax-setup":
                "KBUILD_CFLAGS += $(call cc-option,-mskip-rax-setup)",
            "KBUILD_CFLAGS += -mstack-protector-guard-reg=$(percpu_seg)":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-reg=$(percpu_seg))",
            "KBUILD_CFLAGS += -mstack-protector-guard-symbol=__ref_stack_chk_guard":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-symbol=__ref_stack_chk_guard)",
            "KBUILD_CFLAGS += -mstack-protector-guard=global":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard=global)",
        },
        "Relaxed x86 clang flags",
    )

    # 3) scripts/Makefile.warn: wrap clang warning flags
    _patch_file(
        os.path.join(src_dir, "scripts", "Makefile.warn"),
        {
            "KBUILD_CFLAGS += -Wno-pointer-to-enum-cast":
                "KBUILD_CFLAGS += $(call cc-disable-warning,pointer-to-enum-cast)",
            "KBUILD_CFLAGS += -Wno-tautological-constant-out-of-range-compare":
                "KBUILD_CFLAGS += $(call cc-disable-warning,tautological-constant-out-of-range-compare)",
            "KBUILD_CFLAGS += -Wno-unaligned-access":
                "KBUILD_CFLAGS += $(call cc-disable-warning,unaligned-access)",
            "KBUILD_CFLAGS += -Wno-enum-compare-conditional":
                "KBUILD_CFLAGS += $(call cc-disable-warning,enum-compare-conditional)",
        },
        "Relaxed warning flags",
    )


# ──────────────────────────────────────────────────────────────────────────
# KCOV distance-tracking support
# ──────────────────────────────────────────────────────────────────────────

def ensure_kcov_support(src_dir):
    """Patch kcov.h and kcov.c for SyzDirect distance-tracking support."""
    header_path = os.path.join(src_dir, "include", "linux", "kcov.h")
    source_path = os.path.join(src_dir, "kernel", "kcov.c")

    if os.path.exists(header_path):
        with open(header_path) as f:
            txt = f.read()
        updated = txt
        # Update __sanitizer_cov_trace_pc prototype to accept distance arg
        updated = updated.replace(
            "void __sanitizer_cov_trace_pc(void);",
            "void __sanitizer_cov_trace_pc(u32 dt);")
        if "void notrace kcov_mark_block(u32 i);" not in updated:
            updated = updated.replace(
                "void kcov_remote_stop(void);\n",
                "void kcov_remote_stop(void);\nvoid notrace kcov_mark_block(u32 i);\n")
        if "static inline void kcov_mark_block(u32 i) {}" not in updated:
            updated = updated.replace(
                "static inline void kcov_remote_stop_softirq(void) {}\n",
                "static inline void kcov_remote_stop_softirq(void) {}\n"
                "static inline void kcov_mark_block(u32 i) {}\n")
        if updated != txt:
            with open(header_path, "w") as f:
                f.write(updated)
            print(f"  [kcov] Patched {header_path}")

    if os.path.exists(source_path):
        with open(source_path) as f:
            txt = f.read()
        updated = txt

        if "#define DISTBLOCKSIZE 300" not in updated:
            updated = updated.replace(
                "#define KCOV_WORDS_PER_CMP 4\n",
                "#define KCOV_WORDS_PER_CMP 4\n\n#define DISTBLOCKSIZE 300\n")

        if "void notrace kcov_mark_block(u32 i)" not in updated:
            updated, count = re.subn(
                r"void notrace __sanitizer_cov_trace_pc\(void\)\n\{.*?\n\}\nEXPORT_SYMBOL\(__sanitizer_cov_trace_pc\);\n",
                """void notrace __sanitizer_cov_trace_pc(u32 dt)
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
\tif (dt < READ_ONCE(dt_area[0]))
\t\tWRITE_ONCE(dt_area[0], dt);
\tarea = (unsigned long *)(dt_area + DISTBLOCKSIZE);
\t/* The first 64-bit word is the number of subsequent PCs. */
\tpos = READ_ONCE(area[0]) + 1;
\tif (likely(pos < t->kcov_size - DISTBLOCKSIZE / 2)) {
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

\tdt_area = (u32 *)t->kcov_area;
\tif (i < READ_ONCE(dt_area[0]))
\t\tWRITE_ONCE(dt_area[0], i);
}
EXPORT_SYMBOL(kcov_mark_block);
""",
                updated, count=1, flags=re.S)

        # kcov size checks
        updated = updated.replace(
            "if (size < 2 || size > INT_MAX / sizeof(unsigned long))",
            "if (size < DISTBLOCKSIZE / 2 + 2 || size > INT_MAX / sizeof(unsigned long))")

        updated = updated.replace(
            "\t\tif ((unsigned long)remote_arg->area_size >\n"
            "\t\t    LONG_MAX / sizeof(unsigned long))\n"
            "\t\t\treturn -EINVAL;\n",
            "\t\tif ((unsigned long)remote_arg->area_size >\n"
            "\t\t    LONG_MAX / sizeof(unsigned long) ||\n"
            "\t\t    remote_arg->area_size < DISTBLOCKSIZE / 2)\n"
            "\t\t\treturn -EINVAL;\n")

        # kcov reset area
        updated = updated.replace(
            "\t/* Reset coverage size. */\n\t*(u64 *)area = 0;\n",
            "\t/* Reset coverage size. */\n"
            "\tif (mode == KCOV_MODE_TRACE_PC) {\n"
            "\t\tu32 *dt_area = area;\n\n"
            "\t\tdt_area[0] = 0xffffffff;\n"
            "\t\tfor (int i = 1; i < DISTBLOCKSIZE + 2; i++)\n"
            "\t\t\tdt_area[i] = 0;\n"
            "\t} else {\n"
            "\t\t*(u64 *)area = 0;\n"
            "\t}\n")

        # kcov merge entries
        if "u32 *dst_dt_entries, *src_dt_entries;" not in updated:
            updated = updated.replace(
                "\tvoid *dst_entries, *src_entries;\n",
                "\tvoid *dst_entries, *src_entries;\n"
                "\tu32 *dst_dt_entries, *src_dt_entries;\n")

        updated = updated.replace(
            "\tcase KCOV_MODE_TRACE_PC:\n"
            "\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n"
            "\t\tsrc_len = *(unsigned long *)src_area;\n"
            "\t\tcount_size = sizeof(unsigned long);\n"
            "\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n"
            "\t\tbreak;\n",
            "\tcase KCOV_MODE_TRACE_PC:\n"
            "\t\tdst_dt_entries = dst_area;\n"
            "\t\tsrc_dt_entries = src_area;\n"
            "\t\tdst_area_size -= DISTBLOCKSIZE / 2;\n"
            "\t\tdst_area = dst_dt_entries + DISTBLOCKSIZE;\n"
            "\t\tsrc_area = src_dt_entries + DISTBLOCKSIZE;\n"
            "\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n"
            "\t\tsrc_len = *(unsigned long *)src_area;\n"
            "\t\tcount_size = sizeof(unsigned long);\n"
            "\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n"
            "\t\tbreak;\n")

        if "dst_dt_entries[0] =" not in updated:
            updated = updated.replace(
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
                "\tif (mode == KCOV_MODE_TRACE_PC) {\n"
                "\t\tif (src_dt_entries[0] < dst_dt_entries[0])\n"
                "\t\t\tdst_dt_entries[0] = src_dt_entries[0];\n"
                "\t\tfor (int i = 1; i < DISTBLOCKSIZE; i++)\n"
                "\t\t\tWRITE_ONCE(dst_dt_entries[i], "
                "READ_ONCE(dst_dt_entries[i]) + READ_ONCE(src_dt_entries[i]));\n"
                "\t}\n\t\n"
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n")

        if updated != txt:
            with open(source_path, "w") as f:
                f.write(updated)
            print(f"  [kcov] Patched {source_path}")


# ──────────────────────────────────────────────────────────────────────────
# Build config overrides
# ──────────────────────────────────────────────────────────────────────────

def _append_unique_kconfig(config_path, lines):
    """Append config lines, skipping any that already exist."""
    with open(config_path) as f:
        existing = f.read()
    with open(config_path, "a") as f:
        for line in lines:
            if line and line in existing:
                continue
            f.write(f"{line}\n")


def find_kconfig_for_file(src_dir, target_file):
    """Find CONFIG_* options needed to compile target_file.

    Walks from the target file's directory upward, parsing Makefile/Kbuild
    to find which CONFIG_* symbol gates the target object file.
    Returns a list of 'CONFIG_XXX=y' strings.
    """
    configs = []
    # target_file e.g. "drivers/video/fbdev/smscufx.c"
    obj_name = os.path.basename(target_file).replace(".c", ".o")
    search_dir = os.path.dirname(target_file)

    # Search Makefile/Kbuild in the target directory and parent directories
    for _ in range(5):  # up to 5 levels
        if not search_dir:
            break
        for mf_name in ("Makefile", "Kbuild"):
            mf_path = os.path.join(src_dir, search_dir, mf_name)
            if not os.path.exists(mf_path):
                continue
            try:
                with open(mf_path) as f:
                    mf_text = f.read()
            except OSError:
                continue
            # Match: obj-$(CONFIG_FOO) += bar.o  or  obj-$(CONFIG_FOO) := bar.o
            for m in re.finditer(
                r'obj-\$\((CONFIG_\w+)\)\s*[+:]?=\s*(.*)', mf_text
            ):
                config_sym = m.group(1)
                objects = m.group(2).strip().split()
                if obj_name in objects:
                    configs.append(f"{config_sym}=y")
                    print(f"  [kconfig] {target_file} requires {config_sym}")
                # Also check if target is part of a composite module:
                # foo-y += bar.o  (where foo.o is gated by CONFIG_FOO)
                # First find module names gated by this config
                for obj in objects:
                    mod_name = obj.replace(".o", "")
                    # Look for: mod_name-y += ... obj_name ...
                    mod_pattern = re.compile(
                        rf'{re.escape(mod_name)}-[yobjs]+\s*[+:]?=\s*(.*)')
                    for mm in mod_pattern.finditer(mf_text):
                        sub_objs = mm.group(1).strip().split()
                        if obj_name in sub_objs:
                            configs.append(f"{config_sym}=y")
                            print(f"  [kconfig] {target_file} requires "
                                  f"{config_sym} (via {mod_name})")
        # Check for directory-level gating:
        # obj-$(CONFIG_FOO) += subdir/
        parent_dir = os.path.dirname(search_dir)
        dir_name = os.path.basename(search_dir) + "/"
        for mf_name in ("Makefile", "Kbuild"):
            mf_path = os.path.join(src_dir, parent_dir, mf_name) if parent_dir else None
            if not mf_path or not os.path.exists(mf_path):
                continue
            try:
                with open(mf_path) as f:
                    mf_text = f.read()
            except OSError:
                continue
            for m in re.finditer(
                r'obj-\$\((CONFIG_\w+)\)\s*[+:]?=\s*(.*)', mf_text
            ):
                dirs = m.group(2).strip().split()
                if dir_name in dirs:
                    configs.append(f"{m.group(1)}=y")
                    print(f"  [kconfig] {search_dir}/ requires {m.group(1)}")
        search_dir = parent_dir

    # Deduplicate
    return list(dict.fromkeys(configs))


def append_build_config(config_path, boot_profile="default", target_configs=None):
    """Disable sanitizers/debug-info and enable KCOV in a kernel .config."""
    disabled = [
        "CONFIG_KASAN", "CONFIG_KCSAN", "CONFIG_UBSAN",
        "CONFIG_HAVE_DEBUG_KMEMLEAK", "CONFIG_DEBUG_INFO",
        "CONFIG_DEBUG_INFO_REDUCED", "CONFIG_DEBUG_INFO_COMPRESSED",
        "CONFIG_DEBUG_INFO_SPLIT", "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT",
        "CONFIG_DEBUG_INFO_DWARF4", "CONFIG_DEBUG_INFO_DWARF5",
        "CONFIG_GDB_SCRIPTS",
        "CONFIG_FORTIFY_SOURCE",
        # clang 18 rejects 1E6L long-double literals in drivers/usb/dwc2/hcd_queue.c
        "CONFIG_USB_DWC2",
        # Some older media drivers crash the LLVM bitcode wrapper with clang 18.
        "CONFIG_DVB_B2C2_FLEXCOP_USB",
        # objtool fails to compile with GCC 13 (-Wuse-after-free in subcmd-util.h).
        # objtool is for unwinder validation only; not needed for fuzzing.
        "CONFIG_OBJTOOL",
        "CONFIG_STACK_VALIDATION",
    ]
    lines = [f"{c}=n" for c in disabled]
    lines.extend([
        "",
        "CONFIG_DEBUG_INFO_NONE=y",
        "CONFIG_KCOV=y",
        "CONFIG_KCOV_ENABLE_COMPARISONS=y",
        "CONFIG_IP_VS=n",
        "CONFIG_COMPILE_TEST=y",
    ])
    if boot_profile == "boot_safe_x86":
        lines.extend(BOOT_SAFE_X86_OVERRIDES)
    if target_configs:
        lines.extend([""] + target_configs)
    _append_unique_kconfig(config_path, lines)


# ──────────────────────────────────────────────────────────────────────────
# Script generators
# ──────────────────────────────────────────────────────────────────────────

def write_emit_script(path, clang_path):
    """Write the emit-llvm.sh wrapper script for bitcode compilation."""
    with open(path, "w") as f:
        f.write(f"""#!/bin/sh
CLANG={clang_path}
[ ! -e $CLANG ] && exit
OFILE=`echo $* | sed -e 's/^.* \\(.*\\.o\\) .*$/\\1/'`
if [ "x$OFILE" != x -a "$OFILE" != "$*" ] ; then
    $CLANG -emit-llvm -g "$@" >/dev/null 2>&1
    if [ -f "$OFILE" ] ; then
        BCFILE=`echo $OFILE | sed -e 's/o$/llbc/'`
        [ `file $OFILE | grep -c "LLVM IR bitcode"` -eq 1 ] && mv $OFILE $BCFILE || touch $BCFILE
    fi
fi
exec $CLANG "$@"
""")
    os.chmod(path, 0o775)


def write_makefile_kcov(src_dir, dist_dir, target_func):
    """Write scripts/Makefile.kcov for distance-guided instrumentation.

    If dist_dir is None or empty, the -fsanitize-coverage-distance-dir flag
    is omitted.  This is used for the first-pass bitcode build (step 2) where
    no .dist files exist yet but kcov_mark_block markers are still needed so
    that target_analyzer can identify instrumented blocks.
    """
    path = os.path.join(src_dir, "scripts", "Makefile.kcov")
    flags = (
        f"-fsanitize-coverage=trace-pc,second "
        f"-fsanitize-coverage-kernel-src-dir={src_dir} "
        f"-fsanitize-coverage-target-function={target_func}"
    )
    if dist_dir:
        flags += f" -fsanitize-coverage-distance-dir={dist_dir}"
    with open(path, "w") as f:
        f.write(
            "# SPDX-License-Identifier: GPL-2.0-only\n"
            f"kcov-flags-y += {flags}\n"
            "kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)\t+= -fsanitize-coverage=trace-cmp\n"
            "kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)\t\t+= "
            "-fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so\n"
            "\nexport CFLAGS_KCOV := $(kcov-flags-y)\n"
        )
