"""
SyzDirect Runner — preflight checks and artifact validation.

Catches build/runtime problems BEFORE they happen:
  - Clang version and custom flag support
  - Analysis tool existence
  - VM image / SSH key existence
  - Kernel config safety (CONFIG_IP_VS, boot-critical settings)
  - KCOV source correctness (kcov_mark_block must NOT index by distance)
  - Stage output artifact validation
  - .dist file sanity checks
"""

import os
import re
import subprocess
import sys

from kernel_build import get_clang_version
from paths import _file_is_empty


# ──────────────────────────────────────────────────────────────────────────
# Individual checks (each returns list of error strings, empty = OK)
# ──────────────────────────────────────────────────────────────────────────

def check_clang(clang_path):
    """Verify clang exists and report version."""
    errors = []
    if not os.path.exists(clang_path):
        errors.append(f"clang not found: {clang_path}")
        return errors
    ver = get_clang_version(clang_path)
    if ver is None:
        errors.append(f"Could not detect clang version: {clang_path}")
    else:
        print(f"  [preflight] clang version: {'.'.join(str(v) for v in ver)}")
        if ver < (13, 0, 0):
            errors.append(f"clang version {ver} is too old (minimum 13.0.0)")
    return errors


def check_second_flag(clang_path):
    """Verify clang supports -fsanitize-coverage=second (SyzDirect custom flag)."""
    errors = []
    if not os.path.exists(clang_path):
        return [f"clang not found: {clang_path}"]

    # Test that the custom flag doesn't produce "unsupported" error
    try:
        r = subprocess.run(
            [clang_path, "-fsanitize-coverage=trace-pc,second",
             "-x", "c", "-c", "/dev/null", "-o", "/dev/null"],
            capture_output=True, text=True, timeout=10,
        )
        combined = (r.stdout + r.stderr).lower()
        if "unsupported" in combined or "unknown" in combined:
            errors.append(
                "clang does NOT support -fsanitize-coverage=second. "
                "This is a SyzDirect-custom flag. Make sure you built the "
                "patched LLVM 18 with SanitizerArgs.cpp modifications."
            )
        else:
            print("  [preflight] clang supports -fsanitize-coverage=second")
    except (subprocess.TimeoutExpired, OSError) as e:
        errors.append(f"Could not test clang second flag: {e}")
    return errors


def check_tools(interface_gen, target_analyzer):
    """Verify analysis tools exist and are executable."""
    errors = []
    for name, path in [("interface_generator", interface_gen),
                       ("target_analyzer", target_analyzer)]:
        if not os.path.exists(path):
            errors.append(f"{name} not found: {path}")
        elif not os.access(path, os.X_OK):
            errors.append(f"{name} not executable: {path}")
    return errors


def check_fuzzer(fuzzer_bin_dir):
    """Verify syzkaller fuzzer binaries exist."""
    errors = []
    # syz-manager is the main binary; syz-fuzzer/syz-executor live under linux_amd64/
    syz_manager = os.path.join(fuzzer_bin_dir, "syz-manager")
    if not os.path.exists(syz_manager):
        errors.append(f"syz-manager not found: {syz_manager}")
    # syz-fuzzer and syz-executor are under linux_amd64/
    arch_dir = os.path.join(fuzzer_bin_dir, "linux_amd64")
    for binary in ["syz-fuzzer", "syz-executor"]:
        path = os.path.join(arch_dir, binary)
        if not os.path.exists(path):
            # Not fatal — some builds bundle them differently
            pass
    return errors


def check_vm_image(image_path, ssh_key):
    """Verify VM image and SSH key exist."""
    errors = []
    if not os.path.exists(image_path):
        errors.append(f"VM image not found: {image_path}")
    if not os.path.exists(ssh_key):
        errors.append(f"SSH key not found: {ssh_key}")
    return errors


# ──────────────────────────────────────────────────────────────────────────
# Kernel source checks
# ──────────────────────────────────────────────────────────────────────────

def check_kcov_source(src_dir):
    """Verify kcov.c has correct kcov_mark_block (no array indexing by distance).

    The kcov_mark_block function must ONLY track minimum distance at dt_area[0].
    Using the distance value as an array index (dt_area[i+1]) causes out-of-bounds
    writes because distance values (e.g. 4010) far exceed DISTBLOCKSIZE (300).
    """
    errors = []
    kcov_c = os.path.join(src_dir, "kernel", "kcov.c")
    if not os.path.exists(kcov_c):
        return []  # Not yet patched, that's OK at this stage

    with open(kcov_c) as f:
        content = f.read()

    if "void notrace kcov_mark_block" not in content:
        return []  # Not yet patched

    # Check for the dangerous pattern: using distance as array index
    # Bad: dt_area[i + 1] or dt_area[i+1] inside kcov_mark_block
    mark_block_match = re.search(
        r"void notrace kcov_mark_block\(u32 i\)\s*\{(.*?)\n\}",
        content, re.S
    )
    if mark_block_match:
        body = mark_block_match.group(1)
        if re.search(r"dt_area\[i\s*[+\-]", body):
            errors.append(
                "CRITICAL: kcov_mark_block uses distance value 'i' as array index. "
                "This causes out-of-bounds writes when distance > DISTBLOCKSIZE (300). "
                "The function should ONLY do: if (i < dt_area[0]) dt_area[0] = i;"
            )
        if "DISTBLOCKSIZE" in body or "unlikely" in body:
            errors.append(
                "WARNING: kcov_mark_block has bounds check against DISTBLOCKSIZE. "
                "Distance values are not indices — remove the bounds check. "
                "Only min-distance tracking at dt_area[0] is correct."
            )

    return errors


def check_kconfig(config_path, is_base_config=False):
    """Check kernel .config for known problematic settings.

    Args:
        config_path: Path to the .config file.
        is_base_config: If True, this is the base config (bigconfig) before
            append_build_config() runs — warnings only, not errors, since
            append_build_config() will override dangerous settings.
    """
    errors = []
    warnings = []
    if not os.path.exists(config_path):
        return []

    with open(config_path) as f:
        content = f.read()

    # CONFIG_IP_VS causes NULL pointer dereference in ip_vs_protocol_init
    if "CONFIG_IP_VS=y" in content:
        msg = ("CONFIG_IP_VS=y is set — this causes boot crashes "
               "(NULL pointer dereference in ip_vs_protocol_init) on some kernels.")
        if is_base_config:
            # append_build_config() will override this, just warn
            print(f"  [preflight] NOTE: {msg} (will be overridden by build config)")
        else:
            errors.append(msg)

    # KCOV check only applies to final configs, not base
    if not is_base_config and "CONFIG_KCOV=y" not in content:
        errors.append("CONFIG_KCOV=y is not set — required for distance-guided fuzzing")

    return errors


# ──────────────────────────────────────────────────────────────────────────
# Stage output validation
# ──────────────────────────────────────────────────────────────────────────

def validate_stage_output(stage, layout, ci):
    """Verify that a pipeline stage produced its expected artifacts.

    Returns list of error strings (empty = all OK).
    """
    errors = []

    if stage == "source":
        src = layout.src(ci)
        if not os.path.isdir(os.path.join(src, ".git")):
            errors.append(f"Source tree missing: {src}")
        kcov_errors = check_kcov_source(src)
        errors.extend(kcov_errors)

    elif stage == "bitcode":
        bc = layout.bc(ci)
        bzimage = os.path.join(bc, "arch/x86/boot/bzImage")
        if not os.path.exists(bzimage):
            errors.append(f"Bitcode bzImage missing: {bzimage}")
        # Check for at least some .llbc files
        llbc_count = sum(1 for _, _, files in os.walk(bc)
                        for f in files if f.endswith(".llbc"))
        if llbc_count == 0:
            errors.append(f"No .llbc bitcode files found in {bc}")
        else:
            print(f"  [validate] {llbc_count} .llbc files in bitcode dir")

    elif stage == "analyze":
        sig = layout.kernel_sig(ci)
        if not os.path.exists(sig):
            errors.append(f"Kernel signature missing: {sig}")
        k2s = layout.k2s(ci)
        if not os.path.exists(k2s):
            errors.append(f"kernelCode2syscall.json missing: {k2s}")
        elif os.path.getsize(k2s) < 10:
            errors.append(f"kernelCode2syscall.json is suspiciously small: {k2s}")

    elif stage == "target":
        compact = layout.compact(ci)
        if not os.path.exists(compact):
            errors.append(f"CompactOutput.json missing: {compact}")
        tfinfo = layout.tfinfo(ci)
        if not os.path.exists(tfinfo):
            errors.append(f"target_functions_info.txt missing: {tfinfo}")
        # Check dist files exist
        dist_dir = layout.dist_dir(ci, 0)
        if os.path.isdir(dist_dir):
            dist_count = sum(1 for f in os.listdir(dist_dir) if f.endswith(".dist"))
            if dist_count == 0:
                errors.append(f"No .dist files in {dist_dir}")
            else:
                print(f"  [validate] {dist_count} .dist files found")
                # Sanity check: .dist files should have reasonable values
                dist_errors = _check_dist_file_sanity(dist_dir)
                errors.extend(dist_errors)
        else:
            errors.append(f"Distance directory missing: {dist_dir}")

    elif stage == "distance":
        bz = layout.bzimage(ci)
        if not os.path.exists(bz):
            errors.append(f"Instrumented bzImage missing: {bz}")
        else:
            # Check file size is reasonable (> 1MB)
            size_mb = os.path.getsize(bz) / (1024 * 1024)
            if size_mb < 1:
                errors.append(f"bzImage suspiciously small ({size_mb:.1f}MB): {bz}")
            else:
                print(f"  [validate] bzImage size: {size_mb:.0f}MB")

    elif stage == "fuzz":
        callfile = layout.callfile(ci)
        if _file_is_empty(callfile):
            errors.append(f"Callfile missing or empty: {callfile}")
        bz = layout.bzimage(ci)
        if not os.path.exists(bz):
            errors.append(f"bzImage missing for fuzzing: {bz}")

    return errors


def _check_dist_file_sanity(dist_dir, sample_count=3):
    """Spot-check .dist files for obviously wrong values."""
    errors = []
    dist_files = [f for f in os.listdir(dist_dir) if f.endswith(".dist")]
    if not dist_files:
        return errors

    for fname in dist_files[:sample_count]:
        fpath = os.path.join(dist_dir, fname)
        try:
            with open(fpath) as f:
                lines = f.readlines()
            if not lines:
                errors.append(f".dist file is empty: {fname}")
                continue

            # Check that values are reasonable integers
            bad_lines = 0
            for line in lines[:20]:
                parts = line.split()
                if len(parts) < 3:
                    bad_lines += 1
                    continue
                try:
                    dist_val = int(parts[2])
                    if dist_val < 0:
                        bad_lines += 1
                except ValueError:
                    bad_lines += 1

            if bad_lines > len(lines[:20]) / 2:
                errors.append(f".dist file has many malformed lines: {fname}")
        except OSError:
            continue

    return errors


# ──────────────────────────────────────────────────────────────────────────
# Full preflight check
# ──────────────────────────────────────────────────────────────────────────

def run_preflight(clang_path, interface_gen, target_analyzer,
                  fuzzer_bin_dir, vm_image, ssh_key,
                  check_custom_flags=True):
    """Run all preflight checks before starting a pipeline.

    Returns (ok: bool, errors: list[str]).
    """
    print("\n[preflight] Running pre-pipeline validation...")
    all_errors = []

    all_errors.extend(check_clang(clang_path))
    if check_custom_flags and not all_errors:
        all_errors.extend(check_second_flag(clang_path))
    all_errors.extend(check_tools(interface_gen, target_analyzer))
    all_errors.extend(check_fuzzer(fuzzer_bin_dir))
    all_errors.extend(check_vm_image(vm_image, ssh_key))

    if all_errors:
        print("\n[preflight] FAILED — issues found:")
        for i, err in enumerate(all_errors, 1):
            print(f"  {i}. {err}")
        return False, all_errors

    print("[preflight] All checks passed.\n")
    return True, []


def validate_before_stage(stage, layout, ci, clang_path=None, config_path=None):
    """Validate prerequisites before running a specific stage.

    Returns (ok: bool, errors: list[str]).
    """
    errors = []

    # Check previous stage outputs
    stage_order = ["source", "bitcode", "analyze", "target", "distance", "fuzz"]
    idx = stage_order.index(stage) if stage in stage_order else -1

    if idx > 0:
        prev_stage = stage_order[idx - 1]
        prev_errors = validate_stage_output(prev_stage, layout, ci)
        if prev_errors:
            errors.extend([f"[{prev_stage}] {e}" for e in prev_errors])

    # Stage-specific pre-checks
    if stage == "distance":
        # Verify kcov source is correct before building instrumented kernel
        src = layout.src(ci)
        kcov_errors = check_kcov_source(src)
        errors.extend(kcov_errors)

    if stage in ("bitcode", "distance") and config_path:
        # Base config (bigconfig) will be overridden by append_build_config(),
        # so dangerous settings are warnings, not blocking errors.
        config_errors = check_kconfig(config_path, is_base_config=True)
        errors.extend(config_errors)

    if errors:
        print(f"\n[validate] Pre-{stage} checks FAILED:")
        for err in errors:
            print(f"  - {err}")
        return False, errors

    return True, []
