"""
SyzDirect Runner — NewCVEPipeline, fuzz helpers, and pre-built target setup.

Full six-stage pipeline for new CVE targets plus utility functions for
fuzz-only mode and pre-built target configuration.
"""

import json
import os
import re
import shutil
import subprocess
import sys


def _rg_bin():
    """Resolve the ripgrep binary path, falling back to known locations."""
    path = shutil.which("rg")
    if path:
        return path
    for candidate in (
        "/usr/local/lib/node_modules/@github/copilot/ripgrep/bin/linux-x64/rg",
        "/usr/local/lib/node_modules/@openai/codex/bin/rg",
        "/usr/bin/rg",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "rg"

from paths import (
    BIGCONFIG, CLANG_PATH, FUZZER_BIN, FUZZER_DIR, INTERFACE_GENERATOR,
    KCOV_PATCH, KNOWN_CRASH_DB, PIPELINE_STAGES, RESOURCE_ROOT,
    RUNTIME_BASE, SSH_KEY, TARGET_ANALYZER, TEMPLATE_CONFIG,
    VM_IMAGE, BootFallbackRequested, Q, sh, WorkdirLayout,
    _file_is_empty, _file_exists_and_nonempty, ensure_script_dir_on_path,
)
from kernel_build import (
    append_build_config, ensure_kcov_support, find_kconfig_for_file,
    relax_kernel_build, write_emit_script, write_makefile_kcov,
)
from analysis_utils import run_interface_generator_with_retries
from syscall_scoring import guess_syscalls, narrow_callfile_entries
from llm_enhance import llm_analyze_cve
from pipeline_validate import (
    run_preflight, validate_before_stage, validate_stage_output,
    check_kcov_source, check_kconfig,
)
from runner_config import RunnerConfig


# ──────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────

KERNEL_ORG_URL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
)


def ensure_commit_available(src_dir, commit, fetch_ref):
    """Fetch a commit if needed and fail early with a clear message if missing.

    For relative refs like 'abc123~1', we fetch the base commit with enough
    depth so the parent is available, then resolve the relative ref locally.
    Tries origin first, then falls back to kernel.org (which allows SHA fetch).
    """
    verify_cmd = ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"]
    if subprocess.run(verify_cmd, cwd=src_dir, check=False,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return
    print("  Ensuring requested commit is available locally...")

    # Determine how much depth we need for relative refs (e.g. ~1 needs depth=2)
    is_relative = (fetch_ref != commit)
    rel_match = re.search(r"[~^](\d+)$", commit)
    depth = int(rel_match.group(1)) + 1 if rel_match else (2 if is_relative else 1)

    sh(f"cd {Q(src_dir)} && git fetch --depth={depth} origin {Q(fetch_ref)}", check=False)

    # For relative refs, do NOT try to fetch the relative ref itself —
    # it's only valid as a local revision expression, not a remote refspec.
    if subprocess.run(verify_cmd, cwd=src_dir, check=False,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        # Try deepening further in case the history is too shallow
        if is_relative:
            sh(f"cd {Q(src_dir)} && git fetch --deepen={depth + 5} origin {Q(fetch_ref)}", check=False)

    if subprocess.run(verify_cmd, cwd=src_dir, check=False,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return

    # Fallback: GitHub rejects arbitrary SHA fetches; kernel.org allows them.
    print("  origin fetch failed, trying kernel.org...")
    sh(f"cd {Q(src_dir)} && git remote add kernelorg {Q(KERNEL_ORG_URL)} 2>/dev/null || true")
    sh(f"cd {Q(src_dir)} && git fetch --depth={depth} kernelorg {Q(fetch_ref)}", check=False)
    if subprocess.run(verify_cmd, cwd=src_dir, check=False,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        if is_relative:
            sh(f"cd {Q(src_dir)} && git fetch --deepen={depth + 5} kernelorg {Q(fetch_ref)}", check=False)
        if subprocess.run(verify_cmd, cwd=src_dir, check=False,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            sys.exit(f"[1/6] ERROR: commit not found on origin or kernel.org: {commit}")


def ensure_target_function_info(path, function_name, file_path):
    """Make sure fuzzing has at least one target function entry."""
    if _file_exists_and_nonempty(path):
        with open(path) as f:
            for line in f:
                if line.strip():
                    return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"0 {function_name} {file_path}\n")


def write_target_function_info(path, function_name, file_path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"0 {function_name} {file_path}\n")


def load_target_function_map(tfinfo_path):
    tfmap = {}
    if not os.path.exists(tfinfo_path):
        return tfmap
    with open(tfinfo_path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            tfmap[parts[0]] = (parts[1], parts[2])
    return tfmap


def _read_multi_pts_function(layout, ci):
    path = layout.multi_pts(ci)
    if not os.path.exists(path):
        return ""
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    return parts[1]
    except OSError:
        return ""
    return ""


def _guess_function_path_from_source(layout, ci, function_name):
    if not function_name:
        return ""
    src_dir = layout.src(ci)
    if not os.path.isdir(src_dir):
        return ""
    pattern = rf"^[a-zA-Z_][^;\n]*\b{re.escape(function_name)}\s*\("
    try:
        result = subprocess.run(
            [_rg_bin(), "-n", "-g", "*.c", pattern, src_dir],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode not in (0, 1) or not result.stdout.strip():
        return ""
    first = result.stdout.strip().splitlines()[0]
    rel = os.path.relpath(first.split(":", 1)[0], src_dir)
    return rel


def function_exists_in_file(layout, ci, function_name, file_path):
    """Return True if file_path in the case source tree contains function_name."""
    if not function_name or not file_path:
        return False
    full_path = os.path.join(layout.src(ci), file_path)
    if not os.path.exists(full_path):
        return False
    pattern = rf"\b{re.escape(function_name)}\s*\("
    try:
        result = subprocess.run(
            [_rg_bin(), "-n", pattern, full_path],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


def resolve_prebuilt_target(layout, target):
    """Resolve effective target metadata, preferring workdir-local truth."""
    resolved = dict(target)
    ci = target["idx"]

    multi_func = _read_multi_pts_function(layout, ci)
    tfmap = load_target_function_map(layout.tfinfo(ci))
    tf_entry = tfmap.get("0")

    function_name = multi_func or (tf_entry[0] if tf_entry else target.get("function", ""))
    function_path = tf_entry[1] if tf_entry else target.get("func_path", "")

    if function_name and function_path and not function_exists_in_file(layout, ci, function_name, function_path):
        function_path = ""

    guessed_path = _guess_function_path_from_source(layout, ci, function_name)
    if guessed_path:
        function_path = guessed_path

    if function_name:
        resolved["function"] = function_name
    if function_path:
        resolved["func_path"] = function_path
    if function_name:
        resolved["name"] = function_name
    return resolved


def ensure_callfile(path, syscalls):
    """Write a callfile if missing or empty."""
    if _file_exists_and_nonempty(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(syscalls, f, indent="\t")


def replicate_primary_callfile(layout, ci, tfmap):
    """Copy xidx0 callfile to any missing target slots as a conservative fallback."""
    primary = layout.callfile(ci, 0)
    if _file_is_empty(primary):
        return []

    created = []
    with open(primary) as f:
        primary_data = json.load(f)

    for xidx in tfmap.keys():
        callfile = layout.callfile(ci, xidx)
        if _file_exists_and_nonempty(callfile):
            continue
        ensure_callfile(callfile, primary_data)
        created.append(callfile)
    return created


# ──────────────────────────────────────────────────────────────────────────
# NewCVEPipeline
# ──────────────────────────────────────────────────────────────────────────

class NewCVEPipeline:
    """Six-stage SyzDirect pipeline for a new CVE target."""

    def __init__(self, args):
        self.args = args
        self.cve_id = args.cve
        self.commit = args.commit
        self.function = args.function
        self.file_path = args.file
        self.config_path = args.config or BIGCONFIG
        self.recommend_syscalls = args.syscalls.split(",") if args.syscalls else []
        self.linux_template = args.linux_template
        self.hunt_mode = getattr(args, "hunt_mode", "hybrid")
        self.known_crash_db = getattr(args, "known_crash_db", None)
        self.boot_profile = "default"
        self.boot_fallback_used = False
        self.cpus = args.j
        self.uptime = args.uptime
        self.fuzz_rounds = args.fuzz_rounds
        self.safe_name = self.cve_id.replace("-", "_").lower()
        self.ci = 0  # single target = case 0
        self.layout = WorkdirLayout(args.workdir)
        self.state = {
            "mode": "new",
            "cve": self.cve_id,
            "case_idx": self.ci,
            "commit": self.commit,
            "function": self.function,
            "file": self.file_path,
            "config": self.config_path,
            "recommend_syscalls": list(self.recommend_syscalls),
            "hunt_mode": self.hunt_mode,
            "known_crash_db": self.known_crash_db,
            "boot_profile": self.boot_profile,
            "boot_fallback_used": self.boot_fallback_used,
            "workdir": self.layout.root,
        }

    # ── orchestration ────────────────────────────────────────────────────

    _steps = {
        "source":   "step1_prepare_source",
        "bitcode":  "step2_compile_bitcode",
        "analyze":  "step3_analyze_kernel",
        "target":   "step4_analyze_target_point",
        "distance": "step5_instrument_distance",
        "fuzz":     "step6_fuzz",
    }

    def run(self, from_stage=None):
        self._save_state(None, "initialized")
        print(f"\n{'='*60}")
        print(f"SyzDirect Pipeline: {self.cve_id}")
        print(f"  {self.function} @ {self.file_path}  commit={self.commit}")
        print(f"  workdir={self.layout.root}")
        print(f"{'='*60}\n")

        # ── Preflight checks ─────────────────────────────────────────
        ok, errors = run_preflight(
            CLANG_PATH, INTERFACE_GENERATOR, TARGET_ANALYZER,
            FUZZER_BIN, VM_IMAGE, SSH_KEY,
            check_custom_flags=(from_stage in (None, "source", "bitcode")),
        )
        if not ok:
            sys.exit("[preflight] Pipeline cannot proceed. Fix the issues above.")

        start = PIPELINE_STAGES.index(from_stage) if from_stage else 0
        try:
            for stage in PIPELINE_STAGES[start:]:
                # Validate previous stage output before proceeding
                ok, errs = validate_before_stage(
                    stage, self.layout, self.ci,
                    clang_path=CLANG_PATH,
                    config_path=self.config_path,
                )
                if not ok:
                    sys.exit(f"[validate] Cannot start stage '{stage}'. Fix the issues above.")

                self._save_state(stage, "running")
                getattr(self, self._steps[stage])()

                # Validate this stage's output
                stage_errors = validate_stage_output(stage, self.layout, self.ci)
                if stage_errors:
                    print(f"\n[validate] Stage '{stage}' produced issues:")
                    for err in stage_errors:
                        print(f"  WARNING: {err}")

                self._save_state(stage, "completed")
        except BaseException as e:
            current_stage = PIPELINE_STAGES[start] if start < len(PIPELINE_STAGES) else None
            stage = self.state.get("last_stage") or current_stage
            self._save_state(stage, "failed", error=str(e))
            raise

    # ── stages ───────────────────────────────────────────────────────────

    def step1_prepare_source(self):
        print("\n[1/6] PREPARE_SRC")
        src = self.layout.src(self.ci)
        os.makedirs(os.path.dirname(src), exist_ok=True)

        commit = self.commit
        fetch_ref = re.sub(r"[~^]\d*$", "", commit)

        if os.path.isdir(os.path.join(src, ".git")):
            print(f"  Reusing: {src}")
        else:
            shutil.rmtree(src, ignore_errors=True)
            if self.linux_template and os.path.exists(self.linux_template):
                print(f"  Cloning from local template...")
                sh(f"git clone --local --no-checkout {Q(self.linux_template)} {Q(src)}")
            else:
                print("  Cloning from GitHub...")
                sh(f"git clone --depth=1 https://github.com/torvalds/linux.git {Q(src)}")
                depth = 2 if fetch_ref != commit else 1
                sh(f"cd {Q(src)} && git fetch --depth={depth} origin {fetch_ref}")
        ensure_commit_available(src, commit, fetch_ref)
        sh(f"cd {Q(src)} && git checkout -f {commit}")
        relax_kernel_build(src, CLANG_PATH)

        result = sh(f"cd {Q(src)} && git apply {Q(KCOV_PATCH)} 2>&1",
                     check=False, capture=True)
        if "patch failed" in (result or ""):
            print("  WARNING: kcov patch failed, applying fallback")
        ensure_kcov_support(src)
        print("  Done.")

    def step2_compile_bitcode(self):
        print("\n[2/6] COMPILE_BITCODE")
        bc = self.layout.bc(self.ci)
        if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
            print("  Already compiled, skipping.")
            return

        os.makedirs(bc, exist_ok=True)
        emit = self.layout.emit_script()
        write_emit_script(emit, CLANG_PATH)

        config_dst = os.path.join(bc, ".config")
        shutil.copyfile(self.config_path, config_dst)
        # Auto-detect CONFIG options needed for the target file
        target_configs = find_kconfig_for_file(self.layout.src(self.ci), self.file_path)
        append_build_config(config_dst, boot_profile=self.boot_profile,
                            target_configs=target_configs)

        src_raw = self.layout.src(self.ci)
        src = Q(src_raw)
        # Write Makefile.kcov with 'second' flag (no dist_dir) so bitcode
        # contains kcov_mark_block markers for target_analyzer (step 4).
        write_makefile_kcov(src_raw, None, self.function)
        sh(f"cd {src} && "
           f"make CC={Q(emit)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(bc)} olddefconfig && "
           f"make CC={Q(emit)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(bc)} -j{self.cpus}", big=True)

        if not os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
            sys.exit("[2/6] ERROR: Bitcode compilation failed!")
        print("  Done.")

    def step3_analyze_kernel(self):
        print("\n[3/6] ANALYZE_KERNEL")
        ci = self.ci
        os.makedirs(self.layout.interface(ci), exist_ok=True)

        sig = self.layout.kernel_sig(ci)
        if not os.path.exists(sig):
            syz_sig = self.layout.syz_sig()
            if _file_is_empty(syz_sig):
                sh(f"{Q(os.path.join(FUZZER_BIN, 'syz-features'))} > {Q(syz_sig)}")
            ok = run_interface_generator_with_retries(
                self.layout.bc(ci),
                self.layout.interface(ci),
                sig,
                INTERFACE_GENERATOR,
            )
            if not ok:
                sys.exit("[3/6] ERROR: interface_generator failed!")

        if not os.path.exists(sig):
            sys.exit("[3/6] ERROR: interface_generator failed!")

        k2s = self.layout.k2s(ci)
        if not os.path.exists(k2s):
            ensure_script_dir_on_path()
            from SyscallAnalyze.InterfaceGenerate import MatchSig
            with open(k2s, "w") as f:
                json.dump(MatchSig(self.layout.syz_sig(), sig), f, indent="\t")

        # V7: augment k2s with indirect dispatch resolution so TC/netlink
        # handler functions (tbf_change, fl_change, etc.) are reachable.
        src_dir = self.layout.src(ci)
        if os.path.isdir(src_dir):
            try:
                from indirect_dispatch_resolver import augment_k2s
                augmented = augment_k2s(
                    k2s, src_dir, self.function,
                    self.file_path or None,
                )
                with open(k2s, "w") as f:
                    json.dump(augmented, f, indent="\t")
                print(f"  [V7] k2s augmented with indirect dispatch "
                      f"({len(augmented)} entries)")
            except Exception as e:
                print(f"  [V7] k2s augmentation skipped: {e}")

        print("  Done.")

    def step4_analyze_target_point(self):
        print("\n[4/6] ANALYZE_TARGET_POINT")
        ci = self.ci
        os.makedirs(self.layout.tpa(ci), exist_ok=True)

        pts = self.layout.multi_pts(ci)
        os.makedirs(os.path.dirname(pts), exist_ok=True)
        with open(pts, "w") as f:
            f.write(f"0 {self.function}\n")

        if not os.path.exists(self.layout.tr_map()):
            sh(f"cd {Q(self.layout.root)} && {Q(os.path.join(FUZZER_BIN, 'direct'))}")

        compact = self.layout.compact(ci)
        if not os.path.exists(compact):
            sh(f"cd {Q(self.layout.tpa(ci))} && "
               f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
               f"--distance-output={Q(self.layout.tpa(ci))} "
               f"-kernel-interface-file={Q(self.layout.k2s(ci))} "
               f"-multi-pos-points={Q(pts)} "
               f"{Q(self.layout.bc(ci))} 2>&1 | tee log", big=True)

        dup = self.layout.dup_report(ci)
        if os.path.exists(dup):
            print(f"  WARNING: duplicate points — check {dup}")

        if not os.path.exists(compact):
            sys.exit("[4/6] ERROR: target_analyzer failed!")

        ensure_target_function_info(self.layout.tfinfo(ci), self.function, self.file_path)
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        rcfg.apply_to_legacy_config()
        ensure_script_dir_on_path()
        from SyscallAnalyze.TargetPointAnalyze import PrepareForFuzzing
        PrepareForFuzzing(ci, self.recommend_syscalls)
        if not self._has_nonempty_callfile():
            print("  PrepareForFuzzing produced no usable callfile, falling back to generated inputs")
            self._create_fuzzinps()
        print("  Done.")

    def step5_instrument_distance(self):
        print("\n[5/6] INSTRUMENT_DISTANCE")
        ci = self.ci
        os.makedirs(self.layout.kwithdist(ci), exist_ok=True)

        if os.path.exists(self.layout.bzimage(ci)):
            print("  Instrumented kernel exists, skipping.")
            return

        xidx, target_func = "0", self.function
        tfinfo_path = self.layout.tfinfo(ci)
        if _file_exists_and_nonempty(tfinfo_path):
            with open(tfinfo_path) as _f:
                parts = _f.readline().split()
            if len(parts) >= 2:
                xidx, target_func = parts[0], parts[1]

        dist = self.layout.dist_dir(ci, xidx)
        if not os.path.exists(dist):
            dist = self.layout.dist_dir(ci, 0)

        src = self.layout.src(ci)
        temp = os.path.join(self.layout.kwithdist(ci), "temp_build")
        os.makedirs(temp, exist_ok=True)

        ensure_kcov_support(src)
        write_makefile_kcov(src, dist, target_func)

        sh(f"cd {Q(src)} && make clean && make mrproper", check=False)
        shutil.copyfile(self.config_path, os.path.join(temp, ".config"))
        target_configs = find_kconfig_for_file(src, self.file_path)
        append_build_config(os.path.join(temp, ".config"), boot_profile=self.boot_profile,
                            target_configs=target_configs)

        sh(f"cd {Q(src)} && "
           f"make ARCH=x86_64 CC={Q(CLANG_PATH)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(temp)} olddefconfig && "
           f"make ARCH=x86_64 CC={Q(CLANG_PATH)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(temp)} -j{self.cpus}", big=True)

        bz_src = os.path.join(temp, "arch/x86/boot/bzImage")
        if not os.path.exists(bz_src):
            sys.exit("[5/6] ERROR: Kernel build failed!")

        shutil.copyfile(bz_src, self.layout.bzimage(ci))
        vm_src = os.path.join(temp, "vmlinux")
        if os.path.exists(vm_src):
            shutil.copyfile(vm_src, self.layout.vmlinux(ci))
        shutil.rmtree(temp, ignore_errors=True)
        print(f"  Done: {self.layout.bzimage(ci)}")

    def step6_fuzz(self):
        self._ensure_fuzz_inputs()
        target_info = {"idx": self.ci, "name": self.safe_name,
                       "function": self.function, "func_path": self.file_path}
        agent_rounds = getattr(self.args, "agent_rounds", 0)
        if agent_rounds > 0:
            from agent_loop import AgentLoop
            while True:
                print(f"\n[6/7] FUZZ + AGENT LOOP ({agent_rounds} rounds)")
                agent = AgentLoop(
                    layout=self.layout, target_info=target_info,
                    max_rounds=agent_rounds,
                    window_seconds=getattr(self.args, "agent_window", 300),
                    uptime_per_round=getattr(self.args, "agent_uptime", None) or self.uptime,
                    cpus=self.cpus, fuzz_rounds=self.fuzz_rounds,
                    hunt_mode=self.hunt_mode,
                    known_crash_db=self.known_crash_db,
                    allow_boot_fallback=(not self.boot_fallback_used),
                    stall_timeout=getattr(self.args, "stall_timeout", 1800),
                    dist_stall_timeout=getattr(self.args, "dist_stall_timeout", 600),
                    proactive_seed=getattr(self.args, "proactive_seed", False),
                )
                try:
                    agent.run()
                    break
                except BootFallbackRequested as e:
                    if not self._retry_with_boot_fallback(str(e)):
                        raise
        else:
            print("\n[6/6] FUZZ")
            launch_fuzzing(
                self.layout, self.cpus, self.uptime, self.fuzz_rounds,
                [target_info],
            )

    # ── helpers ──────────────────────────────────────────────────────────

    def _create_fuzzinps(self):
        """Generate callfile via LLM, falling back to heuristics."""
        ci = self.ci
        os.makedirs(self.layout.fuzzinps(ci), exist_ok=True)

        result = llm_analyze_cve(self.cve_id, self.commit, self.function, self.file_path)
        syscalls = (result.get("syscalls") if result else None) or guess_syscalls(self.file_path)
        syscalls = narrow_callfile_entries(
            syscalls,
            self.file_path,
            self.function,
            hunt_mode=self.hunt_mode,
        )
        print(f"  Syscalls: {[s['Target'] for s in syscalls]}")

        with open(self.layout.callfile(ci), "w") as f:
            json.dump(syscalls, f, indent="\t")

        ensure_target_function_info(self.layout.tfinfo(ci), self.function, self.file_path)

    def _ensure_fuzz_inputs(self):
        ci = self.ci
        ensure_target_function_info(self.layout.tfinfo(ci), self.function, self.file_path)
        tfmap = load_target_function_map(self.layout.tfinfo(ci))

        callfile = self.layout.callfile(ci)
        if _file_is_empty(callfile):
            print("  Callfile missing or empty, regenerating fuzz inputs...")
            self._create_fuzzinps()
            tfmap = load_target_function_map(self.layout.tfinfo(ci))

        for xidx in tfmap.keys():
            x_callfile = self.layout.callfile(ci, xidx)
            if _file_is_empty(x_callfile):
                continue
            with open(x_callfile) as f:
                entries = json.load(f)
            normalized = narrow_callfile_entries(
                entries,
                self.file_path,
                self.function,
                hunt_mode=self.hunt_mode,
            )
            if normalized != entries:
                print(f"  Normalized callfile entries for xidx {xidx}")
                with open(x_callfile, "w") as f:
                    json.dump(normalized, f, indent="\t")

        created = replicate_primary_callfile(self.layout, ci, tfmap)
        if created:
            print(f"  Recreated {len(created)} missing callfile(s) from xidx 0")

        self._validate_fuzz_inputs(tfmap)

    def _has_nonempty_callfile(self):
        ci = self.ci
        tfmap = load_target_function_map(self.layout.tfinfo(ci))
        if not tfmap:
            return False
        for xidx in tfmap.keys():
            if _file_exists_and_nonempty(self.layout.callfile(ci, xidx)):
                return True
        return False

    def _retry_with_boot_fallback(self, reason):
        if self.boot_fallback_used:
            return False
        print(f"  Boot failure detected: {reason}")
        print("  Rebuilding instrumented kernel with boot-safe x86 fallback profile...")
        self.boot_profile = "boot_safe_x86"
        self.boot_fallback_used = True
        shutil.rmtree(self.layout.kwithdist(self.ci), ignore_errors=True)
        self._save_state("distance", "running")
        self.step5_instrument_distance()
        self._save_state("distance", "completed")
        self._save_state("fuzz", "running")
        return True

    def _validate_fuzz_inputs(self, tfmap=None):
        ci = self.ci
        tfmap = tfmap or load_target_function_map(self.layout.tfinfo(ci))
        if not tfmap:
            sys.exit(f"[6/6] ERROR: target function map is empty: {self.layout.tfinfo(ci)}")

        missing = []
        for xidx in tfmap.keys():
            callfile = self.layout.callfile(ci, xidx)
            kernel_img = self.layout.bzimage(ci, xidx)
            if _file_is_empty(callfile):
                missing.append(f"callfile[{xidx}]={callfile}")
            if not os.path.exists(kernel_img):
                missing.append(f"bzImage[{xidx}]={kernel_img}")

        if missing:
            joined = "\n  - ".join([""] + missing)
            sys.exit(f"[6/6] ERROR: fuzz prerequisites missing:{joined}")

    def _build_paths_dict(self):
        """Build the paths sub-dict once (values never change for a given ci)."""
        ci = self.ci
        return {
            "src": self.layout.src(ci),
            "bc": self.layout.bc(ci),
            "interface": self.layout.interface(ci),
            "tpa": self.layout.tpa(ci),
            "fuzzinps": self.layout.fuzzinps(ci),
            "kwithdist": self.layout.kwithdist(ci),
            "fuzzres": self.layout.fuzzres(ci),
            "tfinfo": self.layout.tfinfo(ci),
            "callfile": self.layout.callfile(ci),
        }

    def _save_state(self, last_stage, phase, error=None):
        self.state["last_stage"] = last_stage
        self.state["phase"] = phase
        self.state["boot_profile"] = self.boot_profile
        self.state["boot_fallback_used"] = self.boot_fallback_used
        if "paths" not in self.state:
            self.state["paths"] = self._build_paths_dict()
        if error:
            self.state["error"] = error
        else:
            self.state.pop("error", None)
        state_path = self.layout.state_file(self.ci)
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, "w") as f:
            json.dump(self.state, f, indent=2, sort_keys=True)


# ──────────────────────────────────────────────────────────────────────────
# Pre-built targets setup
# ──────────────────────────────────────────────────────────────────────────

def setup_prebuilt(layout, targets, hunt_mode="hybrid"):
    """Symlink pre-built instrumented kernels and write callfiles."""
    for i, target in enumerate(targets):
        t = resolve_prebuilt_target(layout, target)
        targets[i].update(t)
        ci, name = t["idx"], t["name"]
        hunt = os.path.join(RUNTIME_BASE, f"new_hunt_{name}", "instrumented")

        os.makedirs(layout.kwithdist(ci), exist_ok=True)
        for src_name, dst in [("bzImage", layout.bzimage(ci)),
                               ("vmlinux", layout.vmlinux(ci))]:
            src = os.path.join(hunt, src_name)
            if os.path.exists(src) and not os.path.exists(dst):
                os.symlink(src, dst)

        os.makedirs(layout.tpa(ci), exist_ok=True)
        current_tfmap = load_target_function_map(layout.tfinfo(ci))
        current_tf = current_tfmap.get("0")
        if current_tf != (t["function"], t["func_path"]):
            write_target_function_info(layout.tfinfo(ci), t["function"], t["func_path"])

        os.makedirs(layout.fuzzinps(ci), exist_ok=True)
        syscalls = narrow_callfile_entries(
            t["syscalls"],
            t["func_path"],
            t["function"],
            hunt_mode=hunt_mode,
        )
        with open(layout.callfile(ci), "w") as f:
            json.dump(syscalls, f, indent="\t")

        print(f"  [case {ci}] {name}: ready")


# ──────────────────────────────────────────────────────────────────────────
# Fuzz launcher
# ──────────────────────────────────────────────────────────────────────────

def launch_fuzzing(layout, cpus, uptime, fuzz_rounds, targets):
    """Configure the Runner and start Fuzz.MultirunFuzzer."""
    rcfg = RunnerConfig(layout, cpus, uptime, fuzz_rounds)
    Config = rcfg.apply_to_legacy_config()
    import Fuzz

    Config.datapoints = [
        {"idx": t["idx"], "repro bug title": float("nan")}
        for t in targets
    ]

    print(f"\nLaunching: {len(targets)} targets x {fuzz_rounds} rounds, {uptime}h each")
    print(f"Results: {os.path.join(layout.root, 'fuzzres')}\n")
    Fuzz.MultirunFuzzer()
