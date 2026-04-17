"""
SyzDirect Runner — DatasetPipeline: run the original SyzDirect pipeline
on all datapoints in a dataset.xlsx file.
"""

import json
import os
import re
import shutil
import subprocess
import sys

from paths import (
    BIGCONFIG, CLANG_PATH, FUZZER_BIN, FUZZER_DIR, FUNCTION_MODEL_DIR,
    INTERFACE_GENERATOR, KCOV_PATCH, KERNEL_ANALYSIS_DIR, LLVM_BUILD,
    LLVM_ROOT, TARGET_ANALYZER,
    Q, sh, WorkdirLayout,
    _file_is_empty, _file_exists_and_nonempty, ensure_script_dir_on_path,
)
from kernel_build import (
    append_build_config, ensure_kcov_support, relax_kernel_build,
    write_emit_script,
)
from analysis_utils import run_interface_generator_with_retries
from runner_config import RunnerConfig
from pipeline_new_cve import ensure_commit_available as _ensure_commit_available


def _patch_subcmd_util_h(src_dir):
    """Suppress gcc 13 -Wuse-after-free error in objtool host-tool build."""
    path = os.path.join(src_dir, "tools", "lib", "subcmd", "subcmd-util.h")
    if not os.path.exists(path):
        return
    with open(path) as f:
        txt = f.read()
    if "pragma GCC diagnostic" in txt:
        return
    old = "static inline void *xrealloc(void *ptr, size_t size)"
    if old not in txt:
        return
    txt = txt.replace(old,
        '#pragma GCC diagnostic push\n'
        '#pragma GCC diagnostic ignored "-Wuse-after-free"\n'
        + old)
    txt = txt.replace(
        "}\nstatic inline void *xstrdup",
        "}\n#pragma GCC diagnostic pop\nstatic inline void *xstrdup",
        1)
    with open(path, "w") as f:
        f.write(txt)


def _clean_recommend_syscalls(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value).split(',')
    return [str(item).strip() for item in items
            if str(item).strip() and str(item).strip().lower() != 'nan']


def _write_minimal_k2s(k2s_path, target_func, recommend_syscalls):
    """Write a conservative k2s fallback when interface analysis cannot finish."""
    calls = _clean_recommend_syscalls(recommend_syscalls)
    target = str(target_func or '').strip()
    if not target or target.lower() == 'nan' or not calls:
        return False
    os.makedirs(os.path.dirname(k2s_path), exist_ok=True)
    with open(k2s_path, "w") as f:
        json.dump({target: {"none": calls}}, f, indent="\t")
    print(f"  Fallback k2s: mapped {target} -> {calls}")
    return True


def _compact_has_targets(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return False
    if not data:
        return False
    return any(item.get("target syscall infos") for item in data
               if isinstance(item, dict))


class DatasetPipeline:
    """Run the original SyzDirect pipeline on all datapoints in a dataset.xlsx file."""

    ACTIONS = {
        "prepare_for_manual_instrument":     "step1_prepare_source",
        "compile_kernel_bitcode":            "step2_compile_bitcode",
        "analyze_kernel_syscall":            "step3_analyze_kernel",
        "extract_syscall_entry":             "step4_analyze_target_point",
        "instrument_kernel_with_distance":   "step5_instrument_distance",
        "fuzz":                              "step6_fuzz",
    }

    def __init__(self, args):
        self.dataset_file = args.dataset
        self.linux_template = args.linux_template
        self.cpus = args.j
        self.uptime = args.uptime
        self.fuzz_rounds = args.fuzz_rounds
        self.layout = WorkdirLayout(args.workdir)
        self.actions = args.actions

        # load dataset
        import pandas as pd
        assert os.path.exists(self.dataset_file), f"Dataset not found: {self.dataset_file}"
        df = pd.read_excel(self.dataset_file)
        self.datapoints = [dict(zip(df.columns, row)) for row in df.values]
        print(f"Loaded {len(self.datapoints)} datapoints from {self.dataset_file}")

        # normalize datapoints
        for dp in self.datapoints:
            if pd.isna(dp.get('config path', float('nan'))):
                dp['config path'] = BIGCONFIG
            if pd.isna(dp.get('recommend syscall', float('nan'))):
                dp['recommend syscall'] = []
            else:
                dp['recommend syscall'] = str(dp['recommend syscall']).split(',')
            assert os.path.exists(dp['config path']), \
                f"Config path not found for case {dp['idx']}: {dp['config path']}"

        # validate linux template
        if self.linux_template and os.path.exists(self.linux_template):
            r = subprocess.run(f"cd {Q(self.linux_template)} && git remote -v",
                               shell=True, capture_output=True, text=True)
            if "linux.git" not in r.stdout:
                print(f"  WARNING: {self.linux_template} does not seem to be a linux repo")
        else:
            self.linux_template = None

    def run(self):
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Config = rcfg.apply_to_legacy_config()
        Config.datapoints = self.datapoints
        Config.LinuxSrcTemplate = self.linux_template

        # ensure directories
        os.makedirs(self.layout.root, exist_ok=True)
        os.makedirs(os.path.join(self.layout.root, "srcs"), exist_ok=True)

        print(f"\n{'='*60}")
        print(f"SyzDirect Dataset Pipeline")
        print(f"  {len(self.datapoints)} cases, actions: {self.actions}")
        print(f"  workdir={self.layout.root}")
        print(f"{'='*60}\n")

        self._build_tools()

        for action in self.actions:
            if action not in self.ACTIONS:
                sys.exit(f"ERROR: Unknown action '{action}'. Choose from: {list(self.ACTIONS.keys())}")
            print(f"\n{'─'*40}")
            print(f"ACTION: {action}")
            print(f"{'─'*40}")
            getattr(self, self.ACTIONS[action])()

    def _build_tools(self):
        """Build LLVM, interface_generator, kernel_analysis, and fuzzer if needed."""
        if not os.path.exists(CLANG_PATH):
            print("[build] Building customized LLVM...")
            sh(f"cd {Q(LLVM_ROOT)} && "
               f"cmake -S llvm -B build -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release && "
               f"cmake --build build -j {self.cpus}", big=True)
        assert os.path.exists(CLANG_PATH), "Failed to build customized LLVM (clang)"

        if not os.path.exists(INTERFACE_GENERATOR):
            print("[build] Building interface_generator...")
            sh(f"cd {Q(FUNCTION_MODEL_DIR)} && make clean && make LLVM_BUILD={Q(LLVM_BUILD)}", big=True)
        else:
            print(f"[build] interface_generator already exists, skipping.")
        assert os.path.exists(INTERFACE_GENERATOR), "Failed to build interface_generator"

        if not os.path.exists(TARGET_ANALYZER):
            print("[build] Building target_analyzer...")
            sh(f"cd {Q(KERNEL_ANALYSIS_DIR)} && make clean && make LLVM_BUILD={Q(LLVM_BUILD)}", big=True)
        else:
            print(f"[build] target_analyzer already exists, skipping.")
        assert os.path.exists(TARGET_ANALYZER), "Failed to build target_analyzer"

        if not os.path.exists(os.path.join(FUZZER_DIR, "bin", "syz-manager")):
            print("[build] Building fuzzer...")
            sh(f"cd {Q(FUZZER_DIR)} && make", big=True)
        else:
            print(f"[build] fuzzer already exists, skipping.")
        assert os.path.exists(os.path.join(FUZZER_DIR, "bin")), "Failed to build fuzzer"

    # ── stages ───────────────────────────────────────────────────────────

    def step1_prepare_source(self):
        print("\n[1/6] PREPARE_SRC")
        for dp in self.datapoints:
            ci = dp['idx']
            commit = dp['kernel commit']
            src = self.layout.src(ci)
            fetch_ref = re.sub(r"[~^]\d*$", "", commit)

            if os.path.exists(src) and not os.path.exists(os.path.join(src, ".git")):
                shutil.rmtree(src, ignore_errors=True)

            if not os.path.exists(src):
                if self.linux_template:
                    template_git = os.path.join(self.linux_template, ".git")
                    if os.path.exists(template_git):
                        sh(f"git clone --local --no-checkout {Q(self.linux_template)} {Q(src)}")
                        if not os.path.exists(src):
                            shutil.copytree(self.linux_template, src)
                    else:
                        shutil.copytree(self.linux_template, src)
                else:
                    src_root = os.path.join(self.layout.root, "srcs")
                    sh(f"cd {Q(src_root)} && git clone https://github.com/torvalds/linux.git case_{ci}")

            assert os.path.exists(src), f"[case {ci}] Source dir not created"
            _ensure_commit_available(src, commit, fetch_ref)
            sh(f"cd {Q(src)} && git checkout -f {commit}")

            relax_kernel_build(src, CLANG_PATH)

            result = sh(f"cd {Q(src)} && git apply {Q(KCOV_PATCH)} 2>&1",
                        check=False, capture=True)
            if "patch failed" in (result or ""):
                print(f"  [case {ci}] WARNING: kcov patch failed, applying fallback")
            ensure_kcov_support(src)

            print(f"  [case {ci}] Source prepared (commit {commit})")

    def step2_compile_bitcode(self):
        print("\n[2/6] COMPILE_BITCODE")
        emit = self.layout.emit_script()
        write_emit_script(emit, CLANG_PATH)

        for dp in self.datapoints:
            ci = dp['idx']
            config_path = dp['config path']
            bc = self.layout.bc(ci)

            if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
                print(f"  [case {ci}] Already compiled, skipping")
                continue

            if os.path.exists(bc):
                # Use shell rm -rf to reliably remove deep directory trees (shutil.rmtree
                # can leave directories behind in WSL2 when subdirs are not empty)
                subprocess.run(f"rm -rf {Q(bc)}", shell=True)

            os.makedirs(bc, exist_ok=True)
            shutil.copyfile(config_path, os.path.join(bc, ".config"))
            append_build_config(os.path.join(bc, ".config"))

            src = self.layout.src(ci)
            # Fix gcc 13 treating -Wuse-after-free as error in objtool build
            _patch_subcmd_util_h(src)
            sh(f"cd {Q(src)} && git checkout -- scripts/Makefile.kcov 2>/dev/null; "
               f"make CC={Q(emit)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(bc)} olddefconfig && "
               f"make CC={Q(emit)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(bc)} -j{self.cpus}", big=True)

            if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
                print(f"  [case {ci}] Bitcode compiled successfully")
            else:
                print(f"  [case {ci}] ERROR: Bitcode compilation failed!")

    def step3_analyze_kernel(self):
        print("\n[3/6] ANALYZE_KERNEL")

        syz_sig = self.layout.syz_sig()
        if _file_is_empty(syz_sig):
            sh(f"{Q(os.path.join(FUZZER_BIN, 'syz-features'))} > {Q(syz_sig)}")
        assert _file_exists_and_nonempty(syz_sig), \
            "Failed to generate syzkaller signature"

        for dp in self.datapoints:
            ci = dp['idx']
            iface_dir = self.layout.interface(ci)
            os.makedirs(iface_dir, exist_ok=True)
            bc = self.layout.bc(ci)
            sig = self.layout.kernel_sig(ci)
            k2s = self.layout.k2s(ci)

            if not os.path.exists(sig) and not os.path.exists(k2s):
                ok = run_interface_generator_with_retries(
                    bc, iface_dir, sig, INTERFACE_GENERATOR)
                if not ok:
                    print(f"  [case {ci}] ERROR: interface_generator failed!")
                    if not _write_minimal_k2s(k2s, dp.get('function', ''),
                                              dp.get('recommend syscall', [])):
                        continue
            elif not os.path.exists(sig) and os.path.exists(k2s):
                print(f"  [case {ci}] Using existing k2s without kernel_signature_full")

            if not os.path.exists(k2s):
                ensure_script_dir_on_path()
                from SyscallAnalyze.InterfaceGenerate import MatchSig
                try:
                    result = MatchSig(syz_sig, sig)
                    with open(k2s, "w") as f:
                        json.dump(result, f, indent="\t")
                except Exception as e:
                    print(f"  [case {ci}] ERROR: MatchSig failed: {e}")
                    if not _write_minimal_k2s(k2s, dp.get('function', ''),
                                              dp.get('recommend syscall', [])):
                        continue

            # V7: Augment k2s with indirect dispatch resolution
            src_dir = self.layout.src(ci)
            target_func = dp.get('function', '')
            if target_func and str(target_func).strip() not in ('', 'nan') \
               and os.path.isdir(src_dir):
                try:
                    from indirect_dispatch_resolver import augment_k2s
                    target_file = dp.get('file_path', dp.get('file', None))
                    augmented = augment_k2s(k2s, src_dir,
                                            str(target_func).strip(),
                                            str(target_file).strip()
                                            if target_file else None)
                    with open(k2s, "w") as f:
                        json.dump(augmented, f, indent="\t")
                    print(f"  [case {ci}] V7: k2s augmented with indirect "
                          f"dispatch ({len(augmented)} entries)")
                except Exception as e:
                    print(f"  [case {ci}] V7: k2s augmentation failed: {e}")

            print(f"  [case {ci}] Kernel interface analyzed")

    def step4_analyze_target_point(self):
        print("\n[4/6] ANALYZE_TARGET_POINT")

        tr_map = self.layout.tr_map()
        if not os.path.exists(tr_map):
            sh(f"cd {Q(self.layout.root)} && {Q(os.path.join(FUZZER_BIN, 'direct'))}")
        assert os.path.exists(tr_map), "Failed to generate syscall pair map"

        for dp in self.datapoints:
            ci = dp['idx']
            tpa_dir = self.layout.tpa(ci)
            os.makedirs(tpa_dir, exist_ok=True)
            bc = self.layout.bc(ci)
            k2s = self.layout.k2s(ci)

            if not os.path.exists(k2s):
                print(f"  [case {ci}] Skipping: no interface result")
                continue

            compact = self.layout.compact(ci)
            pts = self.layout.multi_pts(ci)

            # Auto-populate multi-pts from xlsx 'function' column if provided
            func_from_xlsx = dp.get('function') if dp.get('function') and str(dp.get('function', '')).strip() not in ('', 'nan') else None
            if func_from_xlsx and not os.path.exists(pts):
                os.makedirs(os.path.dirname(pts), exist_ok=True)
                with open(pts, 'w') as f:
                    f.write(f"0 {func_from_xlsx}\n")
                print(f"  [case {ci}] Auto-set multi-pts from xlsx: 0 {func_from_xlsx}")

            if not os.path.exists(compact):
                sh(f"cd {Q(tpa_dir)} && "
                   f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
                   f"--distance-output={Q(tpa_dir)} "
                   f"-kernel-interface-file={Q(k2s)} "
                   f"-multi-pos-points={Q(pts)} "
                   f"{Q(bc)} 2>&1 | tee log", big=True)

            if not _compact_has_targets(compact):
                target_func = dp.get('function', '')
                if _write_minimal_k2s(k2s, target_func,
                                      dp.get('recommend syscall', [])):
                    print(f"  [case {ci}] Empty target analysis; retrying with fallback k2s")
                    if os.path.exists(compact):
                        os.remove(compact)
                    tfinfo = self.layout.tfinfo(ci)
                    if os.path.exists(tfinfo):
                        os.remove(tfinfo)
                    sh(f"cd {Q(tpa_dir)} && "
                       f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
                       f"--distance-output={Q(tpa_dir)} "
                       f"-kernel-interface-file={Q(k2s)} "
                       f"-multi-pos-points={Q(pts)} "
                       f"{Q(bc)} 2>&1 | tee log", big=True)

            dup = self.layout.dup_report(ci)
            if os.path.exists(dup):
                if func_from_xlsx:
                    # xlsx에 function 있으면 dup_report 무시하고 multi-pts 강제 적용 후 재시도
                    print(f"  [case {ci}] dup_report detected but function specified in xlsx ({func_from_xlsx}), retrying with forced multi-pts")
                    os.remove(dup)
                    if os.path.exists(compact):
                        os.remove(compact)
                    sh(f"cd {Q(tpa_dir)} && "
                       f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
                       f"--distance-output={Q(tpa_dir)} "
                       f"-kernel-interface-file={Q(k2s)} "
                       f"-multi-pos-points={Q(pts)} "
                       f"{Q(bc)} 2>&1 | tee log", big=True)
                    if os.path.exists(self.layout.dup_report(ci)):
                        print(f"  [case {ci}] ERROR: still duplicate after retry")
                        continue
                else:
                    print(f"  [case {ci}] WARNING: duplicate points detected!")
                    print(f"    Check {dup} and specify multi-pts file")
                    print(f"    Format: '0 function_name' per line")
                    continue

            if not os.path.exists(compact):
                print(f"  [case {ci}] ERROR: target_analyzer failed!")
                continue

            print(f"  [case {ci}] Target point analyzed, preparing for fuzzing...")
            ensure_script_dir_on_path()
            from SyscallAnalyze.TargetPointAnalyze import PrepareForFuzzing
            PrepareForFuzzing(ci, dp['recommend syscall'])

    def step5_instrument_distance(self):
        print("\n[5/6] INSTRUMENT_DISTANCE")
        import Config
        for dp in self.datapoints:
            ci = dp['idx']
            config_path = dp['config path']

            tfinfo = self.layout.tfinfo(ci)
            if not os.path.exists(tfinfo):
                print(f"  [case {ci}] Skipping: no tfinfo")
                continue

            tfmap = Config.ParseTargetFunctionsInfoFile(ci)
            kernel_dir = self.layout.kwithdist(ci)
            os.makedirs(kernel_dir, exist_ok=True)
            src = self.layout.src(ci)

            for xidx in tfmap.keys():
                target_func = tfmap[xidx][0]
                bz_dst = self.layout.bzimage(ci, xidx)

                if os.path.exists(bz_dst):
                    print(f"  [case {ci} xidx {xidx}] Already instrumented, skipping")
                    continue

                temp = os.path.join(kernel_dir, "temp_build")
                os.makedirs(temp, exist_ok=True)
                dist_dir = self.layout.dist_dir(ci, xidx)

                from kernel_build import write_makefile_kcov, ensure_kcov_support
                ensure_kcov_support(src)
                write_makefile_kcov(src, dist_dir, target_func)

                sh(f"cd {Q(src)} && make clean && make mrproper", check=False)
                shutil.copyfile(config_path, os.path.join(temp, ".config"))
                append_build_config(os.path.join(temp, ".config"))

                sh(f"cd {Q(src)} && "
                   f"make ARCH=x86_64 CC={Q(CLANG_PATH)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(temp)} olddefconfig && "
                   f"make ARCH=x86_64 CC={Q(CLANG_PATH)} HOSTCC=gcc 'HOSTCFLAGS=-Wno-error=use-after-free -Wno-error=redundant-decls -Wno-error=format-truncation' 'KCFLAGS=-fno-builtin-stpcpy' O={Q(temp)} -j{self.cpus}", big=True)

                bz_src = os.path.join(temp, "arch/x86/boot/bzImage")
                if not os.path.exists(bz_src):
                    print(f"  [case {ci} xidx {xidx}] ERROR: Kernel build failed!")
                    continue

                shutil.copyfile(bz_src, bz_dst)
                vm_src = os.path.join(temp, "vmlinux")
                if os.path.exists(vm_src):
                    shutil.copyfile(vm_src, self.layout.vmlinux(ci, xidx))
                shutil.rmtree(temp, ignore_errors=True)
                print(f"  [case {ci} xidx {xidx}] Instrumented kernel built")

    def step6_fuzz(self):
        print("\n[6/6] FUZZ")
        import Fuzz
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Config = rcfg.apply_to_legacy_config()
        Config.datapoints = self.datapoints
        print(f"Launching fuzzer: {len(self.datapoints)} cases x {self.fuzz_rounds} rounds, "
              f"{self.uptime}h each")
        Fuzz.MultirunFuzzer()
