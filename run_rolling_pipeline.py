#!/usr/bin/env python3
"""
Rolling pipeline: sequential build → overlapped 3-way fuzz → bcs cleanup.

Three conditions run in parallel per case:
  1. baseline  — pure SyzDirect (no agent)
  2. agent     — SyzDirect + agent loop (LLM triage/enhance)
  3. proactive — SyzDirect + agent loop + proactive seed generation

Workflow:
  1. [Build]   prepare + bitcode + analyze + instrument  (sequential, RAM-gated)
  2. [Fuzz]    3 sessions in parallel (up to MAX_FUZZ_SLOTS triplets)
  3. [Cleanup] delete bcs/ when all 3 sessions done

CSV format:
  case_id, dataset_xlsx, workdir_agent, workdir_baseline, workdir_proactive,
           build_j, fuzz_j [, linux_template]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))

MAX_FUZZ_SLOTS  = 3
RAM_REQUIRED_GB = 20.0
RAM_POLL_SECS   = 60

FUZZ_UPTIME_H   = 6
AGENT_ROUNDS    = 3
AGENT_UPTIME_H  = 2
STALL_TIMEOUT_S = 1800
DIST_STALL_S    = 1800

BUILD_STAGES = [
    "prepare_for_manual_instrument",
    "compile_kernel_bitcode",
    "analyze_kernel_syscall",
    "extract_syscall_entry",
    "instrument_kernel_with_distance",
]

LOG_DIR = os.path.join(RUNNER_DIR, "bg_logs", "rolling_pipeline")
REQUIRED_SHARED_SUBDIRS = ("kwithdist", "fuzzinps", "tpa", "interfaces", "consts")
OPTIONAL_SHARED_SUBDIRS = ("srcs", "bcs")
GENERIC_K2S_PREFIXES = (
    "do_arch_prctl",
    "__se_sys_modify_ldt",
    "write_ldt",
    "__se_sys_prctl",
    "prctl_",
    "set_tsc_mode",
    "arch_prctl_",
    "do_syscall_",
    "entry_SYSCALL",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def free_ram_gb() -> float:
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024 / 1024
    return 0.0


def wait_for_ram(required_gb: float, label: str = ""):
    while True:
        free = free_ram_gb()
        if free >= required_gb:
            return
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}] RAM wait ({label}): {free:.1f}G free < {required_gb}G required", flush=True)
        time.sleep(RAM_POLL_SECS)


def tmux_session_alive(name: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", name],
                          capture_output=True).returncode == 0


def log_contains_finish(path: str) -> bool:
    if not os.path.exists(path):
        return False
    try:
        txt = open(path).read()
    except OSError:
        return False
    return ("AGENT LOOP COMPLETE" in txt or "Finish running" in txt or "EXIT" in txt)


def parse_manager_log(log_path: str) -> dict:
    result = {
        "dist_min": None,
        "dist_display": "N/A",
        "dist_state": "missing",
        "crashes": 0,
        "time_to_zero": None,
    }
    if not os.path.exists(log_path):
        return result
    try:
        lines = open(log_path).readlines()
    except OSError:
        return result

    start_ts = None
    dists, crashes = [], []
    saw_dist = False
    saw_zero_zero = False
    for line in lines:
        # timestamp: "2026/04/17 23:13:37 ..." or "   0: 22:26 ..."
        m_ts = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        m_dist = re.search(r"dist (\d+)/(\d+)", line)
        m_cr   = re.search(r"crashes (\d+)", line)
        if m_ts and start_ts is None:
            start_ts = m_ts.group(1)
        if m_dist:
            saw_dist = True
            d, mx = int(m_dist.group(1)), int(m_dist.group(2))
            if mx > 0:  # ignore 0/0 (no-coverage initial state)
                dists.append(d)
                if d == 0 and result["time_to_zero"] is None and m_ts:
                    from datetime import datetime
                    try:
                        t0 = datetime.strptime(start_ts, "%Y/%m/%d %H:%M:%S")
                        t1 = datetime.strptime(m_ts.group(1), "%Y/%m/%d %H:%M:%S")
                        result["time_to_zero"] = int((t1 - t0).total_seconds() // 60)
                    except Exception:
                        pass
            else:
                saw_zero_zero = True
        if m_cr:
            crashes.append(int(m_cr.group(1)))

    if dists:
        result["dist_min"] = min(dists)
        result["dist_display"] = str(result["dist_min"])
        result["dist_state"] = "valid"
    elif saw_zero_zero:
        result["dist_display"] = "0/0"
        result["dist_state"] = "zero_zero"
    elif saw_dist:
        result["dist_state"] = "invalid"
    if crashes:
        result["crashes"] = max(crashes)
    return result


def format_dist(summary: dict) -> str:
    return str(summary.get("dist_display") or summary.get("dist_min") or "N/A")


def k2s_looks_generic(k2s_path: str) -> Optional[str]:
    try:
        data = json.load(open(k2s_path))
    except Exception as e:
        return f"unreadable k2s: {e}"
    if not isinstance(data, dict) or not data:
        return "empty k2s"
    first_keys = [str(k) for k in list(data.keys())[:5]]
    generic = [
        k for k in first_keys
        if any(k.startswith(prefix) for prefix in GENERIC_K2S_PREFIXES)
    ]
    if len(generic) >= 2:
        return f"generic MatchSig anchors: {generic}"
    return None


def existing_manager_dist_state(wdir: str, case_id: str) -> str:
    mgr = os.path.join(wdir, "fuzzres", f"case_{case_id}",
                       "xidx_0", "logs0", "manager.log")
    return parse_manager_log(mgr).get("dist_state", "missing")


# ---------------------------------------------------------------------------
# Case descriptor
# ---------------------------------------------------------------------------

@dataclass
class PipelineCase:
    case_id:            str
    dataset_path:       str
    workdir_agent:      str
    workdir_baseline:   str
    workdir_proactive:  str
    build_j:            int = 4
    fuzz_j:             int = 2
    linux_template:     Optional[str] = None

    build_done:         bool = False
    agent_done:         bool = False
    baseline_done:      bool = False
    proactive_done:     bool = False
    skipped:            bool = False
    error:              Optional[str] = None
    preflight_errors:   dict = field(default_factory=dict)

    @property
    def bcs_path(self):
        return os.path.join(self.workdir_agent, "bcs", f"case_{self.case_id}")

    @property
    def src_path(self):
        return os.path.join(self.workdir_agent, "srcs", f"case_{self.case_id}")

    @property
    def kwithdist_path(self):
        return os.path.join(self.workdir_agent, "kwithdist", f"case_{self.case_id}")

    def is_already_built(self) -> bool:
        bz = os.path.join(self.kwithdist_path, "bzImage_0")
        bz_ready = os.path.exists(bz) or (os.path.islink(bz) and os.path.exists(os.readlink(bz)))
        k2s = os.path.join(self.workdir_agent, "interfaces", f"case_{self.case_id}",
                           "kernelCode2syscall.json")
        if os.path.exists(k2s) and k2s_looks_generic(k2s):
            return False
        return bz_ready and os.path.isdir(self.bcs_path)

    def _fuzzed(self, wdir: str) -> bool:
        k2s = os.path.join(wdir, "interfaces", f"case_{self.case_id}",
                           "kernelCode2syscall.json")
        dist_state = existing_manager_dist_state(wdir, self.case_id)
        if os.path.exists(k2s) and k2s_looks_generic(k2s) and dist_state != "valid":
            return False
        p = os.path.join(wdir, "fuzzres", f"case_{self.case_id}",
                         "xidx_0", "logs0", "manager.log")
        return os.path.exists(p) and dist_state == "valid"

    def is_agent_fuzzed(self)     -> bool: return self._fuzzed(self.workdir_agent)
    def is_baseline_fuzzed(self)  -> bool: return self._fuzzed(self.workdir_baseline)
    def is_proactive_fuzzed(self) -> bool: return self._fuzzed(self.workdir_proactive)

    def _case_path(self, wdir: str, subdir: str) -> str:
        return os.path.join(wdir, subdir, f"case_{self.case_id}")

    def _setup_symlinks(self, wdir: str):
        for subdir in REQUIRED_SHARED_SUBDIRS:
            bl_dir = os.path.join(wdir, subdir)
            os.makedirs(bl_dir, exist_ok=True)
            dst = os.path.join(bl_dir, f"case_{self.case_id}")
            src = os.path.join(self.workdir_agent, subdir, f"case_{self.case_id}")
            if os.path.islink(dst) and not os.path.exists(dst):
                os.remove(dst)
            if os.path.exists(src) and not os.path.lexists(dst):
                os.symlink(src, dst)

    def setup_baseline_symlinks(self):  self._setup_symlinks(self.workdir_baseline)
    def setup_proactive_symlinks(self): self._setup_symlinks(self.workdir_proactive)

    def setup_optional_symlinks(self, wdir: str):
        for subdir in OPTIONAL_SHARED_SUBDIRS:
            dst = self._case_path(wdir, subdir)
            src = self._case_path(self.workdir_agent, subdir)
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.islink(dst) and not os.path.exists(dst):
                    os.remove(dst)
                if os.path.exists(src) and not os.path.lexists(dst):
                    os.symlink(src, dst)
            except OSError:
                # Optional for fuzz execution; required artifacts are checked below.
                pass

    def repair_mode_symlinks(self, mode: str):
        if mode == "agent":
            return
        wdir = self.workdir_baseline if mode == "baseline" else self.workdir_proactive
        self._setup_symlinks(wdir)
        self.setup_optional_symlinks(wdir)

    def preflight_fuzz(self, mode: str) -> list:
        missing = []
        try:
            self.repair_mode_symlinks(mode)
        except OSError as e:
            missing.append(f"symlink repair failed: {e}")

        wdir = {
            "agent":     self.workdir_agent,
            "baseline":  self.workdir_baseline,
            "proactive": self.workdir_proactive,
        }[mode]

        required_files = {
            "bzImage_0": os.path.join(wdir, "kwithdist", f"case_{self.case_id}", "bzImage_0"),
            "inp_0.json": os.path.join(wdir, "fuzzinps", f"case_{self.case_id}", "inp_0.json"),
            "target_functions_info.txt": os.path.join(wdir, "tpa", f"case_{self.case_id}", "target_functions_info.txt"),
            "CompactOutput.json": os.path.join(wdir, "tpa", f"case_{self.case_id}", "CompactOutput.json"),
            "kernelCode2syscall.json": os.path.join(wdir, "interfaces", f"case_{self.case_id}", "kernelCode2syscall.json"),
        }
        for label, path in required_files.items():
            if not os.path.exists(path):
                missing.append(f"{label}: {path}")

        k2s_problem = None
        if os.path.exists(required_files["kernelCode2syscall.json"]):
            k2s_problem = k2s_looks_generic(required_files["kernelCode2syscall.json"])
        dist_state = existing_manager_dist_state(wdir, self.case_id)
        if k2s_problem and dist_state != "valid":
            missing.append(f"invalid k2s: {k2s_problem}")

        dist_dir = os.path.join(wdir, "tpa", f"case_{self.case_id}", "distance_xidx0")
        if not os.path.isdir(dist_dir):
            missing.append(f"distance_xidx0: {dist_dir}")
        else:
            try:
                if not any(name.endswith(".dist") for name in os.listdir(dist_dir)):
                    missing.append(f"distance_xidx0 has no .dist files: {dist_dir}")
            except OSError as e:
                missing.append(f"distance_xidx0 unreadable: {dist_dir} ({e})")

        try:
            from paths import FUZZER_BIN, SSH_KEY, VM_IMAGE
            runtime_files = {
                "syz-manager": os.path.join(FUZZER_BIN, "syz-manager"),
                "VM image": VM_IMAGE,
                "SSH key": SSH_KEY,
            }
            for label, path in runtime_files.items():
                if not os.path.exists(path):
                    missing.append(f"{label}: {path}")
        except Exception as e:
            missing.append(f"runtime path import failed: {e}")

        self.preflight_errors[mode] = missing
        return missing

    def setup_src_sharing(self, donor_case_id: str):
        if donor_case_id == self.case_id:
            return
        donor_src = os.path.join(self.workdir_agent, "srcs", f"case_{donor_case_id}")
        if not os.path.isdir(donor_src) or os.path.exists(self.src_path) or os.path.islink(self.src_path):
            return
        os.makedirs(os.path.dirname(self.src_path), exist_ok=True)
        os.symlink(donor_src, self.src_path)
        print(f"  [{time.strftime('%H:%M:%S')}] [src-share] case_{self.case_id} → case_{donor_case_id}", flush=True)

    def setup_bcs_sharing(self, donor_case_id: str):
        if donor_case_id == self.case_id:
            return
        donor_bcs = os.path.join(self.workdir_agent, "bcs", f"case_{donor_case_id}")
        if not os.path.exists(donor_bcs) or os.path.exists(self.bcs_path) or os.path.islink(self.bcs_path):
            return
        os.makedirs(os.path.dirname(self.bcs_path), exist_ok=True)
        os.symlink(donor_bcs, self.bcs_path)
        print(f"  [{time.strftime('%H:%M:%S')}] [bcs-share] case_{self.case_id} → case_{donor_case_id}", flush=True)

    def cleanup_bcs(self, dry_run: bool = False, keep_if_donor: bool = False):
        ts = time.strftime("%H:%M:%S")
        # Keep bitcode while k2s repair is active. Re-analysis needs bcs/case_N;
        # deleting it lets a stale bzImage make the case look built, then
        # target_analyzer crashes before fuzz can start.
        if not dry_run:
            print(f"  [{ts}] [cleanup] Keeping bcs for case_{self.case_id} (repairable reruns)", flush=True)
            return
        if os.path.islink(self.bcs_path):
            if not dry_run:
                os.remove(self.bcs_path)
                print(f"  [{ts}] [cleanup] Removed bcs symlink for case_{self.case_id}", flush=True)
        elif os.path.exists(self.bcs_path):
            if keep_if_donor:
                print(f"  [{ts}] [cleanup] Keeping bcs for case_{self.case_id} (donor)", flush=True)
            elif not dry_run:
                shutil.rmtree(self.bcs_path, ignore_errors=True)
                print(f"  [{ts}] [cleanup] Deleted bcs for case_{self.case_id}", flush=True)

    def save_results(self, results_dir: str):
        summary = {"case_id": self.case_id}
        if self.preflight_errors:
            summary["preflight_errors"] = self.preflight_errors
        for mode, wdir in [("agent",     self.workdir_agent),
                           ("baseline",  self.workdir_baseline),
                           ("proactive", self.workdir_proactive)]:
            mgr = os.path.join(wdir, "fuzzres", f"case_{self.case_id}",
                               "xidx_0", "logs0", "manager.log")
            summary[mode] = parse_manager_log(mgr)
        os.makedirs(results_dir, exist_ok=True)
        with open(os.path.join(results_dir, f"case_{self.case_id}.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(f"  [{time.strftime('%H:%M:%S')}] [results] case_{self.case_id}: {summary}", flush=True)


# ---------------------------------------------------------------------------
# Build runner
# ---------------------------------------------------------------------------

def run_build(case: PipelineCase, log_dir: str) -> bool:
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"build_case_{case.case_id}.log")
    cmd = [sys.executable, "-u",
           os.path.join(RUNNER_DIR, "run_hunt.py"),
           "dataset",
           "-dataset", case.dataset_path,
           "-workdir", case.workdir_agent,
           "-j", str(case.build_j)]
    if case.linux_template:
        cmd += ["-linux-repo-template", case.linux_template]
    cmd += BUILD_STAGES

    print(f"  [{time.strftime('%H:%M:%S')}] [build] Starting case_{case.case_id} → {log_path}", flush=True)
    with open(log_path, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)

    success = r.returncode == 0 and case.is_already_built()
    ts = time.strftime("%H:%M:%S")
    if success:
        print(f"  [{ts}] [build] ✓ case_{case.case_id} done", flush=True)
    else:
        print(f"  [{ts}] [build] ✗ case_{case.case_id} FAILED (rc={r.returncode})", flush=True)
    return success


# ---------------------------------------------------------------------------
# Fuzz launcher
# ---------------------------------------------------------------------------

def start_fuzz_session(case: PipelineCase, mode: str, log_dir: str) -> str:
    session  = f"rolling_{mode}_case_{case.case_id}"
    log_path = os.path.join(log_dir, f"fuzz_{mode}_case_{case.case_id}.log")

    missing = case.preflight_fuzz(mode)
    if missing:
        os.makedirs(log_dir, exist_ok=True)
        with open(log_path, "w") as f:
            f.write("FUZZ_PREFLIGHT_FAILED\n")
            f.write(f"case={case.case_id}\n")
            f.write(f"mode={mode}\n")
            for item in missing:
                f.write(f"missing={item}\n")
        print(f"  [{time.strftime('%H:%M:%S')}] [fuzz] SKIP {mode} case_{case.case_id}: preflight failed", flush=True)
        for item in missing:
            print(f"    - {item}", flush=True)
        return "__preflight_failed__"

    workdir = {
        "agent":     case.workdir_agent,
        "baseline":  case.workdir_baseline,
        "proactive": case.workdir_proactive,
    }[mode]

    parts = [
        f"cd {RUNNER_DIR}", "&&",
        f"python3 -u run_hunt.py dataset",
        f"-dataset {case.dataset_path}",
        f"-workdir {workdir}",
        f"-j {case.fuzz_j}",
        f"-uptime {FUZZ_UPTIME_H}",
    ]

    if mode == "baseline":
        parts += [
            f"--stall-timeout {STALL_TIMEOUT_S}",
            f"--dist-stall-timeout {DIST_STALL_S}",
        ]
    elif mode == "agent":
        parts += [
            f"--agent-rounds {AGENT_ROUNDS}",
            f"--agent-uptime {AGENT_UPTIME_H}",
            f"--stall-timeout {STALL_TIMEOUT_S}",
            f"--dist-stall-timeout {DIST_STALL_S}",
        ]
    elif mode == "proactive":
        parts += [
            f"--agent-rounds {AGENT_ROUNDS}",
            f"--agent-uptime {AGENT_UPTIME_H}",
            f"--stall-timeout {STALL_TIMEOUT_S}",
            f"--dist-stall-timeout {DIST_STALL_S}",
            f"--proactive-seed",
        ]

    parts += ["fuzz", f"2>&1 | tee {log_path}"]

    if tmux_session_alive(session):
        subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True)
    subprocess.run(["tmux", "new-session", "-d", "-s", session, "-x", "220", "-y", "50"])
    subprocess.run(["tmux", "send-keys", "-t", session, " ".join(parts), "Enter"])

    print(f"  [{time.strftime('%H:%M:%S')}] [fuzz] Started {mode} case_{case.case_id} (session={session})", flush=True)
    return session


def check_fuzz_done(session: str, log_dir: str, case_id: str, mode: str) -> bool:
    if session.startswith("__"):
        return True
    log_path = os.path.join(log_dir, f"fuzz_{mode}_case_{case_id}.log")
    return log_contains_finish(log_path) or not tmux_session_alive(session)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(cases: list, results_dir: str, dry_run: bool = False):
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    active_fuzz: dict = {}
    build_queue = [c for c in cases if not c.skipped]
    build_idx   = 0

    bcs_donors:  dict = {}
    src_donors:  dict = {}
    bcs_pending: dict = {}
    for c in build_queue:
        bcs_pending.setdefault(c.workdir_agent, set()).add(c.case_id)

    def _mark_bcs_done(case, dry_run):
        wdir    = case.workdir_agent
        pending = bcs_pending.get(wdir, set())
        pending.discard(case.case_id)
        donor_id = bcs_donors.get(wdir)
        is_donor = (donor_id == case.case_id)
        case.cleanup_bcs(dry_run=dry_run, keep_if_donor=(is_donor and len(pending) > 0))
        if is_donor and not pending:
            bcs_donors.pop(wdir, None)

    print(f"\n{'='*60}")
    print(f"Rolling pipeline (3-way): {len(build_queue)} cases")
    print(f"MAX_FUZZ_SLOTS={MAX_FUZZ_SLOTS}, FUZZ_UPTIME={FUZZ_UPTIME_H}h")
    print(f"AGENT_ROUNDS={AGENT_ROUNDS}, AGENT_UPTIME={AGENT_UPTIME_H}h")
    print(f"Conditions: [1] baseline  [2] agent  [3] agent+proactive-seed")
    print(f"{'='*60}\n", flush=True)

    while build_idx < len(build_queue) or active_fuzz:

        finished = []
        for cid, info in list(active_fuzz.items()):
            a = check_fuzz_done(info["agent_session"],     LOG_DIR, cid, "agent")
            b = check_fuzz_done(info["baseline_session"],  LOG_DIR, cid, "baseline")
            p = check_fuzz_done(info["proactive_session"], LOG_DIR, cid, "proactive")
            if a and b and p:
                finished.append(cid)

        for cid in finished:
            info = active_fuzz.pop(cid)
            print(f"[{time.strftime('%H:%M:%S')}] ✓ Triplet complete: case_{cid}", flush=True)
            info["case"].save_results(results_dir)
            _mark_bcs_done(info["case"], dry_run=dry_run)

        if build_idx < len(build_queue) and len(active_fuzz) < MAX_FUZZ_SLOTS:
            case = build_queue[build_idx]
            build_idx += 1

            all_done = case.is_agent_fuzzed() and case.is_baseline_fuzzed() and case.is_proactive_fuzzed()
            if all_done:
                print(f"[{time.strftime('%H:%M:%S')}] SKIP case_{case.case_id}: all conditions already fuzzed", flush=True)
                _mark_bcs_done(case, dry_run=dry_run)
                continue

            wdir = case.workdir_agent
            if src_donors.get(wdir) not in (None, case.case_id):
                case.setup_src_sharing(src_donors[wdir])
            if bcs_donors.get(wdir) not in (None, case.case_id):
                case.setup_bcs_sharing(bcs_donors[wdir])

            if not case.is_already_built():
                wait_for_ram(RAM_REQUIRED_GB, f"case_{case.case_id}")
                if dry_run:
                    print(f"[{time.strftime('%H:%M:%S')}] [dry-run] build case_{case.case_id}", flush=True)
                elif not run_build(case, LOG_DIR):
                    print(f"[{time.strftime('%H:%M:%S')}] SKIP case_{case.case_id}: build failed", flush=True)
                    case.skipped = True
                    bcs_pending.get(wdir, set()).discard(case.case_id)
                    continue
            else:
                print(f"  [{time.strftime('%H:%M:%S')}] [build] case_{case.case_id}: already built, skipping", flush=True)

            if wdir not in src_donors and os.path.isdir(case.src_path) and not os.path.islink(case.src_path):
                src_donors[wdir] = case.case_id
                print(f"  [{time.strftime('%H:%M:%S')}] [src-share] case_{case.case_id} registered as src donor for {wdir}", flush=True)
            if wdir not in bcs_donors and os.path.isdir(case.bcs_path) and not os.path.islink(case.bcs_path):
                bcs_donors[wdir] = case.case_id
                print(f"  [{time.strftime('%H:%M:%S')}] [bcs-share] case_{case.case_id} registered as bcs donor for {wdir}", flush=True)

            case.setup_baseline_symlinks()
            case.setup_proactive_symlinks()

            if dry_run:
                a_sess = f"dry_agent_{case.case_id}"
                b_sess = f"dry_baseline_{case.case_id}"
                p_sess = f"dry_proactive_{case.case_id}"
                print(f"[{time.strftime('%H:%M:%S')}] [dry-run] fuzz triplet case_{case.case_id}", flush=True)
            else:
                a_sess = start_fuzz_session(case, "agent",     LOG_DIR) if not case.is_agent_fuzzed()     else "__skip__"
                b_sess = start_fuzz_session(case, "baseline",  LOG_DIR) if not case.is_baseline_fuzzed()  else "__skip__"
                p_sess = start_fuzz_session(case, "proactive", LOG_DIR) if not case.is_proactive_fuzzed() else "__skip__"

            active_fuzz[case.case_id] = {
                "case": case,
                "agent_session":     a_sess,
                "baseline_session":  b_sess,
                "proactive_session": p_sess,
            }

        if active_fuzz or build_idx < len(build_queue):
            time.sleep(30)

    print(f"\n{'='*60}\nPipeline complete. Results: {results_dir}\n{'='*60}\n", flush=True)

    print(f"{'Case':<8} {'Base dist':>10} {'Base cr':>8} {'Agent dist':>11} {'Agent cr':>9} {'Pro dist':>10} {'Pro cr':>8}")
    print("-" * 70)
    for case in build_queue:
        r_path = os.path.join(results_dir, f"case_{case.case_id}.json")
        if os.path.exists(r_path):
            r  = json.load(open(r_path))
            bl = r.get("baseline",  {})
            ag = r.get("agent",     {})
            pr = r.get("proactive", {})
            print(f"{case.case_id:<8}"
                  f"{format_dist(bl):>10}{str(bl.get('crashes',0)):>8}"
                  f"{format_dist(ag):>11}{str(ag.get('crashes',0)):>9}"
                  f"{format_dist(pr):>10}{str(pr.get('crashes',0)):>8}")


# ---------------------------------------------------------------------------
# Case list builder
# ---------------------------------------------------------------------------

def build_case_list(args) -> list:
    """
    CSV format:
      case_id, dataset_xlsx, workdir_agent, workdir_baseline, workdir_proactive
               [, build_j, fuzz_j [, linux_template]]
    """
    cases = []
    with open(args.cases_csv) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 5:
                print(f"  [warn] need 5 fields: {line}")
                continue
            cid, ds, wa, wb, wp = parts[0], parts[1], parts[2], parts[3], parts[4]
            bj   = int(parts[5]) if len(parts) > 5 else 4
            fj   = int(parts[6]) if len(parts) > 6 else 2
            tmpl = parts[7]      if len(parts) > 7 else None
            cases.append(PipelineCase(cid, ds, wa, wb, wp, bj, fj, tmpl))
    return cases


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global MAX_FUZZ_SLOTS, FUZZ_UPTIME_H, RAM_REQUIRED_GB
    ap = argparse.ArgumentParser(
        description="Rolling 3-way pipeline: baseline / agent / agent+proactive-seed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV format:
  case_id, dataset_xlsx, workdir_agent, workdir_baseline, workdir_proactive
           [, build_j, fuzz_j [, linux_template]]

Generate CSV for your environment:
  python3 make_cases_csv.py --workdir /your/workdir --output rolling_cases.csv

Example:
  python3 run_rolling_pipeline.py --cases-csv rolling_cases_1_50.csv \\
      --fuzz-hours 6 --fuzz-slots 3
        """
    )
    ap.add_argument("--cases-csv",   required=True)
    ap.add_argument("--results-dir", default=os.path.join(RUNNER_DIR, "bg_logs", "rolling_results"))
    ap.add_argument("--dry-run",     action="store_true")
    ap.add_argument("--fuzz-slots",  type=int,   default=MAX_FUZZ_SLOTS)
    ap.add_argument("--fuzz-hours",  type=int,   default=FUZZ_UPTIME_H)
    ap.add_argument("--ram-gb",      type=float, default=RAM_REQUIRED_GB)

    args = ap.parse_args()
    MAX_FUZZ_SLOTS  = args.fuzz_slots
    FUZZ_UPTIME_H   = args.fuzz_hours
    RAM_REQUIRED_GB = args.ram_gb

    cases = build_case_list(args)
    if not cases:
        print("No cases loaded.")
        sys.exit(1)

    print(f"Loaded {len(cases)} cases from {args.cases_csv}")
    run_pipeline(cases, args.results_dir, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
