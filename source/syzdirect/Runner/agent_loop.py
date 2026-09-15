"""
SyzDirect Runner — AgentLoop: fuzz → assess → triage → enhance → re-fuzz.

Multi-round fuzzing loop that automatically triages failures and enhances
syscall templates between rounds. Health assessment, triage logic, and
format converters live in separate modules.
"""

import copy as _copy
import json
import os
import shutil
import subprocess
import sys

from paths import (
    HUNT_MODES, KNOWN_CRASH_DB, RESOURCE_ROOT,
    BootFallbackRequested,
)
from Fuzz import _alloc_free_tcp_port, runFuzzer
from crash_triage import collect_crashes, load_known_crash_db
from agent_health import assess_round_health
from agent_triage import (
    triage_failure, callfile_to_templates, templates_to_callfile,
    classify_r4_cause,
)
from syscall_scoring import collect_target_context
from llm_enhance import (
    extract_distance_roadmap, llm_enhance_callfile_for_distance,
    llm_enhance_for_trigger_condition, llm_validate_callfile_semantics,
    llm_generate_seed_program, llm_generate_seed_via_codegen,
    read_stepping_stone_sources,
    extract_closest_program, extract_closest_programs,
    pack_programs_to_corpus, reverse_trace_bottleneck,
    _call_llm, _build_target_seed_profile,
)
from semantic_seed import run_semantic_pipeline, validate_seed
from pipeline_new_cve import (
    ensure_target_function_info, load_target_function_map, resolve_prebuilt_target,
    write_target_function_info,
)
from runner_config import RunnerConfig
from syzlang_parser import get_db as _get_syz_db
from syzbot_mining import mine_seeds_for_target
from vm_verify import iterative_deepen
from target_profile import build_target_profile
from agent_planner import build_agent_plan
from agent_taxonomy import KERNEL_TARGET_STRUCTURE_TAXONOMY


# Path to source/agent/ (relative to this repo)
_AGENT_DIR = os.path.normpath(os.path.join(RESOURCE_ROOT, "..", "..", "agent"))
_GENERIC_BASE_CALLS = {
    "socket", "bind", "write", "read", "close", "open", "openat",
    "sendmsg", "sendto", "recvmsg", "recvfrom", "connect", "accept",
    "accept4", "listen", "ioctl", "setsockopt", "getsockopt",
}


def _ensure_agent_imports():
    """Make source/agent importable."""
    source_dir = os.path.normpath(os.path.join(RESOURCE_ROOT, "..", ".."))
    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)


class AgentLoop:
    """
    Multi-round fuzz → assess → triage → enhance → re-fuzz loop.

    After each fuzzing round, checks health metrics. If the distance is
    stagnant (not decreasing), classifies the failure as R1/R2/R3/R4 and
    dispatches the appropriate agent to enhance the callfile (syscall
    templates). Then re-fuzzes with the enhanced callfile.
    """

    def __init__(self, layout, target_info, max_rounds, window_seconds,
                 uptime_per_round, cpus, fuzz_rounds=1,
                 hunt_mode="hybrid", known_crash_db=None,
                 allow_boot_fallback=False, stall_timeout=0,
                 dist_stall_timeout=600, seed_corpus=None,
                 proactive_seed=False, xi=0, start_round=1):
        self.layout = layout
        self.target = target_info
        self.max_rounds = max_rounds
        self.start_round = start_round
        self.window_seconds = window_seconds
        self.uptime = uptime_per_round
        self.cpus = cpus
        self.fuzz_rounds = fuzz_rounds
        self.ci = target_info["idx"]
        self.xi = xi  # execution index — each parallel instance uses a separate xi
        self.hunt_mode = hunt_mode if hunt_mode in HUNT_MODES else "hybrid"
        self.known_rules = load_known_crash_db(KNOWN_CRASH_DB, known_crash_db)
        self.target_context = collect_target_context(
            target_info.get("func_path", ""),
            target_info.get("function", ""),
        )
        self.target_call_names = self._load_current_call_targets()
        self.allow_boot_fallback = allow_boot_fallback
        self.stall_timeout = stall_timeout
        self.dist_stall_timeout = dist_stall_timeout
        self.seed_corpus = seed_corpus  # path to corpus.db for round 1 seeding
        self.seed_corpus_list = []  # all seed DBs to merge
        # If the caller supplied a hand-crafted seed corpus, register it up
        # front so the merged_seed.db used by later rounds keeps it instead
        # of replacing it with later (e.g. R4) LLM-generated additions.
        if seed_corpus and os.path.exists(seed_corpus):
            self.seed_corpus_list.append(seed_corpus)
        self.proactive_seed = proactive_seed
        self.best_dist_min_ever = None
        self.dist_history = []
        self.dist0_no_crash_rounds = 0
        self.last_semantic_plan = None
        # Run-wide stagnation detection: if best_dist_min_ever stays frozen for
        # `terminal_stagnation_streak` rounds AND the planner has already
        # escalated without breaking through, the campaign is abandoned to free
        # the host for the next target. Threshold is 4 so the escalate plan
        # (first emitted around round 3 of a same-focus stall) always gets at
        # least one fuzz round to prove itself before the run is cut.
        self._no_progress_streak = 0
        self._escalation_count = 0
        self._plan_signature_history = []
        self.terminal_stagnation_streak = 4
        # Semantic validation metrics
        self.ttr_round = None        # round when dist=0 first achieved
        self.ttr_path_round = None   # round when dist=0 achieved with valid CVE path
        self.fake_d0_count = 0       # number of fake dist=0 detections
        # CVE metadata (populated from cve_meta.json if present)
        self.fix_commit_sha = None
        self.cve_kind = []
        self.cve_subject = ""
        # origin_commit is the commit that ADDED the (potentially buggy)
        # code. For 0-day targets we have no fix yet, but the diff of the
        # feature-introducing commit shows exactly the new code the LLM
        # should reason about for bug hypotheses.
        self.origin_commit = ""
        self._syz_db = _get_syz_db()
        self.target_profile = None
        self._last_agent_plan = None
        self._sync_target_metadata()

    def _add_seed_corpus(self, path):
        """Register a seed corpus DB. All registered DBs are merged before fuzzing.

        If the same path was already registered (e.g. llm_seed_{func}.db rewritten
        by a later round), make a timestamped copy so that previous round's programs
        are not lost when the file is overwritten.
        """
        if not path or not os.path.exists(path):
            return
        if path in self.seed_corpus_list:
            # File was already registered — it may have been overwritten with
            # new content.  Copy to a unique name so merge keeps both versions.
            import time as _time
            base, ext = os.path.splitext(path)
            backup = f"{base}_{int(_time.time())}{ext}"
            try:
                shutil.copy2(path, backup)
                self.seed_corpus_list.append(backup)
                print(f"  [seed] Backed up overwritten seed: {backup}")
            except OSError:
                pass
        else:
            self.seed_corpus_list.append(path)
        self.seed_corpus = path  # also set for backwards compat

    def _merge_seed_corpora(self):
        """Merge all registered seed DBs into one. Returns merged path or None."""
        dbs = [p for p in self.seed_corpus_list if os.path.exists(p)]
        if not dbs:
            return self.seed_corpus
        if len(dbs) == 1:
            return dbs[0]
        # Find syz-db binary
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()
        syz_db_bin = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
        if not os.path.exists(syz_db_bin):
            import shutil as _sh
            syz_db_bin = _sh.which("syz-db")
        if not syz_db_bin:
            return dbs[-1]  # fallback to last
        import tempfile
        # Unpack all into one dir, then repack
        merged_dir = tempfile.mkdtemp(prefix="syz_merge_")
        try:
            for db in dbs:
                subprocess.run([syz_db_bin, "unpack", db, merged_dir],
                               capture_output=True, timeout=30)
            out_dir = self.layout.fuzzres_xidx(self.ci, self.xi)
            os.makedirs(out_dir, exist_ok=True)
            merged_path = os.path.join(out_dir, "merged_seed.db")
            pack = subprocess.run([syz_db_bin, "pack", merged_dir, merged_path],
                                  capture_output=True, text=True, timeout=30)
            if pack.returncode == 0:
                prog_count = len([f for f in os.listdir(merged_dir) if os.path.isfile(os.path.join(merged_dir, f))])
                print(f"  [seed] Merged {len(dbs)} seed DBs → {merged_path} ({prog_count} programs)")
                return merged_path
        except Exception as e:
            print(f"  [seed] Merge failed: {e}")
        finally:
            import shutil as _sh
            _sh.rmtree(merged_dir, ignore_errors=True)
        return dbs[-1]

    def _preserve_best_corpus(self, detail_corpus, sub_workdir, round_num):
        """Save the best programs from this round's corpus so they survive overwrites.

        After each fuzz round, extract the top programs by distance from
        detailCorpus.txt and pack them into a round-specific corpus.db.
        This prevents later seed generation from overwriting good programs.
        """
        if not detail_corpus or not os.path.exists(detail_corpus):
            return
        try:
            from llm_enhance import _parse_detail_corpus
            entries = _parse_detail_corpus(detail_corpus)
            if not entries:
                return
            # Keep top 20 programs by distance (lowest dist first)
            entries.sort(key=lambda x: x[1])
            best = entries[:20]
            programs = [p[0] for p in best]
            best_dist = best[0][1]

            rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            Cfg = rcfg.apply_to_legacy_config()
            syz_db_bin = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")

            out_dir = self.layout.fuzzres_xidx(self.ci, self.xi)
            os.makedirs(out_dir, exist_ok=True)
            preserved_path = os.path.join(out_dir, f"best_corpus_r{round_num}.db")
            result = pack_programs_to_corpus(programs, syz_db_bin, preserved_path)
            if result:
                self._add_seed_corpus(result)
                print(f"  [seed] Preserved {len(programs)} best programs from round {round_num} "
                      f"(best_dist={best_dist}): {result}")
        except Exception as e:
            print(f"  [seed] Failed to preserve best corpus: {e}")

    def _relevant_repeat_threshold(self):
        """Tighten relevant-distance frontier for stateful message/config targets."""
        targets = []
        callfile = self.layout.callfile(self.ci, self.xi)
        if os.path.exists(callfile):
            try:
                with open(callfile) as f:
                    entries = json.load(f)
                targets = [e.get("Target", "") for e in entries if e.get("Target")]
            except (OSError, json.JSONDecodeError):
                targets = []
        if len(targets) != 1:
            return 1
        base = targets[0].split("$", 1)[0].lower()
        if base in {"sendmsg", "ioctl", "setsockopt", "mount", "bpf"}:
            return 2
        return 1

    def _roadmap_allowed_targets(self, roadmap, current_callfile):
        allowed = set()
        for entry in current_callfile:
            target = entry.get("Target")
            if target:
                allowed.add(target.lower())
                allowed.add(target.split("$", 1)[0].lower())
            for relate in entry.get("Relate", []):
                if relate:
                    allowed.add(relate.lower())
                    allowed.add(relate.split("$", 1)[0].lower())
        for stone in (roadmap or {}).get("stepping_stones", []):
            for call in stone.get("reachable_via", []) or []:
                if call:
                    allowed.add(call.lower())
                    allowed.add(call.split("$", 1)[0].lower())
        return allowed

    def _allow_new_r4_target(self, target, current_callfile, roadmap):
        if not target:
            return False
        current_targets = {e.get("Target", "").lower() for e in current_callfile if e.get("Target")}
        target_l = target.lower()
        if target_l in current_targets:
            return True
        # Allow novel syscalls suggested by LLM — the LLM's subsystem
        # reasoning is often the only signal for non-TC targets where
        # roadmap reachable_via data is sparse.
        allowed = self._roadmap_allowed_targets(roadmap, current_callfile)
        if target_l in allowed:
            return True
        # Accept any new target that isn't a generic widening of an
        # existing family (e.g. don't add sendmsg if sendmsg$variant exists)
        target_base = target_l.split("$", 1)[0]
        for existing in current_targets:
            if existing.split("$", 1)[0] == target_base and "$" in existing and "$" not in target_l:
                return False
        return True

    def _sync_target_metadata(self):
        resolved = resolve_prebuilt_target(self.layout, self.target)
        self.target.update(resolved)
        tfinfo_path = self.layout.tfinfo(self.ci)
        func = self.target.get("function", "")
        func_path = self.target.get("func_path", "")
        if func and func_path:
            write_target_function_info(tfinfo_path, func, func_path)
        self.target_context = collect_target_context(
            self.target.get("func_path", ""),
            self.target.get("function", ""),
        )

    def _seed_matches_target(self, seed_db):
        if not seed_db:
            return False
        expected = (self.target.get("function") or "").strip().lower()
        if not expected:
            return True
        basename = os.path.basename(seed_db).lower()
        return expected in basename

    # ── Main loop ────────────────────────────────────────────────────────

    def run(self):
        if self.proactive_seed and self.seed_corpus is None:
            self._generate_proactive_seed()

        end_round = self.start_round + self.max_rounds - 1
        for round_num in range(self.start_round, end_round + 1):
            print(f"\n{'=' * 60}")
            print(f"  AGENT ROUND {round_num}/{end_round}")
            print(f"{'=' * 60}")

            round_dir = os.path.join(
                self.layout.fuzzres_xidx(self.ci, self.xi),
                f"agent_round_{round_num}",
            )
            shutil.rmtree(round_dir, ignore_errors=True)
            os.makedirs(round_dir, exist_ok=True)

            # ── A. Fuzz ──────────────────────────────────────────────
            try:
                manager_log, metrics_jsonl, detail_corpus, sub_workdir = self._run_fuzz_round(round_dir, round_num)
            except RuntimeError as e:
                # A single round's syz-manager failure (e.g. transient memory
                # pressure) must not kill the whole multi-round campaign.
                self._round_fail_streak = getattr(self, "_round_fail_streak", 0) + 1
                print(f"  [agent-loop] round {round_num} fuzz failed: {e}")
                if self._round_fail_streak >= 3:
                    print(f"  [agent-loop] {self._round_fail_streak} consecutive "
                          f"failed rounds — stopping campaign")
                    break
                print("  [agent-loop] skipping to next round")
                continue
            self._round_fail_streak = 0
            self._last_sub_workdir = sub_workdir
            self._last_detail_corpus = detail_corpus

            # Preserve best corpus programs from this round so they survive
            # seed overwrites in the enhance phase
            self._preserve_best_corpus(detail_corpus, sub_workdir, round_num)

            crash_summary = self._collect_crashes(round_dir, round_num)

            # ── B. Early success (repro mode only) ───────────────────
            if self._should_stop_early(crash_summary):
                print(f"  Crash summary: {crash_summary['counts']}")
                print(f"  Success condition met for hunt_mode={self.hunt_mode}")
                break
            if crash_summary.get("counts", {}).get("total", 0) > 0:
                print(f"  Crash summary: {crash_summary['counts']}")

            # ── C. Assess health ─────────────────────────────────────
            health = assess_round_health(
                metrics_jsonl, manager_log, crash_summary,
                best_dist_min_ever=self.best_dist_min_ever,
                stall_timeout=self.stall_timeout,
                detail_corpus_path=detail_corpus,
                relevant_call_names=self.target_call_names,
                relevant_repeat_threshold=self._relevant_repeat_threshold(),
            )
            print(f"  Health: status={health['status']}  score={health['score']:.1f}")
            print(f"  Reason: {health['reason']}")

            # Update cross-round distance tracking
            # Only update best_dist_min_ever with real non-zero values;
            # dist_best==0 means target reached (skip LLM), but a false 0
            # from warmup metrics would permanently block LLM enhancement.
            dist_best = health.get("effective_dist_min_best")
            prev_best_dist_min = self.best_dist_min_ever
            if dist_best is not None:
                self.dist_history.append(dist_best)
                if dist_best > 0:
                    if self.best_dist_min_ever is None or dist_best < self.best_dist_min_ever:
                        self.best_dist_min_ever = dist_best
                raw_best = health.get("dist_min_best")
                relevant_best = health.get("relevant_dist_min_best")
                trivial_zeros = health.get("trivial_zero_count", 0)
                rel_count = health.get("relevant_prog_count", 0)
                null_cov = health.get("null_coverage", False)
                if null_cov:
                    if trivial_zeros > 0:
                        print(f"  Distance: NULL COVERAGE ({trivial_zeros}/{rel_count} relevant "
                              f"corpus are trivial-zero — counter never updated)  "
                              f"best_ever={self.best_dist_min_ever}")
                    else:
                        print(f"  Distance: NULL COVERAGE (all relevant corpus at UINT_MAX, "
                              f"raw_best={raw_best})  best_ever={self.best_dist_min_ever}")
                elif relevant_best is not None:
                    print(f"  Distance: best_this_round={dist_best}  raw_best={raw_best}  best_ever={self.best_dist_min_ever}")
                else:
                    print(f"  Distance: best_this_round={dist_best}  best_ever={self.best_dist_min_ever}")

            # ── TTR / path-quality metrics ────────────────────────────
            if dist_best == 0 and self.ttr_round is None:
                self.ttr_round = round_num
                print(f"  [metrics] TTR achieved at round {round_num}")

            # ── Round-1 semantic callfile validation ──────────────────
            # After the very first fuzzing round, verify the callfile is
            # semantically correct for triggering this CVE.
            if round_num == self.start_round and round_num < self.max_rounds:
                self._validate_and_fix_callfile_semantics(round_num)

            # ── dist=0 trigger-condition feedback loop ───────────────────
            # When the target function is being reached (dist=0) but no crash
            # is found, ask the LLM to analyze the specific trigger conditions.
            no_crash = crash_summary.get("counts", {}).get("total", 0) == 0
            if dist_best == 0 and no_crash:
                self.dist0_no_crash_rounds += 1
            else:
                self.dist0_no_crash_rounds = 0

            if self.dist0_no_crash_rounds >= 2 and round_num < self.max_rounds:
                self._run_trigger_condition_enhancement(round_num)

            if health["status"] == "healthy":
                if round_num < self.max_rounds:
                    print("  Fuzzing is healthy, continuing to next round...")
                continue

            if health["status"] == "boot_failed":
                if self.allow_boot_fallback:
                    raise BootFallbackRequested(health["reason"])
                print("  Boot failed and no fallback retries remain. Stopping.")
                break

            if health["status"] == "fatal":
                print("  FATAL: all target calls disabled. Stopping.")
                break

            # ── D. Triage ────────────────────────────────────────────
            triage_result = triage_failure(
                health, manager_log, crash_summary, self.hunt_mode,
            )
            failure_class = triage_result.get("primary", "R3")
            print(f"  Triage result: {failure_class}")
            if triage_result.get("secondary"):
                print(f"  Secondary signals: {triage_result['secondary']}")
            for ev in triage_result.get("evidence", []):
                print(f"    · {ev}")

            if failure_class == "SUCCESS":
                break

            # ── E. Structural agent plan ─────────────────────────────
            self._build_agent_plan(health=health, triage_result=triage_result)
            self._print_agent_plan(prefix="planner")

            # ── E2. Terminal-stagnation early exit ───────────────────
            if self._check_terminal_stagnation(
                    round_num, dist_best, failure_class, prev_best_dist_min):
                break

            # ── F. Enhance callfile ──────────────────────────────────
            self._last_health = health
            if round_num < self.max_rounds:
                enhanced = self._enhance_callfile(triage_result, round_dir, round_num)
                if enhanced:
                    print(f"  Callfile enhanced for next round.")
                else:
                    print("  No enhancement produced, continuing to next round anyway.")
            else:
                print("  Last round, no more enhancements.")

        self._print_summary()

    # ── Fuzzing ──────────────────────────────────────────────────────────

    # B1-1: subsystem → syzkaller syscall families. Restricting enable_syscalls
    # to the target's subsystem makes syzkaller's own grammar generator produce
    # structurally-valid programs (correct netlink dispatch, nested attrs) at
    # high density, so guarded handlers are actually reached — instead of
    # spreading the budget across all syscalls and never building a valid
    # dispatch. Names/globs verified against sys/linux/*.txt; an unknown name
    # makes syz-manager refuse to start, so this stays conservative and only
    # covers subsystems we've checked. Opt-in via SYZDIRECT_FOCUS_SYSCALLS=1.
    _FOCUS_SYSCALLS = [
        ("net/sched/",        ["socket$nl_route", "sendmsg$nl_route",
                               "sendmsg$nl_route_sched"]),
        ("net/netfilter/nf",  ["socket$nl_netfilter", "sendmsg$nl_netfilter"]),
        ("net/core/filter",   ["bpf$*", "socket$inet_tcp", "bind$inet",
                               "connect$inet", "listen", "accept4$inet",
                               "sendmsg$inet", "sendto", "recvmsg",
                               "socket$inet_udp", "socket$inet6_udp",
                               "socket$inet6_tcp", "close"]),
        ("net/core/sock_map", ["bpf$*", "socket$inet_tcp", "bind$inet",
                               "connect$inet", "listen", "accept4$inet",
                               "sendmsg$inet", "sendto", "recvmsg",
                               "socket$inet_udp", "socket$inet6_udp",
                               "socket$inet6_tcp", "close"]),
        ("net/core/skmsg",    ["bpf$*", "socket$inet_tcp", "bind$inet",
                               "connect$inet", "listen", "accept4$inet",
                               "sendmsg$inet", "sendto", "recvmsg",
                               "socket$inet_udp", "socket$inet6_udp",
                               "socket$inet6_tcp", "close"]),
        ("kernel/bpf/",       ["bpf$*"]),
        ("io_uring/",         ["syz_io_uring_setup", "syz_io_uring_submit",
                               "syz_io_uring_complete",
                               "syz_memcpy_off$IO_URING_METADATA_GENERIC",
                               "syz_memcpy_off$IO_URING_METADATA_FLAGS",
                               "io_uring_setup", "io_uring_enter",
                               "io_uring_register$IORING_REGISTER_FILES",
                               "io_uring_register$IORING_REGISTER_BUFFERS",
                               "io_uring_register$IORING_REGISTER_EVENTFD",
                               "io_uring_register$IORING_REGISTER_EVENTFD_ASYNC",
                               "io_uring_register$IORING_UNREGISTER_EVENTFD",
                               "io_uring_register$IORING_REGISTER_PROBE",
                               "io_uring_register$IORING_REGISTER_PBUF_RING",
                               "io_uring_register$IORING_UNREGISTER_PBUF_RING",
                               "io_uring_register$IORING_REGISTER_PBUF_STATUS",
                               "eventfd2", "pipe2", "clock_gettime",
                               "timerfd_create", "epoll_create1",
                               "epoll_ctl", "openat",
                               "socketpair",
                               "socket$inet_tcp", "ioctl$sock_SIOCGIFINDEX",
                               "bind$inet",
                               "connect$inet", "listen", "accept4$inet",
                               "close"]),
    ]
    # Resource producers the subsystem calls transitively need. Without these
    # syzkaller disables the target call (netlink needs the `pid` resource →
    # getpid) and aborts "all target calls are disabled". Keep this to narrow,
    # exact names only — broad patterns like "openat" would pull in hundreds of
    # variants and defeat the focus. Socket/fd resources come from the
    # subsystem's own socket$* call. Add more here only if a run reports another
    # missing resource.
    _FOCUS_BASE = ["getpid", "gettid", "getuid", "geteuid", "getgid", "getegid"]

    def _focus_syscalls(self):
        """enable_syscalls list for the target's subsystem, or None to leave the
        fuzzer unrestricted (current default). Opt-in via env flag so it never
        disturbs runs that don't set it."""
        if os.environ.get("SYZDIRECT_FOCUS_SYSCALLS") != "1":
            return None
        tf = (self.target.get("func_path") or self.target.get("file") or "")
        tf = tf.replace("\\", "/")
        subsys = None
        for needle, calls in self._FOCUS_SYSCALLS:
            if needle in tf:
                subsys = list(calls)
                break
        if subsys is None:
            return None
        # The directed mechanism requires the callfile's Target/Relate calls to
        # stay enabled (SyzDirect targets the generic sendmsg$netlink etc.);
        # restricting to only the structured variants would disable the target
        # call → "all target calls are disabled". So union: callfile calls (keep
        # directed working) + structured subsystem variants (add grammar) + base
        # resource producers (pid/uid/gid, else syzkaller disables the call).
        result = set(subsys) | set(self._FOCUS_BASE)
        try:
            with open(self.layout.callfile(self.ci, self.xi)) as f:
                for entry in json.load(f):
                    if entry.get("Target"):
                        result.add(entry["Target"])
                    result.update(entry.get("Relate", []) or [])
        except Exception as e:
            print(f"  [focus] could not read callfile for syscall union: {e}")
        return sorted(result)

    def _run_fuzz_round(self, round_dir, round_num):
        """Run one round of syz-manager with log capture."""
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()

        ci = self.ci
        template_config = Cfg.LoadJson(Cfg.TemplateConfigPath)
        assert template_config, "Failed to load fuzzing config template"
        template_config["sshkey"] = Cfg.KeyPath

        syzdirect_path = Cfg.FuzzerDir
        # If PrepareForFuzzing moved bin/ to a per-CVE customized path, use it.
        custom_syz = Cfg.getCustomizedSyzByCaseAndXidx(ci, self.xi)
        if os.path.exists(os.path.join(custom_syz, "bin", "syz-manager")):
            syzdirect_path = custom_syz
        tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)
        if not tfmap:
            # For dataset mode, target function may not be known
            target_func = self.target.get("function", "")
            target_func_path = self.target.get("func_path", "")
            
            if target_func and target_func_path:
                ensure_target_function_info(
                    self.layout.tfinfo(ci),
                    target_func,
                    target_func_path,
                )
                tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)
        
        if not tfmap:
            print(f"  [WARNING] No target function map for case {ci}, skipping agent loop")
            return None, None, None

        last_log, last_metrics = None, None

        for xidx in tfmap.keys():
            callfile = self.layout.callfile(ci, self.xi)
            kernel_img = self.layout.bzimage(ci, xidx)
            assert os.path.exists(callfile), f"callfile missing: {callfile}"
            assert os.path.exists(kernel_img), f"bzImage missing: {kernel_img}"

            config = _copy.deepcopy(template_config)
            config["image"] = Cfg.CleanImageTemplatePath
            sub_workdir = os.path.join(round_dir, f"workdir_x{xidx}")
            config["workdir"] = sub_workdir
            port = _alloc_free_tcp_port()
            config["http"] = f"0.0.0.0:{port}"
            vm_cfg = config.setdefault("vm", {})
            existing_cmdline = vm_cfg.get("cmdline", "")
            if "net.ifnames=0" not in existing_cmdline.split():
                vm_cfg["cmdline"] = (existing_cmdline + " net.ifnames=0").strip()
            vm_cfg["kernel"] = kernel_img
            config["syzkaller"] = syzdirect_path
            config["hitindex"] = int(xidx)

            focus = self._focus_syscalls()
            if focus:
                config["enable_syscalls"] = focus
                print(f"  [focus] enable_syscalls → subsystem set {focus}")

            config_path = os.path.join(round_dir, f"config_x{xidx}.json")
            with open(config_path, "w") as f:
                json.dump(config, f, indent="\t")

            fuzzer_file = os.path.join(syzdirect_path, "bin", "syz-manager")
            log_dir = os.path.join(round_dir, f"logs_x{xidx}")

            print(f"  Fuzzing case={ci} xidx={xidx} for {self.uptime}h ...")
            if self.stall_timeout > 0:
                print(f"  Stall detection: terminate if coverage stuck for {self.stall_timeout}s")
            if self.dist_stall_timeout > 0:
                print(f"  Dist stall detection: terminate if dist_min stuck for {self.dist_stall_timeout}s")
            # Merge all registered seed DBs into one before fuzzing
            if len(self.seed_corpus_list) > 1:
                merged = self._merge_seed_corpora()
                if merged:
                    self.seed_corpus = merged

            last_log, last_metrics = runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
                stall_timeout=self.stall_timeout,
                dist_stall_timeout=self.dist_stall_timeout,
                seed_corpus=self.seed_corpus,
            )

        detail_corpus = os.path.join(sub_workdir, "detailCorpus.txt")
        return last_log, last_metrics, detail_corpus, sub_workdir

    # ── Crash detection ──────────────────────────────────────────────────

    def _collect_crashes(self, round_dir, round_num):
        return collect_crashes(
            round_dir, round_num, self.hunt_mode, self.known_rules,
            self.target, self.target_context, self.target_call_names,
        )

    def _should_stop_early(self, crash_summary):
        """Only repro mode stops early on a target-related crash."""
        counts = crash_summary.get("counts", {})
        return self.hunt_mode == "repro" and counts.get("target_related", 0) > 0

    # ── Callfile management ──────────────────────────────────────────────

    def _build_syz_resource_chain(self, callfile_entries):
        """Build a syzlang resource dependency description for LLM prompt injection."""
        if not self._syz_db:
            return ""
        parts = []
        seen = set()
        for entry in callfile_entries:
            sc = entry.get("Target", "")
            if not sc or sc in seen:
                continue
            seen.add(sc)
            if sc in self._syz_db.syscalls:
                text = self._syz_db.format_for_prompt(sc)
                if text:
                    parts.append(text)
        return "\n\n".join(parts)

    def _load_current_call_targets(self):
        call_names = set()
        callfile = self.layout.callfile(self.ci, self.xi)
        if not os.path.exists(callfile):
            return call_names
        try:
            with open(callfile) as f:
                entries = json.load(f)
        except (OSError, json.JSONDecodeError):
            return call_names
        flat_names = []
        has_variant = False
        for entry in entries:
            target = entry.get("Target")
            if target:
                flat_names.append(target)
                if "$" in target:
                    has_variant = True
            for related in entry.get("Relate", []):
                if related:
                    flat_names.append(related)
                    if "$" in related:
                        has_variant = True
        for name in flat_names:
            lowered = name.lower()
            base = lowered.split("$", 1)[0]
            if "$" not in lowered and has_variant and base in _GENERIC_BASE_CALLS:
                continue
            call_names.add(lowered)
            if "$" not in lowered or base not in _GENERIC_BASE_CALLS:
                call_names.add(base)
        return call_names

    def _load_current_callfile_entries(self):
        callfile = self.layout.callfile(self.ci, self.xi)
        if not os.path.exists(callfile):
            return []
        try:
            with open(callfile) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def _build_agent_plan(self, health=None, triage_result=None):
        entries = self._load_current_callfile_entries()
        self.target_profile = build_target_profile(
            self.target,
            callfile_entries=entries,
            health=health,
        )
        self._last_agent_plan = build_agent_plan(
            self.target_profile,
            health=health,
            triage_result=triage_result,
            prev_signatures=self._plan_signature_history,
            # `_no_progress_streak` is updated at the END of the previous
            # round inside `_check_terminal_stagnation`, so it reflects
            # rounds 0..N-1 when round N's plan is being built. Feeding it
            # to the planner lets a stall-escalate plan fire on round N
            # when the streak has crossed `stall_threshold`.
            dist_stall_rounds=self._no_progress_streak,
        )
        return self.target_profile, self._last_agent_plan

    def _print_agent_plan(self, prefix="agent"):
        if not self.target_profile or not self._last_agent_plan:
            return
        print(f"  [{prefix}] Profile: {self.target_profile.one_line()}")
        for line in self._last_agent_plan.to_log_lines():
            print(f"  [{prefix}] Plan: {line}")

    def _check_terminal_stagnation(self, round_num, dist_best, failure_class,
                                   prev_best_dist_min=None):
        """Detect when the campaign is producing zero progress round after round.

        Past runs (cls_fw / cls_flow / cve_2025_40186) wasted 16 rounds at the
        same dist_min — burning ~3h of host time per target. Bail out once the
        distance has been flat for several rounds AND the planner has already
        escalated at least once without breaking through. The escalation gate
        guarantees the `cross_layer_recovery` strategy gets a fair shot before
        the run is abandoned; tying the exit to the plan *signature* (the old
        behaviour) never fired, because escalation itself rotates the signature.
        """
        plan = self._last_agent_plan
        signature = None
        if plan is not None:
            signature = (failure_class, plan.focus_layer, plan.hypothesis)
        if signature is not None:
            self._plan_signature_history.append(signature)

        # Count how many times the planner has escalated so far.
        if plan is not None and getattr(plan, "phase", "") == "escalate":
            self._escalation_count += 1

        # dist progress: count rounds where best_dist_min_ever did not improve.
        # Compare against the value held BEFORE this round (`prev_best`) so
        # that a fresh improvement properly resets the streak.
        is_real_dist = dist_best is not None and dist_best > 0
        if is_real_dist and prev_best_dist_min is not None \
                and dist_best >= prev_best_dist_min:
            self._no_progress_streak += 1
        elif is_real_dist:
            self._no_progress_streak = 0

        # Terminal-stagnation early exit is DISABLED — the user wants 0-day
        # hunt runs to always use the full round budget so the LLM seed
        # generator gets every chance to break through in later rounds.
        # The streak/escalation tracking above still runs (it's cheap and
        # useful telemetry for the planner), but this function never aborts
        # the campaign.
        return False

    def _agent_context_for_prompt(self):
        if not self.target_profile or not self._last_agent_plan:
            self._build_agent_plan()
        if not self.target_profile or not self._last_agent_plan:
            return ""

        profile = self.target_profile
        plan = self._last_agent_plan
        lines = [
            "",
            KERNEL_TARGET_STRUCTURE_TAXONOMY.rstrip(),
            "",
            "AGENT STRUCTURAL PLAN:",
            f"- target profile: {profile.one_line()}",
            f"- syscall: {profile.primary_syscall or 'unknown'}",
            f"- related syscalls: {', '.join(profile.related_syscalls) or 'none'}",
            f"- resource chain: {' -> '.join(profile.resource_chain) or 'unknown'}",
            f"- subsystem state: {profile.subsystem_state}",
            f"- dispatch selector: {profile.dispatch_selector}",
            f"- likely preconditions: {', '.join(profile.likely_preconditions) or 'unknown'}",
            f"- current hypothesis: {plan.hypothesis}",
            f"- focus layer for this round: {plan.focus_layer}",
            "Prompt guardrails:",
            "- First respect the profile, blocking layer, and dispatch selector above.",
            "- Do not generate broad generic seeds when a selector/state layer is identified.",
            "- Preserve existing resource/state setup when the target is close.",
        ]
        for action in plan.actions:
            lines.append(f"- planned action: {action}")
        for guardrail in plan.prompt_guardrails:
            lines.append(f"- guardrail: {guardrail}")
        return "\n".join(lines) + "\n"

    # ── Template enhancement ─────────────────────────────────────────────

    def _enhance_callfile(self, triage_result, round_dir, round_num):
        """Enhance the callfile using the appropriate agent."""
        failure_class = triage_result.get("primary", "R3")
        callfile_path = self.layout.callfile(self.ci, self.xi)
        with open(callfile_path) as f:
            current_callfile = json.load(f)

        template_data = callfile_to_templates(current_callfile, syz_db=self._syz_db)
        agent_input = {
            "failure_class": failure_class,
            "evidence": [f"Agent loop round {round_num} triage: {failure_class}"] + triage_result.get("evidence", []),
            "recommended_actions": [],
        }

        enhanced_templates = None
        _ensure_agent_imports()

        if failure_class in ("R3", "R1"):
            print(f"  [{failure_class}] Using RelatedSyscallAgent (rule-based syscall discovery)")
            print(f"  [{failure_class}] Current targets: {[e.get('Target') for e in current_callfile]}")
            try:
                from source.agent.related_syscall_agent import RelatedSyscallAgent
                agent = RelatedSyscallAgent(
                    template_data=template_data,
                    triage_result=agent_input,
                )
                enhanced_templates = agent.analyze_and_enhance()
                print(f"  [{failure_class}] RelatedSyscallAgent produced {len(enhanced_templates)} templates")
                for t in enhanced_templates:
                    entry = t.get("entry_syscall", {})
                    related = [s.get("syzlang_name", s.get("name", "")) for s in t.get("related_syscalls", [])]
                    print(f"    → {entry.get('syzlang_name', entry.get('name', '?'))}  relate={related}")
            except Exception as e:
                print(f"  WARNING: RelatedSyscallAgent failed: {e}")

        elif failure_class == "R2":
            try:
                from source.agent.object_synthesis_agent import ObjectSynthesisAgent
                image_dir = os.path.join(round_dir, "images")
                agent = ObjectSynthesisAgent(
                    triage_result=agent_input,
                    template_data=template_data,
                    image_dir=image_dir,
                )
                result = agent.analyze_and_synthesize()
                enhanced_templates = result.get("enhanced_templates", [])
                print(f"  ObjectSynthesisAgent produced {len(enhanced_templates)} templates")
            except Exception as e:
                print(f"  WARNING: ObjectSynthesisAgent failed: {e}")

        elif failure_class == "R4":
            enhanced_templates = self._enhance_for_distance_stall(
                current_callfile, round_dir, round_num, triage_result=triage_result,
            )
            # R4 failed → fallback to R1 (related syscall discovery)
            if not enhanced_templates and "R1" in set(triage_result.get("secondary", [])):
                print("  [R4] LLM roadmap failed, falling back to R1 (related syscalls)")
                failure_class = "R1"
                agent_input["failure_class"] = "R1"
                print(f"  [R1-fallback] Current targets: {[e.get('Target') for e in current_callfile]}")
                try:
                    from source.agent.related_syscall_agent import RelatedSyscallAgent
                    agent = RelatedSyscallAgent(
                        template_data=template_data,
                        triage_result=agent_input,
                    )
                    enhanced_templates = agent.analyze_and_enhance()
                    print(f"  [R1-fallback] RelatedSyscallAgent produced {len(enhanced_templates)} templates")
                    for t in enhanced_templates:
                        entry = t.get("entry_syscall", {})
                        related = [s.get("syzlang_name", s.get("name", "")) for s in t.get("related_syscalls", [])]
                        print(f"    → {entry.get('syzlang_name', entry.get('name', '?'))}  relate={related}")
                except Exception as e:
                    print(f"  WARNING: RelatedSyscallAgent fallback failed: {e}")

        if not enhanced_templates:
            return False

        # R4 returns callfile entries directly; others use template format
        if failure_class == "R4":
            new_callfile = enhanced_templates
        else:
            new_callfile = templates_to_callfile(enhanced_templates)
        if not new_callfile:
            return False

        backup = callfile_path + f".round{round_num}"
        shutil.copyfile(callfile_path, backup)

        merged = list(current_callfile)
        merged_by_target = {e["Target"]: e for e in merged if e.get("Target")}
        added = []
        updated = []
        for entry in new_callfile:
            target = entry.get("Target")
            if not target:
                continue
            if target not in merged_by_target:
                merged.append(entry)
                merged_by_target[target] = entry
                added.append(entry)
                continue

            existing = merged_by_target[target]
            before = list(existing.get("Relate", []))
            seen = set(before)
            merged_related = list(before)
            for relate in entry.get("Relate", []):
                if relate and relate != target and relate not in seen:
                    merged_related.append(relate)
                    seen.add(relate)
            if merged_related != before:
                existing["Relate"] = merged_related
                updated.append({
                    "Target": target,
                    "Before": before,
                    "After": merged_related,
                })

        if added:
            print(f"  [enhance] Before: {[e['Target'] for e in current_callfile]}")
            print(f"  [enhance] Adding {len(added)} new entries:")
            for entry in added:
                print(f"    + Target: {entry['Target']}  Relate: {entry.get('Relate', [])}")
            print(f"  [enhance] After: {[e['Target'] for e in merged]}")
        if updated:
            print(f"  [enhance] Updated {len(updated)} existing target(s):")
            for entry in updated:
                print(f"    ~ Target: {entry['Target']}  Relate: {entry['After']}")
        if not added and not updated:
            print(f"  [enhance] No new entries (all duplicates of existing targets)")

        with open(callfile_path, "w") as f:
            json.dump(merged, f, indent="\t")

        self.target_call_names = self._load_current_call_targets()
        return True

    # ── Proactive seed generation ────────────────────────────────────────

    def _generate_proactive_seed(self):
        """Generate LLM seed corpus BEFORE Round 1 using static dist analysis only.

        Reads the dist_dir (static analysis output) and callfile, builds a full
        roadmap of all functions between the entry and target, then asks the LLM
        to synthesize seed programs. Sets self.seed_corpus so Round 1 starts with
        an empty corpus and the seeds become the mutation foundation.
        """
        ci = self.ci
        self._sync_target_metadata()
        dist_dir = self.layout.dist_dir(ci, 0)
        src_dir = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        callfile_path = self.layout.callfile(ci, self.xi)
        print(f"  [proactive] Target metadata: function={target_func} file={target_file}")

        if not os.path.isdir(dist_dir):
            print(f"  [proactive] No dist_dir at {dist_dir}, skipping proactive seed")
            return

        print(f"  [proactive] Building static roadmap for {target_func}...")

        # Use large current_dist so all functions are included as stepping stones
        roadmap = extract_distance_roadmap(
            dist_dir, target_func, current_dist_min=99999,
            k2s_path=k2s_path if os.path.exists(k2s_path) else None,
            src_dir=src_dir if os.path.isdir(src_dir) else None,
            target_file=target_file,
        )

        if not roadmap:
            print("  [proactive] No roadmap from dist files, skipping proactive seed")
            return

        stones = roadmap.get("stepping_stones", [])
        print(f"  [proactive] Static roadmap: {len(stones)} stepping stones, "
              f"total_in_range={roadmap['total_functions_in_range']}")
        if stones:
            print(f"  [proactive] Closest stone: {stones[0]['function']}(dist={stones[0]['distance']})")

        current_callfile = []
        if os.path.exists(callfile_path):
            try:
                with open(callfile_path) as f:
                    current_callfile = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        snippets = ""
        if stones:
            snippets = read_stepping_stone_sources(src_dir, roadmap)
            if snippets:
                print(f"  [proactive] Read {snippets.count('---') + 1} source snippets")

        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()
        syz_db_path = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
        seed_out_dir = self.layout.fuzzres_xidx(ci, self.xi)

        # ── Try semantic pipeline first ────────────────────────────────
        semantic_seeds = self._run_semantic_seeds(None, "proactive")
        if semantic_seeds:
            corpus = self._pack_seeds_to_corpus(semantic_seeds, "proactive")
            if corpus and self._seed_matches_target(corpus):
                print(f"  [proactive] Semantic seed corpus ready: {corpus}")
                self._add_seed_corpus(corpus)
                return  # semantic seeds are better, skip generic LLM path

        print("  [proactive] Querying LLM for seed programs...")
        self._build_agent_plan()
        seed_db = llm_generate_seed_program(
            roadmap=roadmap,
            source_snippets=snippets,
            target_function=target_func,
            target_file=target_file,
            current_callfile=current_callfile,
            syz_db_path=syz_db_path,
            output_dir=seed_out_dir,
            syz_resource_chain=self._build_syz_resource_chain(current_callfile),
            agent_context=self._agent_context_for_prompt(),
            src_root=self.layout.src(self.ci),
            commit_sha=self.origin_commit or self.fix_commit_sha,
        )
        if seed_db and self._seed_matches_target(seed_db):
            print(f"  [proactive] Seed corpus ready: {seed_db}")
            self._add_seed_corpus(seed_db)
        elif seed_db:
            print(f"  [proactive] Rejecting inconsistent seed corpus: {seed_db}")
        else:
            print("  [proactive] Seed generation failed, Round 1 starts with empty corpus")

    # ── Semantic seed pipeline ─────────────────────────────────────────

    def _run_semantic_seeds(self, round_dir, label="R4"):
        """Run the semantic analysis pipeline to generate validated seeds.

        Returns list of seed programs or empty list.
        """
        ci = self.ci
        src_dir = self.layout.src(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")

        if not os.path.isdir(src_dir):
            print(f"  [{label}] No kernel source at {src_dir}, skipping semantic pipeline")
            return []

        plan, seeds = run_semantic_pipeline(
            src_dir, target_func, target_file, llm_call_fn=_call_llm,
        )
        self.last_semantic_plan = plan

        if not seeds:
            print(f"  [{label}] Semantic pipeline produced no valid seeds")
            return []

        print(f"  [{label}] Semantic pipeline produced {len(seeds)} validated seeds")
        return seeds

    def _pack_seeds_to_corpus(self, seeds, label="R4"):
        """Pack seed program dicts into a corpus.db, return path or None."""
        import shutil as _shutil
        import tempfile as _tempfile

        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()
        syz_db = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
        if not os.path.exists(syz_db):
            syz_db = _shutil.which("syz-db")
        if not syz_db or not os.path.exists(syz_db):
            print(f"  [{label}] syz-db not found, cannot pack seeds")
            return None

        prog_dir = _tempfile.mkdtemp(prefix="sem_seed_")
        try:
            for i, seed in enumerate(seeds):
                text = (seed.get("text") or "").strip()
                name = (seed.get("name") or f"prog{i}").replace("/", "_")
                if not text:
                    continue
                with open(os.path.join(prog_dir, f"{i:04d}_{name}"), "w") as f:
                    f.write(text + "\n")

            ci = self.ci
            out_dir = self.layout.fuzzres_xidx(ci, self.xi)
            os.makedirs(out_dir, exist_ok=True)
            target_func = self.target.get("function", "")
            corpus_db = os.path.join(out_dir, f"semantic_seed_{target_func}.db")

            import subprocess as _sp
            pack = _sp.run(
                [syz_db, "pack", prog_dir, corpus_db],
                capture_output=True, text=True, timeout=30,
            )
            if pack.returncode != 0:
                print(f"  [{label}] syz-db pack failed: {pack.stderr[:200]}")
                return None

            print(f"  [{label}] Packed {len(seeds)} semantic seeds → {corpus_db}")
            return corpus_db
        finally:
            _shutil.rmtree(prog_dir, ignore_errors=True)

    # ── Distance-stall enhancement ──────────────────────────────────────

    def _enhance_for_distance_stall(self, current_callfile, round_dir, round_num, triage_result=None):
        """Use semantic analysis + LLM with distance roadmap (R4)."""
        ci = self.ci
        self._sync_target_metadata()
        dist_dir = self.layout.dist_dir(ci, 0)
        src_dir = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        current_dist = self.best_dist_min_ever
        secondary = set((triage_result or {}).get("secondary", []))
        print(f"  [R4] Target metadata: function={target_func} file={target_file}")
        if secondary:
            print(f"  [R4] Recovery routing via secondary signals: {sorted(secondary)}")

        if current_dist is None and self.ttr_round is None:
            # Never got any distance signal at all — nothing to work with.
            print("  [R4] No valid distance data, skipping LLM enhancement")
            return None
        if not current_dist or current_dist <= 0:
            # Fake D=0: every round showed dist=0 due to static instrumentation
            # giving credit to opening the right socket family, but no real BB hit.
            # Use a large sentinel so roadmap finds stepping stones across the full
            # call graph rather than looking within dist=0 (which finds nothing).
            current_dist = 2_000_000
            print(f"  [R4] Fake D=0 (best_ever=None, ttr_round={self.ttr_round}) "
                  f"— using sentinel dist={current_dist} for roadmap")

        # ── Augment k2s with indirect dispatch (once per instance) ───────
        # pipeline_dataset does this at build time; pipeline_new_cve may skip
        # it if src was unavailable, so re-attempt lazily on first R4 round.
        if not getattr(self, "_k2s_augmented", False):
            self._k2s_augmented = True  # set before attempt — don't retry on error
            if os.path.exists(k2s_path) and os.path.isdir(src_dir):
                try:
                    from indirect_dispatch_resolver import (
                        augment_k2s, filter_k2s_by_reachability)
                    # V8: drop MatchSig false positives first
                    with open(k2s_path) as f:
                        k2s_data = json.load(f)
                    before = len(k2s_data)
                    filtered = filter_k2s_by_reachability(
                        k2s_data, target_func, src_dir)
                    if filtered:
                        with open(k2s_path, "w") as f:
                            json.dump(filtered, f)
                        if len(filtered) != before:
                            print(f"  [R4] V8 filter {before} → "
                                  f"{len(filtered)} handlers")
                    augmented = augment_k2s(
                        k2s_path, src_dir, target_func,
                        target_file or None,
                    )
                    with open(k2s_path, "w") as f:
                        json.dump(augmented, f)
                    print(f"  [R4] k2s augmented with indirect dispatch "
                          f"({len(augmented)} entries)")
                except Exception as e:
                    print(f"  [R4] k2s augmentation skipped: {e}")

        # ── Try semantic pipeline first (generic analysis) ───────────
        semantic_seeds = self._run_semantic_seeds(round_dir, "R4")
        if semantic_seeds:
            corpus = self._pack_seeds_to_corpus(semantic_seeds, "R4")
            if corpus and self._seed_matches_target(corpus):
                print(f"  [R4] Semantic seed corpus ready: {corpus}")
                self._add_seed_corpus(corpus)
            elif corpus:
                print(f"  [R4] Rejecting inconsistent semantic corpus")

        print(f"  [R4] Distance stagnant at {current_dist}, building roadmap...")

        roadmap = extract_distance_roadmap(
            dist_dir, target_func, current_dist,
            k2s_path=k2s_path if os.path.exists(k2s_path) else None,
            src_dir=src_dir if os.path.isdir(src_dir) else None,
            target_file=target_file,
        )

        # Log cross-file callers and actual callers if found
        if roadmap and roadmap.get("cross_file_callers"):
            callers = roadmap["cross_file_callers"]
            print(f"  [R4] Cross-file callers of {target_func}: "
                  f"{[(c['function'], c['distance']) for c in callers[:3]]}")
        if roadmap and roadmap.get("actual_callers"):
            print(f"  [R4] Actual callers of {target_func} (from source): "
                  f"{roadmap['actual_callers']}")

        snippets = ""
        rev_trace = ""
        if roadmap and roadmap.get("stepping_stones"):
            stones = roadmap["stepping_stones"]
            print(f"  [R4] Roadmap: {len(stones)} stepping stones, "
                  f"closest={stones[0]['function']}(dist={stones[0]['distance']}), "
                  f"total_in_range={roadmap['total_functions_in_range']}")
            snippets = read_stepping_stone_sources(src_dir, roadmap)
            if snippets:
                print(f"  [R4] Read {snippets.count('---') + 1} source snippets")
            # Reverse trace the bottleneck function (#2)
            bottleneck = stones[0]["function"]
            rev_trace = reverse_trace_bottleneck(
                src_dir, bottleneck,
                k2s_path=k2s_path if os.path.exists(k2s_path) else None,
            )
            if rev_trace:
                print(f"  [R4] Reverse trace for {bottleneck}:\n{rev_trace}")
        else:
            # No stepping stones with narrow threshold — retry with wide threshold
            # so we at least get source snippets for the LLM
            print(f"  [R4] No stepping stones at dist<{current_dist}, "
                  f"retrying with wide threshold...")
            wide_roadmap = extract_distance_roadmap(
                dist_dir, target_func, current_dist_min=99999,
                k2s_path=k2s_path if os.path.exists(k2s_path) else None,
                src_dir=src_dir if os.path.isdir(src_dir) else None,
                target_file=target_file,
            )
            if wide_roadmap and wide_roadmap.get("stepping_stones"):
                stones = wide_roadmap["stepping_stones"]
                print(f"  [R4] Wide roadmap: {len(stones)} stepping stones, "
                      f"closest={stones[0]['function']}(dist={stones[0]['distance']})")
                snippets = read_stepping_stone_sources(src_dir, wide_roadmap)
                if snippets:
                    print(f"  [R4] Read {snippets.count('---') + 1} source snippets "
                          f"(from wide roadmap)")
                # Use wide roadmap's stones for reverse trace too
                bottleneck = stones[0]["function"]
                rev_trace = reverse_trace_bottleneck(
                    src_dir, bottleneck,
                    k2s_path=k2s_path if os.path.exists(k2s_path) else None,
                )
                if rev_trace:
                    print(f"  [R4] Reverse trace for {bottleneck}:\n{rev_trace}")

            # Build a minimal roadmap for downstream use
            roadmap = {
                "target_function": target_func,
                "current_dist_min": current_dist,
                "stepping_stones": (wide_roadmap or {}).get("stepping_stones", []),
                "total_functions_in_range": 0,
            }

        # Always include target function + caller source as a fallback
        if not snippets and os.path.isdir(src_dir):
            from llm_enhance import _extract_caller_conditions
            print(f"  [R4] Reading target function source directly: {target_func}")
            # Read target function source
            try:
                result = subprocess.run(
                    ["grep", "-rn", f"\\b{target_func}\\b", "--include=*.c",
                     "-l", src_dir],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    src_file = result.stdout.strip().split("\n")[0]
                    result2 = subprocess.run(
                        ["grep", "-n", f"\\b{target_func}\\b", src_file],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result2.stdout.strip():
                        lineno = int(result2.stdout.strip().split("\n")[0].split(":")[0])
                        with open(src_file) as f:
                            lines = f.readlines()
                        start = max(0, lineno - 3)
                        end = min(len(lines), lineno + 50)
                        rel_path = os.path.relpath(src_file, src_dir)
                        snippets = f"// TARGET FUNCTION: {rel_path}:{lineno}\n"
                        snippets += "".join(lines[start:end])
                        print(f"  [R4] Read target function source: {rel_path}:{lineno}")
            except Exception as e:
                print(f"  [R4] Failed to read target source: {e}")

            # Also get caller conditions for the target function
            caller_conds = _extract_caller_conditions(src_dir, target_func, max_callers=3)
            if caller_conds:
                cond_text = "\n// CALLER CONDITIONS (what must be true to reach "
                cond_text += f"{target_func}):\n"
                for cc in caller_conds:
                    if cc["conditions"]:
                        cond_text += f"// caller: {cc['caller_file']}:{cc['caller_line']}\n"
                        cond_text += "\n".join(cc["conditions"]) + "\n---\n"
                snippets += cond_text
                print(f"  [R4] Found {len(caller_conds)} caller condition blocks")

        # Read source of actual callers discovered from kernel source grep
        # This catches callers in different files (e.g., tbf_change calling fifo_set_limit)
        if roadmap and roadmap.get("actual_callers") and os.path.isdir(src_dir):
            for caller_fn in roadmap["actual_callers"]:
                if caller_fn in (snippets or ""):
                    continue  # already included
                try:
                    result = subprocess.run(
                        ["grep", "-rn", f"\\b{caller_fn}\\b", "--include=*.c",
                         "-l", src_dir],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.stdout.strip():
                        for src_file in result.stdout.strip().split("\n")[:2]:
                            result2 = subprocess.run(
                                ["grep", "-n", f"\\b{caller_fn}\\b", src_file],
                                capture_output=True, text=True, timeout=5,
                            )
                            if result2.stdout.strip():
                                lineno = int(result2.stdout.strip().split("\n")[0].split(":")[0])
                                with open(src_file) as f:
                                    lines = f.readlines()
                                start = max(0, lineno - 3)
                                end = min(len(lines), lineno + 60)
                                rel_path = os.path.relpath(src_file, src_dir)
                                snippets = (snippets or "") + (
                                    f"\n// ACTUAL CALLER OF {target_func}: "
                                    f"{caller_fn} in {rel_path}:{lineno}\n"
                                    + "".join(lines[start:end]) + "\n---\n"
                                )
                                print(f"  [R4] Read actual caller source: {caller_fn} "
                                      f"in {rel_path}:{lineno}")
                                break
                except Exception as e:
                    print(f"  [R4] Failed to read caller {caller_fn}: {e}")

        # ── Inject semantic pipeline's call chain into snippets ────────
        semantic_plan = getattr(self, "last_semantic_plan", None) or {}
        sem_chain = semantic_plan.get("call_chain") or []
        sem_predicates = semantic_plan.get("branch_conditions") or []
        sem_prerequisites = semantic_plan.get("prerequisite_sequence") or []
        semantic_context = ""
        if sem_chain and len(sem_chain) >= 2:
            chain_text = " → ".join(
                f"{c['function']}({c.get('file', '?')})" for c in sem_chain
            )
            semantic_context += f"\nSEMANTIC CALL CHAIN (verified by static analysis):\n  {chain_text}\n"
            # Read caller function source from chain (the function that calls target)
            caller = sem_chain[-2]  # second to last = direct caller of target
            caller_func = caller.get("function", "")
            caller_file = caller.get("file", "")
            if caller_func and caller_func not in (snippets or ""):
                # Try to read caller source
                try:
                    caller_src_path = None
                    if caller_file and os.path.isdir(src_dir):
                        candidate = os.path.join(src_dir, caller_file)
                        if os.path.isfile(candidate):
                            caller_src_path = candidate
                        else:
                            result = subprocess.run(
                                ["grep", "-rn", f"\\b{caller_func}\\b", "--include=*.c",
                                 "-l", src_dir],
                                capture_output=True, text=True, timeout=10,
                            )
                            if result.stdout.strip():
                                caller_src_path = result.stdout.strip().split("\n")[0]
                    if caller_src_path:
                        result2 = subprocess.run(
                            ["grep", "-n", f"\\b{caller_func}\\b", caller_src_path],
                            capture_output=True, text=True, timeout=5,
                        )
                        if result2.stdout.strip():
                            lineno = int(result2.stdout.strip().split("\n")[0].split(":")[0])
                            with open(caller_src_path) as f:
                                lines = f.readlines()
                            start = max(0, lineno - 3)
                            end = min(len(lines), lineno + 60)
                            rel = os.path.relpath(caller_src_path, src_dir) if src_dir else caller_src_path
                            caller_source = "".join(lines[start:end])
                            snippets = (snippets or "") + f"\n// CALLER FUNCTION (from semantic chain): {rel}:{lineno}\n{caller_source}\n---\n"
                            print(f"  [R4] Injected caller source from semantic chain: {caller_func} in {rel}")
                except Exception as e:
                    print(f"  [R4] Failed to read semantic caller source: {e}")

            if sem_predicates:
                semantic_context += "BRANCH CONDITIONS gating target:\n"
                for p in sem_predicates[:8]:
                    semantic_context += f"  · if ({p.get('expression', '?')})\n"
            if sem_prerequisites:
                semantic_context += "PREREQUISITES (setup steps needed):\n"
                for pr in sem_prerequisites[:8]:
                    semantic_context += f"  · {pr.get('action', '?')}: {pr.get('object', '?')} in {pr.get('source_function', '?')}\n"
            if semantic_context:
                print(f"  [R4] Injected semantic context: chain={len(sem_chain)} funcs, "
                      f"{len(sem_predicates)} predicates")

        # Extract closest program from corpus (#1)
        closest_prog, closest_dist = None, None
        sub_workdir = getattr(self, "_last_sub_workdir", None)
        detail_corpus = getattr(self, "_last_detail_corpus", None)
        if sub_workdir:
            rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            Cfg = rcfg.apply_to_legacy_config()
            syz_db = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
            closest_prog, closest_dist = extract_closest_program(
                sub_workdir, syz_db, detail_corpus_path=detail_corpus,
            )
            if closest_prog:
                print(f"  [R4] Closest corpus program (dist={closest_dist}):\n"
                      f"    {closest_prog[:200]}...")

        # Classify R4 sub-cause (#6)
        health = getattr(self, "_last_health", {})
        r4_cause, r4_evidence = classify_r4_cause(
            health, roadmap, self.dist_history, current_callfile,
        )
        # Override R4-ARG → R4-STATE when semantic chain shows multi-step dependency
        if r4_cause == "R4-ARG" and sem_chain and len(sem_chain) >= 3:
            r4_cause = "R4-STATE"
            r4_evidence.append(f"overridden from R4-ARG: semantic chain has {len(sem_chain)} steps, "
                               f"requires multi-step setup")
            print(f"  [R4] Reclassified R4-ARG → R4-STATE (semantic chain depth={len(sem_chain)})")

        print(f"  [R4] Sub-classification: {r4_cause}")
        for ev in r4_evidence:
            print(f"    · {ev}")

        # Dispatch based on R4 sub-cause
        new_entries = []
        # ZDAY targets carry no fix_commit (the bug hasn't been fixed upstream)
        # but DO carry origin_commit — the commit that introduced the suspect
        # code. For VULN HINT / patch-diff extraction we fall back to it so
        # ZDAY runs get the same LLM context that CVE runs get.
        fix_commit = (self.target.get("commit") or self.target.get("fix_commit")
                      or self.origin_commit or self.target.get("origin_commit")
                      or "")

        if r4_cause == "R4-WRONG":
            # Wrong syscall family — must query LLM for completely new syscalls
            print(f"  [R4-WRONG] Querying LLM for different syscall family...")
            new_entries = llm_enhance_callfile_for_distance(
                current_callfile, roadmap,
                target_func, target_file,
                source_snippets=snippets,
                closest_program=closest_prog, closest_dist=closest_dist,
                reverse_trace=rev_trace,
                src_root=src_dir if os.path.isdir(src_dir) else None,
                fix_commit=fix_commit or None,
                k2s_path=k2s_path if os.path.isfile(k2s_path) else None,
            )
        elif r4_cause == "R4-ARG":
            # Right subsystem but wrong arguments — re-inject closest corpus programs
            # as seeds for the next round, plus generate new LLM seeds
            print(f"  [R4-ARG] Close to target, re-injecting closest corpus programs...")
            if sub_workdir:
                dist_threshold = current_dist * 2 if current_dist else None
                rcfg_r4 = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
                Cfg_r4 = rcfg_r4.apply_to_legacy_config()
                syz_db_bin = os.path.join(Cfg_r4.FuzzerDir, "bin", "syz-db")
                target_profile = _build_target_seed_profile(
                    roadmap, target_func, target_file, snippets,
                )
                print(
                    "  [R4-ARG] Reinjection profile:"
                    f" type={target_profile.get('target_type')}"
                    f" kind={target_profile.get('target_kind')}"
                    f" candidates={[(k, s) for k, s, _ in target_profile.get('kind_candidates', [])[:4]]}"
                )
                closest_progs = extract_closest_programs(
                    sub_workdir, syz_db_bin,
                    detail_corpus_path=detail_corpus,
                    max_programs=20, dist_threshold=dist_threshold,
                    target_profile=target_profile,
                    min_shape_score=5,
                )
                if closest_progs:
                    print(f"  [R4-ARG] Found {len(closest_progs)} closest programs "
                          f"(dist range: {closest_progs[0][1]}-{closest_progs[-1][1]})")
                    seed_dir = self.layout.fuzzres_xidx(ci, self.xi)
                    os.makedirs(seed_dir, exist_ok=True)
                    reinject_path = os.path.join(seed_dir, "corpus_reinject.db")
                    packed = pack_programs_to_corpus(
                        [p[0] for p in closest_progs], syz_db_bin, reinject_path,
                    )
                    if packed:
                        print(f"  [R4-ARG] Re-injected corpus: {packed}")
                        self._add_seed_corpus(packed)
        elif r4_cause == "R4-STATE":
            # Right syscalls but missing prerequisites — query for setup sequences
            print(f"  [R4-STATE] Missing prerequisites, querying LLM for setup sequences...")
            new_entries = llm_enhance_callfile_for_distance(
                current_callfile, roadmap,
                target_func, target_file,
                source_snippets=snippets,
                closest_program=closest_prog, closest_dist=closest_dist,
                reverse_trace=rev_trace,
                src_root=src_dir if os.path.isdir(src_dir) else None,
                fix_commit=fix_commit or None,
                k2s_path=k2s_path if os.path.isfile(k2s_path) else None,
            )

        if new_entries:
            filtered = []
            for entry in new_entries:
                target = entry.get("Target", "")
                related = [r for r in entry.get("Relate", []) if r and r != target]
                if not target:
                    continue
                if not self._allow_new_r4_target(target, current_callfile, roadmap):
                    continue
                filtered.append({"Target": target, "Relate": related})
            new_entries = filtered

        if not new_entries:
            print("  [R4] LLM returned no usable suggestions")
            new_entries = []
        else:
            print(f"  [R4] LLM suggested {len(new_entries)} syscall entries")

        # Merge semantic context into snippets so all downstream LLM calls see it
        if semantic_context:
            snippets = semantic_context + "\n" + (snippets or "")

        # ── dist >= 1000: try syzbot mining + iterative deepening ────────
        if current_dist and current_dist >= 1000:
            print(f"  [R4] dist={current_dist} >= 1000, trying syzbot mining + iterative deepening...")
            rcfg_deep = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            Cfg_deep = rcfg_deep.apply_to_legacy_config()
            syz_db_deep = os.path.join(Cfg_deep.FuzzerDir, "bin", "syz-db")

            # 1순위: syzbot reproducer mining
            try:
                syzbot_corpus = mine_seeds_for_target(
                    target_func, syz_db_deep,
                    self.layout.fuzzres_xidx(ci, self.xi),
                )
                if syzbot_corpus:
                    print(f"  [R4] syzbot seeds found: {syzbot_corpus}")
                    self._add_seed_corpus(syzbot_corpus)
            except Exception as e:
                print(f"  [R4] syzbot mining failed: {e}")

            # 2순위: VM iterative deepening
            try:
                deepened_corpus = iterative_deepen(
                    target_function=target_func,
                    target_file=target_file,
                    layout=self.layout,
                    ci=ci,
                    runner_config=rcfg_deep,
                    current_callfile=current_callfile,
                    source_snippets=snippets,
                    roadmap=roadmap,
                    syz_db_path=syz_db_deep,
                    max_iterations=4,
                    initial_seed=closest_prog,
                    vm_uptime=60,
                )
                if deepened_corpus:
                    print(f"  [R4] Iterative deepening produced: {deepened_corpus}")
                    self._add_seed_corpus(deepened_corpus)
            except Exception as e:
                print(f"  [R4] Iterative deepening failed: {e}")
                import traceback
                traceback.print_exc()

        # ── Also generate seed corpus via LLM ────────────────────────────
        print(f"  [R4] Generating LLM seed programs for next round...")
        if not hasattr(self, '_r4_syz_db_path'):
            rcfg2 = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            Cfg2 = rcfg2.apply_to_legacy_config()
            syz_db_path = os.path.join(Cfg2.FuzzerDir, "bin", "syz-db")
        else:
            syz_db_path = self._r4_syz_db_path
        seed_out_dir = self.layout.fuzzres_xidx(ci, self.xi)

        # 1차: 기존 llm_generate_seed_program (빠름)
        seed_db = llm_generate_seed_program(
            roadmap=roadmap,
            source_snippets=snippets,
            target_function=target_func,
            target_file=target_file,
            current_callfile=current_callfile,
            syz_db_path=syz_db_path,
            output_dir=seed_out_dir,
            closest_program=closest_prog, closest_dist=closest_dist,
            reverse_trace=rev_trace,
            syz_resource_chain=self._build_syz_resource_chain(current_callfile),
            agent_context=self._agent_context_for_prompt(),
            src_root=self.layout.src(ci),
            commit_sha=self.origin_commit or self.fix_commit_sha,
        )
        if seed_db and self._seed_matches_target(seed_db):
            print(f"  [R4] Seed corpus generated: {seed_db}")
            self._add_seed_corpus(seed_db)
        elif seed_db:
            print(f"  [R4] Rejecting inconsistent seed corpus: {seed_db}")
            seed_db = None
        else:
            print(f"  [R4] Seed corpus generation failed")
            seed_db = None

        # 2차: codegen — 기존 seed 없거나, 라운드 2+에서 dist가 안 줄었으면 시도
        dist_not_improving = (round_num >= 2 and self.best_dist_min_ever == current_dist)
        if not seed_db or dist_not_improving:
            print(f"  [R4] Trying codegen fallback (LLM → Python → execute)...")
            codegen_db = llm_generate_seed_via_codegen(
                roadmap=roadmap,
                source_snippets=snippets,
                target_function=target_func,
                target_file=target_file,
                current_callfile=current_callfile,
                syz_db_path=syz_db_path,
                output_dir=seed_out_dir,
                closest_program=closest_prog, closest_dist=closest_dist,
                reverse_trace=rev_trace,
                syz_resource_chain=self._build_syz_resource_chain(current_callfile),
                current_dist=current_dist,
                semantic_context=semantic_context,
                agent_context=self._agent_context_for_prompt(),
            )
            if codegen_db and self._seed_matches_target(codegen_db):
                print(f"  [R4] Codegen seed corpus generated: {codegen_db}")
                self._add_seed_corpus(codegen_db)
            elif codegen_db:
                print(f"  [R4] Rejecting inconsistent codegen corpus: {codegen_db}")
            else:
                print(f"  [R4] Codegen also failed, continuing without seed")

        # dist < 100: boost timeout to give mutation more time on close programs
        if current_dist and current_dist < 100 and self.dist_stall_timeout < 1800:
            print(f"  [R4] dist={current_dist} < 100, boosting dist_stall_timeout "
                  f"{self.dist_stall_timeout} → 1800s")
            self.dist_stall_timeout = 1800

        if not new_entries:
            return None

        return [{"Target": e["Target"], "Relate": e.get("Relate", [])}
                for e in new_entries]

    # ── Trigger-condition enhancement (dist=0, no crash) ─────────────────

    def _check_d0_path_quality(self, closest_programs) -> bool:
        """Return True if dist=0 programs contain CVE-relevant syscalls (real D=0).

        Returns False when the target function is trivially reachable by any
        syscall, indicating a 'fake D=0' where the callfile is misspecified.

        Matching strategy: keep the full variant (e.g. ``sendmsg$nl_netfilter``)
        whenever the callfile entry uses one. Stripping to the base
        (``sendmsg``) and then dropping it via ``_GENERIC_BASE_CALLS`` would
        leave the relevant set empty for every netfilter/packet/route CVE,
        which made this check vacuously return True.
        """
        if not closest_programs:
            return False
        callfile = self._load_current_callfile_entries()
        relevant = set()

        def _add_if_specific(name):
            if not name:
                return
            if "$" in name:
                relevant.add(name)              # variant is inherently specific
            elif name not in _GENERIC_BASE_CALLS:
                relevant.add(name)              # base is non-generic — keep it

        for entry in callfile:
            _add_if_specific(entry.get("Target", ""))
            for r in entry.get("Relate", []):
                _add_if_specific(r)

        if not relevant:
            # Callfile has nothing specific to check against → cannot trust D=0.
            print("  [d0-quality] relevant=∅ (callfile has no non-generic syscalls)")
            return False

        hit = sum(
            1 for prog_text, _ in closest_programs
            if any(sc in prog_text for sc in relevant)
        )
        ratio = hit / len(closest_programs)
        print(f"  [d0-quality] relevant={sorted(relevant)}  hit={hit}/{len(closest_programs)}  ratio={ratio:.2f}")
        return ratio >= 0.3

    def _validate_and_fix_callfile_semantics(self, round_num):
        """Call LLM semantic validator; overwrite callfile if it returns a fix."""
        ci = self.ci
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        src_root = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        fix_commit = (self.fix_commit_sha or self.target.get("commit")
                      or self.origin_commit or self.target.get("origin_commit")
                      or "")

        print(f"\n  [semantic-validator] Checking callfile semantics for {target_func} ...")
        current_callfile = self._load_current_callfile_entries()
        result = llm_validate_callfile_semantics(
            current_callfile,
            target_func, target_file,
            src_root=src_root if os.path.isdir(src_root) else None,
            fix_commit=fix_commit or None,
            k2s_path=k2s_path if os.path.isfile(k2s_path) else None,
            cve_kind=self.cve_kind or None,
            cve_subject=self.cve_subject or None,
        )
        if not result:
            print("  [semantic-validator] LLM returned no result")
            return

        if result.get("valid"):
            print("  [semantic-validator] Callfile is semantically valid")
            return

        issues = result.get("issues", [])
        print(f"  [semantic-validator] Issues found: {issues}")

        fixed = result.get("fixed_entries")
        if not fixed:
            print("  [semantic-validator] No fix suggested by LLM")
            return

        callfile_path = self.layout.callfile(ci, self.xi)
        backup = callfile_path + f".semantic_backup_r{round_num}"
        shutil.copyfile(callfile_path, backup)
        with open(callfile_path, "w") as f:
            json.dump(fixed, f, indent="\t")
        self.target_call_names = self._load_current_call_targets()
        self.fake_d0_count += 1
        print(f"  [semantic-validator] Callfile rewritten ({len(fixed)} entries). Backup: {backup}")

    def _run_trigger_condition_enhancement(self, round_num):
        """Ask LLM to analyse trigger conditions when dist=0 but no crash yet."""
        ci = self.ci
        self._sync_target_metadata()
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        src_root = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        # ZDAY targets carry no fix_commit (the bug hasn't been fixed upstream)
        # but DO carry origin_commit — the commit that introduced the suspect
        # code. For VULN HINT / patch-diff extraction we fall back to it so
        # ZDAY runs get the same LLM context that CVE runs get.
        fix_commit = (self.target.get("commit") or self.target.get("fix_commit")
                      or self.origin_commit or self.target.get("origin_commit")
                      or "")
        callfile_path = self.layout.callfile(ci, self.xi)

        print(
            f"\n  [trigger] dist=0 for {self.dist0_no_crash_rounds} consecutive rounds "
            f"— analysing trigger conditions for {target_func}"
        )

        with open(callfile_path) as f:
            current_callfile = json.load(f)

        # Collect programs that reached dist=0 from the last sub_workdir
        closest_programs = []
        sub_workdir = getattr(self, "_last_sub_workdir", None)
        detail_corpus = getattr(self, "_last_detail_corpus", None)
        if sub_workdir:
            rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            Cfg = rcfg.apply_to_legacy_config()
            syz_db_bin = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
            if not os.path.exists(syz_db_bin):
                import shutil as _sh
                syz_db_bin = _sh.which("syz-db") or ""
            if syz_db_bin:
                closest_programs = extract_closest_programs(
                    sub_workdir, syz_db_bin,
                    detail_corpus_path=detail_corpus,
                    max_programs=5, dist_threshold=0,
                )

        # ── D=0 path quality check ─────────────────────────────────────
        # If most dist=0 programs don't contain CVE-relevant syscalls,
        # the callfile is misspecified (fake D=0). Fix the callfile instead
        # of analysing trigger conditions.
        if not self._check_d0_path_quality(closest_programs):
            print(f"  [trigger] Fake D=0 detected — running semantic validator instead")
            self._validate_and_fix_callfile_semantics(round_num)
            self.dist0_no_crash_rounds = 0
            return

        new_entries = llm_enhance_for_trigger_condition(
            current_callfile=current_callfile,
            target_function=target_func,
            target_file=target_file,
            src_root=src_root if os.path.isdir(src_root) else None,
            fix_commit=fix_commit or None,
            k2s_path=k2s_path if os.path.isfile(k2s_path) else None,
            closest_programs=closest_programs or None,
            dist0_rounds=self.dist0_no_crash_rounds,
        )

        if not new_entries:
            print("  [trigger] LLM returned no new entries")
            return

        # Merge into callfile (same logic as _enhance_callfile)
        backup = callfile_path + f".trigger_round{round_num}"
        shutil.copyfile(callfile_path, backup)
        merged = list(current_callfile)
        merged_by_target = {e["Target"]: e for e in merged if e.get("Target")}
        added, updated = [], []
        for entry in new_entries:
            tgt = entry.get("Target")
            if not tgt:
                continue
            if tgt not in merged_by_target:
                merged.append(entry)
                merged_by_target[tgt] = entry
                added.append(entry)
            else:
                existing = merged_by_target[tgt]
                before = list(existing.get("Relate", []))
                seen = set(before)
                new_relate = list(before)
                for r in entry.get("Relate", []):
                    if r and r != tgt and r not in seen:
                        new_relate.append(r)
                        seen.add(r)
                if new_relate != before:
                    existing["Relate"] = new_relate
                    updated.append({"Target": tgt, "Before": before, "After": new_relate})

        if added:
            print(f"  [trigger] Adding {len(added)} new entries:")
            for e in added:
                print(f"    + {e['Target']}  relate={e.get('Relate', [])}")
        if updated:
            print(f"  [trigger] Updated {len(updated)} existing entry/entries:")
            for e in updated:
                print(f"    ~ {e['Target']}  relate={e['After']}")
        if not added and not updated:
            print("  [trigger] No new entries (all duplicates of existing)")
            return

        with open(callfile_path, "w") as f:
            json.dump(merged, f, indent="\t")
        self.target_call_names = self._load_current_call_targets()
        # Reset counter so we don't re-trigger immediately next round
        self.dist0_no_crash_rounds = 0

    # ── Summary ──────────────────────────────────────────────────────────

    def _print_summary(self):
        print(f"\n{'=' * 60}")
        print("  AGENT LOOP COMPLETE")
        callfile_path = self.layout.callfile(self.ci, self.xi)
        print(f"  Final callfile: {callfile_path}")
        fuzzres = self.layout.fuzzres_xidx(self.ci, self.xi)
        print(f"  Results: {fuzzres}")
        print(f"{'=' * 60}")
