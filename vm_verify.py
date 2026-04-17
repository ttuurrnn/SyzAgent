"""
SyzDirect Runner — VM-based Seed Verification & Iterative Deepening.

Executes seed programs in a VM using short syz-manager runs, measures
which functions are reached, and feeds coverage feedback to the LLM
to iteratively refine seeds — one callgraph hop at a time.
"""

import copy as _copy
import json
import os
import shutil
import subprocess
import tempfile
import time

from Fuzz import _alloc_free_tcp_port, runFuzzer, _parse_stats_line
from llm_enhance import (
    _parse_detail_corpus,
    extract_distance_roadmap,
    _extract_caller_conditions,
    _call_llm,
    pack_programs_to_corpus,
    llm_generate_seed_via_codegen,
)

import Config


# ---------------------------------------------------------------------------
# Seed execution in VM
# ---------------------------------------------------------------------------

def verify_seed_in_vm(seed_corpus_path: str, layout, ci: int,
                      runner_config, uptime_seconds: int = 60) -> dict:
    """Execute seeds in a short syz-manager run and measure distance.

    Uses a very short uptime and procs=1 to minimize mutation — we want
    to measure what the seed itself achieves, not what random mutation finds.

    Args:
        seed_corpus_path: path to corpus.db with seed programs.
        layout: WorkdirLayout instance.
        ci: case index.
        runner_config: RunnerConfig for this case.
        uptime_seconds: VM uptime in seconds (default 60).

    Returns:
        {
            "best_dist": int | None,
            "programs": [(text, dist), ...],  # from detailCorpus
            "metrics": dict | None,           # last metrics line
        }
    """
    if not seed_corpus_path or not os.path.exists(seed_corpus_path):
        return {"best_dist": None, "programs": [], "metrics": None}

    Cfg = runner_config.apply_to_legacy_config()
    template_config = Cfg.LoadJson(Cfg.TemplateConfigPath)
    assert template_config, "Failed to load fuzzing config template"
    template_config["sshkey"] = Cfg.KeyPath

    syzdirect_path = Cfg.FuzzerDir
    tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)
    if not tfmap:
        return {"best_dist": None, "programs": [], "metrics": None}

    xidx = list(tfmap.keys())[0]
    callfile = layout.callfile(ci, xidx)
    kernel_img = layout.bzimage(ci, xidx)

    # Create isolated workdir for verification
    verify_dir = tempfile.mkdtemp(prefix="vm_verify_")
    try:
        config = _copy.deepcopy(template_config)
        config["image"] = Cfg.CleanImageTemplatePath
        sub_workdir = os.path.join(verify_dir, "workdir")
        config["workdir"] = sub_workdir
        config["http"] = f"0.0.0.0:{_alloc_free_tcp_port()}"
        config["vm"]["kernel"] = kernel_img
        config["syzkaller"] = syzdirect_path
        config["hitindex"] = int(xidx)
        # Minimize mutation: use 1 proc
        config["procs"] = 1

        config_path = os.path.join(verify_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent="\t")

        fuzzer_file = os.path.join(syzdirect_path, "bin", "syz-manager")
        log_dir = os.path.join(verify_dir, "logs")

        # syz-manager's -uptime is in HOURS. Set to 1h max and use
        # stall timeouts (in seconds) for early termination.
        original_uptime = Config.FuzzUptime
        Config.FuzzUptime = 1  # 1 hour max

        try:
            print(f"  [vm-verify] Running seed in VM (max 1h, "
                  f"stall timeout={uptime_seconds}s)...")
            manager_log, metrics_jsonl = runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
                stall_timeout=uptime_seconds,
                dist_stall_timeout=uptime_seconds,
                seed_corpus=seed_corpus_path,
            )
        finally:
            Config.FuzzUptime = original_uptime

        # Parse results
        detail_corpus = os.path.join(sub_workdir, "detailCorpus.txt")
        programs = _parse_detail_corpus(detail_corpus)
        programs.sort(key=lambda x: x[1])

        best_dist = programs[0][1] if programs else None

        # Parse last metrics line
        last_metrics = None
        if metrics_jsonl and os.path.exists(metrics_jsonl):
            try:
                with open(metrics_jsonl) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            last_metrics = json.loads(line)
            except (OSError, json.JSONDecodeError):
                pass

        return {
            "best_dist": best_dist,
            "programs": programs[:50],  # keep top 50
            "metrics": last_metrics,
        }
    finally:
        shutil.rmtree(verify_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------

def analyze_reached_functions(programs: list, dist_dir: str,
                              target_function: str,
                              src_dir: str = None) -> dict:
    """Determine which functions were reached and what blocks the next hop.

    Combines detailCorpus distances with .dist file data to identify:
    - Which intermediate functions the seed reached
    - What the next function to penetrate is
    - What condition blocks entry to that function

    Args:
        programs: list of (program_text, distance) from detailCorpus.
        dist_dir: path to distance_xidx0/ directory with .dist files.
        target_function: name of the ultimate target function.
        src_dir: kernel source directory (for condition extraction).

    Returns:
        {
            "best_dist": int,
            "reached_functions": [{"function": str, "dist": int}, ...],
            "next_target": {"function": str, "dist": int} | None,
            "blocking_conditions": str,
        }
    """
    if not programs:
        return {
            "best_dist": None,
            "reached_functions": [],
            "next_target": None,
            "blocking_conditions": "",
        }

    best_dist = min(p[1] for p in programs)

    # Parse all .dist files to get function→dist mapping
    func_dists: dict[str, int] = {}
    if os.path.isdir(dist_dir):
        for fname in os.listdir(dist_dir):
            if not fname.endswith(".dist"):
                continue
            fpath = os.path.join(dist_dir, fname)
            try:
                with open(fpath) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        fn, _blk, dist_s = parts[0], parts[1], parts[2]
                        d = int(dist_s)
                        if fn not in func_dists or d < func_dists[fn]:
                            func_dists[fn] = d
            except (OSError, ValueError):
                continue

    # Functions the seed reached: those with dist >= best_dist (fuzzer got past them)
    # Functions NOT reached: those with dist < best_dist and > 0
    # "Next target": the function with dist just below best_dist
    all_funcs = sorted(func_dists.items(), key=lambda x: x[1], reverse=True)

    reached = []
    unreached = []
    for fn, d in all_funcs:
        if d >= best_dist and d > 0:
            reached.append({"function": fn, "dist": d})
        elif 0 < d < best_dist:
            unreached.append({"function": fn, "dist": d})

    # Next target: function with largest dist that's still below best_dist
    # (= the first function we need to penetrate to reduce dist)
    next_target = None
    if unreached:
        # Sort by dist descending — the highest dist below best_dist is the
        # immediate next barrier
        unreached.sort(key=lambda x: x["dist"], reverse=True)
        next_target = unreached[0]

    # Get blocking conditions for next target
    blocking_conditions = ""
    if next_target and src_dir and os.path.isdir(src_dir):
        try:
            conds = _extract_caller_conditions(
                src_dir, next_target["function"], max_callers=3,
            )
            if conds:
                parts = []
                for cc in conds:
                    if cc["conditions"]:
                        parts.append(
                            f"// Caller: {cc['caller_file']}:{cc['caller_line']}\n"
                            + "\n".join(cc["conditions"])
                        )
                blocking_conditions = "\n---\n".join(parts)
        except Exception:
            pass

    return {
        "best_dist": best_dist,
        "reached_functions": reached[:20],
        "next_target": next_target,
        "blocking_conditions": blocking_conditions,
    }


def build_deepening_feedback(analysis: dict, target_function: str,
                             iteration: int, src_dir: str = None) -> str:
    """Build LLM feedback text from coverage analysis.

    Tells the LLM exactly what was reached, what wasn't, and what
    condition needs to be satisfied to go one hop deeper.
    """
    best_dist = analysis.get("best_dist")
    reached = analysis.get("reached_functions", [])
    next_target = analysis.get("next_target")
    blocking = analysis.get("blocking_conditions", "")

    lines = [f"ITERATION {iteration} FEEDBACK (from VM execution of your seed):"]
    lines.append(f"  Current best distance: {best_dist}")
    lines.append(f"  Ultimate target: {target_function}")

    if reached:
        lines.append(f"\n  REACHED functions ({len(reached)}):")
        for r in reached[:10]:
            lines.append(f"    dist={r['dist']:>6}  {r['function']}")

    if next_target:
        lines.append(f"\n  NEXT BARRIER: {next_target['function']} (dist={next_target['dist']})")
        lines.append(f"  Your seed gets PAST the functions above but FAILS to enter {next_target['function']}.")

        if blocking:
            lines.append(f"\n  CONDITIONS blocking entry to {next_target['function']}:")
            lines.append(blocking)

        lines.append(f"\n  FIX YOUR SEED to satisfy the conditions above and enter {next_target['function']}.")
    else:
        lines.append(f"\n  No clear next barrier identified. Try a different syscall approach.")

    # If we have source, also read the next target function itself
    if next_target and src_dir and os.path.isdir(src_dir):
        try:
            result = subprocess.run(
                ["grep", "-rn", f"\\b{next_target['function']}\\b",
                 "--include=*.c", "-l", src_dir],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                src_file = result.stdout.strip().split("\n")[0]
                result2 = subprocess.run(
                    ["grep", "-n", f"\\b{next_target['function']}\\b", src_file],
                    capture_output=True, text=True, timeout=5,
                )
                if result2.stdout.strip():
                    lineno = int(result2.stdout.strip().split("\n")[0].split(":")[0])
                    with open(src_file) as f:
                        all_lines = f.readlines()
                    start = max(0, lineno - 3)
                    end = min(len(all_lines), lineno + 40)
                    rel = os.path.relpath(src_file, src_dir) if src_dir else src_file
                    lines.append(f"\n  SOURCE of {next_target['function']} ({rel}:{lineno}):")
                    lines.append("".join(all_lines[start:end]))
        except Exception:
            pass

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Iterative deepening main loop
# ---------------------------------------------------------------------------

def iterative_deepen(target_function: str, target_file: str,
                     layout, ci: int, runner_config,
                     current_callfile: list = None,
                     source_snippets: str = "",
                     roadmap: dict = None,
                     syz_db_path: str = None,
                     max_iterations: int = 5,
                     initial_seed: str = None,
                     vm_uptime: int = 60) -> str | None:
    """VM-based iterative deepening: generate → execute → analyze → refine.

    Instead of relying on fuzzer mutation (which destroys multi-step seeds),
    this loop has the LLM directly refine seeds based on execution feedback.
    Each iteration targets one callgraph hop deeper.

    Args:
        target_function: ultimate target function name.
        target_file: kernel source file containing target.
        layout: WorkdirLayout.
        ci: case index.
        runner_config: RunnerConfig.
        current_callfile: current syscall callfile entries.
        source_snippets: kernel source context for LLM.
        roadmap: distance roadmap dict.
        syz_db_path: path to syz-db binary.
        max_iterations: max refinement iterations.
        initial_seed: starting seed program text (optional).
        vm_uptime: seconds per VM verification run.

    Returns:
        Path to corpus.db with best seeds, or None.
    """
    print(f"  [deepen] Starting iterative deepening for {target_function}")
    print(f"  [deepen] Max iterations: {max_iterations}, VM uptime: {vm_uptime}s")

    dist_dir = layout.dist_dir(ci, 0)
    src_dir = layout.src(ci)

    # Resolve syz-db
    if not syz_db_path:
        Cfg = runner_config.apply_to_legacy_config()
        syz_db_path = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")

    output_dir = layout.fuzzres_xidx(ci)
    os.makedirs(output_dir, exist_ok=True)

    best_dist_ever = None
    best_corpus = None
    accumulated_feedback = ""
    no_improve_count = 0

    for iteration in range(1, max_iterations + 1):
        print(f"\n  [deepen] === Iteration {iteration}/{max_iterations} ===")

        # ── Generate seed ──────────────────────────────────────────────
        if iteration == 1 and initial_seed:
            # Use provided initial seed
            seed_programs = [initial_seed]
            seed_db = _pack_seed_programs(seed_programs, syz_db_path, output_dir,
                                          f"deepen_iter{iteration}")
        else:
            # Generate via codegen with accumulated feedback
            enhanced_snippets = source_snippets
            if accumulated_feedback:
                enhanced_snippets = accumulated_feedback + "\n\n" + (source_snippets or "")

            seed_db = llm_generate_seed_via_codegen(
                roadmap=roadmap or {},
                source_snippets=enhanced_snippets,
                target_function=target_function,
                target_file=target_file,
                current_callfile=current_callfile,
                syz_db_path=syz_db_path,
                output_dir=output_dir,
                current_dist=best_dist_ever,
                semantic_context=accumulated_feedback,
            )

        if not seed_db:
            print(f"  [deepen] Seed generation failed at iteration {iteration}")
            no_improve_count += 1
            if no_improve_count >= 2:
                break
            continue

        # ── Execute in VM ──────────────────────────────────────────────
        result = verify_seed_in_vm(
            seed_db, layout, ci, runner_config,
            uptime_seconds=vm_uptime,
        )

        current_dist = result.get("best_dist")
        programs = result.get("programs", [])
        print(f"  [deepen] VM result: best_dist={current_dist}, "
              f"programs_with_dist={len(programs)}")

        if current_dist is None:
            print(f"  [deepen] No distance data from VM run")
            no_improve_count += 1
            if no_improve_count >= 2:
                break
            continue

        # ── Check for success ──────────────────────────────────────────
        if current_dist == 0:
            print(f"  [deepen] TARGET REACHED at iteration {iteration}!")
            best_corpus = seed_db
            best_dist_ever = 0
            break

        # ── Track improvement ──────────────────────────────────────────
        improved = False
        if best_dist_ever is None or current_dist < best_dist_ever:
            improved = True
            print(f"  [deepen] Distance improved: {best_dist_ever} → {current_dist}")
            best_dist_ever = current_dist
            best_corpus = seed_db
            no_improve_count = 0
        else:
            no_improve_count += 1
            print(f"  [deepen] No improvement (best={best_dist_ever}, "
                  f"current={current_dist}, no_improve={no_improve_count}/3)")
            if no_improve_count >= 3:
                print(f"  [deepen] 3 iterations without improvement, stopping")
                break

        # ── Analyze coverage and build feedback ────────────────────────
        analysis = analyze_reached_functions(
            programs, dist_dir, target_function, src_dir=src_dir,
        )
        feedback = build_deepening_feedback(
            analysis, target_function, iteration, src_dir=src_dir,
        )
        accumulated_feedback = feedback  # latest feedback replaces (keeps context short)
        print(f"  [deepen] Next barrier: "
              f"{analysis.get('next_target', {}).get('function', 'unknown')}")

    # ── Return best corpus ─────────────────────────────────────────────
    if best_corpus:
        final_path = os.path.join(output_dir, f"deepened_seed_{target_function}.db")
        if best_corpus != final_path:
            shutil.copy2(best_corpus, final_path)
        print(f"  [deepen] Final best dist: {best_dist_ever}")
        print(f"  [deepen] Best corpus: {final_path}")
        return final_path
    else:
        print(f"  [deepen] No usable seeds produced")
        return None


def _pack_seed_programs(programs: list[str], syz_db_path: str,
                        output_dir: str, label: str) -> str | None:
    """Pack program text list into corpus.db."""
    prog_dir = tempfile.mkdtemp(prefix="syz_deepen_")
    try:
        for i, prog in enumerate(programs):
            with open(os.path.join(prog_dir, f"{i:04d}_{label}"), "w") as f:
                f.write(prog.strip() + "\n")

        os.makedirs(output_dir, exist_ok=True)
        corpus_db = os.path.join(output_dir, f"{label}.db")

        result = subprocess.run(
            [syz_db_path, "pack", prog_dir, corpus_db],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  [deepen] syz-db pack failed: {result.stderr[:200]}")
            return None
        return corpus_db
    finally:
        shutil.rmtree(prog_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI entry point for testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    print("vm_verify.py — VM-based seed verification and iterative deepening")
    print("This module is designed to be imported by agent_loop.py")
    print("Use: from vm_verify import verify_seed_in_vm, iterative_deepen")
