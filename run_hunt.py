#!/usr/bin/env python3
"""
General-purpose SyzDirect CVE hunt runner.

Usage:
  # Dataset mode — run original SyzDirect pipeline from dataset.xlsx:
  python3 run_hunt.py dataset -dataset dataset.xlsx -j 8 \\
      prepare_for_manual_instrument compile_kernel_bitcode \\
      analyze_kernel_syscall extract_syscall_entry \\
      instrument_kernel_with_distance fuzz

  # New CVE — CVE number only (auto-resolves commit/function/file):
  python3 run_hunt.py new --cve CVE-2025-XXXXX

  # New CVE — with manual overrides:
  python3 run_hunt.py new --cve CVE-2025-XXXXX --commit abc123 \\
      --function vuln_func --file net/core/sock.c -j 8

  # Pre-built targets — fuzz only:
  python3 run_hunt.py fuzz [--targets 0 3 5]
"""

import argparse
import os
import sys

from case_registry import select_prebuilt_targets
from paths import HUNT_MODES, PIPELINE_STAGES, WorkdirLayout
from pipeline_dataset import DatasetPipeline
from pipeline_new_cve import NewCVEPipeline, launch_fuzzing, setup_prebuilt
from agent_loop import AgentLoop


DATASET_ACTION_NAMES = list(DatasetPipeline.ACTIONS.keys())


def clean_dataset_value(value, default=""):
    if value is None:
        return default
    try:
        if value != value:
            return default
    except TypeError:
        pass
    return value


def add_common_args(parser):
    parser.add_argument("-j", type=int, default=4, help="CPU cores (default: 4)")
    parser.add_argument("-uptime", type=int, default=24, help="Fuzzing hours (default: 24)")
    parser.add_argument("-fuzz-rounds", type=int, default=1, dest="fuzz_rounds")
    parser.add_argument("-workdir", default="./workdir")


def add_agent_args(parser):
    parser.add_argument("--agent-rounds", type=int, default=0, dest="agent_rounds",
                        help="Agent loop iterations (0=off, >0=auto triage+enhance)")
    parser.add_argument("--agent-window", type=int, default=300, dest="agent_window",
                        help="Health check window in seconds (default: 300)")
    parser.add_argument("--agent-uptime", type=int, default=None, dest="agent_uptime",
                        help="Uptime per agent round in hours (default: same as -uptime)")
    parser.add_argument("--hunt-mode", default="hybrid", choices=HUNT_MODES,
                        dest="hunt_mode",
                        help="repro=target reproduction, harvest=incidental crash hunting, hybrid=both")
    parser.add_argument("--known-crash-db", default=None, dest="known_crash_db",
                        help="Optional JSON file with known crash signatures to filter 1-days")
    parser.add_argument("--stall-timeout", type=int, default=1800, dest="stall_timeout",
                        help="Seconds of zero coverage growth before early round termination "
                             "(default: 1800=30min, 0=disabled)")
    parser.add_argument("--dist-stall-timeout", type=int, default=600,
                        dest="dist_stall_timeout",
                        help="Seconds of no dist_min improvement before early round termination "
                             "(default: 600=10min, 0=disabled)")
    parser.add_argument("--proactive-seed", action="store_true", default=False,
                        dest="proactive_seed",
                        help="LLM generates seed corpus from static dist analysis before Round 1")


def build_parser():
    parser = argparse.ArgumentParser(
        description="SyzDirect CVE Hunt Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Dataset mode (like original Main.py):
  python3 run_hunt.py dataset -dataset dataset_hunt.xlsx -j 8 \\
      prepare_for_manual_instrument compile_kernel_bitcode \\
      analyze_kernel_syscall extract_syscall_entry \\
      instrument_kernel_with_distance fuzz

  # New CVE — full pipeline:
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c -j 8

  # Resume from a specific stage:
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c --from-stage distance

  # Pre-built targets — fuzz only:
  python3 run_hunt.py fuzz --targets 0 3 5 -uptime 12
  python3 run_hunt.py fuzz

  # Agent loop — fuzz + auto triage/enhance (3 rounds, 6h each):
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c \\
      --agent-rounds 3 --agent-uptime 6
  python3 run_hunt.py fuzz --targets 0 --agent-rounds 5

Available dataset actions:
  {', '.join(DATASET_ACTION_NAMES)}
""",
    )
    sub = parser.add_subparsers(dest="mode")

    # dataset mode
    p_ds = sub.add_parser("dataset", help="Run pipeline from dataset.xlsx (like Main.py)")
    add_common_args(p_ds)
    p_ds.add_argument("actions", nargs="+", choices=DATASET_ACTION_NAMES,
                       metavar="ACTION", help="Pipeline actions to run")
    p_ds.add_argument("-dataset", default="dataset.xlsx",
                       help="Path to dataset .xlsx file (default: dataset.xlsx)")
    p_ds.add_argument("-linux-repo-template", dest="linux_template", default=None,
                       help="Local linux repo to clone from (saves time)")

    # new CVE mode
    p_new = sub.add_parser("new", help="Full pipeline for a new CVE")
    add_common_args(p_new)
    p_new.add_argument("--cve", required=True)
    p_new.add_argument("--commit", default=None,
                        help="Kernel commit to check out (auto-resolved from CVE if omitted)")
    p_new.add_argument("--function", default=None,
                        help="Target function (auto-resolved from CVE patch if omitted)")
    p_new.add_argument("--file", default=None,
                        help="Target source file (auto-resolved from CVE patch if omitted)")
    p_new.add_argument("--verify-patch", action="store_true", dest="verify_patch",
                        help="Patch verification mode: fuzz the FIXED kernel to confirm bug is gone")
    p_new.add_argument("--syscalls", default="")
    p_new.add_argument("--config", default=None)
    p_new.add_argument("--linux-template", default=None)
    p_new.add_argument("--from-stage", default=None, dest="from_stage",
                        choices=PIPELINE_STAGES)

    # fuzz-only mode
    p_fuzz = sub.add_parser("fuzz", help="Fuzz pre-built targets only")
    add_common_args(p_fuzz)
    p_fuzz.add_argument("--targets", nargs="*", type=int, default=None)

    for p in [p_ds, p_new, p_fuzz]:
        add_agent_args(p)

    p_ds.set_defaults(handler=run_dataset_mode)
    p_new.set_defaults(handler=run_new_mode)
    p_fuzz.set_defaults(handler=run_fuzz_mode)

    return parser


def build_agent_loop(layout, target_info, args):
    return AgentLoop(
        layout=layout,
        target_info=target_info,
        max_rounds=args.agent_rounds,
        window_seconds=args.agent_window,
        uptime_per_round=args.agent_uptime or args.uptime,
        cpus=args.j,
        fuzz_rounds=args.fuzz_rounds,
        hunt_mode=args.hunt_mode,
        known_crash_db=args.known_crash_db,
        stall_timeout=args.stall_timeout,
        dist_stall_timeout=args.dist_stall_timeout,
        proactive_seed=args.proactive_seed,
    )


def run_dataset_agent_loop(pipeline, args):
    if getattr(args, "agent_rounds", 0) <= 0 or "fuzz" not in args.actions:
        return

    print(f"\n{'=' * 60}")
    print(f"Agent Loop: {args.agent_rounds} rounds per case")
    print(f"{'=' * 60}\n")
    for dp in pipeline.datapoints:
        ci = dp["idx"]
        target_syscall = clean_dataset_value(dp.get("recommend syscall"), [])
        if isinstance(target_syscall, str):
            target_syscall = [s.strip() for s in target_syscall.split(",") if s.strip()]
        related = [s for s in target_syscall[1:] if s]
        primary = target_syscall[0] if target_syscall else ""
        target_info = {
            "idx": ci,
            "name": clean_dataset_value(dp.get("repro bug title"), f"case_{ci}"),
            "commit": clean_dataset_value(dp.get("kernel commit")),
            "function": clean_dataset_value(dp.get("function")),
            "func_path": clean_dataset_value(dp.get("file_path")),
        }
        if primary:
            target_info["syscalls"] = [{"Target": primary, "Relate": related}]
        build_agent_loop(pipeline.layout, target_info, args).run()


def run_dataset_mode(args):
    pipeline = DatasetPipeline(args)
    pipeline.run()
    run_dataset_agent_loop(pipeline, args)


def resolve_cve_args(args):
    if all([args.commit, args.function, args.file]):
        return

    from cve_resolver import CVEResolver, CVEResolveError
    try:
        resolved = CVEResolver(args.cve).resolve()
        if getattr(args, "verify_patch", False):
            args.commit = args.commit or resolved["fix_commit"]
            mode_label = "PATCH VERIFICATION (post-fix)"
        else:
            args.commit = args.commit or resolved["commit"]
            mode_label = "1-DAY REPRODUCTION (pre-fix)"
        args.function = args.function or resolved["function"]
        args.file = args.file or resolved["file"]
        print(f"\n[CVE Resolver] Auto-resolved from {args.cve}:")
        print(f"  mode        : {mode_label}")
        print(f"  fix commit  : {resolved['fix_commit']}")
        print(f"  checkout    : {args.commit}")
        print(f"  function    : {args.function}")
        print(f"  file        : {args.file}")
        print()
    except CVEResolveError as e:
        sys.exit(f"ERROR: CVE auto-resolve failed: {e}")


def run_new_mode(args):
    resolve_cve_args(args)
    NewCVEPipeline(args).run(args.from_stage)


def run_fuzz_mode(args):
    layout = WorkdirLayout(args.workdir)
    os.makedirs(layout.root, exist_ok=True)

    try:
        targets = select_prebuilt_targets(args.targets)
    except KeyError as e:
        sys.exit(f"ERROR: {e}")

    print(f"Targets: {[t['name'] for t in targets]}")
    setup_prebuilt(layout, targets, hunt_mode=args.hunt_mode)

    if args.agent_rounds > 0:
        for target in targets:
            build_agent_loop(layout, target, args).run()
    else:
        launch_fuzzing(layout, args.j, args.uptime, args.fuzz_rounds, targets)


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    args.handler(args)


if __name__ == "__main__":
    main()
