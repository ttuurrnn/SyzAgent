#!/usr/bin/env python3
"""
SyzAgent CLI

Runs the SyzDirect analysis pipeline and classifies failures to enhance templates.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "source"))

from syzagent.pipeline import SyzAgentPipeline


def parse_args():
    parser = argparse.ArgumentParser(
        prog="syzagent",
        description="SyzDirect-based Kernel Fuzzing Agent — Automated R1/R2/R3/R4 failure mitigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analysis + Template generation
  python -m syzagent --target target.json --kernel /path/to/linux

  # Triage fuzzing logs and enhance templates
  python -m syzagent --triage --log fuzz.log --templates templates.json

  # Full pipeline (Analyze → Distance → Template → Agent Loop)
  python -m syzagent --full --target target.json --kernel /path/to/linux

  # Run by dataset case ID
  python -m syzagent --case 54
        """,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--analyze",
        action="store_true",
        help="Run static analysis only (syscall identification + template generation)",
    )
    mode.add_argument(
        "--triage",
        action="store_true",
        help="Analyze fuzzing logs → classify R1/R2/R3/R4 failures + enhance templates",
    )
    mode.add_argument(
        "--full",
        action="store_true",
        help="Full pipeline: Analyze → Distance → Template → Agent Loop",
    )
    mode.add_argument(
        "--case",
        type=int,
        metavar="CASE_ID",
        help="Run SyzDirect dataset case by ID (e.g., --case 54)",
    )

    parser.add_argument("--target", metavar="JSON", help="Path to target.json")
    parser.add_argument("--kernel", metavar="DIR", help="Path to kernel source")
    parser.add_argument("--log", metavar="LOG", help="Fuzzing log file (for --triage)")
    parser.add_argument(
        "--templates", metavar="JSON", help="Template file (for --triage)"
    )
    parser.add_argument(
        "--output", metavar="DIR", default="syzagent_output", help="Output directory"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "syzdirect", "agent-loop"],
        default="agent-loop",
        help="Fuzzing mode (for --case, default: agent-loop)",
    )
    parser.add_argument(
        "--budget-hours",
        type=float,
        default=1.0,
        metavar="H",
        help="Fuzzing budget in hours (default: 1)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    pipeline = SyzAgentPipeline(args)

    if args.case is not None:
        pipeline.run_dataset_case()
    elif args.full:
        pipeline.run_full()
    elif args.analyze:
        pipeline.run_analyze()
    elif args.triage:
        pipeline.run_triage()


if __name__ == "__main__":
    main()
