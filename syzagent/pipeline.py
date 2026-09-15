#!/usr/bin/env python3
"""
SyzAgent Pipeline

Orchestrates analyze → distance → template → agent loop in sequence.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SOURCE = ROOT / "source"
sys.path.insert(0, str(SOURCE))


class SyzAgentPipeline:
    """SyzAgent full pipeline orchestrator"""

    def __init__(self, args):
        self.args = args
        self.output = Path(args.output)
        self.output.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 공개 진입점
    # ------------------------------------------------------------------

    def run_dataset_case(self):
        """--case: run_dataset_case.py wrapper"""
        case_id = self.args.case
        script = ROOT / "scripts" / "run_dataset_case.py"
        cmd = [
            sys.executable,
            str(script),
            "--case-id", str(case_id),
            "--dataset-kind", "known-bugs",
            "--mode", self.args.mode,
            "--budget-hours", str(self.args.budget_hours),
            "--output-root", str(self.output),
        ]
        print(f"[syzagent] Executing case {case_id}: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

    def run_analyze(self):
        """--analyze: Static analysis + Template generation"""
        target_file = self._require("--target", self.args.target)
        kernel_dir = self._require("--kernel", self.args.kernel)

        templates_out = self.output / "templates.json"
        distances_out = self.output / "distances.json"
        fuzz_out = self.output / "fuzz_templates"

        # 1. syscall analysis
        self._run_module(
            SOURCE / "analyzer" / "syscall_analyzer.py",
            ["--kernel", kernel_dir, "--target", target_file, "--output", str(templates_out)],
        )

        # 2. distance calculation
        target = self._load_json(target_file)
        self._write_json(self.output / "target.json", target)
        self._run_module(
            SOURCE / "distance" / "distance_calculator.py",
            [
                "--kernel", kernel_dir,
                "--target-file", target.get("file_path", ""),
                "--target-line", str(target.get("line", 0)),
                "--output", str(distances_out),
            ],
        )

        # 3. template generation (template bundle + legacy callfile)
        callfile_out = self.output / "callfile.json"
        programs_out = self.output / "programs"
        self._run_module(
            SOURCE / "template" / "template_generator.py",
            [
                "--analysis", str(templates_out),
                "--distances", str(distances_out),
                "--output", str(fuzz_out),
                "--callfile-output", str(callfile_out),
                "--program-output", str(programs_out),
            ],
        )

        print(f"\n[syzagent] Analysis complete. Output: {self.output}/")
        print(f"  Templates:  {fuzz_out}/")
        print(f"  Callfile:   {callfile_out}")
        print(f"  Programs:   {programs_out}/")

    def run_triage(self):
        """--triage: Fuzzing log triage → Agent enhancement"""
        log_file = self._require("--log", self.args.log)
        tmpl_file = self._require("--templates", self.args.templates)

        triage_out = self.output / "triage_result.json"
        enhanced_out = self.output / "enhanced_templates.json"
        static_info = self._resolve_triage_static_info()

        # 1. Failure triage
        triage_args = ["--logs", log_file, "--output", str(triage_out)]
        if static_info:
            triage_args.extend(["--static-info", static_info])
        self._run_module(
            SOURCE / "agent" / "failure_triage.py",
            triage_args,
        )

        triage = self._load_json(triage_out)
        failure_class = triage.get("failure_class", "UNKNOWN")
        print(f"[syzagent] Failure classification: {failure_class}")

        # 2. Execute agent based on classification
        if failure_class in ("R1", "R3", "MIXED"):
            print(f"[syzagent] {failure_class} → RelatedSyscallAgent executing")
            self._run_module(
                SOURCE / "agent" / "related_syscall_agent.py",
                ["--templates", tmpl_file, "--triage", str(triage_out), "--output", str(enhanced_out)],
            )
        elif failure_class == "R2":
            print("[syzagent] R2 → ObjectSynthesisAgent executing")
            self._run_module(
                SOURCE / "agent" / "object_synthesis_agent.py",
                ["--templates", tmpl_file, "--triage", str(triage_out), "--output", str(enhanced_out)],
            )
        elif failure_class == "R4":
            print("[syzagent] R4 → DistanceEnhancementAgent executing")
            self._run_module(
                SOURCE / "agent" / "distance_enhancement_agent.py",
                ["--templates", tmpl_file, "--triage", str(triage_out), "--output", str(enhanced_out)],
            )
        else:
            print(f"[syzagent] {failure_class} — Manual analysis required")
            return

        print(f"[syzagent] Enhanced templates: {enhanced_out}")

    def run_full(self):
        """--full: Analysis → triage loop"""
        self.run_analyze()
        callfile_out = self.output / "callfile.json"
        print("\n[syzagent] Execute fuzzing:")
        print(f"  python3 run_hunt.py fuzz -workdir <WORKDIR> -uptime 24")
        print(f"  (callfile: {callfile_out})")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_module(self, script: Path, extra_args: list):
        cmd = [sys.executable, str(script)] + [str(a) for a in extra_args]
        print(f"[syzagent] → {Path(script).name} {' '.join(str(a) for a in extra_args)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"[syzagent] Warning: {script.name} exited with non-zero code ({result.returncode})")

    def _require(self, flag: str, value):
        if not value:
            print(f"[syzagent] Error: {flag} is required.", file=sys.stderr)
            sys.exit(1)
        return value

    def _load_json(self, path):
        with open(path) as f:
            return json.load(f)

    def _write_json(self, path: Path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _resolve_triage_static_info(self):
        candidates = []
        if self.args.target:
            candidates.append(Path(self.args.target))
        candidates.append(self.output / "target.json")
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None
