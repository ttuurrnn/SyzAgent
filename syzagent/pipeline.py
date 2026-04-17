#!/usr/bin/env python3
"""
SyzAgent Pipeline

analyze → distance → template → agent loop 을 순서대로 조율합니다.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SOURCE = ROOT / "source"
sys.path.insert(0, str(SOURCE))


class SyzAgentPipeline:
    """SyzAgent 전체 파이프라인 조율자"""

    def __init__(self, args):
        self.args = args
        self.output = Path(args.output)
        self.output.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 공개 진입점
    # ------------------------------------------------------------------

    def run_dataset_case(self):
        """--case: run_dataset_case.py 래퍼"""
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
        print(f"[syzagent] 케이스 {case_id} 실행: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

    def run_analyze(self):
        """--analyze: 정적 분석 + 템플릿 생성"""
        target_file = self._require("--target", self.args.target)
        kernel_dir = self._require("--kernel", self.args.kernel)

        templates_out = self.output / "templates.json"
        distances_out = self.output / "distances.json"
        fuzz_out = self.output / "fuzz_templates"

        # 1. syscall 분석
        self._run_module(
            SOURCE / "analyzer" / "syscall_analyzer.py",
            ["--kernel", kernel_dir, "--target", target_file, "--output", str(templates_out)],
        )

        # 2. 거리 계산
        target = self._load_json(target_file)
        self._run_module(
            SOURCE / "distance" / "distance_calculator.py",
            [
                "--kernel", kernel_dir,
                "--target-file", target.get("file_path", ""),
                "--target-line", str(target.get("line", 0)),
                "--output", str(distances_out),
            ],
        )

        # 3. 템플릿 생성
        self._run_module(
            SOURCE / "template" / "template_generator.py",
            [
                "--analysis", str(templates_out),
                "--distances", str(distances_out),
                "--output", str(fuzz_out),
            ],
        )

        print(f"\n[syzagent] 분석 완료. 출력: {self.output}/")

    def run_triage(self):
        """--triage: 퍼징 로그 분류 → 에이전트 강화"""
        log_file = self._require("--log", self.args.log)
        tmpl_file = self._require("--templates", self.args.templates)

        triage_out = self.output / "triage_result.json"
        enhanced_out = self.output / "enhanced_templates.json"

        # 1. 실패 분류
        self._run_module(
            SOURCE / "agent" / "failure_triage.py",
            ["--logs", log_file, "--output", str(triage_out)],
        )

        triage = self._load_json(triage_out)
        failure_class = triage.get("failure_class", "UNKNOWN")
        print(f"[syzagent] 실패 분류: {failure_class}")

        # 2. 분류에 따른 에이전트 실행
        if failure_class in ("R3", "MIXED"):
            print("[syzagent] R3 → RelatedSyscallAgent 실행")
            self._run_module(
                SOURCE / "agent" / "related_syscall_agent.py",
                ["--templates", tmpl_file, "--triage", str(triage_out), "--output", str(enhanced_out)],
            )
        elif failure_class == "R2":
            print("[syzagent] R2 → ObjectSynthesisAgent 실행")
            self._run_module(
                SOURCE / "agent" / "object_synthesis_agent.py",
                ["--templates", tmpl_file, "--triage", str(triage_out), "--output", str(enhanced_out)],
            )
        else:
            print(f"[syzagent] {failure_class} — 수동 분석 필요")
            return

        print(f"[syzagent] 강화된 템플릿: {enhanced_out}")

    def run_full(self):
        """--full: 분석 → triage 루프"""
        self.run_analyze()
        print("\n[syzagent] 퍼징은 생성된 템플릿으로 run_experiment.sh를 통해 실행하세요.")
        print(f"  bash scripts/run_experiment.sh agent-loop {self.output}/fuzz_templates")

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _run_module(self, script: Path, extra_args: list):
        cmd = [sys.executable, str(script)] + [str(a) for a in extra_args]
        print(f"[syzagent] → {Path(script).name} {' '.join(str(a) for a in extra_args)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"[syzagent] 경고: {script.name} 가 0이 아닌 코드로 종료됨 ({result.returncode})")

    def _require(self, flag: str, value):
        if not value:
            print(f"[syzagent] 오류: {flag} 가 필요합니다.", file=sys.stderr)
            sys.exit(1)
        return value

    def _load_json(self, path):
        with open(path) as f:
            return json.load(f)
