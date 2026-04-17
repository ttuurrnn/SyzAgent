#!/usr/bin/env python3
"""
SyzAgent CLI

SyzDirect 분석 파이프라인을 실행하고, 실패를 분류하여 템플릿을 강화합니다.
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
        description="SyzDirect 기반 커널 퍼징 에이전트 — R1/R2/R3 실패 자동 보완",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 분석 + 템플릿 생성
  python -m syzagent --target target.json --kernel /path/to/linux

  # 퍼징 로그로 실패 분류 후 템플릿 강화
  python -m syzagent --triage --log fuzz.log --templates templates.json

  # 전체 파이프라인 (분석 → 거리 계산 → 템플릿 → 에이전트 루프)
  python -m syzagent --full --target target.json --kernel /path/to/linux

  # 케이스 번호로 실행 (datasets 사용)
  python -m syzagent --case 54
        """,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--analyze",
        action="store_true",
        help="정적 분석만 실행 (syscall 식별 + 템플릿 생성)",
    )
    mode.add_argument(
        "--triage",
        action="store_true",
        help="퍼징 로그 분석 → R1/R2/R3 실패 분류 + 템플릿 강화",
    )
    mode.add_argument(
        "--full",
        action="store_true",
        help="전체 파이프라인: 분석 → 거리 계산 → 템플릿 → 에이전트 루프",
    )
    mode.add_argument(
        "--case",
        type=int,
        metavar="CASE_ID",
        help="SyzDirect 데이터셋 케이스 번호 실행 (예: --case 54)",
    )

    parser.add_argument("--target", metavar="JSON", help="target.json 경로")
    parser.add_argument("--kernel", metavar="DIR", help="커널 소스 경로")
    parser.add_argument("--log", metavar="LOG", help="퍼징 로그 파일 (--triage 전용)")
    parser.add_argument(
        "--templates", metavar="JSON", help="템플릿 파일 (--triage 전용)"
    )
    parser.add_argument(
        "--output", metavar="DIR", default="syzagent_output", help="출력 디렉토리"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "syzdirect", "agent-loop"],
        default="agent-loop",
        help="퍼징 모드 (--case 전용, 기본값: agent-loop)",
    )
    parser.add_argument(
        "--budget-hours",
        type=float,
        default=1.0,
        metavar="H",
        help="퍼징 예산 (시간, 기본값: 1)",
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
