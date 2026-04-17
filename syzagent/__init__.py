"""
SyzAgent: SyzDirect 기반 커널 퍼징 에이전트 루프

R1/R2/R3 실패 패턴을 자동 분류하고 템플릿을 강화하여 퍼징 효율을 개선합니다.

Usage:
    python -m syzagent --target target.json --kernel /path/to/linux
    python -m syzagent --help
"""

__version__ = "0.1.0"
__author__ = "whysocscs"
