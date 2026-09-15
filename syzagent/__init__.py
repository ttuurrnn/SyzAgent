"""
SyzAgent: SyzDirect-based Kernel Fuzzing Agent Loop

Improves fuzzing efficiency by automatically classifying R1/R2/R3/R4 failure patterns
and enhancing templates.

Usage:
    python -m syzagent --target target.json --kernel /path/to/linux
    python -m syzagent --help
"""

__version__ = "0.1.0"
__author__ = "whysocscs"
