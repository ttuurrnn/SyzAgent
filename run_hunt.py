#!/usr/bin/env python3
"""Compatibility wrapper for the SyzDirect runner."""

from pathlib import Path
import runpy
import sys

RUNNER_DIR = Path(__file__).resolve().parent / "source" / "syzdirect" / "Runner"
sys.path.insert(0, str(RUNNER_DIR))

runpy.run_path(str(RUNNER_DIR / "run_hunt.py"), run_name="__main__")
