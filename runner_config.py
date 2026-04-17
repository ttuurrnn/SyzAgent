"""
SyzDirect Runner — RunnerConfig class.

Replaces the old `configure_runner()` function with a proper config object.
Bridges to the legacy Config module globals for backward compatibility with
Main.py, Fuzz.py, and SyscallAnalyze/.
"""

import json
import os

from paths import (
    BIGCONFIG, CLANG_PATH, FUZZER_BIN, FUZZER_DIR, FUNCTION_MODEL_DIR,
    INTERFACE_GENERATOR, KCOV_PATCH, KERNEL_ANALYSIS_DIR, LLVM_BUILD,
    LLVM_ROOT, SSH_KEY, TARGET_ANALYZER, TEMPLATE_CONFIG, VM_IMAGE,
    Q, WorkdirLayout,
)


def ensure_template_config(path):
    """Create a minimal syz-manager template if the repo copy is missing."""
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    template = {
        "target": "linux/amd64",
        "sshkey": SSH_KEY,
        "procs": 8,
        "type": "qemu",
        "vm": {
            "count": 1,
            "cpu": 2,
            "mem": 4096,
        },
        "reproduce": False,
    }
    with open(path, "w") as f:
        json.dump(template, f, indent="\t")


class RunnerConfig:
    """Runtime configuration for the SyzDirect pipeline.

    Holds all settings needed by the pipeline stages. Call
    apply_to_legacy_config() to bridge to the old Config module.
    """

    def __init__(self, layout, cpus=4, uptime=24, fuzz_rounds=1):
        self.layout = layout
        self.cpus = cpus
        self.uptime = uptime
        self.fuzz_rounds = fuzz_rounds

    def apply_to_legacy_config(self):
        """Set all Config module globals needed by Fuzz.MultirunFuzzer and friends."""
        import Config
        ensure_template_config(TEMPLATE_CONFIG)
        self.layout.apply_to_config(Config)
        Config.CPUNum = self.cpus
        Config.FuzzRounds = self.fuzz_rounds
        Config.FuzzUptime = self.uptime
        Config.FuzzerDir = FUZZER_DIR
        Config.FuzzerBinDir = FUZZER_BIN
        Config.SyzManagerPath = os.path.join(FUZZER_BIN, "syz-manager")
        Config.SyzTRMapPath = os.path.join(FUZZER_BIN, "direct")
        Config.SyzFeaturePath = os.path.join(FUZZER_BIN, "syz-features")
        Config.TRMapPath = self.layout.tr_map()
        Config.SyzkallerSignaturePath = self.layout.syz_sig()
        Config.EmitScriptPath = self.layout.emit_script()
        Config.TemplateConfigPath = TEMPLATE_CONFIG
        Config.CleanImageTemplatePath = VM_IMAGE
        Config.KeyPath = SSH_KEY
        Config.ClangPath = CLANG_PATH
        Config.LLVMRootDir = LLVM_ROOT
        Config.LLVMBuildDir = LLVM_BUILD
        Config.KcovPatchPath = KCOV_PATCH
        Config.BigConfigPath = BIGCONFIG
        Config.FunctionModelDirRoot = FUNCTION_MODEL_DIR
        Config.FunctionModelBinary = INTERFACE_GENERATOR
        Config.TargetPointAnalysisDirRoot = KERNEL_ANALYSIS_DIR
        Config.TargetPointAnalysisBinary = TARGET_ANALYZER
        Config.Q = Q
        return Config
