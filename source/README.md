# Source Components

This directory contains the reusable implementation pieces used by the top-level SyzAgent runners.

## Directories

- `agent/`: failure triage, fuzzing health monitoring, related syscall expansion, and object synthesis.
- `analyzer/`: syscall analysis wrapper used by `python3 -m syzagent --analyze`.
- `distance/`: target distance calculation wrapper.
- `template/`: template bundle, callfile, and seed program generation.
- `common/`: shared target and template data helpers.
- `syzdirect/`: SyzDirect LLVM passes, kernel analysis tool, patched fuzzer, and static configs.
- `kcov_patches/`, `syzdirect_patches/`: patch files used during local builds.

Build outputs and downloaded toolchains are intentionally ignored. Use `../scripts/setup.sh` from the repository root to build the required LLVM/SyzDirect components.
