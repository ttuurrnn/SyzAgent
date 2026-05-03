# SyzAgent

SyzAgent combines the SyzDirect directed kernel fuzzing pipeline with an agent loop that diagnoses stalled fuzzing runs and regenerates syscall templates or seeds. The repository is intentionally kept as a code-focused release: experiment outputs, generated datasets, case-specific shell scripts, and rolling benchmark artifacts are excluded from `main`.

## What Is Included

- `syzagent/`: command-line wrapper for analysis, triage, full pipeline preparation, and dataset case execution.
- `source/agent/`: failure triage and template/seed enhancement agents.
- `source/analyzer/`, `source/distance/`, `source/template/`: Python analysis, distance, and template generation helpers.
- `source/syzdirect/`: SyzDirect LLVM analysis tools, kernel analysis tools, and syzkaller-based fuzzer fork.
- Root runner modules such as `run_hunt.py`, `pipeline_new_cve.py`, `pipeline_dataset.py`, `agent_loop.py`, and related helpers.
- `scripts/`: setup, host bootstrap, health check, case runner, dataset runner, and experiment runner wrappers.

## Repository Layout

```text
.
├── syzagent/                 # python -m syzagent entry point
├── source/
│   ├── agent/                # R1/R2/R3/R4 triage and intervention agents
│   ├── analyzer/             # syscall analysis wrapper
│   ├── distance/             # target distance calculation wrapper
│   ├── template/             # syz template/callfile generation
│   └── syzdirect/            # SyzDirect engine and patched syzkaller fork
├── scripts/
│   ├── setup.sh              # build LLVM/SyzDirect/syzkaller components
│   ├── bootstrap_host.sh     # install host packages
│   ├── doctor.py             # environment check
│   ├── run_case.sh           # convenience wrapper for one dataset case
│   ├── run_dataset_case.py   # fetch/prepare/run one public syzbot dataset case
│   └── run_experiment.sh     # baseline/SyzDirect/agent-loop experiment runner
├── targets/example_target.json
├── configs/run_case.env.example
└── Makefile
```

## Requirements

- Ubuntu 20.04+ or Debian 11+; WSL2 works for analysis and build preparation.
- Python 3.10+, Go, CMake, Ninja, QEMU, and common Linux build tools.
- 32 GB RAM minimum for LLVM/kernel builds; 48 GB+ is recommended.
- KVM is recommended for fuzzing. Without KVM, QEMU TCG works but is much slower.

## Setup

Install host dependencies:

```bash
make bootstrap
```

Build the SyzDirect toolchain and fuzzer components:

```bash
./scripts/setup.sh --jobs 8
```

Check the local environment:

```bash
make doctor
```

## Basic Usage

Run static analysis, distance calculation, and template generation for a target:

```bash
python3 -m syzagent --analyze \
  --target targets/example_target.json \
  --kernel /path/to/linux \
  --output .runtime/analyze
```

Run the full preparation flow:

```bash
python3 -m syzagent --full \
  --target targets/example_target.json \
  --kernel /path/to/linux \
  --output .runtime/full
```

Triage an existing fuzzing log and enhance templates:

```bash
python3 -m syzagent --triage \
  --log /path/to/manager.log \
  --templates .runtime/analyze/templates.json \
  --output .runtime/triage
```

Prepare and optionally run one public dataset case:

```bash
python3 -m syzagent --case 54 --output .runtime
```

Equivalent Make target:

```bash
make run-case CASE=54 BUDGET_HOURS=1 MODE=agent-loop
```

## SyzDirect Runner

The lower-level runner remains available for direct use:

```bash
python3 run_hunt.py new \
  --cve CVE-2025-XXXXX \
  --commit <kernel-commit> \
  --function <target-function> \
  --file <kernel/source/file.c> \
  --agent-rounds 3 \
  --agent-uptime 6
```

For an already prepared workdir:

```bash
python3 run_hunt.py fuzz \
  -workdir /path/to/workdir \
  --targets 0 \
  --agent-rounds 5 \
  --agent-uptime 1
```

## Agent Loop

The fuzzing loop monitors execution health and classifies failures:

- `R1`: wrong or missing syscall entry selection.
- `R2`: argument/object construction failure.
- `R3`: missing dependency syscall chain.
- `R4`: distance or coverage stall after apparently valid execution.

Depending on the class, the agent loop updates callfiles, synthesizes object-aware seeds, or reinjects guided seeds before the next fuzzing round.

## Generated Files

Generated artifacts should stay out of Git:

- `.runtime/`, `workdir/`, `runs/`, `results/`, `logs/`, `bg_logs/`
- `generated_datasets/`
- `rolling_cases*.csv`
- kernel build products such as `bzImage`, `vmlinux`, `*.bc`, `*.ll`, `*.ko`
- local config files such as `configs/run_case.env`

Use `configs/run_case.env.example` as the template for local settings.
