SHELL := /bin/bash

CASE ?= 54
DATASET_KIND ?= known-bugs
MODE ?= agent-loop
BUDGET_HOURS ?= 1
REPETITIONS ?= 1
VM_CPU ?= 1
KERNEL_CMDLINE_EXTRA ?= maxcpus=1 net.ifnames=0 biosdevname=0

.PHONY: help bootstrap doctor run-case

help:
	@printf 'Targets:\n'
	@printf '  make bootstrap              Install host dependencies on Ubuntu/WSL\n'
	@printf '  make doctor                 Check host prerequisites\n'
	@printf '  make run-case CASE=54       Run one dataset case with repo-local defaults\n'

bootstrap:
	bash scripts/bootstrap_host.sh

doctor:
	python3 scripts/doctor.py

run-case:
	DATASET_KIND="$(DATASET_KIND)" \
	MODE="$(MODE)" \
	BUDGET_HOURS="$(BUDGET_HOURS)" \
	REPETITIONS="$(REPETITIONS)" \
	VM_CPU="$(VM_CPU)" \
	KERNEL_CMDLINE_EXTRA="$(KERNEL_CMDLINE_EXTRA)" \
	bash scripts/run_case.sh "$(CASE)"
