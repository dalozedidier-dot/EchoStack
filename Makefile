SHELL := /usr/bin/env bash

.PHONY: help install lint format test audit-examples precommit verify

help:
	@echo "make install        Install dev dependencies (editable)"
	@echo "make lint           Run ruff + black --check"
	@echo "make format         Auto-format (black) + autofix (ruff)"
	@echo "make test           Run pytest"
	@echo "make audit-examples Audit echostack/examples into _ci_out/ (writes index.json)"
	@echo "make precommit      Run pre-commit on all files"
	@echo "make verify         Lint + test + audit-examples"

install:
	python -m pip install -U pip
	pip install -e ".[dev]"

lint:
	ruff check .
	black --check .

format:
	black .
	ruff check . --fix

test:
	pytest -q

audit-examples:
	mkdir -p _ci_out
	echostack audit-dir echostack/examples --out-dir _ci_out --index

precommit:
	pre-commit run --all-files

verify: lint test audit-examples
