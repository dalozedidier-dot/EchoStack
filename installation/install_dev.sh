#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

ruff check .
black --check .
pytest -q

echostack audit-dir echostack/examples --out-dir _ci_out --index
printf "\nOK: dev install + tests + example audit-dir\n"
