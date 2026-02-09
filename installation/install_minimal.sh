#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip
python -m pip install -e .

echostack --help

echostack validate echostack/examples/qhigt_alpha_claim.yml

echostack audit echostack/examples/qhigt_alpha_claim.yml --out /tmp/echostack_audit_qhigt.json --pretty
printf "\nWrote: /tmp/echostack_audit_qhigt.json\n"
