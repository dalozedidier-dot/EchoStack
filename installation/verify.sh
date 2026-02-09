#!/usr/bin/env bash
set -euo pipefail

python -c "import echostack; print('echostack', echostack.__version__)"

# Validate examples
for f in echostack/examples/*.yml; do
  echo "validate $f"
  echostack validate "$f"
done

# Audit key examples
mkdir -p _ci_out

echostack audit echostack/examples/qhigt_alpha_claim.yml --out _ci_out/audit_qhigt.json

echostack audit echostack/examples/qed_alpha_claim.yml --out _ci_out/audit_qed.json

python - <<'PY'
import json
from pathlib import Path

q = json.loads(Path('_ci_out/audit_qhigt.json').read_text())
d = json.loads(Path('_ci_out/audit_qed.json').read_text())

assert q['summary']['overall'] == 'fail', q['summary']
assert d['summary']['overall'] == 'pass', d['summary']
print('OK: expected outcomes')
PY


# Audit dir (batch)
echostack audit-dir echostack/examples --out-dir _ci_out/audit_dir --index
