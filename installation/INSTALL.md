# Installation (clean, reproducible)

This folder is meant to make EchoStack installation boring and predictable.

## Requirements

- Python 3.11+
- pip

## Fresh venv (recommended)

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

## Install

### Minimal (runtime only)

```bash
pip install -e .
```

### Dev (tests + lint + formatting)

```bash
pip install -e ".[dev]"
```

## Verify

```bash
echostack --help
echostack validate echostack/examples/qhigt_alpha_claim.yml
echostack validate echostack/examples/qed_alpha_claim.yml
echostack audit echostack/examples/qed_alpha_claim.yml --out /tmp/audit_qed.json
pytest -q
```

## Typical workflows

### Audit a directory of claims

```bash
mkdir -p _ci_out
echostack audit-dir claims/ --out-dir _ci_out --index
```

### CI behaviour (expected)

- `qhigt_alpha_claim.yml` validates but audits to **overall=fail** (intentionally under-specified).
- `qed_alpha_claim.yml` validates and audits to **overall=pass** (reference example).
