# EchoStack Spec (minimal)

## Purpose

Turn a structured claim manifest into a strict audit report of specification quality.

## Scope

- YAML ingestion
- JSON Schema validation
- E-Strict audit (E1..E5)
- JSON report output
- Batch auditing via `audit-dir`

## Non-goals

- Proving or disproving physics claims
- Implementing QED/SM calculations
- Any inference beyond declared inputs

## CLI

- `echostack init [out.yml]`
- `echostack validate <claim.yml>`
- `echostack audit <claim.yml> [--out report.json] [--pretty]`
- `echostack audit-dir <paths...> --out-dir <dir> [--index] [--fail-on-fail]`

## Layout

- `echostack/` — package
- `echostack/schemas/` — formal schema
- `echostack/examples/` — bundled claims
- `tests/` — black-box CLI tests
- `installation/` — reproducible install scripts
