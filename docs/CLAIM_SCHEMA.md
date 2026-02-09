# Claim Manifest Schema (EchoStack)

EchoStack ingests a **claim manifest** (YAML) that is intentionally declarative.

## Minimal required keys

- `claim_id` (string)
- `source` (string)

## Recommended structure

- `title`, `author`, `date`
- `assertions`: list of `{id, statement}`
- `domain`:
  - `theory` (string)
  - `regime` (string)
  - `scale_Q` (string)
  - `renormalization_scheme` (string)
  - `conventions` (string|null)
- `parameters`: mapping keyed by parameter name (e.g. `alpha0`), each entry:
  - `status` (e.g. `input`, `derived`, `claimed_output`)
  - `scale_dependent` (bool|string)
  - `boundary_condition` (e.g. `input`, `claimed_closed`, `not_applicable`)
  - `notes` (string|null)
- `methods`:
  - `approach` (list of strings)
  - `closure_mechanism` (string|null)
  - `calibration` (string|null)
- `predictions`: list of:
  - `id`
  - `target`
  - `value`
  - `is_independent` (bool)
  - `test_protocol` (string)

The formal validator is `echostack/schemas/claim_schema.json`.
