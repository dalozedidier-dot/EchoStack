# EchoStack

EchoStack is a small, self-contained Python toolkit to **structure** and **audit** theoretical claims.

It does **not** decide whether a theory is true.
It checks whether a claim is **sufficiently specified** to be meaningfully testable, reproducible, and falsifiable.

## Install

User install (editable, minimal):

```bash
pip install -e .
```

Developer install (includes pytest/ruff/black):

```bash
pip install -e ".[dev]"
```

## Quickstart

Show version:

```bash
echostack --version
```

Create a new claim template (schema-valid, but will fail E2/E3 until you specify scale/scheme):

```bash
echostack init my_claim.yml --claim-id my_claim_v1 --source zenodo:123456
```


Validate a claim against the schema:

```bash
echostack validate echostack/examples/qhigt_alpha_claim.yml
```

Audit a claim (E1..E5) into a JSON report:

```bash
echostack audit echostack/examples/qhigt_alpha_claim.yml --out audit_report.json
```

Note: reports include an `input` block with the source file `path` and `sha256` (content hash)
to make audits reproducible and verifiable.

Audit a whole directory (writes multiple JSON reports + optional index):

```bash
echostack audit-dir echostack/examples --out-dir _ci_out --index
```

## E-Strict levels (E1..E5)

- **E1 Variables explicit**: domain + parameters + methods declared.
- **E2 Scale declared**: `domain.scale_Q` is not `unspecified`.
- **E3 Scheme declared**: `domain.renormalization_scheme` is not `unspecified`.
- **E4 Closure mechanism**: if closure is claimed, `methods.closure_mechanism` must explain how boundary conditions are closed.
- **E5 Independent predictions**: at least one prediction marked `is_independent: true`.

Each level yields: `pass | partial | fail`.

## License

MIT
