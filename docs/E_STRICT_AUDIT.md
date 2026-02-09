# E-Strict Audit (E1..E5)

EchoStack implements a structural audit with 5 levels.

It does **not** evaluate scientific truth.
It evaluates whether a claim is **sufficiently specified**.

## E1 — Variables explicit

Checks that:

- `domain` contains `theory`, `regime`, `scale_Q`, `renormalization_scheme`
- `parameters` is a non-empty mapping
- `methods.approach` exists
- schema validation is clean

## E2 — Scale declared

Checks that `domain.scale_Q` is a **non-empty string** and not `unspecified`.

## E3 — Scheme declared

Checks that `domain.renormalization_scheme` is a **non-empty string** and not `unspecified`.

## E4 — Closure mechanism

If the claim marks parameters as:

- `status: claimed_output` and/or
- `boundary_condition: claimed_closed`

then `methods.closure_mechanism` must be present and substantive.

If the claim does **not** claim closure, E4 returns `partial` (honest limitation).

## E5 — Independent predictions

Checks that at least one item in `predictions` has `is_independent: true`.

## Outcomes

Each level yields:

- `pass`
- `partial`
- `fail`

The top-level `summary.overall` is strict: it is `pass` only if all E-levels are `pass`.
