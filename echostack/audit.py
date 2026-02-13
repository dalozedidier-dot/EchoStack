from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .claim import Claim

from . import __version__ as _ECHOSTACK_VERSION


@dataclass(frozen=True)
class CriterionResult:
    status: str  # pass | partial | fail
    reasons: list[str]
    evidence_paths: list[str]


def _status(pass_cond: bool, partial_cond: bool) -> str:
    if pass_cond:
        return "pass"
    if partial_cond:
        return "partial"
    return "fail"


def _is_unspecified(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        s = value.strip()
        if s == "":
            return True
        if s.lower() == "unspecified":
            return True
    return False


def _looks_like_scale_q(value: object) -> bool:
    """Return True if the value meaningfully specifies the energy scale Q.

    We accept either a numeric Q or an explicit limiting statement like "Q -> 0+",
    as long as it is not "unspecified".
    """
    if isinstance(value, int | float):
        return True

    s = str(value).strip()
    if s == "":
        return False

    s_low = s.lower()

    # Limit/proxy statements are acceptable as explicit scale specifications.
    if "q" in s_low and ("->" in s_low or "limit" in s_low or "proxy" in s_low):
        return True

    # Numeric string is also acceptable (permissive: the goal is to avoid "unspecified").
    try:
        float(re.sub(r"[^\deE+.\-]", "", s))
        return True
    except Exception:
        return False


def _normalize_scheme(scheme: str) -> str:
    s = scheme.strip().lower()
    s = s.replace("_", "-")
    s = re.sub(r"\s+", "", s)

    # Common aliases.
    if s in {"os", "on-shell", "onshell"}:
        return "on-shell"
    if s in {"msbar", "ms-bar", "ms\\bar", "ms"}:
        return "msbar"
    if s in {"mom", "momentum-subtraction"}:
        return "mom"

    return s


def audit_claim(claim: Claim) -> dict[str, Any]:
    issues = claim.validate()
    validation_ok = len(issues) == 0

    # E1: variables explicitly declared (domain + parameters + methods)
    domain = claim.get("domain", default={})
    params = claim.get("parameters", default={})
    methods = claim.get("methods", default={})

    has_domain = isinstance(domain, dict) and all(
        k in domain for k in ("theory", "regime", "scale_Q", "renormalization_scheme")
    )
    has_params = isinstance(params, dict) and len(params) > 0
    has_methods = isinstance(methods, dict) and "approach" in methods

    e1_pass = validation_ok and has_domain and has_params and has_methods
    e1_partial = has_domain and has_params

    e1 = CriterionResult(
        status=_status(e1_pass, e1_partial),
        reasons=[
            *([] if has_domain else ["Missing or incomplete /domain section."]),
            *([] if has_params else ["Missing or empty /parameters section."]),
            *([] if has_methods else ["Missing /methods/approach section."]),
            *([f"Schema validation issues: {len(issues)}"] if not validation_ok else []),
        ],
        evidence_paths=["/domain", "/parameters", "/methods"],
    )

    # E2: energy scale Q is explicitly specified (strict: 'unspecified' fails)
    scale_q = claim.get("domain", "scale_Q", default=None)
    if _is_unspecified(scale_q):
        e2_pass = False
        e2_partial = False
        e2_reasons = ["domain.scale_Q is missing/empty or set to 'unspecified'."]
    else:
        e2_pass = _looks_like_scale_q(scale_q)
        e2_partial = not e2_pass
        e2_reasons = (
            []
            if e2_pass
            else ["domain.scale_Q is present but does not look like a scale or limit statement."]
        )

    e2 = CriterionResult(
        status=_status(e2_pass, e2_partial),
        reasons=e2_reasons,
        evidence_paths=["/domain/scale_Q"],
    )

    # E3: renormalization scheme explicitly specified (strict: 'unspecified' fails)
    raw_scheme = claim.get("domain", "renormalization_scheme", default=None)
    if _is_unspecified(raw_scheme):
        e3_pass = False
        e3_partial = False
        e3_reasons = ["domain.renormalization_scheme is missing/empty or set to 'unspecified'."]
    else:
        scheme_str = str(raw_scheme)
        norm = _normalize_scheme(scheme_str)
        known = {"on-shell", "msbar", "mom"}
        e3_pass = norm in known
        e3_partial = not e3_pass
        e3_reasons = (
            []
            if e3_pass
            else [
                "domain.renormalization_scheme is present but not recognized. "
                "Use e.g. on-shell, MSbar, MOM, or a clear equivalent."
            ]
        )

    e3 = CriterionResult(
        status=_status(e3_pass, e3_partial),
        reasons=e3_reasons,
        evidence_paths=["/domain/renormalization_scheme"],
    )

    # E4: closure mechanism when boundary condition is claimed closed
    closure_mech = claim.get("methods", "closure_mechanism", default=None)
    claimed_closed = False
    claimed_outputs: list[str] = []

    if isinstance(params, dict):
        for pname, pinfo in params.items():
            if not isinstance(pinfo, dict):
                continue
            if pinfo.get("boundary_condition") == "claimed_closed":
                claimed_closed = True
            if pinfo.get("status") == "claimed_output":
                claimed_outputs.append(pname)

    if claimed_closed or claimed_outputs:
        cm_str = str(closure_mech).strip() if isinstance(closure_mech, str) else ""
        e4_pass = len(cm_str) >= 20
        e4_partial = len(cm_str) > 0
        reasons: list[str] = []

        if not claimed_outputs and claimed_closed:
            reasons.append(
                "Boundary condition is claimed closed but no parameters are marked as claimed_output."
            )
        if claimed_outputs and not claimed_closed:
            reasons.append(
                "Parameters are marked claimed_output but boundary_condition is not declared claimed_closed."
            )
        if not e4_pass:
            reasons.append(
                "methods.closure_mechanism is missing or too weak to specify a closure mechanism."
            )
    else:
        # No closure claimed: E4 is not applicable; we treat as partial (honest limitation)
        e4_pass = False
        e4_partial = True
        reasons = [
            "No closure claimed; boundary condition remains an explicit input (honest limitation)."
        ]

    e4 = CriterionResult(
        status=_status(e4_pass, e4_partial),
        reasons=reasons,
        evidence_paths=["/methods/closure_mechanism", "/parameters"],
    )

    # E5: independent, falsifiable predictions declared
    preds = claim.get("predictions", default=[])
    if not isinstance(preds, list):
        preds = []
    independent = [p for p in preds if isinstance(p, dict) and p.get("is_independent") is True]
    any_preds = len(preds) > 0
    e5_pass = any_preds and len(independent) > 0
    e5_partial = any_preds

    e5_reasons: list[str] = []
    if not any_preds:
        e5_reasons.append("No predictions declared.")
    elif len(independent) == 0:
        e5_reasons.append(
            "No independent predictions declared (all are calibrated or unspecified)."
        )

    e5 = CriterionResult(
        status=_status(e5_pass, e5_partial),
        reasons=[] if e5_pass else e5_reasons,
        evidence_paths=["/predictions"],
    )

    results = (e1, e2, e3, e4, e5)
    all_pass = all(r.status == "pass" for r in results)
    any_fail = any(r.status == "fail" for r in results)
    overall = "pass" if all_pass else ("fail" if any_fail else "partial")

    blocking_levels = [
        lvl
        for lvl, r in zip(("E1", "E2", "E3", "E4", "E5"), results, strict=False)
        if r.status == "fail"
    ]

    report: dict[str, Any] = {
        "audit_version": _ECHOSTACK_VERSION,
        "claim_id": claim.claim_id,
        "validation": {
            "status": "pass" if validation_ok else "fail",
            "issues": [
                {
                    "path": i.path,
                    "message": i.message,
                    "validator": getattr(i, "validator", None),
                    "schema_path": getattr(i, "schema_path", None),
                }
                for i in issues
            ],
        },
        "criteria": {
            "E1": e1.__dict__,
            "E2": e2.__dict__,
            "E3": e3.__dict__,
            "E4": e4.__dict__,
            "E5": e5.__dict__,
        },
        "summary": {
            "overall": overall,
            "blocking_levels": blocking_levels,
            "notes": [
                "EchoStack audits claim specification quality, not truth.",
                "Statuses: pass|partial|fail. 'partial' indicates incomplete/ambiguous specification.",
            ],
        },
    }
    return report
