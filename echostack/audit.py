from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .claim import Claim
from .validation import ValidationIssue


@dataclass(frozen=True)
class CriterionResult:
    status: str  # pass | partial | fail
    reasons: List[str]
    evidence_paths: List[str]


def _status(pass_cond: bool, partial_cond: bool) -> str:
    if pass_cond:
        return "pass"
    if partial_cond:
        return "partial"
    return "fail"


def audit_claim(claim: Claim) -> Dict[str, Any]:
    issues = claim.validate()
    validation_ok = len(issues) == 0

    # E1: variables explicitly declared (domain + parameters + methods)
    domain = claim.get("domain", default={})
    params = claim.get("parameters", default={})
    methods = claim.get("methods", default={})
    has_domain = isinstance(domain, dict) and all(k in domain for k in ("theory", "regime", "scale_Q", "renormalization_scheme"))
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

    # E2: scale Q declared (not 'unspecified')
    scale_q = claim.get("domain", "scale_Q", default="unspecified")
    e2_pass = isinstance(scale_q, str) and scale_q.strip().lower() not in ("unspecified", "")
    e2_partial = isinstance(scale_q, str) and scale_q.strip() != ""
    e2 = CriterionResult(
        status=_status(e2_pass, e2_partial),
        reasons=[] if e2_pass else ["domain.scale_Q is unspecified or empty."],
        evidence_paths=["/domain/scale_Q"],
    )

    # E3: renormalization scheme declared (not 'unspecified')
    scheme = claim.get("domain", "renormalization_scheme", default="unspecified")
    e3_pass = isinstance(scheme, str) and scheme.strip().lower() not in ("unspecified", "")
    e3_partial = isinstance(scheme, str) and scheme.strip() != ""
    e3 = CriterionResult(
        status=_status(e3_pass, e3_partial),
        reasons=[] if e3_pass else ["domain.renormalization_scheme is unspecified or empty."],
        evidence_paths=["/domain/renormalization_scheme"],
    )

    # E4: closure mechanism when boundary condition is claimed closed
    closure_mech = claim.get("methods", "closure_mechanism", default=None)
    claimed_closed = False
    claimed_outputs: List[str] = []
    if isinstance(params, dict):
        for pname, pinfo in params.items():
            if isinstance(pinfo, dict):
                if pinfo.get("boundary_condition") == "claimed_closed":
                    claimed_closed = True
                if pinfo.get("status") == "claimed_output":
                    claimed_outputs.append(pname)

    if claimed_closed or claimed_outputs:
        e4_pass = isinstance(closure_mech, str) and len(closure_mech.strip()) >= 20
        e4_partial = isinstance(closure_mech, str) and len(closure_mech.strip()) > 0
        reasons = []
        if not claimed_outputs and claimed_closed:
            reasons.append("Boundary condition is claimed closed but no parameters are marked as claimed_output.")
        if claimed_outputs and not claimed_closed:
            reasons.append("Parameters are marked claimed_output but boundary_condition is not declared claimed_closed.")
        if not e4_pass:
            reasons.append("methods.closure_mechanism is missing or too weak to specify a closure mechanism.")
    else:
        # No closure claimed: E4 is not applicable; we treat as partial (honest limitation)
        e4_pass = False
        e4_partial = True
        reasons = ["No closure claimed; boundary condition remains an explicit input (honest limitation)."]

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
    e5_reasons = []
    if not any_preds:
        e5_reasons.append("No predictions declared.")
    elif len(independent) == 0:
        e5_reasons.append("No independent predictions declared (all are calibrated or unspecified).")

    e5 = CriterionResult(
        status=_status(e5_pass, e5_partial),
        reasons=[] if e5_pass else e5_reasons,
        evidence_paths=["/predictions"],
    )

    report: Dict[str, Any] = {
        "audit_version": "0.2.1",
        "claim_id": claim.claim_id,
        "validation": {
            "status": "pass" if validation_ok else "fail",
            "issues": [{"path": i.path, "message": i.message} for i in issues],
        },
        "criteria": {
            "E1": e1.__dict__,
            "E2": e2.__dict__,
            "E3": e3.__dict__,
            "E4": e4.__dict__,
            "E5": e5.__dict__,
        },
        "summary": {
            "overall": "pass" if all(r.status == "pass" for r in (e1,e2,e3,e4,e5)) else "fail",
            "notes": [
                "EchoStack audits claim specification quality, not truth.",
                "Statuses: pass|partial|fail. 'partial' often indicates an honest limitation or incomplete specification.",
            ],
        },
    }
    return report
