from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise TypeError("Claim root must be a mapping/object.")
    return data


def _schema_path() -> Path:
    return Path(__file__).resolve().parent / "schemas" / "claim_schema.json"


def validate_claim(data: dict[str, Any]) -> list[ValidationIssue]:
    import json

    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    issues: list[ValidationIssue] = []
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(data), key=lambda e: e.path):
        path = "/" + "/".join(str(p) for p in err.path)
        issues.append(ValidationIssue(path=path, message=err.message))

    # Semantic normalization requirements: unknown must be explicit "unspecified"
    if isinstance(data.get("domain"), dict):
        for k in ("scale_Q", "renormalization_scheme"):
            v = data["domain"].get(k)
            if v in (None, ""):
                issues.append(
                    ValidationIssue(
                        path=f"/domain/{k}",
                        message="Must be provided. Use 'unspecified' if unknown.",
                    )
                )

    return issues
