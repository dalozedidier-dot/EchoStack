from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .validation import ValidationIssue, load_yaml, validate_claim


@dataclass(frozen=True)
class Claim:
    """A normalized claim manifest loaded from YAML and validated against the Claim Manifest schema."""

    data: dict[str, Any]
    path: Path | None = None
    source_sha256: str | None = None

    @property
    def claim_id(self) -> str:
        return str(self.data.get("claim_id", "unknown"))

    def get(self, *keys: str, default: Any = None) -> Any:
        cur: Any = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    @staticmethod
    def from_yaml(path: Path) -> Claim:
        data = load_yaml(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return Claim(data=data, path=path, source_sha256=digest)

    def validate(self) -> list[ValidationIssue]:
        return validate_claim(self.data)
