from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .validation import ValidationIssue, load_yaml, validate_claim


@dataclass(frozen=True)
class Claim:
    """A normalized claim manifest loaded from YAML and validated against the Claim Manifest schema."""

    data: Dict[str, Any]
    path: Optional[Path] = None

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
    def from_yaml(path: Path) -> "Claim":
        data = load_yaml(path)
        return Claim(data=data, path=path)

    def validate(self) -> List[ValidationIssue]:
        return validate_claim(self.data)
