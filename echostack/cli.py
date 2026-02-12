from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .audit import audit_claim
from .claim import Claim

# Exit codes (CI-grade)
# 0: success
# 1: invalid input / validation failure (schema or load error)
# 2: audit overall failure (only when explicitly requested via --fail-on-*)
EXIT_OK = 0
EXIT_INVALID = 1
EXIT_AUDIT_FAIL = 2


def _write_json(obj: object, out: Path | None, pretty: bool) -> None:
    payload = json.dumps(obj, indent=2 if pretty else None, sort_keys=True)
    if out is None:
        sys.stdout.write(payload + "\n")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload + "\n", encoding="utf-8")


def _is_glob(s: str) -> bool:
    return any(ch in s for ch in "*?[")


def _iter_claim_paths(inputs: list[str]) -> list[Path]:
    """Expand files/dirs/globs into a stable, de-duplicated list of YAML paths."""
    paths: list[Path] = []

    def add(p: Path) -> None:
        if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
            paths.append(p)

    for raw in inputs:
        if _is_glob(raw):
            for p in sorted(Path().glob(raw)):
                add(p)
            continue

        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*.yml")):
                add(f)
            for f in sorted(p.rglob("*.yaml")):
                add(f)
            continue

        add(p)

    # de-dup, keep stable order
    seen: set[Path] = set()
    out: list[Path] = []
    for p in paths:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def _safe_slug(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("_") or "unknown"


def _load_claim(path: Path) -> Claim:
    return Claim.from_yaml(path)


def cmd_validate(args: argparse.Namespace) -> int:
    out_path = Path(args.out) if args.out else None
    claim_path = Path(args.claim)

    try:
        claim = _load_claim(claim_path)
    except Exception as e:
        msg = f"Cannot load claim '{claim_path}': {e}"
        if args.json:
            _write_json(
                {"path": str(claim_path), "status": "error", "error": msg},
                out=out_path,
                pretty=args.pretty,
            )
        else:
            sys.stderr.write("ERROR: " + msg + "\n")
        return EXIT_INVALID

    issues = claim.validate()
    ok = len(issues) == 0
    status = "pass" if ok else "fail"

    if args.json:
        payload: dict[str, object] = {
            "claim_id": claim.claim_id,
            "path": str(claim_path),
            "status": status,
            "issues": [],
        }
        for i in issues:
            item = {"path": i.path, "message": i.message}
            if args.explain:
                item["validator"] = i.validator
                item["schema_path"] = i.schema_path
            payload["issues"].append(item)
        _write_json(payload, out=out_path, pretty=args.pretty)
    else:
        if not ok:
            for i in issues:
                line = f"{i.path}: {i.message}"
                if args.explain:
                    extra = []
                    if i.validator:
                        extra.append(f"validator={i.validator}")
                    if i.schema_path:
                        extra.append(f"schema_path={i.schema_path}")
                    if extra:
                        line += " [" + ", ".join(extra) + "]"
                sys.stderr.write(line + "\n")
        else:
            sys.stdout.write("OK\n")

    return EXIT_OK if ok else EXIT_INVALID


def _audit_and_write(
    claim_path: Path, out_path: Path | None, pretty: bool
) -> dict[str, object] | None:
    try:
        claim = _load_claim(claim_path)
    except Exception as e:
        sys.stderr.write(f"ERROR: Cannot load claim '{claim_path}': {e}\n")
        return None

    report = audit_claim(claim)
    _write_json(report, out=out_path, pretty=pretty)
    return report


def cmd_audit(args: argparse.Namespace) -> int:
    out_path = Path(args.out) if args.out else None
    claim_path = Path(args.claim)

    report = _audit_and_write(claim_path, out_path=out_path, pretty=args.pretty)
    if report is None:
        return EXIT_INVALID

    validation_status = str(report.get("validation", {}).get("status", "fail"))
    overall = str(report.get("summary", {}).get("overall", "fail"))

    if validation_status != "pass":
        return EXIT_INVALID

    if args.fail_on_not_pass and overall != "pass":
        return EXIT_AUDIT_FAIL

    if args.fail_on_fail and overall == "fail":
        return EXIT_AUDIT_FAIL

    return EXIT_OK


def cmd_audit_dir(args: argparse.Namespace) -> int:
    claim_paths = _iter_claim_paths(list(args.inputs))
    if not claim_paths:
        sys.stderr.write("No YAML claim files found.\n")
        return EXIT_INVALID

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    index: list[dict[str, object]] = []
    any_invalid = False
    any_fail = False
    any_not_pass = False

    for p in claim_paths:
        try:
            claim = _load_claim(p)
        except Exception as e:
            any_invalid = True
            index.append(
                {
                    "claim_id": None,
                    "path": str(p),
                    "report": None,
                    "overall": "error",
                    "error": str(e),
                }
            )
            continue

        report = audit_claim(claim)
        slug = _safe_slug(str(report.get("claim_id", p.stem)))
        out_path = out_dir / f"audit_{slug}.json"
        _write_json(report, out=out_path, pretty=args.pretty)

        validation_status = str(report.get("validation", {}).get("status", "fail"))
        overall = str(report.get("summary", {}).get("overall", "fail"))

        if validation_status != "pass":
            any_invalid = True

        if overall == "fail":
            any_fail = True
        if overall != "pass":
            any_not_pass = True

        index.append(
            {
                "claim_id": report.get("claim_id"),
                "path": str(p),
                "report": str(out_path),
                "overall": overall,
                "validation": validation_status,
            }
        )

    if args.index:
        _write_json({"reports": index}, out=out_dir / "index.json", pretty=True)

    if args.fail_on_not_pass:
        if any_invalid:
            return EXIT_INVALID
        if any_not_pass:
            return EXIT_AUDIT_FAIL

    if args.fail_on_fail:
        if any_invalid:
            return EXIT_INVALID
        if any_fail:
            return EXIT_AUDIT_FAIL

    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="echostack",
        description="EchoStack: claim manifest -> E-Strict audit report (spec quality, not truth)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"echostack {__version__}",
        help="Print version and exit",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate a claim manifest against the schema")
    p_val.add_argument("claim", help="Path to claim YAML")
    p_val.add_argument("--json", action="store_true", help="Emit JSON instead of plain text")
    p_val.add_argument("--out", default=None, help="Write JSON output to file")
    p_val.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    p_val.add_argument(
        "--explain",
        action="store_true",
        help="Include schema details (validator and schema_path) in output",
    )
    p_val.set_defaults(func=cmd_validate)

    p_aud = sub.add_parser("audit", help="Run E-Strict audit and emit a JSON report")
    p_aud.add_argument("claim", help="Path to claim YAML")
    p_aud.add_argument("--out", default=None, help="Write report JSON to file")
    p_aud.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    p_aud.add_argument(
        "--fail-on-fail",
        dest="fail_on_fail",
        action="store_true",
        help="Exit with code 2 if overall=fail (code 1 if schema/load fails)",
    )
    p_aud.add_argument(
        "--fail-on-not-pass",
        dest="fail_on_not_pass",
        action="store_true",
        help="Exit with code 2 if overall!=pass (code 1 if schema/load fails)",
    )
    p_aud.set_defaults(func=cmd_audit)

    p_dir = sub.add_parser("audit-dir", help="Audit all claim YAML files under dirs/files/globs")
    p_dir.add_argument(
        "inputs",
        nargs="+",
        help="Files, directories, or globs (e.g. echostack/examples or claims/**/*.yml)",
    )
    p_dir.add_argument("--out-dir", default="_ci_out", help="Directory to write report JSON files")
    p_dir.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    p_dir.add_argument("--index", action="store_true", help="Write an index.json summary")
    p_dir.add_argument(
        "--fail-on-fail",
        dest="fail_on_fail",
        action="store_true",
        help="Exit with code 2 if any report has overall=fail (code 1 if schema/load fails)",
    )
    p_dir.add_argument(
        "--fail-on-not-pass",
        dest="fail_on_not_pass",
        action="store_true",
        help="Exit with code 2 if any report has overall!=pass (code 1 if schema/load fails)",
    )
    p_dir.set_defaults(func=cmd_audit_dir)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
