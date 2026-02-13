from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

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


def _yaml_scalar(value: Any) -> str:
    """Return a YAML scalar.

    We use JSON-style quoted strings for safety, which are valid YAML.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _render_init_template(
    *,
    claim_id: str,
    source: str,
    date: str | None,
    title: str | None,
    author: str | None,
    abstract: str | None,
    theory: str,
    regime: str,
    scale_q: str,
    scheme: str,
) -> str:
    # Must satisfy the JSON Schema. Defaults are schema-valid but intentionally
    # incomplete for E2/E3 until the author specifies scale and scheme.
    lines: list[str] = []

    lines.append(f"claim_id: {_yaml_scalar(claim_id)}")
    lines.append(f"title: {_yaml_scalar(title)}")
    lines.append(f"abstract: {_yaml_scalar(abstract)}")
    lines.append(f"author: {_yaml_scalar(author)}")
    lines.append(f"source: {_yaml_scalar(source)}")
    lines.append(f"date: {_yaml_scalar(date)}")
    lines.append("")

    lines.append("assertions:")
    lines.append("  - id: A1")
    lines.append(f"    statement: {_yaml_scalar('State the core claim in one sentence.')} ")
    lines.append("")

    lines.append("domain:")
    lines.append(f"  theory: {_yaml_scalar(theory)}")
    lines.append(f"  regime: {_yaml_scalar(regime)}")
    lines.append(f"  scale_Q: {_yaml_scalar(scale_q)}")
    lines.append(f"  renormalization_scheme: {_yaml_scalar(scheme)}")
    lines.append("  conventions: null")
    lines.append("")

    lines.append("parameters:")
    lines.append("  alpha:")
    lines.append("    status: claimed_output")
    lines.append("    scale_dependent: unspecified")
    lines.append("    boundary_condition: claimed_closed")
    lines.append("    notes: null")
    lines.append("")

    lines.append("methods:")
    lines.append("  approach: [geometric_construction]")
    lines.append("  closure_mechanism: null")
    lines.append("  calibration: null")
    lines.append("")

    lines.append("predictions:")
    lines.append("  - id: P1")
    lines.append(f"    target: {_yaml_scalar('alpha_inverse')}")
    lines.append("    value: 137.035999")
    lines.append("    is_independent: false")
    lines.append(
        f"    test_protocol: {_yaml_scalar('Describe an independent measurement protocol and expected comparison.')}"
    )
    lines.append("")

    return "\n".join(lines)


def cmd_init(args: argparse.Namespace) -> int:
    out_path = Path(args.out)

    if out_path.exists() and not args.force:
        sys.stderr.write(f"ERROR: Refusing to overwrite existing file: {out_path} (use --force)\n")
        return EXIT_INVALID

    content = _render_init_template(
        claim_id=args.claim_id,
        source=args.source,
        date=args.date,
        title=args.title,
        author=args.author,
        abstract=args.abstract,
        theory=args.theory,
        regime=args.regime,
        scale_q=args.scale_q,
        scheme=args.scheme,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")
    sys.stdout.write(str(out_path) + "\n")
    return EXIT_OK


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

    total_inputs = len(claim_paths)
    processed = 0
    stopped_early = False

    index: list[dict[str, object]] = []
    any_invalid = False
    any_fail = False
    any_not_pass = False

    for pth in claim_paths:
        processed += 1

        try:
            claim = _load_claim(pth)
        except Exception as e:
            any_invalid = True
            index.append(
                {
                    "claim_id": None,
                    "path": str(pth),
                    "report": None,
                    "overall": "error",
                    "validation": "fail",
                    "error": str(e),
                }
            )
            if args.fail_fast:
                stopped_early = True
                break
            continue

        report = audit_claim(claim)
        slug = _safe_slug(str(report.get("claim_id", pth.stem)))
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

        # Keep index portable: report path is relative to out_dir, never absolute.
        report_rel = out_path.name
        input_block = report.get("input", {}) if isinstance(report.get("input", {}), dict) else {}
        criteria_block = (
            report.get("criteria", {}) if isinstance(report.get("criteria", {}), dict) else {}
        )

        index.append(
            {
                "claim_id": report.get("claim_id"),
                "path": str(pth),
                "report": report_rel,
                "audit_version": report.get("audit_version"),
                "input_sha256": input_block.get("sha256"),
                "overall": overall,
                "validation": validation_status,
                "criteria": {
                    k: v.get("status") for k, v in criteria_block.items() if isinstance(v, dict)
                },
            }
        )

        if args.fail_fast and (validation_status != "pass" or overall == "fail"):
            stopped_early = True
            break

    # Stable ordering for diff-friendly CI artifacts.
    index_sorted = sorted(
        index,
        key=lambda r: (r.get("claim_id") is None, str(r.get("claim_id") or "")),
    )

    if args.index:
        _write_json(
            {
                "audit_version": __version__,
                "total_inputs": total_inputs,
                "processed": processed,
                "stopped_early": stopped_early,
                "reports": index_sorted,
            },
            out=out_dir / "index.json",
            pretty=True,
        )

    # --fail-fast: stop at first invalid or overall=fail and return non-zero.
    if args.fail_fast:
        if any_invalid:
            return EXIT_INVALID
        if any_fail:
            return EXIT_AUDIT_FAIL
        return EXIT_OK

    # --fail-on-*: audit everything and only then enforce exit codes.
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

    p_init = sub.add_parser("init", help="Create a schema-valid claim manifest template")
    p_init.add_argument(
        "out",
        nargs="?",
        default="claim.yml",
        help="Output path for the new claim YAML (default: claim.yml)",
    )
    p_init.add_argument("--force", action="store_true", help="Overwrite existing file")
    p_init.add_argument("--claim-id", default="example_claim", help="Claim identifier")
    p_init.add_argument("--source", default="zenodo:000000", help="Source reference")
    p_init.add_argument("--date", default=None, help="ISO date YYYY-MM-DD (optional)")
    p_init.add_argument("--title", default=None, help="Optional title")
    p_init.add_argument("--abstract", default=None, help="Optional abstract")
    p_init.add_argument("--author", default=None, help="Optional author")
    p_init.add_argument("--theory", default="QED / beyond-SM", help="Domain theory")
    p_init.add_argument("--regime", default="IR / low-energy", help="Domain regime")
    p_init.add_argument(
        "--scale-q",
        dest="scale_q",
        default="unspecified",
        help="Energy scale Q (use 'unspecified' if unknown)",
    )
    p_init.add_argument(
        "--scheme",
        dest="scheme",
        default="unspecified",
        help="Renormalization scheme (use 'unspecified' if unknown)",
    )
    p_init.set_defaults(func=cmd_init)

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
    p_dir.add_argument(
        "--fail-fast",
        dest="fail_fast",
        action="store_true",
        help="Stop at the first invalid input or overall=fail (exit code 1 for invalid, 2 for fail)",
    )
    p_dir.set_defaults(func=cmd_audit_dir)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
