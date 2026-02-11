from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the CLI via module invocation (works even if console-scripts aren't installed)."""
    cmd = [sys.executable, "-m", "echostack.cli", *args]
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def test_validate_passes_on_examples() -> None:
    for rel in [
        "echostack/examples/qhigt_alpha_claim.yml",
        "echostack/examples/qed_alpha_claim.yml",
        "echostack/examples/standard_model_alpha_claim.yml",
        "echostack/examples/adversarial_well_formed.yml",
    ]:
        p = _run(["validate", rel])
        assert p.returncode == 0, p.stderr


def test_validate_fails_on_invalid() -> None:
    p = _run(["validate", "echostack/examples/invalid_missing_fields.yml"])
    assert p.returncode != 0


def test_validate_explain_includes_schema_details() -> None:
    p = _run(["validate", "echostack/examples/invalid_missing_fields.yml", "--json", "--explain"])
    assert p.returncode != 0
    data = json.loads(p.stdout)
    assert data["status"] == "fail"
    assert data["issues"]
    assert "schema_path" in data["issues"][0]


def test_audit_qhigt_expected_pass() -> None:
    out = ROOT / "_ci_out" / "audit_qhigt_test.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    p = _run(["audit", "echostack/examples/qhigt_alpha_claim.yml", "--out", str(out)])
    assert p.returncode == 0, p.stderr

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["audit_version"] == "0.2.4"
    assert data["summary"]["overall"] == "pass"
    for lvl in ("E1", "E2", "E3", "E4", "E5"):
        assert data["criteria"][lvl]["status"] == "pass", (lvl, data["criteria"][lvl])


def test_audit_qed_expected_pass() -> None:
    out = ROOT / "_ci_out" / "audit_qed_test.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    p = _run(["audit", "echostack/examples/qed_alpha_claim.yml", "--out", str(out)])
    assert p.returncode == 0, p.stderr

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["audit_version"] == "0.2.4"
    assert data["summary"]["overall"] == "pass"
    for lvl in ("E1", "E2", "E3", "E4", "E5"):
        assert data["criteria"][lvl]["status"] == "pass", (lvl, data["criteria"][lvl])


def test_audit_dir_writes_reports_and_index() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir"
    if out_dir.exists():
        for p in out_dir.rglob("*"):
            if p.is_file():
                p.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)

    p = _run(["audit-dir", "echostack/examples", "--out-dir", str(out_dir), "--index"])
    assert p.returncode == 0, p.stderr

    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert "reports" in index
    assert any(r["claim_id"] == "qed_alpha_on_shell_ref_v1" for r in index["reports"])
    assert any(r["claim_id"] == "qhigt_alpha_v3_1" for r in index["reports"])


def test_audit_fail_on_fail_exit_codes() -> None:
    # adversarial example is overall fail -> exit code 2 when fail-on-fail
    p = _run(["audit", "echostack/examples/adversarial_well_formed.yml", "--fail-on-fail"])
    assert p.returncode == 2, p.stderr

    # qed is pass -> exit code 0
    p2 = _run(["audit", "echostack/examples/qed_alpha_claim.yml", "--fail-on-fail"])
    assert p2.returncode == 0, p2.stderr


def test_audit_invalid_claim_exit_code_1() -> None:
    p = _run(["audit", "echostack/examples/invalid_missing_fields.yml", "--fail-on-fail"])
    assert p.returncode == 1


def test_audit_dir_fail_on_fail_exit_codes() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir_fail_on_fail"
    out_dir.mkdir(parents=True, exist_ok=True)

    p = _run(
        [
            "audit-dir",
            "echostack/examples",
            "--out-dir",
            str(out_dir),
            "--index",
            "--fail-on-fail",
        ]
    )
    # examples include at least one overall fail, but also include an invalid manifest -> code 1
    assert p.returncode == 1, p.stderr
