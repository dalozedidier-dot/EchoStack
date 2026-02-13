from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import echostack

ROOT = Path(__file__).resolve().parents[1]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the CLI via module invocation (works even if console-scripts aren't installed)."""
    cmd = [sys.executable, "-m", "echostack.cli", *args]
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def _clean_dir(out_dir: Path) -> None:
    if out_dir.exists():
        for p in out_dir.rglob("*"):
            if p.is_file():
                p.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)


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
    p = _run(
        [
            "validate",
            "echostack/examples/invalid_missing_fields.yml",
            "--json",
            "--explain",
        ]
    )
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
    assert data["audit_version"] == echostack.__version__
    assert data["input"]["path"] == "echostack/examples/qhigt_alpha_claim.yml"
    assert data["input"]["sha256"] == _sha256_file(
        ROOT / "echostack/examples/qhigt_alpha_claim.yml"
    )
    assert data["summary"]["overall"] == "pass"
    for lvl in ("E1", "E2", "E3", "E4", "E5"):
        assert data["criteria"][lvl]["status"] == "pass", (lvl, data["criteria"][lvl])


def test_audit_qed_expected_pass() -> None:
    out = ROOT / "_ci_out" / "audit_qed_test.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    p = _run(["audit", "echostack/examples/qed_alpha_claim.yml", "--out", str(out)])
    assert p.returncode == 0, p.stderr

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["audit_version"] == echostack.__version__
    assert data["summary"]["overall"] == "pass"
    for lvl in ("E1", "E2", "E3", "E4", "E5"):
        assert data["criteria"][lvl]["status"] == "pass", (lvl, data["criteria"][lvl])


def test_audit_dir_writes_reports_and_index() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir"
    _clean_dir(out_dir)

    p = _run(["audit-dir", "echostack/examples", "--out-dir", str(out_dir), "--index"])
    assert p.returncode == 0, p.stderr

    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["audit_version"] == echostack.__version__
    assert index["total_inputs"] >= 1
    assert index["processed"] == index["total_inputs"]
    assert index["stopped_early"] is False
    assert "reports" in index
    assert any(r["claim_id"] == "qed_alpha_on_shell_ref_v1" for r in index["reports"])
    assert any(r["claim_id"] == "qhigt_alpha_v3_1" for r in index["reports"])

    qed = next(r for r in index["reports"] if r["claim_id"] == "qed_alpha_on_shell_ref_v1")
    assert qed["input_sha256"] == _sha256_file(ROOT / "echostack/examples/qed_alpha_claim.yml")


def test_audit_fail_on_fail_exit_codes() -> None:
    p = _run(["audit", "echostack/examples/adversarial_well_formed.yml", "--fail-on-fail"])
    assert p.returncode == 2, p.stderr

    p2 = _run(["audit", "echostack/examples/qed_alpha_claim.yml", "--fail-on-fail"])
    assert p2.returncode == 0, p2.stderr


def test_audit_invalid_claim_exit_code_1() -> None:
    p = _run(["audit", "echostack/examples/invalid_missing_fields.yml", "--fail-on-fail"])
    assert p.returncode == 1


def test_audit_dir_fail_on_fail_exit_codes() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir_fail_on_fail"
    _clean_dir(out_dir)

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


def test_audit_dir_fail_fast_stops_on_first_fail() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir_fail_fast_first_fail"
    _clean_dir(out_dir)

    p = _run(
        [
            "audit-dir",
            "echostack/examples",
            "--out-dir",
            str(out_dir),
            "--index",
            "--fail-fast",
        ]
    )
    assert p.returncode == 2, p.stderr

    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["stopped_early"] is True
    assert index["processed"] == 1
    assert len(index["reports"]) == 1
    assert index["reports"][0]["claim_id"] == "adversarial_claim_well_formed"


def test_audit_dir_fail_fast_stops_on_invalid() -> None:
    out_dir = ROOT / "_ci_out" / "audit_dir_fail_fast_invalid"
    _clean_dir(out_dir)

    p = _run(
        [
            "audit-dir",
            "echostack/examples/invalid_missing_fields.yml",
            "echostack/examples/qed_alpha_claim.yml",
            "--out-dir",
            str(out_dir),
            "--index",
            "--fail-fast",
        ]
    )
    assert p.returncode == 1, p.stderr

    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["stopped_early"] is True
    assert index["processed"] == 1
    assert len(index["reports"]) == 1
    assert index["reports"][0]["claim_id"] == "unknown"


def test_init_creates_schema_valid_claim(tmp_path: Path) -> None:
    out = tmp_path / "new_claim.yml"

    p = _run(
        [
            "init",
            str(out),
            "--claim-id",
            "my_claim_v1",
            "--source",
            "zenodo:999999",
        ]
    )
    assert p.returncode == 0, p.stderr
    assert out.exists()

    p2 = _run(["validate", str(out)])
    assert p2.returncode == 0, p2.stderr

    p3 = _run(["init", str(out)])
    assert p3.returncode != 0

    p4 = _run(["init", str(out), "--force"])
    assert p4.returncode == 0, p4.stderr
