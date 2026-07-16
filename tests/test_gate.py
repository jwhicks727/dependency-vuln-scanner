"""
test_gate.py - The gate's policy, expressed as tests.

These tests ARE the specification. Write gate.py until every one passes.
Run with:  python -m pytest tests/ -v

The policy under test:
  - A finding BREACHES the gate if it is KEV-listed, OR its EPSS score
    is at or above the threshold (default 0.10, inclusive).
  - Everything else is a WARNING: reported, but does not fail the build.
  - --prod-only downgrades breaches on dev dependencies to warnings
    (build tooling risk is real but is not production attack surface).
  - Exit codes: 0 = pass (warnings allowed), 1 = gate breach,
    2 = usage/data error (missing file, malformed JSON). CI must be able
    to tell "policy failed" apart from "the tool itself broke."
"""
import json
import sys
import pytest

sys.path.insert(0, ".")  # allow `import gate` when tests/ is a subfolder
import gate


def f(**kw):
    """Tiny finding factory with safe defaults."""
    base = {
        "package": "example", "ecosystem": "npm", "installed_version": "1.0.0",
        "dependency_type": "prod", "cve_id": "CVE-2020-00001",
        "kev": "false", "epss_score": "", "risk_tier": "UNSCORED",
    }
    base.update(kw)
    return base


# ---------- evaluate(): the pure policy function ----------

def test_kev_finding_breaches():
    breaches, warnings = gate.evaluate([f(kev="true")])
    assert len(breaches) == 1 and not warnings

def test_epss_at_threshold_breaches():
    # Boundary is inclusive: exactly 0.10 fails the build.
    breaches, _ = gate.evaluate([f(epss_score="0.10")])
    assert len(breaches) == 1

def test_epss_below_threshold_warns_only():
    breaches, warnings = gate.evaluate([f(epss_score="0.09999")])
    assert not breaches and len(warnings) == 1

def test_unscored_finding_warns_only():
    # Blank EPSS (GHSA-only id, or EPSS has no data) must never breach.
    breaches, warnings = gate.evaluate([f(epss_score="")])
    assert not breaches and len(warnings) == 1

def test_custom_threshold_respected():
    breaches, _ = gate.evaluate([f(epss_score="0.05")], epss_threshold=0.05)
    assert len(breaches) == 1

def test_empty_findings_pass():
    breaches, warnings = gate.evaluate([])
    assert not breaches and not warnings

def test_kev_wins_even_with_blank_epss():
    breaches, _ = gate.evaluate([f(kev="true", epss_score="")])
    assert len(breaches) == 1

def test_breach_carries_reasons():
    # Each breach must say WHY - the summary and PR comment depend on it.
    breaches, _ = gate.evaluate([f(kev="true", epss_score="0.97")])
    finding, reasons = breaches[0]
    assert any("KEV" in r for r in reasons)
    assert any("EPSS" in r for r in reasons)


# ---------- --prod-only policy knob ----------

def test_prod_only_downgrades_dev_breach():
    breaches, warnings = gate.evaluate(
        [f(kev="true", dependency_type="dev")], prod_only=True)
    assert not breaches and len(warnings) == 1

def test_prod_only_still_fails_prod_breach():
    breaches, _ = gate.evaluate(
        [f(kev="true", dependency_type="prod")], prod_only=True)
    assert len(breaches) == 1

def test_prod_only_off_by_default_dev_kev_breaches():
    breaches, _ = gate.evaluate([f(kev="true", dependency_type="dev")])
    assert len(breaches) == 1


# ---------- CLI behavior and exit codes ----------

def run_cli(tmp_path, findings, *extra_args):
    p = tmp_path / "enriched.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    argv = ["gate.py", "--input", str(p), *extra_args]
    old = sys.argv
    sys.argv = argv
    try:
        with pytest.raises(SystemExit) as exc:
            gate.main()
        return exc.value.code
    finally:
        sys.argv = old

def test_exit_0_when_clean(tmp_path):
    assert run_cli(tmp_path, [f(epss_score="0.001")]) == 0

def test_exit_1_on_breach(tmp_path):
    assert run_cli(tmp_path, [f(kev="true")]) == 1

def test_exit_2_when_input_missing(tmp_path):
    argv = ["gate.py", "--input", str(tmp_path / "nope.json")]
    old = sys.argv
    sys.argv = argv
    try:
        with pytest.raises(SystemExit) as exc:
            gate.main()
        assert exc.value.code == 2
    finally:
        sys.argv = old

def test_exit_2_on_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    argv = ["gate.py", "--input", str(p)]
    old = sys.argv
    sys.argv = argv
    try:
        with pytest.raises(SystemExit) as exc:
            gate.main()
        assert exc.value.code == 2
    finally:
        sys.argv = old

def test_markdown_summary_written(tmp_path):
    md = tmp_path / "summary.md"
    code = run_cli(tmp_path, [f(kev="true")],
                   "--markdown-summary", str(md))
    assert code == 1
    text = md.read_text(encoding="utf-8")
    assert "KEV" in text and "example" in text
