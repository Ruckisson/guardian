"""Tests for the command-line interface: output and exit codes."""

from collections import Counter
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli.main import EXIT_ERROR, EXIT_FINDINGS, app
from guardian.core.audit import run_audit
from guardian.core.models import Severity
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.rules.loader import load_rules
from guardian.core.rules.model import AREA_DESCRIPTIONS

FIXTURES = Path(__file__).parent / "fixtures" / "configs"
runner = CliRunner()


def test_audit_compliant_config_exits_zero() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "hardened_switch.cfg")])

    assert result.exit_code == 0
    assert "No findings" in result.output


def test_audit_with_findings_exits_one_and_sorts_by_severity() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "insecure_switch.cfg")])

    assert result.exit_code == EXIT_FINDINGS
    assert f"{len(run_audit(FIXTURES / 'insecure_switch.cfg'))} finding(s)" in result.output
    assert result.output.index("HIGH") < result.output.index("MEDIUM") < result.output.index("LOW")
    assert "Xq7-lab-write" not in result.output


def test_audit_works_from_any_folder(tmp_path, monkeypatch) -> None:
    config = (FIXTURES / "vty_ssh.cfg").resolve()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["audit", str(config)])

    assert result.exit_code == EXIT_FINDINGS
    assert "IOS-MGMT-002" in result.output


def test_audit_unknown_platform_exits_two() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "--platform", "junos"])

    assert result.exit_code == EXIT_ERROR
    assert "unknown platform 'junos'" in result.output


def test_audit_broken_rules_exits_two_with_reason(tmp_path) -> None:
    (tmp_path / "bad.yaml").write_text("id: IOS-TEST-001\nseverity: hihg\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "--rules", str(tmp_path)])

    assert result.exit_code == EXIT_ERROR
    assert "bad.yaml: title: missing required key" in result.output


def test_audit_missing_config_is_a_usage_error() -> None:
    result = runner.invoke(app, ["audit", "does-not-exist.cfg"])

    assert result.exit_code == 2


def test_rules_lists_bundled_rules() -> None:
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert "IOS-SNMP-001" in result.output
    bundled = load_rules(get_platform(DEFAULT_PLATFORM).rules_dir)
    assert f"{len(bundled)} rule(s)" in result.output


def test_rules_are_grouped_by_area_then_severity() -> None:
    result = runner.invoke(app, ["rules"], terminal_width=200)

    assert result.exit_code == 0
    headings = [
        line.strip()
        for line in result.output.splitlines()
        if line.split(":")[0] in AREA_DESCRIPTIONS
    ]
    expected_areas = ["AAA", "IF", "L2", "LOG", "MGMT", "NTP", "PASS", "SNMP", "SVC"]
    assert [h.split(":")[0] for h in headings] == expected_areas
    assert f"PASS: {AREA_DESCRIPTIONS['PASS']}" in result.output
    # Within a group the most severe rules come first, ties ordered by id.
    order = ["IOS-MGMT-001", "IOS-MGMT-006", "IOS-MGMT-002", "IOS-MGMT-005"]
    positions = [result.output.index(rule_id) for rule_id in order]
    assert positions == sorted(positions)


def test_rules_unknown_area_has_no_description(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: Hostname must be set\nseverity: low\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\nremediation: x\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["rules", "--rules", str(tmp_path)], terminal_width=200)

    assert result.exit_code == 0
    assert "TEST" in [line.strip() for line in result.output.splitlines()]
    assert "1 rule(s)" in result.output


def test_audit_groups_findings_by_rule() -> None:
    result = runner.invoke(
        app, ["audit", str(FIXTURES / "insecure_switch.cfg")], terminal_width=200
    )

    # Rule and title are printed once, each failing place below it.
    assert result.output.count("IOS-MGMT-001") == 1
    assert result.output.count("VTY lines must accept SSH only") == 1
    assert "→ line vty 0 4" in result.output
    assert "→ line vty 5 15" in result.output
    # The summary matches the audit itself, so new rules do not break this test.
    findings = run_audit(FIXTURES / "insecure_switch.cfg")
    counts = Counter(f.severity for f in findings)
    by_severity = ", ".join(f"{counts[s]} {s}" for s in reversed(Severity) if counts[s])
    rules_hit = len({f.rule_id for f in findings})
    assert f"{len(findings)} finding(s) in {rules_hit} rule(s): {by_severity}" in result.output
