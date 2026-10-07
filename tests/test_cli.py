"""Tests for the command-line interface: output and exit codes."""

from pathlib import Path

from typer.testing import CliRunner

from guardian.cli.main import EXIT_ERROR, EXIT_FINDINGS, app

FIXTURES = Path(__file__).parent / "fixtures" / "configs"
runner = CliRunner()


def test_audit_compliant_config_exits_zero() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "hardened_switch.cfg")])

    assert result.exit_code == 0
    assert "No findings" in result.output


def test_audit_with_findings_exits_one_and_sorts_by_severity() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "insecure_switch.cfg")])

    assert result.exit_code == EXIT_FINDINGS
    assert "16 finding(s)" in result.output
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
    assert "12 rule(s)" in result.output
