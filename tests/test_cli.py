"""Tests for the command-line interface: output and exit codes."""

import json
import stat
from collections import Counter

import pytest
from typer.testing import CliRunner

from conftest import FIXTURES
from guardian.cli.main import EXIT_ERROR, EXIT_FINDINGS, app
from guardian.core.audit import run_audit
from guardian.core.models import Severity
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.rules.loader import load_rules
from guardian.core.rules.model import AREA_DESCRIPTIONS

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
    order = ["IOS-MGMT-001", "IOS-MGMT-006", "IOS-MGMT-002", "IOS-MGMT-008"]
    positions = [result.output.index(rule_id) for rule_id in order]
    assert positions == sorted(positions)


def test_rules_unknown_area_has_no_description(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: Hostname must be set\nseverity: low\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\n"
        "remediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references: {stig: [], nist_800_53: [], cisco_guide: null, cisa: false}\n",
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


# ------------------------------------------------------- formats and exit codes


def test_json_format_prints_only_json() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "insecure_switch.cfg"), "-f", "json"])

    assert result.exit_code == EXIT_FINDINGS
    data = json.loads(result.stdout)  # nothing but JSON on stdout
    assert data["input"]["file"] == "insecure_switch.cfg"
    assert "Xq7-lab-write" not in result.stdout


def test_html_format_prints_only_html() -> None:
    result = runner.invoke(
        app, ["audit", str(FIXTURES / "insecure_switch.cfg"), "--format", "html"]
    )

    assert result.stdout.startswith("<!doctype html>")
    assert result.stdout.rstrip().endswith("</html>")
    assert "✘" not in result.stdout


@pytest.mark.parametrize("fmt", ["text", "json", "html"])
def test_output_file_is_private_and_stdout_stays_empty(tmp_path, fmt) -> None:
    out = tmp_path / f"report.{fmt}"

    result = runner.invoke(
        app, ["audit", str(FIXTURES / "insecure_switch.cfg"), "-f", fmt, "-o", str(out)]
    )

    assert result.exit_code == EXIT_FINDINGS
    assert result.stdout == ""
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "IOS-MGMT-001" in out.read_text(encoding="utf-8")


def test_output_to_missing_directory_exits_two(tmp_path) -> None:
    out = tmp_path / "missing" / "report.json"

    result = runner.invoke(
        app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "-f", "json", "-o", str(out)]
    )

    assert result.exit_code == EXIT_ERROR
    assert "cannot write" in result.stderr


@pytest.mark.parametrize(
    ("fail_on", "code"),
    [("high", 0), ("medium", EXIT_FINDINGS), ("low", EXIT_FINDINGS)],
)
def test_fail_on_threshold(tmp_path, fail_on, code) -> None:
    # One medium finding: below "high", at "medium", above "low".
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: Hostname must be set\nseverity: medium\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\n"
        "remediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references: {stig: [], nist_800_53: [], cisco_guide: null, cisa: false}\n",
        encoding="utf-8",
    )
    config = tmp_path / "c.cfg"
    config.write_text("version 15.1\n", encoding="utf-8")

    result = runner.invoke(
        app, ["audit", str(config), "--rules", str(tmp_path), "--fail-on", fail_on]
    )

    assert result.exit_code == code
    assert "LAB-TEST-001" in result.stdout  # findings below the threshold are still shown


def test_fail_on_default_counts_every_finding() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "insecure_router.cfg"), "-f", "json"])

    assert result.exit_code == EXIT_FINDINGS
    assert runner.invoke(app, ["audit", str(FIXTURES / "hardened_switch.cfg")]).exit_code == 0


def test_fail_on_rejects_unknown_level() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "--fail-on", "info"])

    assert result.exit_code == EXIT_ERROR


def test_unreadable_config_exits_two(tmp_path) -> None:
    config = tmp_path / "binary.cfg"
    config.write_bytes(b"\xff\xfe\x00bad")

    result = runner.invoke(app, ["audit", str(config)])

    assert result.exit_code == EXIT_ERROR
    assert "cannot read" in result.stderr


@pytest.mark.parametrize("content", ["", "\n\n", "!\n! only comments\n!\nend\n"])
def test_config_without_lines_is_an_error_not_a_pass(tmp_path, content) -> None:
    # Missing data must never pass: an empty file would pass every must_not_exist rule.
    config = tmp_path / "empty.cfg"
    config.write_text(content, encoding="utf-8")

    result = runner.invoke(app, ["audit", str(config), "-f", "json"])

    assert result.exit_code == EXIT_ERROR
    assert result.stdout == ""
    assert "no configuration lines" in result.stderr


def test_output_symlink_is_refused(tmp_path) -> None:
    target = tmp_path / "important.txt"
    target.write_text("keep me", encoding="utf-8")
    link = tmp_path / "report.html"
    link.symlink_to(target)

    result = runner.invoke(
        app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "-f", "html", "-o", str(link)]
    )

    assert result.exit_code == EXIT_ERROR
    assert "symbolic link" in result.stderr
    assert target.read_text(encoding="utf-8") == "keep me"
    assert link.is_symlink()


@pytest.mark.parametrize("fmt", ["text", "json", "html"])
def test_output_over_the_input_is_refused(tmp_path, fmt) -> None:
    config = tmp_path / "r1.cfg"
    original = (FIXTURES / "vty_ssh.cfg").read_text(encoding="utf-8")
    config.write_text(original, encoding="utf-8")
    sneaky = tmp_path / "sub" / ".." / "r1.cfg"
    (tmp_path / "sub").mkdir()

    result = runner.invoke(app, ["audit", str(config), "-f", fmt, "-o", str(sneaky)])

    assert result.exit_code == EXIT_ERROR
    assert "over the input file" in result.stderr
    assert config.read_text(encoding="utf-8") == original


def test_output_leaves_no_temporary_files(tmp_path) -> None:
    out = tmp_path / "r.json"

    runner.invoke(app, ["audit", str(FIXTURES / "vty_ssh.cfg"), "-f", "json", "-o", str(out)])

    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_file_name_with_markup_is_printed_literally(tmp_path) -> None:
    config = tmp_path / "[red]x.cfg"
    config.write_text((FIXTURES / "vty_ssh.cfg").read_text(encoding="utf-8"), encoding="utf-8")

    result = runner.invoke(app, ["audit", str(config)], terminal_width=200)

    assert "Audit: [red]x.cfg" in result.stdout


def test_rule_title_with_markup_is_printed_literally(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: '[bold red]Hostname[/] must be set'\nseverity: low\n"
        "scope: global\ncheck:\n  must_exist: '^hostname '\nrationale: x\n"
        "remediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references: {stig: [], nist_800_53: [], cisco_guide: null, cisa: false}\n",
        encoding="utf-8",
    )
    config = tmp_path / "c.cfg"
    config.write_text("version 15.1\n", encoding="utf-8")

    audit = runner.invoke(app, ["audit", str(config), "--rules", str(tmp_path)], terminal_width=200)
    rules = runner.invoke(app, ["rules", "--rules", str(tmp_path)], terminal_width=200)

    assert "[bold red]Hostname[/] must be set" in audit.stdout
    assert "[bold red]Hostname[/] must be set" in rules.stdout


def test_text_output_shows_rule_counts() -> None:
    result = runner.invoke(app, ["audit", str(FIXTURES / "hardened_switch.cfg")])

    assert "No findings" in result.stdout
    assert " pass, 0 fail, " in result.stdout


def test_nothing_checked_is_not_compliant(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: VTY lines need SSH\nseverity: low\n"
        "scope: {path: '^line vty '}\ncheck:\n  must_exist: '^transport input ssh$'\n"
        "rationale: x\nremediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references: {stig: [], nist_800_53: [], cisco_guide: null, cisa: false}\n",
        encoding="utf-8",
    )
    config = tmp_path / "c.cfg"
    config.write_text("hostname R1\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(config), "--rules", str(tmp_path)])

    assert "Nothing was checked" in result.stdout
    assert "compliant" not in result.stdout


def test_config_over_the_size_limit_exits_two(tmp_path, monkeypatch) -> None:
    import guardian.core.audit as audit_module

    monkeypatch.setattr(audit_module, "MAX_CONFIG_BYTES", 100)
    config = tmp_path / "big.cfg"
    config.write_text("hostname R1\n" * 20, encoding="utf-8")

    result = runner.invoke(app, ["audit", str(config), "-f", "json"])

    assert result.exit_code == EXIT_ERROR
    assert result.stdout == ""
    assert "limit" in result.stderr


@pytest.mark.parametrize("command", ["rules", "audit"])
def test_unreadable_rule_file_is_reported_without_traceback(tmp_path, command) -> None:
    (tmp_path / "bad.yaml").write_bytes(b"id: \xff\xfe broken\n")
    args = [command, "--rules", str(tmp_path)]
    if command == "audit":
        args.insert(1, str(FIXTURES / "vty_ssh.cfg"))

    result = runner.invoke(app, args)

    assert result.exit_code == EXIT_ERROR
    assert "bad.yaml: cannot read the rule file" in result.stderr
    assert "Traceback" not in result.output
    assert "vty_ssh.cfg" not in result.stderr  # the config is not blamed


def test_fail_on_critical(tmp_path) -> None:
    config = tmp_path / "r.cfg"
    config.write_text("line vty 0 4\n transport input telnet\n", encoding="utf-8")
    only_high = tmp_path / "h.cfg"
    only_high.write_text((FIXTURES / "hardened_switch.cfg").read_text() + "ip http server\n")

    assert runner.invoke(app, ["audit", str(config), "--fail-on", "critical"]).exit_code == 1
    assert runner.invoke(app, ["audit", str(only_high), "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, ["audit", str(only_high), "--fail-on", "high"]).exit_code == 1
