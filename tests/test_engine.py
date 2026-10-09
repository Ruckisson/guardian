"""Tests for every scope and check type the engine supports."""

import pytest

from guardian.core.models import Severity, Status
from guardian.core.parsers.cisco import parse
from guardian.core.rules import custom
from guardian.core.rules.custom import NotApplicable
from guardian.core.rules.engine import GLOBAL_TARGET, evaluate, evaluate_rule
from guardian.core.rules.loader import parse_rule


def make_rule(scope, check, **extra):
    data = {
        "id": "TEST-RULE-001",
        "title": "Test rule",
        "severity": "medium",
        "scope": scope,
        "check": check,
        "rationale": "Because.",
        "remediation": {"recommended_change": ["fix it"], "before_you_apply": ["Check."]},
        "references": {"stig": [], "nist_800_53": [], "cisco_guide": None, "cisa": False},
    }
    data.update(extra)
    return parse_rule(data)


def targets(rule, text):
    return [f.target for f in evaluate(rule, parse(text))]


# ------------------------------------------------------------------ scope


def test_global_scope_reports_global_target() -> None:
    rule = make_rule("global", {"must_exist": "^service timestamps log datetime"})

    assert targets(rule, "hostname SW1\n") == [GLOBAL_TARGET]
    assert targets(rule, "service timestamps log datetime msec\n") == []


def test_global_scope_ignores_nested_lines() -> None:
    rule = make_rule("global", {"must_not_exist": "^shutdown$"})

    assert targets(rule, "interface Ethernet0/1\n shutdown\n") == []


def test_path_selects_blocks_by_text() -> None:
    rule = make_rule({"path": "^line vty "}, {"must_exist": "^transport input ssh$"})

    text = "line con 0\nline vty 0 4\n transport input ssh\nline vty 5 15\n"
    assert targets(rule, text) == ["line vty 5 15"]


def test_nested_path_and_readable_target() -> None:
    rule = make_rule(
        {"path": ["^router bgp ", "^address-family "]},
        {"must_exist": "^neighbor \\S+ activate$"},
    )
    text = (
        "router bgp 65000\n"
        " address-family ipv4\n"
        "  neighbor 10.0.0.1 activate\n"
        " address-family ipv6\n"
        "  network 2001:db8::/32\n"
    )

    assert targets(rule, text) == ["router bgp 65000 > address-family ipv6"]


def test_has_child_and_not_has_child_filters() -> None:
    rule = make_rule(
        {
            "path": "^interface ",
            "has_child": "^switchport mode access$",
            "not_has_child": "^shutdown$",
        },
        {"must_exist": "^switchport port-security$"},
    )
    text = (
        "interface Ethernet0/0\n switchport mode trunk\n"
        "interface Ethernet0/1\n switchport mode access\n"
        "interface Ethernet0/2\n switchport mode access\n shutdown\n"
        "interface Ethernet0/3\n switchport mode access\n switchport port-security\n"
        "interface Vlan1\n"
    )

    assert targets(rule, text) == ["interface Ethernet0/1"]


def test_has_child_list_requires_all() -> None:
    rule = make_rule(
        {"path": "^interface ", "has_child": ["^switchport mode access$", "^description "]},
        {"must_exist": "^switchport port-security$"},
    )
    text = (
        "interface Ethernet0/1\n switchport mode access\n"
        "interface Ethernet0/2\n description HOST\n switchport mode access\n"
    )

    assert targets(rule, text) == ["interface Ethernet0/2"]


def test_no_matching_blocks_means_no_findings() -> None:
    rule = make_rule({"path": "^line vty "}, {"must_exist": "^transport input ssh$"})

    assert targets(rule, "hostname SW1\n") == []


# ------------------------------------------------------------------ checks


def test_must_not_exist_global_reports_each_line() -> None:
    rule = make_rule("global", {"must_not_exist": "^ip http (secure-)?server$"})

    text = "ip http server\nip http secure-server\nhostname SW1\n"
    assert targets(rule, text) == ["ip http server", "ip http secure-server"]


def test_must_not_exist_in_block_reports_block_once() -> None:
    rule = make_rule({"path": "^line vty "}, {"must_not_exist": "^transport input .*telnet"})

    text = "line vty 0 4\n transport input telnet\n transport input telnet ssh\n"
    assert targets(rule, text) == ["line vty 0 4"]


def test_each_must_match() -> None:
    rule = make_rule(
        "global",
        {"each_must_match": {"select": "^ntp server ", "pattern": " key \\d+$"}},
    )
    text = "ntp server 10.0.0.1 key 1\nntp server 10.0.0.2\nhostname SW1\n"

    assert targets(rule, text) == ["ntp server 10.0.0.2"]


def test_each_must_match_with_nothing_selected_passes() -> None:
    rule = make_rule(
        "global",
        {"each_must_match": {"select": "^ntp server ", "pattern": " key \\d+$"}},
    )

    assert targets(rule, "hostname SW1\n") == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("security passwords min-length 12\n", []),
        ("security passwords min-length 10\n", []),
        ("security passwords min-length 6\n", [GLOBAL_TARGET]),
        ("hostname SW1\n", [GLOBAL_TARGET]),
    ],
)
def test_value_min_and_missing_fails(text, expected) -> None:
    rule = make_rule(
        "global",
        {"value": {"pattern": "^security passwords min-length (\\d+)$", "min": 10}},
    )

    assert targets(rule, text) == expected


@pytest.mark.parametrize(
    ("timeout", "expected"),
    [
        ("exec-timeout 5 0", []),
        ("exec-timeout 10", []),
        ("exec-timeout 11 0", ["line vty 0 4"]),
        ("", []),
    ],
)
def test_value_max_and_missing_passes(timeout, expected) -> None:
    rule = make_rule(
        {"path": "^line vty "},
        {"value": {"pattern": "^exec-timeout (\\d+)", "max": 10, "if_missing": "pass"}},
    )

    assert targets(rule, f"line vty 0 4\n {timeout}\n") == expected


def test_value_between_min_and_max() -> None:
    rule = make_rule(
        "global", {"value": {"pattern": "^logging buffered (\\d+)", "min": 4096, "max": 1000000}}
    )

    assert targets(rule, "logging buffered 64000\n") == []
    assert targets(rule, "logging buffered 1024\n") == [GLOBAL_TARGET]
    assert targets(rule, "logging buffered 9999999\n") == [GLOBAL_TARGET]


REFERENCE = {
    "reference": {
        "capture": "^access-class (?P<acl>\\S+) in$",
        "must_exist": "^(ip access-list (standard|extended) {acl}$|access-list {acl} )",
    }
}


@pytest.mark.parametrize(
    ("acl_definition", "expected"),
    [
        ("ip access-list standard MGMT\n permit any\n", []),
        ("access-list MGMT permit any\n", []),
        ("ip access-list standard OTHER\n", ["line vty 0 4"]),
        ("ip access-list standard MGMT-OLD\n", ["line vty 0 4"]),
        ("", ["line vty 0 4"]),
    ],
)
def test_reference(acl_definition, expected) -> None:
    rule = make_rule({"path": "^line vty "}, REFERENCE)

    assert targets(rule, f"{acl_definition}line vty 0 4\n access-class MGMT in\n") == expected


def test_reference_value_is_escaped() -> None:
    rule = make_rule({"path": "^line vty "}, REFERENCE)
    text = "ip access-list standard AXB\nline vty 0 4\n access-class A.B in\n"

    assert targets(rule, text) == ["line vty 0 4"]


def test_reference_without_capture_passes() -> None:
    rule = make_rule({"path": "^line vty "}, REFERENCE)

    assert targets(rule, "line vty 0 4\n transport input ssh\n") == []


def test_reference_template_keeps_regex_quantifiers() -> None:
    rule = make_rule(
        {"path": "^line vty "},
        {
            "reference": {
                "capture": "^access-class (?P<acl>\\d+) in$",
                "must_exist": "^access-list {acl} \\w{4,6} ",
            }
        },
    )

    assert targets(rule, "access-list 10 permit any\nline vty 0 4\n access-class 10 in\n") == []


def test_python_check(monkeypatch) -> None:
    monkeypatch.setitem(
        custom.CHECKS,
        "has-two-vty-blocks",
        lambda block, config: (
            len([line for line in config if line.text.startswith("line vty")]) == 2
        ),
    )
    rule = make_rule("global", {"python": "has-two-vty-blocks"})

    assert targets(rule, "line vty 0 4\nline vty 5 15\n") == []
    assert targets(rule, "line vty 0 4\n") == [GLOBAL_TARGET]


def test_register_rejects_duplicate_names(monkeypatch) -> None:
    monkeypatch.setattr(custom, "CHECKS", {})
    custom.register("x")(lambda block, config: True)

    with pytest.raises(ValueError, match="already registered"):
        custom.register("x")(lambda block, config: True)


# ------------------------------------------------------------------ findings


def test_finding_fields_and_redacted_target() -> None:
    rule = make_rule("global", {"must_not_exist": "^snmp-server community "}, severity="high")

    (finding,) = evaluate(rule, parse("snmp-server community s3cret RO\n"))

    assert finding.rule_id == "TEST-RULE-001"
    assert finding.severity is Severity.HIGH
    assert finding.title == "Test rule"
    assert "s3cret" not in finding.target
    assert finding.target == "snmp-server community <redacted> RO"


def test_severity_rank_orders_low_to_critical() -> None:
    ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]

    assert ranks == [0, 1, 2, 3]


def test_value_that_is_not_a_number_is_a_finding() -> None:
    rule = make_rule("global", {"value": {"pattern": "^logging buffered (\\S+)", "max": 10}})

    assert targets(rule, "logging buffered informational\n") == [GLOBAL_TARGET]


# ------------------------------------------------------------------ status


def status(rule, text):
    outcome = evaluate_rule(rule, parse(text))
    return outcome.status, outcome.reason


def test_status_pass_and_fail() -> None:
    rule = make_rule({"path": "^line vty "}, {"must_exist": "^transport input ssh$"})

    assert status(rule, "line vty 0 4\n transport input ssh\n") == (Status.PASS, "")
    assert status(rule, "line vty 0 4\n")[0] is Status.FAIL


def test_empty_scope_is_not_applicable_with_reason() -> None:
    rule = make_rule({"path": "^line vty "}, {"must_exist": "^transport input ssh$"})

    result, reason = status(rule, "hostname SW1\n")

    assert result is Status.NOT_APPLICABLE
    assert "^line vty " in reason


def test_applies_to_gives_readable_reason() -> None:
    rule = make_rule(
        {"path": "^line vty "}, {"must_exist": "^transport input ssh$"}, applies_to="VTY lines"
    )

    assert status(rule, "hostname SW1\n") == (Status.NOT_APPLICABLE, "the config has no VTY lines")


def test_custom_check_can_be_not_applicable(monkeypatch) -> None:
    monkeypatch.setitem(
        custom.CHECKS,
        "only-with-http",
        lambda block, config: (
            any(line.text == "ip http server" for line in config) or NotApplicable("no HTTP")
        ),
    )
    rule = make_rule("global", {"python": "only-with-http"})

    assert status(rule, "hostname SW1\n") == (Status.NOT_APPLICABLE, "no HTTP")
    assert status(rule, "ip http server\n") == (Status.PASS, "")
    assert evaluate(rule, parse("hostname SW1\n")) == []


def test_global_check_with_nothing_to_check_passes() -> None:
    # each_must_match with no selected lines: nothing is wrong, the rule passes.
    rule = make_rule(
        "global", {"each_must_match": {"select": "^ntp server ", "pattern": " key \\d+$"}}
    )

    assert status(rule, "hostname SW1\n") == (Status.PASS, "")


def test_status_values_are_stable() -> None:
    assert [s.value for s in Status] == ["pass", "fail", "na"]
