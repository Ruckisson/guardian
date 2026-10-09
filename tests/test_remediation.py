"""Tests for remediations: YAML validation, config variables and secrets."""

import re

import pytest

from conftest import FIXTURES, SECRETS
from guardian.core.audit import audit_file
from guardian.core.models import ConfigLine, Remediation
from guardian.core.parsers.cisco import parse
from guardian.core.platforms import PLATFORMS
from guardian.core.rules.engine import evaluate
from guardian.core.rules.loader import RuleError, load_rules, parse_rule
from guardian.core.rules.remediation import (
    UNSAFE_VALUE_NOTE,
    VARIABLES,
    Context,
    is_safe,
    render,
)

BUNDLED = [rule for platform in PLATFORMS.values() for rule in load_rules(platform.rules_dir)]
ALL_FIXTURES = sorted(FIXTURES.glob("*.cfg"))

VALID = {
    "id": "IOS-TEST-001",
    "title": "Test rule",
    "severity": "low",
    "scope": {"path": "^interface "},
    "check": {"must_exist": "^no ip proxy-arp$"},
    "rationale": "Because.",
    "remediation": {
        "recommended_change": ["{block}", " no ip proxy-arp"],
        "before_you_apply": ["Check `show ip arp {interface}`."],
    },
    "references": {"stig": [], "nist_800_53": [], "cisco_guide": None, "cisa": False},
}


def problems(remediation, scope=None) -> str:
    data = {**VALID, "remediation": remediation}
    if scope is not None:
        data["scope"] = scope
    with pytest.raises(RuleError) as exc:
        parse_rule(data, "rule.yaml")
    return "\n".join(exc.value.problems)


def texts(r: Remediation) -> list[str]:
    """Every string of a rendered remediation."""
    out = [*r.recommended_change, *r.before_you_apply, *r.notes]
    if r.if_service_needed:
        out += [r.if_service_needed.text, *r.if_service_needed.commands]
    return out


# ----------------------------------------------------------- bundled rules


@pytest.mark.parametrize("rule", [pytest.param(r, id=r.id) for r in BUNDLED])
def test_every_rule_has_recommended_change_and_before_you_apply(rule) -> None:
    spec = rule.remediation
    assert spec.recommended_change and all(v.commands for v in spec.recommended_change)
    assert spec.before_you_apply


@pytest.mark.parametrize("rule", [pytest.param(r, id=r.id) for r in BUNDLED])
def test_secrets_in_rules_are_always_placeholders(rule) -> None:
    spec = rule.remediation
    commands = [c for v in spec.recommended_change for c in v.commands]
    if spec.if_service_needed:
        commands += spec.if_service_needed.commands
    for command in commands:
        words = command.split()
        for keyword in ("secret", "password", "key-string", "community"):
            if keyword in words and words.index(keyword) + 1 < len(words):
                value = words[words.index(keyword) + 1]
                assert value in ("public", "private") or re.fullmatch(r"<[A-Z0-9_]+>", value), (
                    f"{command!r}: the value after {keyword} must be a <PLACEHOLDER>"
                )


def test_lockout_and_both_ends_flags() -> None:
    cut = {r.id for r in BUNDLED if r.remediation.may_cut_access}
    both = {r.id for r in BUNDLED if r.remediation.change_both_ends}

    lockout = {"IOS-AAA-001", "IOS-MGMT-001", "IOS-MGMT-002", "IOS-MGMT-003", "IOS-MGMT-010"}
    lockout |= {"IOS-MGMT-015", "IOS-PASS-002", "IOS-PASS-003", "IOS-PASS-010"}
    lockout |= {"IOS-MGMT-006", "IOS-MGMT-011"}
    assert lockout <= cut
    assert both == {"IOS-L2-004", "IOS-L2-006"}


def test_no_variable_copies_the_offending_line() -> None:
    # A fix must never be "no <offending line>", so no variable provides it.
    assert not {"matched", "line", "target"} & set(VARIABLES)


# ------------------------------------------------- rendered on the fixtures


@pytest.mark.parametrize("fixture", sorted(SECRETS))
def test_no_secret_from_the_config_in_any_remediation(fixture) -> None:
    for finding in audit_file(FIXTURES / fixture).findings:
        for text in texts(finding.remediation):
            leaked = [s for s in SECRETS[fixture] if s in text]
            assert not leaked, f"{finding.rule_id}: {leaked} in {text!r}"


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_rendered_remediations_are_clean(fixture) -> None:
    for finding in audit_file(fixture).findings:
        for text in texts(finding.remediation):
            assert "{" not in text and "}" not in text, f"{finding.rule_id}: {text!r}"
            assert not re.search(r"[\x00-\x1f\x7f]", text)
        for command in finding.remediation.recommended_change:
            assert not re.match(r"\s*(wr|write|copy run|reload)\b", command)


def test_values_from_the_config_are_filled_in() -> None:
    result = audit_file(FIXTURES / "insecure_switch.cfg")
    by_rule = {f.rule_id: f.remediation for f in result.findings}

    assert "no username admin" in by_rule["IOS-PASS-002"].recommended_change
    assert "ip access-list standard MGMT-ACCESS" in by_rule["IOS-MGMT-003"].recommended_change
    assert "no snmp-server group LEGACY v3 noauth" in by_rule["IOS-SNMP-004"].recommended_change


def test_aaa_decides_the_login_variant() -> None:
    with_aaa = audit_file(FIXTURES / "insecure_router.cfg")
    without_aaa = audit_file(FIXTURES / "vty_telnet.cfg")

    def login(result):
        (finding,) = [f for f in result.findings if f.rule_id == "IOS-MGMT-010"][:1]
        return finding.remediation.recommended_change[1]

    assert login(with_aaa) == " login authentication default"
    assert login(without_aaa) == " login local"


# ------------------------------------------------------------- validation


def ctx_block(header: str, *children: str) -> Context:
    block = ConfigLine(header, [ConfigLine(c) for c in children])
    return Context([block], block=block, label=header)


def spec(*commands, before=("Check.",), scope=None):
    data = {
        **VALID,
        "remediation": {"recommended_change": list(commands), "before_you_apply": list(before)},
    }
    if scope is not None:
        data["scope"] = scope
    return parse_rule(data).remediation


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("block", "interface Gi1/0/1\nno username admin"),
        ("block", "interface Gi1/0/1 ; reload"),
        ("block", "archive > log config"),
        ("interface", "Gi1/0/1\r"),
        ("interface", "<script>"),
        ("username", "admin\x1b[2J"),
        ("username", "a b"),
        ("acl_name", "MGMT;reload"),
        ("snmp_level", "priv"),
        ("ntp_source", "server 10.0.0.1; reload"),
        ("ntp_source", "server 10.0.0.1 key 1"),
    ],
)
def test_unsafe_values_are_rejected(name, value) -> None:
    assert not is_safe(name, value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("block", "interface TenGigabitEthernet1/1/1.100"),
        ("block", "line vty 5 15"),
        ("interface", "Port-channel10"),
        ("username", "net.admin_01"),
        ("acl_name", "99"),
        ("ntp_source", "server vrf Mgmt-vrf 10.0.98.123 prefer"),
        ("ntp_source", "peer 2001:db8::123 source Loopback0 version 4"),
    ],
)
def test_safe_values_are_accepted(name, value) -> None:
    assert is_safe(name, value)


def test_unsafe_value_becomes_placeholder_with_note() -> None:
    remediation = render(
        spec("{block}", " access-class {acl_name} in"),
        ctx_block("line vty 0 4", "access-class MGMT\x07X in"),
    )

    assert remediation.recommended_change == ("line vty 0 4", " access-class <ACL_NAME> in")
    assert UNSAFE_VALUE_NOTE in remediation.notes


def test_missing_value_becomes_placeholder_without_note() -> None:
    remediation = render(
        spec("{block}", " switchport mode {switchport_mode}"),
        ctx_block("interface Gi1/0/5", "description x"),
    )

    assert remediation.recommended_change[1] == " switchport mode <ACCESS_OR_TRUNK>"
    assert UNSAFE_VALUE_NOTE not in remediation.notes


def test_username_from_a_hostile_offending_line() -> None:
    rule = parse_rule(
        {
            **VALID,
            "scope": "global",
            "remediation": {
                "recommended_change": ["username {username} secret <NEW_PASSWORD>"],
                "before_you_apply": ["Check."],
            },
        }
    )
    config = parse("username ad$min password 0 s3cret\n")
    line = config[0].text

    remediation = render(rule.remediation, Context(config, line=line))

    assert remediation.recommended_change == ("username <USERNAME> secret <NEW_PASSWORD>",)
    assert "s3cret" not in " ".join(texts(remediation))


def test_list_variable_repeats_the_command() -> None:
    config = parse("ntp server 10.0.0.1\nntp server vrf MGMT 10.0.0.2\n")

    remediation = render(spec("ntp {ntp_source} key 1", scope="global"), Context(config))

    assert remediation.recommended_change == (
        "ntp server 10.0.0.1 key 1",
        "ntp server vrf MGMT 10.0.0.2 key 1",
    )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ntp server ip ntp1.example.com prefer", "ntp server ntp1.example.com prefer key 1"),
        ("ntp server ipv6 2001:db8::1", "ntp server 2001:db8::1 key 1"),
        (
            "ntp server vrf Mgmt-vrf 10.0.0.1 key 3 prefer source Loopback0 version 4",
            "ntp server vrf Mgmt-vrf 10.0.0.1 prefer source Loopback0 version 4 key 1",
        ),
        ("ntp peer 10.0.0.9 key 2", "ntp peer 10.0.0.9 key 1"),
    ],
)
def test_ntp_fix_keeps_options_and_drops_old_key(line, expected) -> None:
    remediation = render(spec("ntp {ntp_source} key 1", scope="global"), Context(parse(line)))

    assert remediation.recommended_change == (expected,)


@pytest.mark.parametrize(
    ("remediation", "message"),
    [
        ("Fix it.", "must be a mapping with recommended_change"),
        ({"before_you_apply": ["x"]}, "recommended_change: missing required key"),
        ({"recommended_change": ["x"]}, "before_you_apply: missing required key"),
        ({"recommended_change": ["x"], "before_you_apply": []}, "needs at least one item"),
        ({"recommended_change": [], "before_you_apply": ["x"]}, "needs at least one command"),
        ({"recommended_change": ["write memory"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["wr"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["copy run start"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["do write memory"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["do reload in 10"], "before_you_apply": ["x"]}, "must not save"),
        (
            {"recommended_change": ["erase startup-config"], "before_you_apply": ["x"]},
            "must not save",
        ),
        ({"recommended_change": ["delete flash:x"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["format flash:"], "before_you_apply": ["x"]}, "must not save"),
        ({"recommended_change": ["reload in 10"], "before_you_apply": ["x"]}, "reload, erase"),
        ({"recommended_change": ["a\nb"], "before_you_apply": ["x"]}, "control characters"),
        ({"recommended_change": ["{matched}"], "before_you_apply": ["x"]}, "unknown variable"),
        ({"recommended_change": ["<ntp ip>"], "before_you_apply": ["x"]}, "<UPPER_CASE>"),
        ({"recommended_change": ["x"], "before_you_apply": ["{nope}"]}, "unknown variable"),
        (
            {"recommended_change": ["x"], "before_you_apply": ["x"], "may_cut_access": "yes"},
            "must be true or false",
        ),
        (
            {"recommended_change": ["x"], "before_you_apply": ["x"], "kind": "exact"},
            "remediation.kind: unknown key",
        ),
        (
            {
                "recommended_change": [{"when_config": "^aaa", "commands": ["x"]}],
                "before_you_apply": ["x"],
            },
            "the last variant is the default",
        ),
        (
            {
                "recommended_change": [{"commands": ["x"]}, {"commands": ["y"]}],
                "before_you_apply": ["x"],
            },
            "only the last variant may be without conditions",
        ),
        (
            {"recommended_change": ["username {username} x"], "before_you_apply": ["x"]},
            "{username} needs a global scope",
        ),
    ],
)
def test_invalid_remediation(remediation, message) -> None:
    assert message in problems(remediation)


def test_block_variable_needs_block_scope() -> None:
    remediation = {"recommended_change": ["{block}", " x"], "before_you_apply": ["x"]}

    assert "{block} needs a block scope" in problems(remediation, scope="global")


def test_old_fix_key_is_refused() -> None:
    with pytest.raises(RuleError, match="fix: old rule format"):
        parse_rule({**VALID, "fix": {"kind": "exact", "commands": ["x"]}})


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("ip http server\nip http secure-server\n", "ip http authentication local"),
        (
            "ip http server\nip http secure-server\nip http authentication aaa\n",
            "ip http authentication aaa",
        ),
        (
            "ip http server\nip http secure-server\n"
            "ip http authentication aaa login-authentication WEB\n",
            "ip http authentication aaa login-authentication WEB",
        ),
    ],
)
def test_http_alternatives_keep_the_login_method(tmp_path, config, expected) -> None:
    path = tmp_path / "r.cfg"
    path.write_text(config, encoding="utf-8")

    by_rule = {f.rule_id: f.remediation for f in audit_file(path).findings}

    assert by_rule["IOS-MGMT-006"].recommended_change == ("no ip http server",)
    assert expected in by_rule["IOS-MGMT-006"].if_service_needed.commands
    assert by_rule["IOS-MGMT-006"].may_cut_access
    assert expected in by_rule["IOS-MGMT-011"].if_service_needed.commands
    assert by_rule["IOS-MGMT-011"].may_cut_access


@pytest.mark.parametrize("block", ["line 2", "line 33 48", "line 0/0/0 0/0/15", "line tty 1/0 1/7"])
def test_async_line_names_are_safe(block) -> None:
    assert is_safe("block", block)


def test_async_line_gets_a_concrete_fix() -> None:
    (rule,) = [r for r in BUNDLED if r.id == "IOS-MGMT-009"]
    (finding,) = evaluate(rule, parse("line 0/0/0 0/0/15\n transport input telnet\n"))

    assert finding.remediation.recommended_change == ("line 0/0/0 0/0/15", " transport input none")


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "access-class 10 in",
            ("access-list 10 permit <MGMT_NETWORK> <WILDCARD>", "access-list 10 deny any log"),
        ),
        (
            "access-class 110 in",
            (
                "access-list 110 permit tcp <MGMT_NETWORK> <WILDCARD> any eq 22",
                "access-list 110 deny ip any any log",
            ),
        ),
        (
            "access-class 1310 in",
            (
                "access-list 1310 permit <MGMT_NETWORK> <WILDCARD>",
                "access-list 1310 deny any log",
            ),
        ),
        (
            "access-class 2010 in",
            (
                "access-list 2010 permit tcp <MGMT_NETWORK> <WILDCARD> any eq 22",
                "access-list 2010 deny ip any any log",
            ),
        ),
        (
            "access-class MGMT in",
            ("ip access-list standard MGMT", " permit <MGMT_NETWORK> <WILDCARD>", " deny any log"),
        ),
    ],
)
def test_undefined_vty_acl_fix_matches_numbered_or_named(line, expected) -> None:
    (rule,) = [r for r in BUNDLED if r.id == "IOS-MGMT-003"]

    (finding,) = evaluate(rule, parse(f"line vty 0 4\n {line}\n"))

    assert finding.remediation.recommended_change == expected


@pytest.mark.parametrize(
    "line",
    [
        "spanning-tree portfast disable",
        "spanning-tree portfast edge disable",
        "no spanning-tree portfast",
    ],
)
def test_bpduguard_fix_keeps_portfast_off(line) -> None:
    (rule,) = [r for r in BUNDLED if r.id == "IOS-L2-005"]

    (finding,) = evaluate(rule, parse(f"interface Ethernet0/1\n switchport mode access\n {line}\n"))

    assert finding.remediation.recommended_change == (
        "interface Ethernet0/1",
        " spanning-tree bpduguard enable",
    )
    assert finding.remediation.notes[0].startswith("PortFast was turned off on purpose")


def test_bpduguard_fix_enables_portfast_by_default() -> None:
    (rule,) = [r for r in BUNDLED if r.id == "IOS-L2-005"]

    (finding,) = evaluate(rule, parse("interface Ethernet0/1\n switchport mode access\n"))

    assert " spanning-tree portfast edge" in finding.remediation.recommended_change
    assert not [n for n in finding.remediation.notes if n.startswith("PortFast was turned off")]


def test_quiet_mode_acl_comes_from_the_vty_access_class() -> None:
    (rule,) = [r for r in BUNDLED if r.id == "IOS-PASS-010"]

    with_acl = evaluate(rule, parse("line vty 0 4\n access-class MGMT in\n"))[0]
    without_acl = evaluate(rule, parse("hostname R1\n"))[0]

    assert with_acl.remediation.recommended_change[0] == "login quiet-mode access-class MGMT"
    assert without_acl.remediation.recommended_change[0] == (
        "login quiet-mode access-class <MGMT_ACL>"
    )
