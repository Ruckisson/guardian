"""End-to-end tests: config file -> run_audit with all bundled rules -> findings."""

from pathlib import Path

import pytest

from guardian.core.audit import run_audit
from guardian.core.platforms import UnknownPlatformError

FIXTURES = Path(__file__).parent / "fixtures" / "configs"
R = "<redacted>"


# Focused fixtures list only the areas they were written for (``areas``);
# the others are checked against every bundled rule (``areas=None``).
MGMT = ("MGMT",)
PASS = ("PASS",)


@pytest.mark.parametrize(
    ("fixture", "areas", "expected"),
    [
        (
            "vty_telnet.cfg",
            MGMT,
            {
                ("IOS-MGMT-001", "line vty 0 4"),
                ("IOS-MGMT-001", "line vty 5 15"),
                ("IOS-MGMT-002", "line vty 0 4"),
                ("IOS-MGMT-002", "line vty 5 15"),
                ("IOS-MGMT-007", "(global)"),
                ("IOS-MGMT-008", "line aux 0"),
                ("IOS-MGMT-009", "line aux 0"),
                ("IOS-MGMT-010", "line con 0"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-MGMT-014", "(global)"),
            },
        ),
        (
            "vty_ssh.cfg",
            MGMT,
            {
                ("IOS-MGMT-002", "line vty 0 4"),
                ("IOS-MGMT-002", "line vty 5 15"),
                ("IOS-MGMT-008", "line aux 0"),
                ("IOS-MGMT-009", "line aux 0"),
                ("IOS-MGMT-010", "line con 0"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-MGMT-014", "(global)"),
            },
        ),
        (
            "vty_access_class.cfg",
            MGMT,
            {
                ("IOS-MGMT-002", "line vty 5 15"),
                ("IOS-MGMT-008", "line aux 0"),
                ("IOS-MGMT-009", "line aux 0"),
                ("IOS-MGMT-010", "line con 0"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-MGMT-014", "(global)"),
            },
        ),
        ("hardened_switch.cfg", None, set()),
        # Every case that used to be a false positive; must stay clean.
        ("l3_switch_edge_cases.cfg", None, set()),
        (
            "insecure_switch.cfg",
            None,
            {
                ("IOS-AAA-001", "(global)"),
                ("IOS-IF-001", "(global)"),
                ("IOS-IF-002", "interface Vlan1"),
                ("IOS-IF-003", "interface Vlan1"),
                ("IOS-L2-001", "interface Ethernet0/1"),
                ("IOS-L2-001", "interface Ethernet0/2"),
                ("IOS-L2-003", "interface Ethernet0/0"),
                ("IOS-L2-005", "interface Ethernet0/1"),
                ("IOS-L2-005", "interface Ethernet0/2"),
                ("IOS-L2-006", "interface Ethernet0/0"),
                ("IOS-L2-007", "(global)"),
                ("IOS-LOG-001", "(global)"),
                ("IOS-LOG-002", "(global)"),
                ("IOS-LOG-003", "(global)"),
                ("IOS-LOG-005", "(global)"),
                ("IOS-LOG-006", "(global)"),
                ("IOS-MGMT-001", "line vty 0 4"),
                ("IOS-MGMT-001", "line vty 5 15"),
                ("IOS-MGMT-002", "line vty 5 15"),
                ("IOS-MGMT-003", "line vty 0 4"),
                ("IOS-MGMT-004", "line con 0"),
                ("IOS-MGMT-004", "line vty 5 15"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-006", "ip http server"),
                ("IOS-MGMT-007", "(global)"),
                ("IOS-MGMT-008", "line aux 0"),
                ("IOS-MGMT-009", "line aux 0"),
                ("IOS-MGMT-010", "line con 0"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-NTP-001", "(global)"),
                ("IOS-NTP-002", "(global)"),
                ("IOS-PASS-001", f"enable password {R}"),
                ("IOS-PASS-002", f"username admin privilege 15 password 0 {R}"),
                ("IOS-PASS-003", "line vty 0 4"),
                ("IOS-PASS-004", "(global)"),
                ("IOS-PASS-007", "(global)"),
                ("IOS-PASS-008", "(global)"),
                ("IOS-PASS-010", "(global)"),
                ("IOS-SNMP-001", f"snmp-server community {R} RO"),
                ("IOS-SNMP-002", f"snmp-server community {R} RW"),
                ("IOS-SNMP-003", f"snmp-server community {R} RO"),
                ("IOS-SNMP-003", f"snmp-server community {R} RW"),
                ("IOS-SNMP-004", "snmp-server group LEGACY v3 noauth"),
                ("IOS-SVC-006", "(global)"),
                ("IOS-SVC-007", "(global)"),
                ("IOS-SVC-008", "(global)"),
                ("IOS-SVC-009", "(global)"),
            },
        ),
        (
            "insecure_router.cfg",
            None,
            {
                ("IOS-IF-002", "interface GigabitEthernet0/0"),
                ("IOS-IF-003", "interface GigabitEthernet0/2"),
                ("IOS-L2-004", "interface GigabitEthernet0/1"),
                ("IOS-L2-004", "interface GigabitEthernet0/2"),
                ("IOS-LOG-004", "archive > log config"),
                ("IOS-LOG-005", "(global)"),
                ("IOS-LOG-006", "(global)"),
                ("IOS-MGMT-008", "line aux 0"),
                ("IOS-MGMT-009", "line aux 0"),
                ("IOS-MGMT-009", "line tty 2 3"),
                ("IOS-MGMT-010", "line con 0"),
                ("IOS-MGMT-010", "line vty 0 4"),
                ("IOS-MGMT-011", "(global)"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-MGMT-014", "(global)"),
                ("IOS-MGMT-015", "line vty 0 4"),
                ("IOS-NTP-003", "(global)"),
                ("IOS-PASS-009", "username guest nopassword"),
                ("IOS-SNMP-005", "snmp-server system-shutdown"),
                ("IOS-SVC-001", "service tcp-small-servers"),
                ("IOS-SVC-001", "service udp-small-servers"),
                ("IOS-SVC-002", "ip finger"),
                ("IOS-SVC-003", f"boot network ftp://backup:{R}@10.9.9.9/edge-r1-confg"),
                ("IOS-SVC-003", "service config"),
                ("IOS-SVC-004", "ip rcmd rcp-enable"),
                ("IOS-SVC-004", "ip rcmd rsh-enable"),
                ("IOS-SVC-005", "iox"),
                ("IOS-SVC-007", "(global)"),
                ("IOS-SVC-008", "(global)"),
                ("IOS-SVC-009", "(global)"),
            },
        ),
        (
            "passwords.cfg",
            PASS,
            {
                ("IOS-PASS-001", f"enable password {R}"),
                ("IOS-PASS-002", f"username helpdesk privilege 1 password 0 {R}"),
                ("IOS-PASS-002", f"username olduser password 7 {R}"),
                ("IOS-PASS-003", "line con 0"),
                ("IOS-PASS-003", "line aux 0"),
                ("IOS-PASS-003", "line vty 5 15"),
                ("IOS-PASS-004", "(global)"),
                ("IOS-PASS-005", f"enable secret 5 {R}"),
                ("IOS-PASS-005", f"username backup privilege 15 secret 5 {R}"),
                ("IOS-PASS-007", "(global)"),
                ("IOS-PASS-010", "(global)"),
                ("IOS-PASS-011", "(global)"),
            },
        ),
    ],
)
def test_audit_fixture(
    fixture: str, areas: tuple[str, ...] | None, expected: set[tuple[str, str]]
) -> None:
    findings = run_audit(FIXTURES / fixture)

    found = {(f.rule_id, f.target) for f in findings}
    if areas is not None:
        found = {(rule_id, target) for rule_id, target in found if rule_id.split("-")[1] in areas}
    assert found == expected


def test_router_findings_never_contain_secrets() -> None:
    text = (FIXTURES / "insecure_router.cfg").read_text()
    secrets = [
        "rtlab-fhrp-key",
        "rtlab-ftp-pass",
        "$9$rtLabSaltAbCd$",
        "$9$rtLabSaltEfGh$",
    ]
    assert all(s in text for s in secrets)

    findings = run_audit(FIXTURES / "insecure_router.cfg")

    assert not any(s in f.target for f in findings for s in secrets)


def test_findings_never_contain_secrets() -> None:
    text = (FIXTURES / "insecure_switch.cfg").read_text()
    secrets = ["Xq7-lab-write", "lab-vty-secret", "lab-user-secret", "lab-enable-secret"]
    assert all(s in text for s in secrets)

    findings = run_audit(FIXTURES / "insecure_switch.cfg")

    assert not any(s in f.target for f in findings for s in secrets)


def test_password_findings_never_contain_secrets() -> None:
    text = (FIXTURES / "passwords.cfg").read_text()
    secrets = ["pw-enable-clear", "pw-helpdesk-clear", "pw-olduser-type7", "$1$pw00$", "$1$pw01$"]
    assert all(s in text for s in secrets)

    findings = run_audit(FIXTURES / "passwords.cfg")

    assert not any(s in f.target for f in findings for s in secrets)


def test_custom_rules_directory(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: Hostname must be set\nseverity: low\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\nremediation: x\n",
        encoding="utf-8",
    )
    config = tmp_path / "c.cfg"
    config.write_text("version 15.1\n", encoding="utf-8")

    findings = run_audit(config, rules_dir=tmp_path)

    assert [(f.rule_id, f.target) for f in findings] == [("LAB-TEST-001", "(global)")]


def test_unknown_platform() -> None:
    with pytest.raises(UnknownPlatformError, match="supported: cisco_ios"):
        run_audit(FIXTURES / "vty_ssh.cfg", platform="junos")
