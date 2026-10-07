"""End-to-end tests: config file -> run_audit with all bundled rules -> findings."""

from pathlib import Path

import pytest

from guardian.core.audit import run_audit
from guardian.core.platforms import UnknownPlatformError

FIXTURES = Path(__file__).parent / "fixtures" / "configs"
R = "<redacted>"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "vty_telnet.cfg",
            {
                ("IOS-MGMT-001", "line vty 0 4"),
                ("IOS-MGMT-001", "line vty 5 15"),
                ("IOS-MGMT-002", "line vty 0 4"),
                ("IOS-MGMT-002", "line vty 5 15"),
            },
        ),
        (
            "vty_ssh.cfg",
            {
                ("IOS-MGMT-002", "line vty 0 4"),
                ("IOS-MGMT-002", "line vty 5 15"),
            },
        ),
        (
            "vty_access_class.cfg",
            {
                ("IOS-MGMT-002", "line vty 5 15"),
            },
        ),
        ("hardened_switch.cfg", set()),
        (
            "insecure_switch.cfg",
            {
                ("IOS-L2-001", "interface Ethernet0/1"),
                ("IOS-L2-001", "interface Ethernet0/2"),
                ("IOS-LOG-001", "(global)"),
                ("IOS-MGMT-001", "line vty 0 4"),
                ("IOS-MGMT-001", "line vty 5 15"),
                ("IOS-MGMT-002", "line vty 5 15"),
                ("IOS-MGMT-003", "line vty 0 4"),
                ("IOS-MGMT-004", "line con 0"),
                ("IOS-MGMT-004", "line vty 5 15"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-SNMP-001", f"snmp-server community {R} RO"),
                ("IOS-SNMP-002", f"snmp-server community {R} RW"),
                ("IOS-SNMP-003", f"snmp-server community {R} RO"),
                ("IOS-SNMP-003", f"snmp-server community {R} RW"),
                ("IOS-SNMP-004", "snmp-server group LEGACY v3 noauth"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-006", "ip http server"),
                ("IOS-SNMP-001", f"snmp-server community {R} RO"),
            },
        ),
    ],
)
def test_audit_fixture(fixture: str, expected: set[tuple[str, str]]) -> None:
    findings = run_audit(FIXTURES / fixture)

    assert {(f.rule_id, f.target) for f in findings} == expected


def test_findings_never_contain_secrets() -> None:
    text = (FIXTURES / "insecure_switch.cfg").read_text()
    secrets = ["Xq7-lab-write", "lab-vty-secret", "lab-user-secret", "lab-enable-secret"]
    assert all(s in text for s in secrets)

    findings = run_audit(FIXTURES / "insecure_switch.cfg")

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
