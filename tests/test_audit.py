"""End-to-end tests: config file -> run_audit with all rules -> findings."""

from pathlib import Path

import pytest

from guardian.core.audit import run_audit

ROOT = Path(__file__).parents[1]
RULES = ROOT / "rules" / "cisco_ios"
FIXTURES = Path(__file__).parent / "fixtures" / "configs"


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
    ],
)
def test_audit_fixture(fixture: str, expected: set[tuple[str, str]]) -> None:
    findings = run_audit(FIXTURES / fixture, RULES)

    assert {(f.rule_id, f.target) for f in findings} == expected
