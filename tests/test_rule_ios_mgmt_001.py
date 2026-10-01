"""Tests for rule IOS-MGMT-001 (VTY lines must accept SSH only)."""

from pathlib import Path

import pytest

from guardian.core.audit import run_audit
from guardian.core.parsers.cisco_ios import parse
from guardian.core.rules.engine import evaluate, load_rules

ROOT = Path(__file__).parents[1]
RULES = ROOT / "rules" / "cisco_ios"
FIXTURES = Path(__file__).parent / "fixtures" / "configs"


@pytest.fixture
def rule():
    return next(r for r in load_rules(RULES) if r.id == "IOS-MGMT-001")


def test_telnet_config_has_findings() -> None:
    findings = run_audit(FIXTURES / "vty_telnet.cfg", RULES)

    assert {f.target for f in findings} == {"line vty 0 4", "line vty 5 15"}


def test_ssh_config_is_compliant() -> None:
    assert run_audit(FIXTURES / "vty_ssh.cfg", RULES) == []


@pytest.mark.parametrize(
    ("transport", "compliant"),
    [
        ("transport input ssh", True),
        ("transport input none", True),
        ("transport input telnet", False),
        ("transport input ssh telnet", False),
        ("transport input all", False),
    ],
)
def test_transport_variants(rule, transport: str, compliant: bool) -> None:
    config = parse(f"line vty 0 4\n login local\n {transport}\n")

    assert (evaluate(rule, config) == []) is compliant
