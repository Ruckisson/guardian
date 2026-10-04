"""Tests for rule IOS-MGMT-002 (VTY lines must restrict sources with access-class)."""

from pathlib import Path

import pytest

from guardian.core.parsers.cisco_ios import parse
from guardian.core.rules.engine import evaluate, load_rules

ROOT = Path(__file__).parents[1]
RULES = ROOT / "rules" / "cisco_ios"
FIXTURES = Path(__file__).parent / "fixtures" / "configs"


@pytest.fixture
def rule():
    return next(r for r in load_rules(RULES) if r.id == "IOS-MGMT-002")


def test_fixture_flags_only_outbound_access_class(rule) -> None:
    config = parse((FIXTURES / "vty_access_class.cfg").read_text())

    findings = evaluate(rule, config)

    assert [f.target for f in findings] == ["line vty 5 15"]


def test_console_and_aux_lines_are_ignored(rule) -> None:
    config = parse("line con 0\n logging synchronous\nline aux 0\n")

    assert evaluate(rule, config) == []


@pytest.mark.parametrize(
    ("access_class", "compliant"),
    [
        ("access-class MGMT-ACCESS in", True),
        ("access-class 10 in", True),
        ("access-class MGMT-ACCESS in vrf-also", True),
        ("access-class MGMT-ACCESS out", False),
        ("", False),  # access-class missing entirely
    ],
)
def test_access_class_variants(rule, access_class: str, compliant: bool) -> None:
    config = parse(f"line vty 0 4\n {access_class}\n transport input ssh\n")

    assert (evaluate(rule, config) == []) is compliant
