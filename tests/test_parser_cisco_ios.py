"""Tests for the Cisco IOS parser."""

from pathlib import Path

from guardian.core.parsers.cisco_ios import parse

FIXTURES = Path(__file__).parent / "fixtures" / "configs"


def test_nested_lines_become_children() -> None:
    config = parse("line vty 0 4\n login\n transport input telnet\n")

    assert len(config) == 1
    assert config[0].text == "line vty 0 4"
    assert [c.text for c in config[0].children] == ["login", "transport input telnet"]


def test_header_comments_and_end_are_skipped() -> None:
    config = parse(
        "Building configuration...\n\nCurrent configuration : 10 bytes\n!\nhostname R1\n!\nend\n"
    )

    assert [line.text for line in config] == ["hostname R1"]


def test_fixture_contains_both_vty_blocks() -> None:
    config = parse((FIXTURES / "vty_telnet.cfg").read_text())

    vty = [line.text for line in config if line.text.startswith("line vty")]
    assert vty == ["line vty 0 4", "line vty 5 15"]
