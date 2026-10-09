"""Tests for the Cisco (indentation-based) parser."""

from conftest import FIXTURES
from guardian.core.parsers.cisco import parse


def texts(lines):
    return [line.text for line in lines]


def test_nested_lines_become_children() -> None:
    config = parse("line vty 0 4\n login\n transport input telnet\n")

    assert len(config) == 1
    assert config[0].text == "line vty 0 4"
    assert texts(config[0].children) == ["login", "transport input telnet"]


def test_header_comments_and_end_are_skipped() -> None:
    config = parse(
        "Building configuration...\n\nCurrent configuration : 10 bytes\n!\nhostname R1\n!\nend\n"
    )

    assert texts(config) == ["hostname R1"]


def test_fixture_contains_both_vty_blocks() -> None:
    config = parse((FIXTURES / "vty_telnet.cfg").read_text())

    vty = [line.text for line in config if line.text.startswith("line vty")]
    assert vty == ["line vty 0 4", "line vty 5 15"]


def test_deep_nesting() -> None:
    config = parse(
        "router bgp 65000\n"
        " neighbor 10.0.0.1 remote-as 65001\n"
        " address-family ipv4\n"
        "  neighbor 10.0.0.1 activate\n"
        " exit-address-family\n"
        "hostname R1\n"
    )

    bgp = config[0]
    assert texts(bgp.children) == [
        "neighbor 10.0.0.1 remote-as 65001",
        "address-family ipv4",
        "exit-address-family",
    ]
    assert texts(bgp.children[1].children) == ["neighbor 10.0.0.1 activate"]
    assert config[1].text == "hostname R1"


def test_multiline_banner_text_is_not_configuration() -> None:
    config = parse(
        "banner motd ^C\n"
        "Authorized access only\n"
        "line vty 0 4\n"
        "^C\n"
        "line vty 0 4\n"
        " transport input ssh\n"
    )

    assert texts(config) == ["banner motd", "line vty 0 4"]
    assert texts(config[0].children) == ["Authorized access only", "line vty 0 4"]
    assert texts(config[1].children) == ["transport input ssh"]


def test_banner_on_one_line_with_custom_delimiter() -> None:
    config = parse("banner login #Lab switch#\nhostname SW1\n")

    assert texts(config) == ["banner login", "hostname SW1"]
    assert texts(config[0].children) == ["Lab switch"]


def test_banner_text_starting_on_first_line() -> None:
    config = parse("banner exec ^CWelcome\nto the lab^C\nhostname SW1\n")

    assert texts(config[0].children) == ["Welcome", "to the lab"]
    assert config[1].text == "hostname SW1"


def test_unterminated_banner_does_not_swallow_config() -> None:
    config = parse("banner motd ^CText without end\nhostname SW1\n")

    assert texts(config) == ["banner motd", "hostname SW1"]


def test_banner_lines_starting_with_bang_are_kept() -> None:
    config = parse("banner motd ^C\n! Warning !\n^C\n")

    assert texts(config[0].children) == ["! Warning !"]


def test_certificate_chain_with_tab_indentation() -> None:
    config = parse(
        "crypto pki certificate chain TP-1\n"
        " certificate self-signed 01\n"
        "  3082022B 30820194\n"
        "  \tquit\n"
        "hostname SW1\n"
    )

    chain = config[0]
    assert texts(chain.children) == ["certificate self-signed 01"]
    assert texts(chain.children[0].children) == ["3082022B 30820194", "quit"]
    assert config[1].text == "hostname SW1"


def test_windows_line_endings_and_bom() -> None:
    config = parse("﻿hostname SW1\r\nline vty 0 4\r\n transport input ssh\r\n")

    assert texts(config) == ["hostname SW1", "line vty 0 4"]
    assert texts(config[1].children) == ["transport input ssh"]


def test_other_platform_headers_are_skipped() -> None:
    nxos = "!Command: show running-config\n!Time: Mon Oct  5 10:00:00 2026\nversion 9.3(8)\n"
    asa = ": Saved\n: Serial Number: 9A1234\nASA Version 9.16(4)\n"
    xr = "Mon Oct  5 10:00:00.123 UTC\n!! IOS XR Configuration 7.5.2\nhostname XR1\n"

    assert texts(parse(nxos)) == ["version 9.3(8)"]
    assert texts(parse(asa)) == ["ASA Version 9.16(4)"]
    assert texts(parse(xr)) == ["hostname XR1"]


def test_empty_input() -> None:
    assert parse("") == []
    assert parse("!\n!\nend\n") == []


def test_control_characters_become_question_marks() -> None:
    (interface,) = parse("interface Gi0/1\x1b]0;PWNED\x07\x1b[2J\n description x\x00y\n")

    assert "\x1b" not in interface.text and "\x07" not in interface.text
    assert interface.text == "interface Gi0/1?]0;PWNED??[2J"
    assert interface.children[0].text == "description x?y"
