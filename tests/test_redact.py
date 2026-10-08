"""Tests for secret masking in finding targets."""

import pytest

from guardian.core.redact import MASK, redact


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("snmp-server community s3cret RO 10", f"snmp-server community {MASK} RO 10"),
        ("snmp-server community snmp RW", f"snmp-server community {MASK} RW"),
        (
            "snmp-server host 10.0.0.5 version 2c s3cret",
            f"snmp-server host 10.0.0.5 version 2c {MASK}",
        ),
        ("snmp-server host 10.0.0.5 traps s3cret", f"snmp-server host 10.0.0.5 traps {MASK}"),
        ("enable secret 5 $1$abc$def", f"enable secret 5 {MASK}"),
        ("enable password cisco", f"enable password {MASK}"),
        (
            "username admin privilege 15 secret 9 $9$x",
            f"username admin privilege 15 secret 9 {MASK}",
        ),
        (" password 7 0822455D0A16", f" password 7 {MASK}"),
        ("tacacs-server key 7 0822455D0A16", f"tacacs-server key 7 {MASK}"),
        (
            "boot network ftp://admin:S3cret@10.0.0.5/r1-confg",
            f"boot network ftp://admin:{MASK}@10.0.0.5/r1-confg",
        ),
        (" key-string 7 0822455D0A16", f" key-string 7 {MASK}"),
    ],
)
def test_secrets_are_masked(line: str, expected: str) -> None:
    assert redact(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "line vty 0 4",
        "service password-encryption",
        "security passwords min-length 10",
        "snmp-server host 10.0.0.5 version 3 priv MONUSER",
        "snmp-server group ADMINS v3 priv",
        "interface Ethernet0/1",
    ],
)
def test_lines_without_secrets_are_unchanged(line: str) -> None:
    assert redact(line) == line


def test_redact_is_idempotent() -> None:
    once = redact("snmp-server community s3cret RO")

    assert redact(once) == once
