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


@pytest.mark.parametrize(
    ("line", "secrets"),
    [
        ("ntp authentication-key 1 md5 ntpkey01 7", ["ntpkey01"]),
        ("ntp authentication-key 2 hmac-sha2-256 ntpkey02", ["ntpkey02"]),
        ("crypto isakmp key isakmp01 address 192.0.2.1", ["isakmp01"]),
        ("crypto isakmp key 6 isakmp02 address 0.0.0.0", ["isakmp02"]),
        ("standby 1 authentication hsrp01", ["hsrp01"]),
        ("standby authentication text hsrp02", ["hsrp02"]),
        ("standby 2 authentication md5 key-string 7 hsrp03", ["hsrp03"]),
        ("vrrp 3 authentication text vrrp01", ["vrrp01"]),
        ("ip ospf message-digest-key 1 md5 7 ospf01", ["ospf01"]),
        ("ip ospf message-digest-key 1 md5 ospf02", ["ospf02"]),
        (
            "snmp-server user MON NMS v3 auth sha snmpauth01 priv aes 128 snmppriv01",
            ["snmpauth01", "snmppriv01"],
        ),
        (
            "snmp-server user MON NMS v3 auth md5 snmpauth02 priv des snmppriv02",
            ["snmpauth02", "snmppriv02"],
        ),
        ("pre-shared-key local 0 psk01", ["psk01"]),
        ("pre-shared-key psk02", ["psk02"]),
        ("wpa-psk ascii 0 wifi01", ["wifi01"]),
    ],
)
def test_more_secret_forms_are_masked(line: str, secrets: list[str]) -> None:
    masked = redact(line)

    assert not [s for s in secrets if s in masked]
    assert MASK in masked


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("tacacs-server key 12345678", f"tacacs-server key {MASK}"),
        ("radius-server key 0 123456", f"radius-server key 0 {MASK}"),
        ("tacacs-server key 7 08224550", f"tacacs-server key 7 {MASK}"),
        (
            "ip ospf authentication-key 7 0822455D0A16",
            f"ip ospf authentication-key 7 {MASK}",
        ),
        ("ip ospf authentication-key Secret1", f"ip ospf authentication-key {MASK}"),
        ("ipv6 ospf authentication-key S2", f"ipv6 ospf authentication-key {MASK}"),
        ("ntp authentication-key 1 md5 ntpkey01 7", f"ntp authentication-key 1 md5 {MASK} 7"),
        (
            "key config-key password-encrypt MasterKey1",
            f"key config-key password-encrypt {MASK}",
        ),
    ],
)
def test_numeric_keys_are_masked(line: str, expected: str) -> None:
    assert redact(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "key 1",
        " key 1",
        "ntp server 10.0.0.1 key 1",
        "ntp trusted-key 1",
        "standby 2 authentication md5 key-chain FHRP",
        "snmp-server group LEGACY v3 auth",
        "ntp peer 10.0.0.2 key 2",
        "crypto key generate rsa modulus 2048",
        "key chain FHRP",
    ],
)
def test_key_ids_are_not_secrets(line: str) -> None:
    assert redact(line) == line


def test_key_in_server_block_is_masked() -> None:
    assert redact(" key 123456", block="tacacs server ISE") == f" key {MASK}"


def test_key_id_in_key_chain_is_unchanged() -> None:
    assert redact(" key 1", block="key chain FHRP") == " key 1"
