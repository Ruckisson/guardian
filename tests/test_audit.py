"""End-to-end tests: config file -> run_audit with all bundled rules -> findings."""

import pytest

from conftest import FIXTURES, SECRETS
from guardian.core.audit import audit_file, run_audit
from guardian.core.models import Status
from guardian.core.platforms import UnknownPlatformError

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
                ("IOS-MGMT-005", "line con 0"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-005", "line vty 5 15"),
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
                ("IOS-MGMT-005", "line con 0"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-005", "line vty 5 15"),
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
                ("IOS-MGMT-005", "line con 0"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-005", "line vty 5 15"),
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
                ("IOS-MGMT-005", "line con 0"),
                ("IOS-MGMT-005", "line vty 5 15"),
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
                ("IOS-LOG-002", "(global)"),
                ("IOS-NTP-001", "(global)"),
                ("IOS-PASS-006", "(global)"),
                ("IOS-PASS-010", "(global)"),
                ("IOS-SVC-009", "interface GigabitEthernet0/0"),
            },
        ),
        # Anonymized realistic configs: IOS 15 router and IOS-XE 16 switch.
        (
            "ios15_branch_router.cfg",
            None,
            {
                ("IOS-IF-003", "interface GigabitEthernet0/2"),
                ("IOS-L2-004", "interface GigabitEthernet0/2"),
                ("IOS-LOG-003", "(global)"),
                ("IOS-LOG-005", "(global)"),
                ("IOS-LOG-006", "(global)"),
                ("IOS-NTP-002", "(global)"),
                ("IOS-NTP-003", "(global)"),
                ("IOS-PASS-005", f"username breakglass privilege 15 secret 5 {R}"),
                ("IOS-PASS-010", "(global)"),
                ("IOS-PASS-011", "(global)"),
                ("IOS-LOG-002", "(global)"),
                ("IOS-MGMT-005", "line vty 0 4"),
                ("IOS-MGMT-005", "line vty 5 15"),
                ("IOS-PASS-006", "(global)"),
                ("IOS-MGMT-009", "line 2"),
            },
        ),
        (
            "iosxe16_access_switch.cfg",
            None,
            {
                ("IOS-IF-002", "interface Vlan10"),
                ("IOS-L2-001", "interface GigabitEthernet1/0/2"),
                ("IOS-L2-002", "interface GigabitEthernet1/0/5"),
                ("IOS-L2-003", "interface GigabitEthernet1/0/4"),
                ("IOS-LOG-003", "(global)"),
                ("IOS-MGMT-003", "line vty 5 15"),
                ("IOS-MGMT-005", "line vty 5 15"),
                ("IOS-MGMT-006", "ip http server"),
                ("IOS-MGMT-012", "(global)"),
                ("IOS-MGMT-015", "line vty 5 15"),
                ("IOS-NTP-002", "(global)"),
                ("IOS-PASS-002", f"username monitor privilege 1 password 7 {R}"),
                ("IOS-SNMP-004", "snmp-server group LEGACY v3 auth"),
                ("IOS-SVC-006", "(global)"),
                ("IOS-LOG-002", "(global)"),
                ("IOS-PASS-007", "(global)"),
                ("IOS-PASS-010", "(global)"),
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


@pytest.mark.parametrize("fixture", sorted(SECRETS))
def test_findings_never_contain_secrets(fixture: str) -> None:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    assert all(s in text for s in SECRETS[fixture])

    findings = run_audit(FIXTURES / fixture)

    leaked = [s for f in findings for s in SECRETS[fixture] if s in f.target + f.location]
    assert not leaked


def test_custom_rules_directory(tmp_path) -> None:
    (tmp_path / "rule.yaml").write_text(
        "id: LAB-TEST-001\ntitle: Hostname must be set\nseverity: low\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\n"
        "remediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references: {stig: [], nist_800_53: [], cisco_guide: null, cisa: false}\n",
        encoding="utf-8",
    )
    config = tmp_path / "c.cfg"
    config.write_text("version 15.1\n", encoding="utf-8")

    findings = run_audit(config, rules_dir=tmp_path)

    assert [(f.rule_id, f.target) for f in findings] == [("LAB-TEST-001", "(global)")]


def test_unknown_platform() -> None:
    with pytest.raises(UnknownPlatformError, match="supported: cisco_ios"):
        run_audit(FIXTURES / "vty_ssh.cfg", platform="junos")


def _status(tmp_path, text: str, rule_id: str) -> Status:
    config = tmp_path / "variant.cfg"
    config.write_text(text, encoding="utf-8")
    return {r.rule_id: r.status for r in audit_file(config).rules}[rule_id]


@pytest.mark.parametrize(
    "line",
    [
        "logging host 10.0.0.41",
        "logging 10.0.0.41",  # older syntax without "host"
        "logging host 10.0.0.41 vrf Mgmt-vrf",
        "logging host syslog.example.net",
        "logging host ipv6 2001:db8::41",
    ],
)
def test_remote_syslog_syntax_variants(tmp_path, line) -> None:
    # Each variant counts as one server; DISA STIG asks for two.
    assert _status(tmp_path, f"{line}\n", "IOS-LOG-002") is Status.FAIL
    assert _status(tmp_path, f"{line}\nlogging host 10.9.9.9\n", "IOS-LOG-002") is Status.PASS


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (["ntp server 10.0.0.1", "ntp server 10.0.0.2"], Status.PASS),
        (["ntp server vrf M 10.0.0.1", "ntp peer 10.0.0.2 key 1"], Status.PASS),
        (["ntp server 10.0.0.1"], Status.FAIL),
        # The same server twice (also in another VRF) counts once.
        (["ntp server 10.0.0.1", "ntp server vrf M 10.0.0.1"], Status.FAIL),
    ],
)
def test_ntp_needs_two_servers(tmp_path, lines, expected) -> None:
    assert _status(tmp_path, "\n".join(lines) + "\n", "IOS-NTP-001") is expected


QUIET = "login quiet-mode access-class MGMT"


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (["login block-for 900 attempts 3 within 120", QUIET], Status.PASS),
        (["login block-for 901 attempts 1 within 121", QUIET], Status.PASS),
        (["login block-for 899 attempts 3 within 120", QUIET], Status.FAIL),
        (["login block-for 900 attempts 4 within 120", QUIET], Status.FAIL),
        (["login block-for 900 attempts 3 within 119", QUIET], Status.FAIL),
        (["login block-for 900 attempts 3 within 120"], Status.FAIL),
        ([QUIET], Status.FAIL),
    ],
)
def test_login_block_for_stig_values_and_quiet_mode(tmp_path, lines, expected) -> None:
    assert _status(tmp_path, "\n".join(lines) + "\n", "IOS-PASS-010") is expected


@pytest.mark.parametrize(
    ("text", "rule_id", "expected"),
    [
        ("security passwords min-length 15\n", "IOS-PASS-006", Status.PASS),
        ("security passwords min-length 14\n", "IOS-PASS-006", Status.FAIL),
        ("line vty 0 4\n exec-timeout 5 0\n", "IOS-MGMT-005", Status.PASS),
        ("line vty 0 4\n exec-timeout 6 0\n", "IOS-MGMT-005", Status.FAIL),
        # No exec-timeout line means the IOS default of 10 minutes.
        ("line vty 0 4\n transport input ssh\n", "IOS-MGMT-005", Status.FAIL),
        (
            "aaa new-model\naaa local authentication attempts max-fail 3\n",
            "IOS-PASS-011",
            Status.PASS,
        ),
        (
            "aaa new-model\naaa local authentication attempts max-fail 4\n",
            "IOS-PASS-011",
            Status.FAIL,
        ),
    ],
)
def test_stig_thresholds(tmp_path, text, rule_id, expected) -> None:
    assert _status(tmp_path, text, rule_id) is expected


@pytest.mark.parametrize(
    ("acl", "access_class"),
    [
        ("ip access-list standard MGMT\n 10 permit 10.0.0.0 0.0.0.255\n", "MGMT in"),
        ("ip access-list standard MGMT\n permit 10.0.0.0 0.0.0.255\n", "MGMT in vrf-also"),
        ("access-list 10 permit 10.0.0.0 0.0.0.255\n", "10 in"),
        ("ip access-list standard 10\n 10 permit 10.0.0.0 0.0.0.255\n", "10 in"),
        ("ip access-list extended 110\n 10 permit tcp any any eq 22\n", "110 in"),
    ],
)
def test_vty_acl_by_number_and_name(tmp_path, acl, access_class) -> None:
    text = f"{acl}line vty 0 4\n access-class {access_class}\n"

    assert _status(tmp_path, text, "IOS-MGMT-002") is Status.PASS
    assert _status(tmp_path, text, "IOS-MGMT-003") is Status.PASS


def test_vty_acl_name_typo_fails(tmp_path) -> None:
    text = "ip access-list standard MGMT\nline vty 0 4\n access-class MGMT1 in\n"

    assert _status(tmp_path, text, "IOS-MGMT-003") is Status.FAIL


@pytest.mark.parametrize(
    "server",
    ["ntp server 10.0.0.1 key 1", "ntp server vrf Mgmt-vrf 10.0.0.1 key 1 prefer"],
)
def test_ntp_authentication_with_and_without_vrf(tmp_path, server) -> None:
    text = (
        "ntp authentication-key 1 md5 fake-ntp-key 7\nntp authenticate\n"
        f"ntp trusted-key 1\n{server}\n"
    )

    assert _status(tmp_path, text, "IOS-NTP-003") is Status.PASS


@pytest.mark.parametrize(
    "community", ["snmp-server community fake RO 30", "snmp-server community fake RO SNMP-ACL"]
)
def test_snmp_acl_by_number_and_name(tmp_path, community) -> None:
    assert _status(tmp_path, f"{community}\n", "IOS-SNMP-003") is Status.PASS


@pytest.mark.parametrize(
    "rule_id", ["IOS-MGMT-002", "IOS-MGMT-003", "IOS-MGMT-004", "IOS-MGMT-005", "IOS-MGMT-015"]
)
def test_vty_without_connections_is_not_applicable(tmp_path, rule_id) -> None:
    text = (
        "interface Vlan1\n ipv6 address 2001:db8::1/64\n"
        "line vty 5 15\n access-class MISSING in\n exec-timeout 0 0\n transport input none\n"
    )
    config = tmp_path / "vty.cfg"
    config.write_text(text, encoding="utf-8")

    (rule,) = [r for r in audit_file(config).rules if r.rule_id == rule_id]

    assert rule.status is Status.NOT_APPLICABLE
    assert "accepts no connections" in rule.reason


def test_vty_none_does_not_hide_other_vty_lines(tmp_path) -> None:
    text = "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input none\n"

    assert _status(tmp_path, text, "IOS-MGMT-002") is Status.FAIL


GLOBAL_GUARD = (
    "spanning-tree portfast edge default\nspanning-tree portfast edge bpduguard default\n"
)


@pytest.mark.parametrize(
    ("port_lines", "expected"),
    [
        ([], Status.PASS),
        (["spanning-tree portfast disable"], Status.FAIL),
        (["spanning-tree portfast edge disable"], Status.FAIL),
        (["no spanning-tree portfast"], Status.FAIL),
        (["spanning-tree portfast disable", "spanning-tree bpduguard enable"], Status.PASS),
    ],
)
def test_bpduguard_with_portfast_disabled(tmp_path, port_lines, expected) -> None:
    port = "".join(f" {line}\n" for line in port_lines)
    text = f"{GLOBAL_GUARD}interface Gi1/0/1\n switchport mode access\n{port}"

    assert _status(tmp_path, text, "IOS-L2-005") is expected


@pytest.mark.parametrize(
    "text",
    [
        "mpls traffic-eng tunnels\n",
        "interface Gi0/1\n mpls traffic-eng tunnels\n",
        "interface Gi0/1\n ip rsvp bandwidth 1000\n",
        "ip multicast-routing\n",
    ],
)
def test_ip_options_drop_is_na_with_router_alert_users(tmp_path, text) -> None:
    assert _status(tmp_path, text, "IOS-IF-001") is Status.NOT_APPLICABLE


def test_cdp_switch_without_external_interface_is_na(tmp_path) -> None:
    text = (
        "interface Vlan10\n ip address 10.0.10.2 255.255.255.0\n"
        "interface GigabitEthernet1/0/1\n switchport mode access\n switchport voice vlan 20\n"
    )

    assert _status(tmp_path, text, "IOS-SVC-009") is Status.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("198.51.100.2 255.255.255.252", Status.FAIL),
        ("dhcp", Status.FAIL),
        ("negotiated", Status.FAIL),
        ("10.0.0.1 255.255.255.0", Status.NOT_APPLICABLE),
        ("172.31.0.1 255.255.255.0", Status.NOT_APPLICABLE),
        ("100.64.1.1 255.255.255.252", Status.NOT_APPLICABLE),
        ("169.254.1.1 255.255.0.0", Status.NOT_APPLICABLE),
    ],
)
def test_cdp_router_external_interface(tmp_path, address, expected) -> None:
    text = f"interface GigabitEthernet0/0\n ip address {address}\n"

    assert _status(tmp_path, text, "IOS-SVC-009") is expected


def test_cdp_no_cdp_run_passes(tmp_path) -> None:
    text = "no cdp run\ninterface GigabitEthernet0/0\n ip address 198.51.100.2 255.255.255.252\n"

    assert _status(tmp_path, text, "IOS-SVC-009") is Status.PASS


def test_cdp_skips_logical_interfaces(tmp_path) -> None:
    text = (
        "interface Dialer1\n ip address negotiated\n"
        "interface Virtual-Template1\n ip address 198.51.100.9 255.255.255.0\n"
    )

    assert _status(tmp_path, text, "IOS-SVC-009") is Status.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("timeout", "expected"),
    [
        ("exec-timeout 5 0", Status.PASS),
        ("exec-timeout 4 59", Status.PASS),
        ("exec-timeout 5", Status.PASS),
        ("exec-timeout 5 30", Status.FAIL),
        ("exec-timeout 6", Status.FAIL),
        ("exec-timeout 0 0", Status.FAIL),
        ("exec-timeout 0", Status.FAIL),
    ],
)
def test_exec_timeout_minutes_and_seconds(tmp_path, timeout, expected) -> None:
    assert _status(tmp_path, f"line vty 0 4\n {timeout}\n", "IOS-MGMT-005") is expected
