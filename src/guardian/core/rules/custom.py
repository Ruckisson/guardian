"""Registry of Python checks for logic that YAML cannot express.

A YAML rule refers to a check by name (``check: {python: <name>}``); it can
never point at an arbitrary module, so rule files cannot execute code.

A check receives the selected block (or a virtual root for global scope)
and the whole parsed configuration, and returns True when compliant::

    @register("vty-count-matches-something")
    def _vty_count(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
        ...

When the rule does not apply to this config at all (no HTTPS server, not a
switch, ...) the check returns ``NotApplicable("reason")`` instead of True,
so reports can tell N/A apart from PASS.
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

from guardian.core.models import ConfigLine


@dataclass(frozen=True)
class NotApplicable:
    """The rule does not apply here; ``reason`` says why, for the report."""

    reason: str


CheckResult = bool | NotApplicable
CustomCheck = Callable[[ConfigLine, list[ConfigLine]], CheckResult]

CHECKS: dict[str, CustomCheck] = {}


def register(name: str) -> Callable[[CustomCheck], CustomCheck]:
    """Decorator that makes a function available to YAML rules under ``name``."""

    def decorator(func: CustomCheck) -> CustomCheck:
        if name in CHECKS:
            raise ValueError(f"custom check {name!r} is already registered")
        CHECKS[name] = func
        return func

    return decorator


# ----------------------------------------------------------------- passwords
#
# IOS-PASS-006 and IOS-PASS-007 check the same thing (minimum password length)
# with a different severity: weak length matters more when passwords are also
# stored in clear text or as reversible type 7. Exactly one of them can fail.

MIN_PASSWORD_LENGTH = 15  # DISA STIG (Cisco IOS XE)

_MIN_LENGTH = re.compile(r"^security passwords min-length (\d+)")
# Passwords stored in clear text or as reversible type 7 (not a one-way hash).
_GLOBAL_PASSWORD = re.compile(r"^(enable password |username \S+ (.* )?password )")
_LINE_BLOCK = re.compile(r"^line ")
_LINE_PASSWORD = re.compile(r"^password ")


def _min_length_ok(config: list[ConfigLine]) -> bool:
    values = [int(m.group(1)) for line in config if (m := _MIN_LENGTH.search(line.text))]
    return bool(values) and all(v >= MIN_PASSWORD_LENGTH for v in values)


def _has_reversible_password(config: list[ConfigLine]) -> bool:
    for line in config:
        if _GLOBAL_PASSWORD.search(line.text):
            return True
        if _LINE_BLOCK.search(line.text) and any(
            _LINE_PASSWORD.search(child.text) for child in line.children
        ):
            return True
    return False


@register("password-min-length-hashed")
def _min_length_hashed(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    return _min_length_ok(config) or _has_reversible_password(config)


@register("password-min-length-reversible")
def _min_length_reversible(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    return _min_length_ok(config) or not _has_reversible_password(config)


# ------------------------------------------------------------------- helpers

NOT_A_SWITCH = "the device is not a switch (no switchport, spanning-tree or VTP lines)"


def _has_line(lines: list[ConfigLine], pattern: str) -> bool:
    return any(re.search(pattern, line.text) for line in lines)


def _blocks(config: list[ConfigLine], pattern: str) -> list[ConfigLine]:
    return [line for line in config if re.search(pattern, line.text)]


def _is_switch(config: list[ConfigLine]) -> bool:
    """A switch has switchport lines, or (with all ports at defaults) at least
    spanning-tree, VTP or VLAN interfaces."""
    if _has_line(config, r"^(spanning-tree mode |vtp |interface Vlan\d)"):
        return True
    return any(
        _has_line(interface.children, r"^switchport")
        for interface in _blocks(config, r"^interface ")
    )


def _ipv6_enabled(config: list[ConfigLine]) -> bool:
    return any(
        _has_line(interface.children, r"^ipv6 (address|enable)")
        for interface in _blocks(config, r"^interface ")
    )


# ---------------------------------------------------------------- management


def _login_list_ok(config: list[ConfigLine], name: str) -> bool:
    """Login method list ``name`` is defined and never falls back to ``none``."""
    for line in config:
        if m := re.match(rf"^aaa authentication login {re.escape(name)} (.+)$", line.text):
            return "none" not in m.group(1).split()
    return False


@register("line-requires-login")
def _line_requires_login(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Console / VTY line asks for credentials (IOS-MGMT-010).

    With ``aaa new-model`` the ``login`` line commands are ignored. The line
    uses its ``login authentication <list>``, else the default list; a list
    that is undefined or contains ``none`` fails. With no default list at all
    VTY lines check the local user database, the console checks nothing.
    Without AAA the line needs ``login`` (line password) or ``login local``.
    """
    if not _has_line(config, r"^aaa new-model$"):
        return _has_line(block.children, r"^login( local)?$")
    for child in block.children:
        if m := re.match(r"^login authentication (\S+)", child.text):
            return _login_list_ok(config, m.group(1))
    if _has_line(config, r"^aaa authentication login default "):
        return _login_list_ok(config, "default")
    return block.text.startswith("line vty") and _has_line(config, r"^username \S+ ")


@register("vty-ipv6-access-class")
def _vty_ipv6_access_class(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """With IPv6 on any interface, the VTY line has an IPv6 access-class."""
    if not _ipv6_enabled(config):
        return NotApplicable("no interface has IPv6 enabled")
    return _has_line(block.children, r"^ipv6 access-class \S+ in$")


@register("https-server-restricted")
def _https_server_restricted(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """If the HTTPS server runs, it has an access-class and real authentication."""
    if not _has_line(config, r"^ip http secure-server$"):
        return NotApplicable("the HTTPS server (ip http secure-server) is not enabled")
    return _has_line(config, r"^ip http access-class ") and _has_line(
        config, r"^ip http authentication (local|aaa)"
    )


MAX_EXEC_TIMEOUT_SECONDS = 5 * 60  # DISA STIG (Cisco IOS XE)
_EXEC_TIMEOUT = re.compile(r"^exec-timeout (\d+)(?: (\d+))?$")


@register("exec-timeout-max")
def _exec_timeout_max(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Session timeout of at most 5 minutes, minutes and seconds (IOS-MGMT-005).

    "exec-timeout 5 30" is 5.5 minutes. "exec-timeout 0 0" never times out.
    Without the line IOS uses 10 minutes, which is too long.
    """
    values = [
        int(m.group(1)) * 60 + int(m.group(2) or 0)
        for child in block.children
        if (m := _EXEC_TIMEOUT.match(child.text))
    ]
    return bool(values) and all(0 < v <= MAX_EXEC_TIMEOUT_SECONDS for v in values)


@register("smart-install-disabled")
def _smart_install_disabled(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Switches (any interface with a switchport line) carry ``no vstack``.

    Smart Install exists only on switches; on a router the rule does not apply.
    """
    if not _is_switch(config):
        return NotApplicable(NOT_A_SWITCH)
    return _has_line(config, r"^no vstack$")


# ------------------------------------------------------------------- logging


MIN_SYSLOG_SERVERS = 2  # DISA STIG (Cisco IOS XE)

# "logging host <addr> [vrf ...]", "logging host ipv6 <addr>", or the older "logging <ipv4>".
_SYSLOG_HOST = re.compile(r"^logging (?:host (?:ipv6 )?(\S+)|(\d+\.\d+\.\d+\.\d+)$)")


@register("remote-syslog-servers")
def _remote_syslog_servers(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """At least MIN_SYSLOG_SERVERS different syslog servers (IOS-LOG-002)."""
    hosts = {m.group(1) or m.group(2) for line in config if (m := _SYSLOG_HOST.match(line.text))}
    return len(hosts) >= MIN_SYSLOG_SERVERS


@register("config-change-logging")
def _config_change_logging(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """``archive`` > ``log config`` > ``logging enable`` exists (IOS-LOG-003)."""
    for archive in _blocks(config, r"^archive$"):
        for log_config in _blocks(archive.children, r"^log config$"):
            if _has_line(log_config.children, r"^logging enable$"):
                return True
    return False


# ------------------------------------------------------------------------ L2


@register("bpduguard")
def _bpduguard(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Access port is protected by BPDU guard (IOS-L2-005).

    Either the port enables it itself, or the global "bpduguard default"
    applies, which covers only PortFast ports (per port or global default).
    A port with PortFast disabled needs its own "bpduguard enable".
    """
    ports = block.children
    if _has_line(ports, r"^spanning-tree bpduguard disable$"):
        return False
    if _has_line(ports, r"^spanning-tree bpduguard enable$"):
        return True
    # PortFast switched off on the port: the global defaults do not reach it.
    if _has_line(ports, r"^(spanning-tree portfast (edge )?disable|no spanning-tree portfast)$"):
        return False
    global_guard = _has_line(config, r"^spanning-tree portfast (edge )?bpduguard default$")
    portfast = _has_line(ports, r"^spanning-tree portfast( edge)?$") or _has_line(
        config, r"^spanning-tree portfast (edge )?default$"
    )
    return global_guard and portfast


# "standby 1 ip 10.0.0.1", "standby ip 10.0.0.1" (HSRP group 0), "standby 1 ip"
# (address learned from the peer) and "vrrp 2 ip 10.0.0.1".
_FHRP_GROUP = re.compile(r"^(standby|vrrp)(?: (\d+))? ip( |$)")


def fhrp_groups_without_md5(children: list[ConfigLine]) -> list[tuple[str, str]]:
    """(protocol, group) of every HSRP / VRRP group without MD5, in config order.

    HSRP group 0 is written without a number ("standby ip ...").
    """
    groups = dict.fromkeys(
        (m.group(1), m.group(2) or "0") for c in children if (m := _FHRP_GROUP.search(c.text))
    )

    def has_md5(protocol: str, group: str) -> bool:
        number = "( 0)?" if protocol == "standby" and group == "0" else f" {group}"
        return _has_line(children, rf"^{protocol}{number} authentication md5 ")

    return [(p, g) for p, g in groups if not has_md5(p, g)]


@register("fhrp-authentication")
def _fhrp_authentication(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Every HSRP / VRRP group on the interface uses MD5 (IOS-L2-004)."""
    return not fhrp_groups_without_md5(block.children)


# ----------------------------------------------------------------------- NTP


MIN_NTP_SERVERS = 2  # DISA STIG V-215838; the remediation recommends 3 to 4

_NTP_SOURCE = re.compile(r"^ntp (?:server|peer) (?:vrf \S+ )?(?:ip |ipv6 )?(\S+)")


@register("ntp-servers")
def _ntp_servers(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """At least MIN_NTP_SERVERS different NTP servers or peers (IOS-NTP-001)."""
    sources = {m.group(1) for line in config if (m := _NTP_SOURCE.match(line.text))}
    return len(sources) >= MIN_NTP_SERVERS


@register("ntp-authentication")
def _ntp_authentication(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """NTP servers and peers are authenticated (IOS-NTP-003).

    Needs ``ntp authenticate`` and ``key <n>`` on every server / peer line,
    where key n is defined (``ntp authentication-key n``) and trusted
    (``ntp trusted-key n`` or a range ``a - b``). N/A without servers
    (IOS-NTP-001 reports that).
    """
    sources = [line for line in config if re.search(r"^ntp (server|peer) ", line.text)]
    if not sources:
        return NotApplicable("no NTP server or peer is configured (see IOS-NTP-001)")
    if not _has_line(config, r"^ntp authenticate$"):
        return False
    defined = {
        int(m.group(1))
        for line in config
        if (m := re.match(r"^ntp authentication-key (\d+) ", line.text))
    }
    trusted: set[int] = set()
    for line in config:
        if m := re.match(r"^ntp trusted-key (\d+)(?: - (\d+))?$", line.text):
            low = int(m.group(1))
            trusted.update(range(low, int(m.group(2) or low) + 1))
    for source in sources:
        m = re.search(r" key (\d+)( |$)", source.text)
        if not m or int(m.group(1)) not in defined & trusted:
            return False
    return True


# ------------------------------------------------------------ IF, L2 and SVC


@register("ip-options-drop")
def _ip_options_drop(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """``ip options drop`` is set, except where Router Alert is needed (IOS-IF-001).

    Dropping IP options also drops packets with the Router Alert option that
    IGMP, PIM and RSVP (MPLS TE) rely on, so the rule does not apply where
    multicast routing or RSVP runs.
    """
    interfaces = _blocks(config, r"^interface ")
    if _has_line(config, r"^ip multicast-routing( |$)") or any(
        _has_line(interface.children, r"^ip pim ") for interface in interfaces
    ):
        return NotApplicable("the device routes multicast (ip multicast-routing or ip pim)")
    if _has_line(config, r"^mpls traffic-eng tunnels$") or any(
        _has_line(interface.children, r"^(mpls traffic-eng tunnels$|ip rsvp )")
        for interface in interfaces
    ):
        return NotApplicable("the device runs RSVP (mpls traffic-eng tunnels or ip rsvp)")
    return _has_line(config, r"^ip options drop$")


@register("dhcp-snooping")
def _dhcp_snooping(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Switches run DHCP snooping on at least one VLAN (IOS-L2-007)."""
    if not _is_switch(config):
        return NotApplicable(NOT_A_SWITCH)
    return _has_line(config, r"^ip dhcp snooping$") and _has_line(
        config, r"^ip dhcp snooping vlan \d"
    )


# Addresses that do not face the internet: RFC 1918, shared address space
# (carrier-grade NAT), link-local and loopback.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
    + ("169.254.0.0/16", "127.0.0.0/8")
]
_IP_ADDRESS = re.compile(r"^ip address (dhcp|negotiated|\d+\.\d+\.\d+\.\d+)\b")


def _is_external(interface: ConfigLine) -> bool:
    """The interface faces another network: a public IPv4 address, DHCP or PPP."""
    for child in interface.children:
        if m := _IP_ADDRESS.match(child.text):
            value = m.group(1)
            if value in ("dhcp", "negotiated"):
                return True
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not any(address in network for network in _INTERNAL_NETWORKS):
                return True
    return False


@register("cdp-external")
def _cdp_external(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """CDP is off on an interface that faces another network (IOS-SVC-009).

    Passes with "no cdp run". Internal interfaces are N/A: phones, access
    points and topology tools need CDP there.
    """
    if _has_line(config, r"^no cdp run$"):
        return True
    if not _is_external(block):
        return NotApplicable(
            "no interface faces another network (public address, dhcp or negotiated)"
        )
    return _has_line(block.children, r"^no cdp enable$")


# DISA STIG V-215813: block for 900 s after 3 failures within 120 s.
MIN_BLOCK_SECONDS = 900
MAX_BLOCK_ATTEMPTS = 3
MIN_BLOCK_WINDOW = 120

_BLOCK_FOR = re.compile(r"^login block-for (\d+) attempts (\d+) within (\d+)$")


@register("login-block-for")
def _login_block_for(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Login rate limiting at STIG values, with an exception for management (IOS-PASS-010).

    "login block-for" alone lets anyone lock every administrator out by
    failing logins on purpose, so it only counts together with
    "login quiet-mode access-class <ACL>".
    """
    values = [
        (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        for line in config
        if (m := _BLOCK_FOR.match(line.text))
    ]
    strict_enough = bool(values) and all(
        seconds >= MIN_BLOCK_SECONDS
        and attempts <= MAX_BLOCK_ATTEMPTS
        and window >= MIN_BLOCK_WINDOW
        for seconds, attempts, window in values
    )
    return strict_enough and _has_line(config, r"^login quiet-mode access-class \S+")


MAX_LOGIN_FAILURES = 3  # DISA STIG (Cisco IOS XE)


@register("local-max-fail")
def _local_max_fail(block: ConfigLine, config: list[ConfigLine]) -> CheckResult:
    """Local accounts lock after at most MAX_LOGIN_FAILURES failures (IOS-PASS-011).

    The command needs ``aaa new-model``; without AAA the rule does not apply
    (IOS-AAA-001 reports the missing AAA).
    """
    if not _has_line(config, r"^aaa new-model$"):
        return NotApplicable("aaa new-model is not enabled (see IOS-AAA-001)")
    values = [
        int(m.group(1))
        for line in config
        if (m := re.match(r"^aaa local authentication attempts max-fail (\d+)", line.text))
    ]
    return bool(values) and all(v <= MAX_LOGIN_FAILURES for v in values)
