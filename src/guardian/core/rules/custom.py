"""Registry of Python checks for logic that YAML cannot express.

A YAML rule refers to a check by name (``check: {python: <name>}``); it can
never point at an arbitrary module, so rule files cannot execute code.

A check receives the selected block (or a virtual root for global scope)
and the whole parsed configuration, and returns True when compliant::

    @register("vty-count-matches-something")
    def _vty_count(block: ConfigLine, config: list[ConfigLine]) -> bool:
        ...
"""

import re
from collections.abc import Callable

from guardian.core.models import ConfigLine

CustomCheck = Callable[[ConfigLine, list[ConfigLine]], bool]

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

MIN_PASSWORD_LENGTH = 8

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
def _min_length_hashed(block: ConfigLine, config: list[ConfigLine]) -> bool:
    return _min_length_ok(config) or _has_reversible_password(config)


@register("password-min-length-reversible")
def _min_length_reversible(block: ConfigLine, config: list[ConfigLine]) -> bool:
    return _min_length_ok(config) or not _has_reversible_password(config)


# ------------------------------------------------------------------- helpers


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
def _line_requires_login(block: ConfigLine, config: list[ConfigLine]) -> bool:
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
def _vty_ipv6_access_class(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """With IPv6 on any interface, the VTY line has an IPv6 access-class."""
    if not _ipv6_enabled(config):
        return True
    return _has_line(block.children, r"^ipv6 access-class \S+ in$")


@register("https-server-restricted")
def _https_server_restricted(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """If the HTTPS server runs, it has an access-class and real authentication."""
    if not _has_line(config, r"^ip http secure-server$"):
        return True
    return _has_line(config, r"^ip http access-class ") and _has_line(
        config, r"^ip http authentication (local|aaa)"
    )


@register("smart-install-disabled")
def _smart_install_disabled(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """Switches (any interface with a switchport line) carry ``no vstack``.

    Smart Install exists only on switches; on a router the check passes.
    """
    return not _is_switch(config) or _has_line(config, r"^no vstack$")


# ------------------------------------------------------------------- logging


@register("config-change-logging")
def _config_change_logging(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """``archive`` > ``log config`` > ``logging enable`` exists (IOS-LOG-003)."""
    for archive in _blocks(config, r"^archive$"):
        for log_config in _blocks(archive.children, r"^log config$"):
            if _has_line(log_config.children, r"^logging enable$"):
                return True
    return False


# ------------------------------------------------------------------------ L2


@register("bpduguard")
def _bpduguard(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """Access port is protected by BPDU guard (IOS-L2-005).

    Either the port enables it itself, or the global "bpduguard default"
    applies, which covers only PortFast ports (per port or global default).
    """
    ports = block.children
    if _has_line(ports, r"^spanning-tree bpduguard disable$"):
        return False
    if _has_line(ports, r"^spanning-tree bpduguard enable$"):
        return True
    global_guard = _has_line(config, r"^spanning-tree portfast (edge )?bpduguard default$")
    portfast = _has_line(ports, r"^spanning-tree portfast( edge)?$") or _has_line(
        config, r"^spanning-tree portfast (edge )?default$"
    )
    return global_guard and portfast


_FHRP_GROUP = re.compile(r"^(standby|vrrp)(?: (\d+))? ip ")


@register("fhrp-authentication")
def _fhrp_authentication(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """Every HSRP / VRRP group on the interface uses MD5 (IOS-L2-004).

    HSRP group 0 is written without a number ("standby ip ...").
    """
    children = block.children
    groups = {
        (m.group(1), m.group(2) or "0") for c in children if (m := _FHRP_GROUP.search(c.text))
    }

    def has_md5(protocol: str, group: str) -> bool:
        number = "( 0)?" if protocol == "standby" and group == "0" else f" {group}"
        return _has_line(children, rf"^{protocol}{number} authentication md5 ")

    return all(has_md5(protocol, group) for protocol, group in groups)


# ----------------------------------------------------------------------- NTP


@register("ntp-authentication")
def _ntp_authentication(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """NTP servers and peers are authenticated (IOS-NTP-003).

    Needs ``ntp authenticate`` and ``key <n>`` on every server / peer line,
    where key n is defined (``ntp authentication-key n``) and trusted
    (``ntp trusted-key n`` or a range ``a - b``). Passes without servers.
    """
    sources = [line for line in config if re.search(r"^ntp (server|peer) ", line.text)]
    if not sources:
        return True
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
def _ip_options_drop(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """``ip options drop`` is set, except on multicast routers (IOS-IF-001).

    Dropping IP options also drops Router Alert packets used by IGMP, PIM and
    RSVP, so the rule does not apply where multicast routing runs.
    """
    if _has_line(config, r"^ip multicast-routing( |$)") or any(
        _has_line(interface.children, r"^ip pim ") for interface in _blocks(config, r"^interface ")
    ):
        return True
    return _has_line(config, r"^ip options drop$")


@register("dhcp-snooping")
def _dhcp_snooping(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """Switches run DHCP snooping on at least one VLAN (IOS-L2-007)."""
    if not _is_switch(config):
        return True
    return _has_line(config, r"^ip dhcp snooping$") and _has_line(
        config, r"^ip dhcp snooping vlan \d"
    )


@register("cdp-disabled")
def _cdp_disabled(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """CDP is off globally, or on every active physical interface (IOS-SVC-009)."""
    if _has_line(config, r"^no cdp run$"):
        return True
    physical = [
        interface
        # Logical and internal interfaces and subinterfaces (CDP is set on the parent).
        for interface in _blocks(
            config,
            r"^interface (?!Loopback|Vlan|Tunnel|Null|Port-channel|AppGigabitEthernet)[^.]*$",
        )
        if not _has_line(interface.children, r"^shutdown$")
    ]
    return all(_has_line(interface.children, r"^no cdp enable$") for interface in physical)


@register("local-max-fail")
def _local_max_fail(block: ConfigLine, config: list[ConfigLine]) -> bool:
    """Local accounts lock after at most 5 failures (IOS-PASS-011).

    The command needs ``aaa new-model``; without AAA the rule does not apply
    (IOS-AAA-001 reports the missing AAA).
    """
    if not _has_line(config, r"^aaa new-model$"):
        return True
    values = [
        int(m.group(1))
        for line in config
        if (m := re.match(r"^aaa local authentication attempts max-fail (\d+)", line.text))
    ]
    return bool(values) and all(v <= 5 for v in values)
