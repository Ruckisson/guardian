"""Render a rule's remediation for one finding.

Remediations are written by hand in the rule's YAML. Guardian never derives
one by putting ``no`` in front of the offending line (``no username admin``
would delete the user instead of fixing its password).

A few values can be taken from the config so the operator does not have to
type them: the failing block, an interface or ACL name, a user name, NTP
servers. They end up in commands an operator may paste into a device, so
each one must match a whitelist; a value that does not (control characters,
spaces, unexpected names) is replaced by its ``<PLACEHOLDER>`` and a note
says so. Secrets (passwords, keys, SNMP communities, URLs) are never taken
from the config; rules use placeholders such as ``<NEW_PASSWORD>`` instead.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from guardian.core.models import Alternative, ConfigLine, Remediation
from guardian.core.rules.custom import fhrp_groups_without_md5
from guardian.core.rules.model import RemediationSpec, Variant

VARIABLE = re.compile(r"\{(\w+)\}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

UNSAFE_VALUE_NOTE = (
    "A value from the config did not pass validation, so it is shown as a placeholder. "
    "Fill it in by hand."
)

_NAME = r"[A-Za-z0-9_.-]{1,64}"
_INTERFACE = r"[A-Za-z][A-Za-z0-9./:-]{0,63}"


@dataclass(frozen=True)
class Context:
    """Where a finding was found: the failing block, the offending line, the config.

    ``line`` is the raw offending line of a global check, before redaction. It
    may contain secrets; only whitelisted parts of it are ever used.
    """

    config: list[ConfigLine]
    block: ConfigLine | None = None
    label: str | None = None
    line: str | None = None


@dataclass(frozen=True)
class Variable:
    placeholder: str
    extract: Callable[[Context], list[str]]
    valid: re.Pattern[str]
    needs: str  # "block" (block scope), "line" (global scope) or "config" (any)
    default: str | None = None  # used when the config has no value (never when one is rejected)


def _children(ctx: Context, pattern: str) -> list[str]:
    if ctx.block is None:
        return []
    return [m.group(1) for c in ctx.block.children if (m := re.match(pattern, c.text))]


def _from_line(pattern: str) -> Callable[[Context], list[str]]:
    def extract(ctx: Context) -> list[str]:
        m = re.match(pattern, ctx.line or "")
        return [m.group(1)] if m else []

    return extract


def _interface(ctx: Context) -> list[str]:
    label = ctx.label or ""
    return [label.removeprefix("interface ")] if label.startswith("interface ") else []


def _switchport_mode(ctx: Context) -> list[str]:
    """Guess the intended mode from the other lines of the port."""
    if _children(ctx, r"^switchport (trunk) "):
        return ["trunk"]
    if _children(ctx, r"^switchport (access) vlan "):
        return ["access"]
    return []


def _fhrp_groups(ctx: Context) -> list[str]:
    """Only the groups that fail IOS-L2-004, as their command prefix.

    "standby 1", "vrrp 2", or "standby" for HSRP group 0, which is written
    without a number. Groups that already use MD5 are left alone, so their
    key chain is never overwritten.
    """
    if ctx.block is None:
        return []
    return [
        protocol if protocol == "standby" and group == "0" else f"{protocol} {group}"
        for protocol, group in fhrp_groups_without_md5(ctx.block.children)
    ]


def _http_auth(ctx: Context) -> list[str]:
    """The configured "ip http authentication" method, so a fix never replaces aaa."""
    for line in ctx.config:
        if m := re.match(r"^ip http authentication (.+)$", line.text):
            return [m.group(1)]
    return []


def _vty_acl(ctx: Context) -> list[str]:
    for line in ctx.config:
        if line.text.startswith("line vty "):
            for child in line.children:
                if m := re.match(r"^access-class (\S+) in", child.text):
                    return [m.group(1)]
    return []


_NTP_LINE = re.compile(r"^ntp (server|peer) (?:(vrf \S+) )?(?:(?:ip|ipv6) )?(\S+)(.*)$")
# Options that carry no secret and are kept when the line is entered again.
_NTP_OPTION = re.compile(r"\s*(prefer|iburst|burst|source \S+|version \d|minpoll \d+|maxpoll \d+)")


def _ntp_sources(ctx: Context) -> list[str]:
    """Each "ntp server/peer" line without "ntp " and without its key.

    "ntp server ip ntp1.example.com prefer key 3" becomes
    "server ntp1.example.com prefer": the ip/ipv6 keyword and the old key are
    dropped, the options without secrets are kept, because entering the line
    again replaces its options.
    """
    sources = []
    for line in ctx.config:
        if not (m := _NTP_LINE.match(line.text)):
            continue
        kind, vrf, address, rest = m.groups()
        options = [o.group(1) for o in _NTP_OPTION.finditer(rest)]
        sources.append(" ".join([kind, *([vrf] if vrf else []), address, *options]))
    return sources


VARIABLES: dict[str, Variable] = {
    "block": Variable(
        "<BLOCK>",
        lambda ctx: [ctx.label] if ctx.label else [],
        re.compile(
            rf"interface {_INTERFACE}"
            r"|line (?:(?:con|aux|vty|tty) )?\d+(?:/\d+)*(?: \d+(?:/\d+)*)?"
        ),
        "block",
    ),
    "interface": Variable("<INTERFACE>", _interface, re.compile(_INTERFACE), "block"),
    "switchport_mode": Variable(
        "<ACCESS_OR_TRUNK>", _switchport_mode, re.compile("access|trunk"), "block"
    ),
    "acl_name": Variable(
        "<ACL_NAME>",
        lambda ctx: _children(ctx, r"^access-class (\S+) in"),
        re.compile(_NAME),
        "block",
    ),
    "fhrp_group": Variable(
        "<FHRP_GROUP>",
        _fhrp_groups,
        re.compile(r"(?:standby|vrrp)(?: \d{1,4})?"),
        "block",
    ),
    "username": Variable("<USERNAME>", _from_line(r"^username (\S+) "), re.compile(_NAME), "line"),
    "snmp_group": Variable(
        "<GROUP>", _from_line(r"^snmp-server group (\S+) v3 "), re.compile(_NAME), "line"
    ),
    "snmp_level": Variable(
        "<OLD_LEVEL>",
        _from_line(r"^snmp-server group \S+ v3 (noauth|auth)\b"),
        re.compile("noauth|auth"),
        "line",
    ),
    "vty_acl": Variable("<MGMT_ACL>", _vty_acl, re.compile(_NAME), "config"),
    "http_auth": Variable(
        "<HTTP_AUTH_METHOD>",
        _http_auth,
        re.compile(rf"local|enable|aaa(?: login-authentication {_NAME})?"),
        "config",
        default="local",
    ),
    "ntp_source": Variable(
        "server <NTP_SERVER_IP>",
        _ntp_sources,
        re.compile(
            rf"(?:server|peer)(?: vrf {_NAME})? [A-Za-z0-9.:-]{{1,253}}"
            r"(?: (?:prefer|iburst|burst|source [A-Za-z][A-Za-z0-9./:-]{0,63}"
            r"|version \d|minpoll \d+|maxpoll \d+))*"
        ),
        "config",
    ),
}

# Variables that can have several values: a command using one is repeated.
LIST_VARIABLES = {"ntp_source", "fhrp_group"}


def is_safe(name: str, value: str) -> bool:
    """True if ``value`` may be put into a command as variable ``name``."""
    return not _CONTROL.search(value) and bool(VARIABLES[name].valid.fullmatch(value))


class _Values:
    """Variable values for one finding, extracted once and validated."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.cache: dict[str, list[str] | None] = {}
        self.rejected = False

    def get(self, name: str) -> list[str] | None:
        """Valid values, or None when the placeholder must be used."""
        if name not in self.cache:
            variable = VARIABLES[name]
            values = variable.extract(self.ctx)
            safe = [v for v in values if is_safe(name, v)]
            if len(safe) < len(values):
                self.rejected = True
                safe = []
            elif not values and variable.default is not None:
                safe = [variable.default]
            self.cache[name] = safe or None
        return self.cache[name]

    def text(self, template: str) -> str:
        """Fill variables in a text; several values are joined with commas."""

        def fill(m: re.Match[str]) -> str:
            values = self.get(m.group(1))
            return ", ".join(values) if values else VARIABLES[m.group(1)].placeholder

        return VARIABLE.sub(fill, template)

    def commands(self, commands: tuple[str, ...]) -> tuple[str, ...]:
        out: list[str] = []
        for command in commands:
            names = VARIABLE.findall(command)
            repeat = [n for n in names if n in LIST_VARIABLES]
            values = self.get(repeat[0]) if repeat else None
            if values and len(values) > 1:
                for value in values:
                    out.append(self.text(command.replace("{" + repeat[0] + "}", value)))
            else:
                out.append(self.text(command))
        return tuple(out)


def _matches(variant: Variant, ctx: Context) -> bool:
    if variant.when_config and not any(variant.when_config.search(c.text) for c in ctx.config):
        return False
    if variant.when_block:
        children = ctx.block.children if ctx.block else []
        if not any(variant.when_block.search(c.text) for c in children):
            return False
    return not (variant.when_line and not variant.when_line.search(ctx.line or ""))


def choose_variant(spec: RemediationSpec, ctx: Context) -> Variant:
    """The first variant whose conditions hold; the last one is the default."""
    return next(
        (v for v in spec.recommended_change if _matches(v, ctx)), spec.recommended_change[-1]
    )


def render(spec: RemediationSpec, ctx: Context) -> Remediation:
    values = _Values(ctx)
    variant = choose_variant(spec, ctx)
    alternative = None
    if spec.if_service_needed:
        alternative = Alternative(
            values.text(spec.if_service_needed.text),
            values.commands(spec.if_service_needed.commands),
        )
    commands = values.commands(variant.commands)
    before = tuple(values.text(t) for t in spec.before_you_apply)
    notes = tuple(values.text(t) for t in (*variant.notes, *spec.notes))
    if values.rejected:
        notes = (*notes, UNSAFE_VALUE_NOTE)
    return Remediation(
        recommended_change=commands,
        before_you_apply=before,
        notes=notes,
        if_service_needed=alternative,
        may_cut_access=spec.may_cut_access,
        change_both_ends=spec.change_both_ends,
    )
