"""In-memory form of a compliance rule, as produced by the loader.

A rule has two parts:

* a **scope** that says where to look: the global configuration, or blocks
  selected by a path of regexes, optionally filtered by their children;
* a **check** that says what must be true inside every selected place.

Regexes are compiled once by the loader, so evaluation never has to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from guardian.core.models import References, Severity

Pattern = re.Pattern[str]


@dataclass(frozen=True)
class Skip:
    """A selected block is N/A when its header matches ``block`` and a child ``child``."""

    child: Pattern
    reason: str
    block: Pattern | None = None


@dataclass(frozen=True)
class Scope:
    """Where a rule looks.

    An empty ``path`` means the global configuration (the top-level lines).
    Otherwise each regex in ``path`` selects lines one nesting level deeper:
    ``("^router bgp ", "^address-family ")`` selects address families inside
    BGP. ``has_child`` / ``not_has_child`` then keep only blocks that do /
    do not contain a matching child line. ``skip_if`` marks selected blocks
    as N/A with a reason, e.g. VTY lines that accept no connections.
    """

    path: tuple[Pattern, ...] = ()
    has_child: tuple[Pattern, ...] = ()
    not_has_child: tuple[Pattern, ...] = ()
    skip_if: tuple[Skip, ...] = ()

    @property
    def is_global(self) -> bool:
        return not self.path


@dataclass(frozen=True)
class MustExist:
    """At least one line in the scope must match."""

    pattern: Pattern


@dataclass(frozen=True)
class MustNotExist:
    """No line in the scope may match."""

    pattern: Pattern


@dataclass(frozen=True)
class EachMustMatch:
    """Every line matching ``select`` must also match ``pattern``."""

    select: Pattern
    pattern: Pattern


@dataclass(frozen=True)
class Value:
    """A number captured by ``pattern`` (group 1) must lie within min/max.

    ``if_missing`` decides what happens when no line matches: "pass" for
    settings whose platform default is already compliant, "fail" otherwise.
    """

    pattern: Pattern
    min: int | None = None
    max: int | None = None
    if_missing: Literal["pass", "fail"] = "fail"


@dataclass(frozen=True)
class Reference:
    """Every value captured by ``capture`` must be defined elsewhere.

    ``must_exist`` is a regex template searched among the top-level lines;
    ``{name}`` is replaced by the escaped value of the named group ``name``.
    """

    capture: Pattern
    must_exist: str


@dataclass(frozen=True)
class Python:
    """Escape hatch: a check function registered in ``guardian.core.rules.custom``."""

    name: str


Check = MustExist | MustNotExist | EachMustMatch | Value | Reference | Python


@dataclass(frozen=True)
class Examples:
    """Config snippets used by the test suite; the engine ignores them."""

    compliant: tuple[str, ...] = ()  # must PASS
    non_compliant: tuple[str, ...] = ()  # must FAIL
    not_applicable: tuple[str, ...] = ()  # must be N/A


@dataclass(frozen=True)
class Variant:
    """One version of the recommended change, used when its conditions hold.

    ``when_config`` must match a top-level line, ``when_block`` a line inside
    the failing block, ``when_line`` the offending config line. A variant
    without conditions is the default and comes last. Its ``notes`` are shown
    before the rule's notes.
    """

    commands: tuple[str, ...]
    notes: tuple[str, ...] = ()
    when_config: Pattern | None = None
    when_block: Pattern | None = None
    when_line: Pattern | None = None


@dataclass(frozen=True)
class AlternativeSpec:
    text: str
    commands: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationSpec:
    """The remediation of a rule as written in YAML.

    Commands and texts may contain ``{variables}`` filled from the config
    (see ``guardian.core.rules.remediation``) and ``<PLACEHOLDERS>`` that a
    person fills in.
    """

    recommended_change: tuple[Variant, ...]
    before_you_apply: tuple[str, ...]
    notes: tuple[str, ...] = ()
    if_service_needed: AlternativeSpec | None = None
    may_cut_access: bool = False
    change_both_ends: bool = False


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    scope: Scope
    check: Check
    rationale: str
    remediation: RemediationSpec
    references: References = field(default_factory=References)
    applies_to: str = ""  # what the scope selects, e.g. "VTY lines"; for N/A reasons
    examples: Examples = field(default_factory=Examples)
    source: Path | None = None

    @property
    def area(self) -> str:
        """The AREA part of the PLATFORM-AREA-NNN id, e.g. ``SNMP``."""
        return self.id.split("-")[1]


# Short descriptions of rule areas, shown above each group by "guardian rules".
# An area missing here (e.g. in a custom rule directory) is shown without one.
AREA_DESCRIPTIONS = {
    "AAA": "Authentication, authorization and accounting",
    "IF": "Interfaces and IP packet handling (proxy ARP, redirects, IP options)",
    "L2": "Layer 2 security (port security/802.1X, DTP, native VLAN, BPDU guard, DHCP snooping)",
    "LOG": "Logging (timestamps, remote syslog, config changes, logins)",
    "MGMT": "Management access (VTY, console, AUX, SSH, HTTP/HTTPS server, banner)",
    "NTP": "Time synchronization (NTP servers and authentication)",
    "PASS": "Passwords, secrets and login protection",
    "SNMP": "SNMP communities and SNMPv3",
    "SVC": "Unneeded services (small servers, r-services, Smart Install, source routing, CDP)",
}
