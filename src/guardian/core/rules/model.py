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

from guardian.core.models import Severity

Pattern = re.Pattern[str]


@dataclass(frozen=True)
class Scope:
    """Where a rule looks.

    An empty ``path`` means the global configuration (the top-level lines).
    Otherwise each regex in ``path`` selects lines one nesting level deeper:
    ``("^router bgp ", "^address-family ")`` selects address families inside
    BGP. ``has_child`` / ``not_has_child`` then keep only blocks that do /
    do not contain a matching child line.
    """

    path: tuple[Pattern, ...] = ()
    has_child: tuple[Pattern, ...] = ()
    not_has_child: tuple[Pattern, ...] = ()

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

    compliant: tuple[str, ...] = ()
    non_compliant: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    scope: Scope
    check: Check
    rationale: str
    remediation: str
    references: tuple[str, ...] = ()
    examples: Examples = field(default_factory=Examples)
    source: Path | None = None
