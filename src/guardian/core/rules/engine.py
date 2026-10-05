"""Evaluate rules against a parsed configuration.

The engine is vendor-neutral: it only knows the ``ConfigLine`` tree that a
parser produced. Evaluation has two steps:

1. ``select`` turns the rule's scope into a list of *places*: the global
   configuration, or every block that the scope path and filters select;
2. the rule's check runs in every place and reports the places that fail.

Every failing place becomes one ``Finding``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardian.core.models import ConfigLine, Finding
from guardian.core.redact import redact
from guardian.core.rules import custom
from guardian.core.rules.loader import PLACEHOLDER
from guardian.core.rules.model import (
    Check,
    EachMustMatch,
    MustExist,
    MustNotExist,
    Python,
    Reference,
    Rule,
    Scope,
    Value,
)

GLOBAL_TARGET = "(global)"
PATH_SEPARATOR = " > "


@dataclass(frozen=True)
class Place:
    """Where a check runs: a block (or the virtual root) and its readable label."""

    line: ConfigLine
    label: str
    is_global: bool = False


def evaluate(rule: Rule, config: list[ConfigLine]) -> list[Finding]:
    """Return one finding for every place in the rule's scope that fails its check."""
    findings = []
    for place in select(rule.scope, config):
        for target in run_check(rule.check, place, config):
            findings.append(Finding(rule.id, rule.severity, redact(target), rule.title))
    return findings


def evaluate_all(rules: list[Rule], config: list[ConfigLine]) -> list[Finding]:
    """Evaluate several rules and return all their findings."""
    return [finding for rule in rules for finding in evaluate(rule, config)]


# --------------------------------------------------------------------- scope


def select(scope: Scope, config: list[ConfigLine]) -> list[Place]:
    """Turn a scope into the places where the check must run."""
    if scope.is_global:
        return [Place(ConfigLine(GLOBAL_TARGET, list(config)), GLOBAL_TARGET, is_global=True)]

    places = [Place(line, line.text) for line in config if scope.path[0].search(line.text)]
    for pattern in scope.path[1:]:
        places = [
            Place(child, place.label + PATH_SEPARATOR + child.text)
            for place in places
            for child in place.line.children
            if pattern.search(child.text)
        ]
    return [place for place in places if _passes_filters(scope, place.line)]


def _passes_filters(scope: Scope, block: ConfigLine) -> bool:
    has_all = all(_any_child(block, p) for p in scope.has_child)
    has_none = not any(_any_child(block, p) for p in scope.not_has_child)
    return has_all and has_none


def _any_child(block: ConfigLine, pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(child.text) for child in block.children)


# --------------------------------------------------------------------- checks


def run_check(check: Check, place: Place, config: list[ConfigLine]) -> list[str]:
    """Run one check in one place; return the targets of the findings (may be empty).

    The target is the place's label, except for checks that point at offending
    lines in the global configuration: there each offending line is its own
    target, because the line is the thing to fix.
    """
    lines = place.line.children
    match check:
        case MustExist(pattern):
            return [] if any(pattern.search(line.text) for line in lines) else [place.label]

        case MustNotExist(pattern):
            return _offending(place, [line for line in lines if pattern.search(line.text)])

        case EachMustMatch(select_, pattern):
            bad = [
                line
                for line in lines
                if select_.search(line.text) and not pattern.search(line.text)
            ]
            return _offending(place, bad)

        case Value(pattern, low, high, if_missing):
            values = [m.group(1) for line in lines if (m := pattern.search(line.text))]
            if not values:
                return [] if if_missing == "pass" else [place.label]
            return [] if all(_in_range(v, low, high) for v in values) else [place.label]

        case Reference(capture, template):
            for line in lines:
                if (m := capture.search(line.text)) and not _defined(template, m, config):
                    return [place.label]
            return []

        case Python(name):
            return [] if custom.CHECKS[name](place.line, config) else [place.label]

    raise TypeError(f"unsupported check: {check!r}")  # pragma: no cover


def _in_range(value: str | None, low: int | None, high: int | None) -> bool:
    """True if ``value`` is a whole number within the limits.

    A value that is not a number (a regex that captured the wrong thing) is
    treated as out of range, so a mistake shows up as a finding instead of
    silently passing.
    """
    if value is None or not value.isdigit():
        return False
    number = int(value)
    return (low is None or number >= low) and (high is None or number <= high)


def _offending(place: Place, bad: list[ConfigLine]) -> list[str]:
    if not bad:
        return []
    if place.is_global:
        return [line.text for line in bad]
    return [place.label]


def _defined(template: str, match: re.Match[str], config: list[ConfigLine]) -> bool:
    values = match.groupdict()

    def fill(m: re.Match[str]) -> str:
        name = m.group(1)
        if name in values and values[name] is not None:
            return re.escape(values[name])
        return m.group(0)

    pattern = re.compile(PLACEHOLDER.sub(fill, template))
    return any(pattern.search(line.text) for line in config)
