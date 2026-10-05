"""Vendor-neutral data models shared by all core modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


@dataclass
class ConfigLine:
    """One line of configuration and the lines nested under it."""

    text: str
    children: list[ConfigLine] = field(default_factory=list)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric order for sorting: low = 0 ... critical = 3."""
        return list(Severity).index(self)


@dataclass(frozen=True)
class Finding:
    """A single rule violation.

    The pair (rule_id, target) identifies the finding; later versions use it
    for waivers and compliance drift.
    """

    rule_id: str
    severity: Severity
    target: str
    message: str
