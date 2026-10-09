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


class Status(StrEnum):
    """Outcome of one rule on one config.

    The values are a stable enum in the JSON report. "na" means there was
    nothing to check; missing data must never give "pass".
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "na"


@dataclass(frozen=True)
class StigReference:
    """One DISA STIG requirement a rule satisfies or is related to."""

    id: str  # V-215813
    stig_id: str  # CISC-ND-000150
    benchmark: str  # Cisco IOS XE Router NDM V3R7
    severity: str  # CAT I / CAT II / CAT III
    relation: str  # satisfies / related


@dataclass(frozen=True)
class References:
    """Official sources behind a rule. Informative; Guardian is not a STIG scanner."""

    stig: tuple[StigReference, ...] = ()
    nist_800_53: tuple[str, ...] = ()
    cisco_guide: str | None = None
    cisa: bool = False


@dataclass(frozen=True)
class Alternative:
    """A milder option when the service must stay: restrict instead of disable."""

    text: str
    commands: tuple[str, ...] = ()


@dataclass(frozen=True)
class Remediation:
    """How to fix one finding, rendered for its place in the config.

    ``recommended_change`` are config commands; values taken from the config
    passed validation, everything else is a ``<PLACEHOLDER>``. Secrets are
    never taken from the config. Nothing here saves the config.
    """

    recommended_change: tuple[str, ...]
    before_you_apply: tuple[str, ...]
    notes: tuple[str, ...] = ()
    if_service_needed: Alternative | None = None
    may_cut_access: bool = False
    change_both_ends: bool = False


@dataclass(frozen=True)
class Finding:
    """A single rule violation.

    The pair (rule_id, target) identifies the finding; later versions use it
    for waivers and compliance drift.
    """

    rule_id: str
    severity: Severity
    target: str
    title: str  # the rule title
    rationale: str = ""
    remediation: Remediation | None = None
    # The place the check ran: a block header or "(global)". For global rules
    # that report offending lines, ``target`` is the line and this is "(global)".
    location: str = ""


@dataclass(frozen=True)
class RuleResult:
    """How one rule came out: PASS, FAIL or N/A (with the reason)."""

    rule_id: str
    title: str
    severity: Severity
    status: Status
    reason: str = ""
    references: References = field(default_factory=References)


@dataclass(frozen=True)
class AuditResult:
    """Everything one audit produced, ready for any report format.

    ``rules`` holds every evaluated rule, ``findings`` every failing place.
    Config values (hostname, version) are copied as they are; findings
    targets are already redacted.
    """

    file: str
    platform: str
    hostname: str | None
    version: str | None
    sha256: str
    generated_at: str  # UTC, ISO 8601
    guardian_version: str
    rules: list[RuleResult]
    findings: list[Finding]
