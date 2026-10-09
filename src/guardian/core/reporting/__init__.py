"""Reporting: renders an ``AuditResult`` as JSON or HTML.

Both formats use the same order: most severe first, then by rule ID (and
for findings by target), so two runs on the same config differ only in the
time stamp.
"""

import os
import secrets
from collections import Counter
from pathlib import Path

from guardian.core.models import AuditResult, Finding, RuleResult, Severity, Status


def sorted_rules(result: AuditResult) -> list[RuleResult]:
    return sorted(result.rules, key=lambda r: (-r.severity.rank, r.rule_id))


def sorted_findings(result: AuditResult) -> list[Finding]:
    return sorted(result.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.target))


def summary(result: AuditResult) -> dict:
    """Counts shared by all report formats."""
    statuses = Counter(r.status for r in result.rules)
    severities = Counter(f.severity for f in result.findings)
    return {
        "rules": len(result.rules),
        "pass": statuses[Status.PASS],
        "fail": statuses[Status.FAIL],
        "na": statuses[Status.NOT_APPLICABLE],
        "findings": len(result.findings),
        "findings_by_severity": {s.value: severities[s] for s in reversed(Severity)},
    }


def write_private(path: Path, text: str) -> None:
    """Write a report readable by the owner only (0600).

    Reports describe the weak spots of a device, so other local users must
    not read them. The text goes to a new temporary file next to ``path``,
    which then replaces ``path`` in one step: a reader never sees half a
    report, and an existing file keeps no old permissions. A symlink at
    ``path`` is refused instead of followed (it could point anywhere).
    """
    if path.is_symlink():
        raise OSError(f"{path} is a symbolic link; refusing to write through it")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), 0o600)
            f.write(text)
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
