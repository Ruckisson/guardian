"""Machine-readable JSON report.

Only data, nothing for presentation. Keys are fixed and always present
(``null`` when a value is unknown); ``schema_version`` changes when a key is
renamed or removed. Config values in the report are the hostname, the
version line and finding targets, which are already redacted.
"""

import json
from typing import Any

from guardian.core.models import AuditResult, Finding, References, Remediation
from guardian.core.reporting import sorted_findings, sorted_rules, summary

# 2: findings carry "remediation" (recommended_change, before_you_apply, ...)
# instead of "fix" (kind, commands, precheck).
# 3: rule "status" is "pass" / "fail" / "na" (was "PASS" / "FAIL" / "N/A"),
# summary "not_applicable" is now "na".
# 4: every rule result has "references" (stig, nist_800_53, cisco_guide, cisa).
SCHEMA_VERSION = 4


def to_dict(result: AuditResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "guardian_version": result.guardian_version,
        "generated_at": result.generated_at,
        "input": {
            "file": result.file,
            "sha256": result.sha256,
            "platform": result.platform,
            "hostname": result.hostname,
            "version": result.version,
        },
        "summary": summary(result),
        "rules": [
            {
                "id": r.rule_id,
                "title": r.title,
                "severity": r.severity.value,
                "status": r.status.value,
                "reason": r.reason or None,
                "references": _references(r.references),
            }
            for r in sorted_rules(result)
        ],
        "findings": [_finding(f) for f in sorted_findings(result)],
    }


def render(result: AuditResult) -> str:
    """The report as JSON text, ending with a newline."""
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "target": finding.target,
        "location": finding.location,
        "rationale": finding.rationale,
        "remediation": _remediation(finding.remediation),
    }


def _references(refs: References) -> dict[str, Any]:
    """Same structure as the rule's YAML."""
    return {
        "stig": [
            {
                "id": s.id,
                "stig_id": s.stig_id,
                "benchmark": s.benchmark,
                "severity": s.severity,
                "relation": s.relation,
            }
            for s in refs.stig
        ],
        "nist_800_53": list(refs.nist_800_53),
        "cisco_guide": refs.cisco_guide,
        "cisa": refs.cisa,
    }


def _remediation(remediation: Remediation | None) -> dict[str, Any] | None:
    if remediation is None:
        return None
    alternative = remediation.if_service_needed
    return {
        "recommended_change": list(remediation.recommended_change),
        "before_you_apply": list(remediation.before_you_apply),
        "notes": list(remediation.notes),
        "if_service_needed": (
            {"text": alternative.text, "commands": list(alternative.commands)}
            if alternative
            else None
        ),
        "may_cut_access": remediation.may_cut_access,
        "change_both_ends": remediation.change_both_ends,
    }
