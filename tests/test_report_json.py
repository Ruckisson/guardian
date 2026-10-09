"""Tests for the JSON report: stable structure, order and no secrets."""

import json
from datetime import UTC, datetime

import pytest

from conftest import FIXTURES, SECRETS
from guardian.core.audit import audit_file
from guardian.core.models import Severity
from guardian.core.reporting import json as json_report

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def report(fixture: str) -> dict:
    return json.loads(json_report.render(audit_file(FIXTURES / fixture, now=NOW)))


def test_top_level_keys_and_order() -> None:
    data = report("insecure_router.cfg")

    assert list(data) == [
        "schema_version",
        "guardian_version",
        "generated_at",
        "input",
        "summary",
        "rules",
        "findings",
    ]
    assert data["schema_version"] == json_report.SCHEMA_VERSION
    assert data["generated_at"] == "2026-10-08T12:00:00Z"
    assert list(data["input"]) == ["file", "sha256", "platform", "hostname", "version"]
    assert data["input"]["hostname"] == "EDGE-R1"


def test_rule_and_finding_keys() -> None:
    data = report("insecure_router.cfg")

    rule_keys = ["id", "title", "severity", "status", "reason", "references"]
    assert all(list(r) == rule_keys for r in data["rules"])
    for rule in data["rules"]:
        assert list(rule["references"]) == ["stig", "nist_800_53", "cisco_guide", "cisa"]
    for finding in data["findings"]:
        assert list(finding) == [
            "rule_id",
            "severity",
            "title",
            "target",
            "location",
            "rationale",
            "remediation",
        ]
        assert list(finding["remediation"]) == [
            "recommended_change",
            "before_you_apply",
            "notes",
            "if_service_needed",
            "may_cut_access",
            "change_both_ends",
        ]
        assert isinstance(finding["remediation"]["may_cut_access"], bool)
        assert isinstance(finding["remediation"]["change_both_ends"], bool)


def test_schema_version_is_4() -> None:
    assert report("insecure_router.cfg")["schema_version"] == 4


def test_references_match_the_rule_yaml() -> None:
    by_id = {r["id"]: r["references"] for r in report("insecure_switch.cfg")["rules"]}

    assert by_id["IOS-PASS-010"] == {
        "stig": [
            {
                "id": "V-215813",
                "stig_id": "CISC-ND-000150",
                "benchmark": "Cisco IOS XE Router NDM V3R7",
                "severity": "CAT II",
                "relation": "satisfies",
            }
        ],
        "nist_800_53": ["AC-7"],
        "cisco_guide": None,
        "cisa": False,
    }
    assert by_id["IOS-SNMP-005"] == {
        "stig": [],
        "nist_800_53": [],
        "cisco_guide": None,
        "cisa": False,
    }


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.cfg")))
def test_status_is_a_stable_lowercase_enum(fixture) -> None:
    data = report(fixture)

    assert {r["status"] for r in data["rules"]} <= {"pass", "fail", "na"}
    failing = {f["rule_id"] for f in data["findings"]}
    for rule in data["rules"]:
        # fail exactly when there are findings; na always with a reason
        assert (rule["status"] == "fail") == (rule["id"] in failing)
        assert (rule["status"] == "na") == (rule["reason"] is not None)


def test_remediation_flags_and_alternative() -> None:
    data = report("insecure_switch.cfg")
    by_rule = {f["rule_id"]: f["remediation"] for f in data["findings"]}

    assert by_rule["IOS-MGMT-001"]["may_cut_access"] is True
    assert by_rule["IOS-L2-006"]["change_both_ends"] is True
    assert by_rule["IOS-L2-003"]["change_both_ends"] is False
    assert by_rule["IOS-LOG-001"]["may_cut_access"] is False
    http = by_rule["IOS-MGMT-006"]
    assert http["recommended_change"] == ["no ip http server"]
    assert http["may_cut_access"] is True
    assert http["if_service_needed"]["text"]
    assert "ip http active-session-modules none" in http["if_service_needed"]["commands"]


def test_summary_matches_lists() -> None:
    data = report("insecure_switch.cfg")
    summary = data["summary"]

    assert summary["rules"] == len(data["rules"])
    assert summary["findings"] == len(data["findings"])
    assert summary["pass"] + summary["fail"] + summary["na"] == summary["rules"]
    assert sum(summary["findings_by_severity"].values()) == summary["findings"]
    assert list(summary["findings_by_severity"]) == ["critical", "high", "medium", "low"]


def test_sorted_by_severity_then_rule_id() -> None:
    data = report("insecure_switch.cfg")

    def key(item, id_key):
        return (-Severity(item["severity"]).rank, item[id_key])

    assert data["rules"] == sorted(data["rules"], key=lambda r: key(r, "id"))
    findings = [(key(f, "rule_id"), f["target"]) for f in data["findings"]]
    assert findings == sorted(findings)


def test_not_applicable_has_reason() -> None:
    data = report("insecure_router.cfg")

    na = [r for r in data["rules"] if r["status"] == "na"]
    assert na and all(r["reason"] for r in na)
    assert all(r["reason"] is None for r in data["rules"] if r["status"] != "na")


def test_same_input_gives_same_output() -> None:
    first = json_report.render(audit_file(FIXTURES / "insecure_switch.cfg", now=NOW))
    second = json_report.render(audit_file(FIXTURES / "insecure_switch.cfg", now=NOW))

    assert first == second


@pytest.mark.parametrize("fixture", sorted(SECRETS))
def test_no_secrets_in_report(fixture: str) -> None:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    assert all(s in text for s in SECRETS[fixture])

    output = json_report.render(audit_file(FIXTURES / fixture))

    assert not [s for s in SECRETS[fixture] if s in output]
