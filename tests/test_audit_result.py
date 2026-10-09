"""Tests for AuditResult: input details and PASS / FAIL / N/A of every rule."""

import hashlib
from datetime import UTC, datetime, timedelta, timezone

from conftest import FIXTURES
from guardian import __version__
from guardian.core.audit import audit_file, run_audit
from guardian.core.models import Status
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.rules.loader import load_rules

BUNDLED = load_rules(get_platform(DEFAULT_PLATFORM).rules_dir)


def statuses(result) -> dict[str, Status]:
    return {r.rule_id: r.status for r in result.rules}


def test_input_details() -> None:
    path = FIXTURES / "insecure_router.cfg"
    now = datetime(2026, 10, 8, 14, 30, tzinfo=timezone(timedelta(hours=2)))

    result = audit_file(path, now=now)

    assert result.file == "insecure_router.cfg"
    assert result.platform == "cisco_ios"
    assert result.hostname == "EDGE-R1"
    assert result.version == "15.4"
    assert result.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.generated_at == "2026-10-08T12:30:00Z"
    assert result.guardian_version == __version__


def test_generated_at_defaults_to_now_in_utc() -> None:
    result = audit_file(FIXTURES / "vty_ssh.cfg")

    stamp = datetime.fromisoformat(result.generated_at)
    assert stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)
    assert abs(datetime.now(UTC) - stamp) < timedelta(minutes=1)


def test_every_rule_has_a_status_once() -> None:
    result = audit_file(FIXTURES / "insecure_switch.cfg")

    assert [r.rule_id for r in result.rules] == [r.id for r in BUNDLED]


def test_status_matches_findings() -> None:
    result = audit_file(FIXTURES / "insecure_switch.cfg")

    failing = {f.rule_id for f in result.findings}
    assert failing == {r.rule_id for r in result.rules if r.status is Status.FAIL}
    assert all(r.reason == "" for r in result.rules if r.status is not Status.NOT_APPLICABLE)


def test_run_audit_is_kept_and_returns_the_same_findings() -> None:
    path = FIXTURES / "insecure_router.cfg"

    assert run_audit(path) == audit_file(path).findings


def test_not_applicable_rules_on_a_router() -> None:
    result = audit_file(FIXTURES / "insecure_router.cfg")
    by_id = {r.rule_id: r for r in result.rules}

    # No switch ports: the scope selects nothing.
    assert by_id["IOS-L2-001"].status is Status.NOT_APPLICABLE
    assert "active access ports" in by_id["IOS-L2-001"].reason
    # Custom checks that only apply to switches.
    assert by_id["IOS-L2-007"].status is Status.NOT_APPLICABLE
    assert "not a switch" in by_id["IOS-L2-007"].reason
    assert by_id["IOS-SVC-006"].status is Status.NOT_APPLICABLE


def test_not_applicable_when_feature_is_off() -> None:
    result = statuses(audit_file(FIXTURES / "hardened_switch.cfg"))

    assert result["IOS-MGMT-011"] is Status.NOT_APPLICABLE  # no HTTPS server
    assert result["IOS-MGMT-015"] is Status.NOT_APPLICABLE  # no IPv6
    assert result["IOS-L2-004"] is Status.NOT_APPLICABLE  # no HSRP / VRRP
    assert result["IOS-MGMT-001"] is Status.PASS


def test_multicast_router_makes_ip_options_not_applicable() -> None:
    result = statuses(audit_file(FIXTURES / "l3_switch_edge_cases.cfg"))

    assert result["IOS-IF-001"] is Status.NOT_APPLICABLE


def test_ntp_and_aaa_dependent_rules(tmp_path) -> None:
    config = tmp_path / "bare.cfg"
    config.write_text("hostname BARE\n", encoding="utf-8")

    result = statuses(audit_file(config))

    assert result["IOS-NTP-001"] is Status.FAIL
    assert result["IOS-NTP-003"] is Status.NOT_APPLICABLE
    assert result["IOS-AAA-001"] is Status.FAIL
    assert result["IOS-PASS-011"] is Status.NOT_APPLICABLE


def test_findings_carry_rationale_and_rendered_remediation() -> None:
    result = audit_file(FIXTURES / "insecure_switch.cfg")

    for finding in result.findings:
        assert finding.rationale and "\n" not in finding.rationale
        assert finding.remediation is not None
        assert finding.remediation.recommended_change
        assert finding.remediation.before_you_apply

    (proxy_arp,) = [f for f in result.findings if f.rule_id == "IOS-IF-002"]
    assert proxy_arp.remediation.recommended_change == ("interface Vlan1", " no ip proxy-arp")
    assert "show ip arp Vlan1" in " ".join(proxy_arp.remediation.before_you_apply)
