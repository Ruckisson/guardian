"""Tests for the HTML report: escaping, offline page, no secrets, file mode."""

import os
import re
import stat

import pytest

from conftest import FIXTURES, SECRETS
from guardian.core.audit import audit_bytes, audit_file
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.reporting import html as html_report
from guardian.core.reporting import write_private
from guardian.core.rules.loader import load_rules

RULES = load_rules(get_platform(DEFAULT_PLATFORM).rules_dir)
SOURCE_LINKS = {
    html_report.CISCO_GUIDE_URL,
    html_report.CISA_URL,
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://unit42.paloaltonetworks.com/threat-brief-cve-2023-20198-cisco-ios-xe/",
    "https://blog.talosintelligence.com/critical-infrastructure-at-risk/",
    "https://www.verizon.com/business/resources/reports/dbir/",
}

HOSTILE = b"""\
version 15.1
hostname <b>R1</b>
banner motd ^C
<script>alert('banner')</script>
^C
snmp-server group <script>alert(1)</script> v3 noauth
interface GigabitEthernet0/1
 description <script>alert('description')</script> $x ${y}
 ip address 10.0.0.1 255.255.255.0
"""


def render(data: bytes, name: str = "r1.cfg") -> str:
    return html_report.render(audit_bytes(data, RULES, name=name))


def test_config_content_is_escaped() -> None:
    page = render(HOSTILE, name='<img src=x onerror="alert(1)">.cfg')

    assert "<script" not in page.lower()
    assert "<b>R1" not in page
    assert "<img" not in page
    # The values are still shown, as text.
    assert "&lt;b&gt;R1&lt;/b&gt;" in page
    assert "snmp-server group &lt;script&gt;alert(1)&lt;/script&gt; v3 noauth" in page
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;.cfg" in page


def test_page_is_self_contained() -> None:
    page = render(HOSTILE)

    lowered = page.lower()
    for forbidden in ("<script", "<link", "@import", "url(", "src=", "@font-face", "<iframe"):
        assert forbidden not in lowered
    # Nothing is loaded; the only URLs are links to the sources of the static
    # "Why it matters" block.
    urls = re.findall(r"https?://[^\s\"'<>]+", page)
    hrefs = re.findall(r'href="([^"]+)"', page)
    assert set(urls) == set(hrefs)
    assert set(urls) <= SOURCE_LINKS
    assert "<svg" in page and "<style>" in page
    assert (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
    ) in page
    # Every link leaks no referrer.
    assert page.count("<a ") == page.count('<a rel="noreferrer" ') + page.count(
        '<a class="ref" rel="noreferrer" '
    )


def test_structure_follows_the_design() -> None:
    page = html_report.render(audit_file(FIXTURES / "insecure_switch.cfg"))

    for heading in ("1. Summary", "2. Findings", "3. Other rules", "4. Context"):
        assert f"<h2>{heading}</h2>" in page
    assert page.count("How to use the suggested changes.") == 1
    assert 'aria-label="Failed rules by severity"' in page
    assert 'aria-label="Compliance by area, worst first"' in page
    assert "compliance score" in page
    # N/A and passed rules are in collapsed sections.
    assert '<details class="appendix"><summary>Not applicable (' in page
    assert '<details class="appendix"><summary>Passed (' in page
    assert '<details class="appendix why-sec">' in page
    assert "last updated 2026-10-04" in page
    # Printing switches to a light page.
    assert "@media print" in page and "background:#fff!important" in page


def test_one_section_per_failed_rule_with_its_remediation() -> None:
    result = audit_file(FIXTURES / "insecure_switch.cfg")
    page = html_report.render(result)

    failed = {f.rule_id for f in result.findings}
    assert page.count('<section class="finding">') == len(failed)
    # No fix-kind labels or warning bars any more.
    for gone in ("kind-exact", "kind-template", "kind-manual", "fix-warn", "fix-label"):
        assert gone not in page
    assert page.count("<h4>Recommended change</h4>") == len(failed)
    assert page.count("<h4>Before you apply</h4>") == len(failed)
    assert "<h4>If the service is needed</h4>" in page
    # Placeholders are highlighted, block names filled in.
    assert '<mark class="ph">&lt;NEW_PASSWORD&gt;</mark>' in page
    assert "line vty 0 4\n transport input ssh" in page


def test_global_commands_appear_once_for_several_blocks() -> None:
    page = html_report.render(audit_file(FIXTURES / "insecure_switch.cfg"))

    assert page.count("crypto key generate rsa modulus 2048") == 1
    # The per-block lines stay for every VTY block.
    assert "line vty 0 4\n transport input ssh" in page
    assert "line vty 5 15\n transport input ssh" in page


def test_risk_badges_sit_in_the_finding_heading() -> None:
    page = html_report.render(audit_file(FIXTURES / "insecure_switch.cfg"))

    vty = _section(page, "IOS-MGMT-001")
    heading = vty[: vty.index("</h3>")]
    assert html_report.LOCKOUT_BADGE in heading
    native = _section(page, "IOS-L2-006")
    assert html_report.BOTH_ENDS_BADGE in native[: native.index("</h3>")]
    # Both badges are explained once in the guide box.
    guide = page[page.index('<div class="banner guide"') :]
    guide = guide[: guide.index("</div>")]
    assert html_report.LOCKOUT_BADGE in guide and html_report.BOTH_ENDS_BADGE in guide
    assert "other side of the link" in guide


def test_backticks_and_placeholders_in_prose() -> None:
    page = html_report.render(audit_file(FIXTURES / "insecure_switch.cfg"))

    vty = _section(page, "IOS-MGMT-001")
    assert "<code>show ip ssh</code>" in vty
    assert "`" not in vty
    acl = _section(page, "IOS-MGMT-002")
    checks = acl[acl.index('<ul class="checks">') :]
    assert "<code>show users</code>" in checks
    nat = _section(page, "IOS-L2-006")
    assert '<mark class="ph">&lt;NATIVE_VLAN&gt;</mark> is an unused VLAN' in nat


def test_backticks_cannot_inject_markup() -> None:
    assert html_report._text("`<script>`") == "<code>&lt;script&gt;</code>"


def test_before_you_apply_only_when_present() -> None:
    from guardian.core.models import Remediation

    block = html_report._remediation(Remediation(recommended_change=("x",), before_you_apply=()))

    assert "Before you apply" not in block


def _section(page: str, rule_id: str) -> str:
    """The finding section of one rule (up to the next finding or chapter)."""
    start = page.index(f'<span class="id">{rule_id}</span>')
    ends = [page.find(marker, start) for marker in ('<section class="finding">', "<h2>")]
    return page[start : min(e for e in ends if e != -1)]


def test_references_row() -> None:
    page = html_report.render(audit_file(FIXTURES / "insecure_switch.cfg"))

    vty = _section(page, "IOS-MGMT-001")
    assert "<dt>References</dt>" in vty
    assert '<span class="ref">Related to STIG V-215845 · CAT I</span>' in vty
    assert '<span class="ref">NIST MA-4</span>' in vty
    assert (
        f'<a class="ref" rel="noreferrer" href="{html_report.CISCO_GUIDE_URL}">'
        "Cisco Hardening Guide: "
        "Control Transport for vty and tty Lines</a>"
    ) in vty
    assert f'<a class="ref" rel="noreferrer" href="{html_report.CISA_URL}">CISA 2024</a>' in vty
    # A satisfied STIG requirement without "Related to"; STIG tags are never links.
    timeout = _section(page, "IOS-MGMT-005")
    assert '<span class="ref">STIG V-215833 · CAT I</span>' in timeout
    assert "CISA 2024" not in timeout
    assert 'href="https://public.cyber.mil' not in page
    # No references at all (IOS-PASS-009): no row.
    router = html_report.render(audit_file(FIXTURES / "insecure_router.cfg"))
    assert "<dt>References</dt>" not in _section(router, "IOS-PASS-009")
    # Empty fields are left out.
    assert "NIST" not in _section(page, "IOS-SNMP-001")


def test_footer_names_the_sources() -> None:
    page = html_report.render(audit_file(FIXTURES / "hardened_switch.cfg"))

    assert html_report.REFERENCES_NOTE in page
    assert "Guardian is not an official STIG scanner" in page


def test_summary_numbers_come_from_the_result() -> None:
    result = audit_file(FIXTURES / "insecure_router.cfg")
    page = html_report.render(result)

    statuses = [r.status.value for r in result.rules]
    passed, failed = statuses.count("pass"), statuses.count("fail")
    assert f"{failed} of {passed + failed} applicable rules failed" in page
    assert f"{round(100 * passed / (passed + failed))}&nbsp;%" in page
    assert f"Not applicable ({statuses.count('na')})" in page
    assert result.sha256 in page
    assert "EDGE-R1" in page


@pytest.mark.parametrize("fixture", sorted(SECRETS))
def test_no_secrets_in_report(fixture: str) -> None:
    page = html_report.render(audit_file(FIXTURES / fixture))

    assert not [s for s in SECRETS[fixture] if s in page]


def test_report_without_findings() -> None:
    page = html_report.render(audit_file(FIXTURES / "hardened_switch.cfg"))

    assert "No findings. Every applicable rule passed." in page
    assert "No failed rules." in page
    assert 'aria-label="Failed rules by severity"' not in page
    assert "verdict ok" in page and "How to use the suggested changes." not in page


def test_write_private_creates_owner_only_file(tmp_path) -> None:
    path = tmp_path / "report.html"

    write_private(path, "<p>x</p>")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8") == "<p>x</p>"


def test_write_private_tightens_an_existing_file(tmp_path) -> None:
    path = tmp_path / "report.html"
    path.write_text("old and longer", encoding="utf-8")
    os.chmod(path, 0o644)

    write_private(path, "new")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8") == "new"


def test_template_files_are_read_on_first_render_not_at_import(monkeypatch) -> None:
    import importlib
    import importlib.resources

    def missing(_package):
        raise FileNotFoundError("graphite.css")

    monkeypatch.setattr(importlib.resources, "files", missing)
    try:
        importlib.reload(html_report)  # importing must not need the CSS
    finally:
        monkeypatch.undo()
        importlib.reload(html_report)
