"""Every bundled rule names its official sources, and severity follows the STIG CAT."""

import pytest

from guardian.core.models import Severity
from guardian.core.platforms import PLATFORMS
from guardian.core.rules.loader import (
    NIST_CONTROL,
    STIG_RULE_ID,
    STIG_VULN_ID,
    RuleLoadError,
    load_rules,
)

BUNDLED = [rule for platform in PLATFORMS.values() for rule in load_rules(platform.rules_dir)]
RULES = [pytest.param(r, id=r.id) for r in BUNDLED]
CAT_SEVERITY = {"CAT I": Severity.HIGH, "CAT II": Severity.MEDIUM, "CAT III": Severity.LOW}
BENCHMARKS = {
    "Cisco IOS XE Router NDM V3R7",
    "Cisco IOS XE Router RTR V3R5",
    "Cisco IOS XE Switch L2S V3R2",
}


@pytest.mark.parametrize("rule", RULES)
def test_references_have_the_right_format(rule) -> None:
    refs = rule.references
    for stig in refs.stig:
        assert STIG_VULN_ID.fullmatch(stig.id)
        assert STIG_RULE_ID.fullmatch(stig.stig_id)
        assert stig.benchmark in BENCHMARKS
        assert stig.severity in CAT_SEVERITY
        assert stig.relation in ("satisfies", "related")
    assert all(NIST_CONTROL.fullmatch(c) for c in refs.nist_800_53)
    assert refs.cisco_guide is None or refs.cisco_guide.strip()
    assert isinstance(refs.cisa, bool)


# Direct remote takeover risk: critical whatever the STIG says.
CRITICAL = {"IOS-MGMT-001", "IOS-MGMT-010", "IOS-SNMP-001", "IOS-SNMP-002"}


@pytest.mark.parametrize("rule", RULES)
def test_severity_follows_the_satisfied_stig_cat(rule) -> None:
    if rule.id in CRITICAL:
        assert rule.severity is Severity.CRITICAL
        return
    satisfied = [s for s in rule.references.stig if s.relation == "satisfies"]
    if not satisfied:
        # Only related or no STIG requirement: the rule keeps its own severity.
        assert rule.severity is not Severity.CRITICAL
        return
    highest = max((CAT_SEVERITY[s.severity] for s in satisfied), key=lambda s: s.rank)

    assert rule.severity is highest


def test_exactly_four_critical_rules() -> None:
    assert {r.id for r in BUNDLED if r.severity is Severity.CRITICAL} == CRITICAL


def test_every_bundled_rule_file_has_references() -> None:
    for platform in PLATFORMS.values():
        for path in platform.rules_dir.glob("*.yaml"):
            assert "\nreferences:\n" in path.read_text(encoding="utf-8"), path.name


def test_reference_error_names_file_and_key(tmp_path) -> None:
    (tmp_path / "bad.yaml").write_text(
        "id: LAB-TEST-001\ntitle: T\nseverity: low\nscope: global\n"
        "check:\n  must_exist: '^hostname '\nrationale: x\n"
        "remediation: {recommended_change: [x], before_you_apply: [x]}\n"
        "references:\n  stig: [{id: V-1, stig_id: CISC-ND-000150, benchmark: B,"
        " severity: CAT II, relation: satisfies}]\n"
        "  nist_800_53: []\n  cisco_guide: null\n  cisa: false\n",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError) as exc:
        load_rules(tmp_path)

    assert any(e.startswith("bad.yaml: references.stig[0].id:") for e in exc.value.errors)
