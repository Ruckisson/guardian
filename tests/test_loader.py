"""Tests for rule validation: every mistake must produce a clear message."""

import pytest

from guardian.core.rules.loader import RuleError, RuleLoadError, load_rules, parse_rule
from guardian.core.rules.model import MustExist, Scope

VALID = {
    "id": "IOS-TEST-001",
    "title": "Test rule",
    "severity": "low",
    "scope": "global",
    "check": {"must_exist": "^hostname "},
    "rationale": "Because.",
    "remediation": {"recommended_change": ["no ip http server"], "before_you_apply": ["Check."]},
    "references": {"stig": [], "nist_800_53": [], "cisco_guide": None, "cisa": False},
}


def problems(**changes):
    data = {**VALID, **changes}
    data = {k: v for k, v in data.items() if v is not None}
    with pytest.raises(RuleError) as exc:
        parse_rule(data, "rule.yaml")
    return "\n".join(exc.value.problems)


def test_valid_rule_loads() -> None:
    rule = parse_rule(VALID)

    assert rule.id == "IOS-TEST-001"
    assert rule.scope == Scope()
    assert isinstance(rule.check, MustExist)
    assert rule.examples.compliant == ()


def test_not_a_mapping() -> None:
    with pytest.raises(RuleError, match="YAML mapping"):
        parse_rule(["a", "b"])


def test_missing_and_unknown_keys() -> None:
    text = problems(check=None, chek={"must_exist": "x"})

    assert "check: missing required key" in text
    assert "chek: unknown key" in text


def test_old_format_gets_a_hint() -> None:
    assert "old rule format" in problems(match={"block": "^line vty "})


@pytest.mark.parametrize("bad_id", ["ios-mgmt-001", "IOS_MGMT_001", "IOSMGMT", "", "IOS-X-001\n"])
def test_id_format(bad_id) -> None:
    assert "id:" in problems(id=bad_id)


def test_bad_severity_lists_allowed_values() -> None:
    assert "low, medium, high, critical" in problems(severity="hihg")


def test_multiline_title() -> None:
    assert "single line" in problems(title="First\nSecond")


def test_invalid_regex_is_reported_with_key() -> None:
    assert "check.must_exist: invalid regex" in problems(check={"must_exist": "^transport (ssh"})


def test_check_needs_exactly_one_type() -> None:
    assert "exactly one of" in problems(check={"must_exist": "a", "must_not_exist": "b"})
    assert "exactly one of" in problems(check={})


def test_unknown_check_type() -> None:
    assert "unknown check type 'must_be'" in problems(check={"must_be": "a"})


def test_scope_forms() -> None:
    assert "scope.path: missing" in problems(scope={"has_child": "x"})
    assert "must be 'global' or a mapping" in problems(scope="everywhere")
    assert "scope.pth: unknown key" in problems(scope={"path": "^x", "pth": "y"})
    assert "scope.path: must be a regex or a non-empty list" in problems(scope={"path": []})


def test_scope_path_string_or_list() -> None:
    one = parse_rule({**VALID, "scope": {"path": "^interface "}})
    two = parse_rule({**VALID, "scope": {"path": ["^router bgp ", "^address-family "]}})

    assert len(one.scope.path) == 1
    assert len(two.scope.path) == 2


def test_each_must_match_needs_both_parts() -> None:
    assert "check.each_must_match.pattern" in problems(check={"each_must_match": {"select": "^x"}})


def test_value_validation() -> None:
    assert "capture group" in problems(check={"value": {"pattern": "^x \\d+", "max": 1}})
    assert "needs 'min', 'max' or both" in problems(check={"value": {"pattern": "^x (\\d+)"}})
    assert "greater than max" in problems(
        check={"value": {"pattern": "^x (\\d+)", "min": 5, "max": 1}}
    )
    assert "whole number" in problems(check={"value": {"pattern": "^x (\\d+)", "max": "10"}})
    assert "whole number" in problems(check={"value": {"pattern": "^x (\\d+)", "max": True}})
    assert "'pass' or 'fail'" in problems(
        check={"value": {"pattern": "^x (\\d+)", "max": 1, "if_missing": "ok"}}
    )


def test_reference_validation() -> None:
    assert "named group" in problems(
        check={"reference": {"capture": "^a (\\S+)", "must_exist": "^b"}}
    )
    assert "placeholder" in problems(
        check={"reference": {"capture": "^a (?P<acl>\\S+)", "must_exist": "^b {other}"}}
    )
    assert "invalid regex template" in problems(
        check={"reference": {"capture": "^a (?P<acl>\\S+)", "must_exist": "^b ({acl}"}}
    )


def test_unknown_python_check() -> None:
    assert "unknown custom check 'nope'" in problems(check={"python": "nope"})


STIG = {
    "id": "V-215813",
    "stig_id": "CISC-ND-000150",
    "benchmark": "Cisco IOS XE Router NDM V3R7",
    "severity": "CAT II",
    "relation": "satisfies",
}


def refs(**changes):
    return {"stig": [], "nist_800_53": [], "cisco_guide": None, "cisa": False, **changes}


def test_references_load() -> None:
    rule = parse_rule(
        {**VALID, "references": refs(stig=[STIG], nist_800_53=["AC-7", "IA-5(1)"], cisa=True)}
    )

    (stig,) = rule.references.stig
    assert (stig.id, stig.stig_id, stig.severity, stig.relation) == (
        "V-215813",
        "CISC-ND-000150",
        "CAT II",
        "satisfies",
    )
    assert rule.references.nist_800_53 == ("AC-7", "IA-5(1)")
    assert rule.references.cisco_guide is None
    assert rule.references.cisa is True


@pytest.mark.parametrize(
    ("references", "message"),
    [
        (None, "references: missing required key"),
        ("CIS 1.1", "references: must be a mapping"),
        ({"stig": []}, "references.nist_800_53: missing required key"),
        (refs(cis=["1.1"]), "references.cis: unknown key"),
        (refs(stig="V-215813"), "references.stig: must be a list"),
        (refs(stig=[{**STIG, "id": "V-21581"}]), "references.stig[0].id"),
        (refs(stig=[{**STIG, "stig_id": "CISC-XX-000150"}]), "references.stig[0].stig_id"),
        (refs(stig=[{**STIG, "severity": "CAT IV"}]), "must be CAT I, CAT II or CAT III"),
        (refs(stig=[{**STIG, "relation": "maps"}]), "must be satisfies or related"),
        (refs(stig=[{k: v for k, v in STIG.items() if k != "benchmark"}]), "benchmark: missing"),
        (refs(stig=[{**STIG, "url": "x"}]), "references.stig[0].url: unknown key"),
        (refs(nist_800_53=["AC7"]), "'AC7' must look like AC-7"),
        (refs(nist_800_53=["ac-7"]), "'ac-7' must look like AC-7"),
        (refs(cisco_guide=""), "references.cisco_guide: must be non-empty text"),
        (refs(cisa="yes"), "references.cisa: must be true or false"),
    ],
)
def test_invalid_references(references, message) -> None:
    assert message in problems(references=references)


def test_examples_types() -> None:
    assert "examples.compliant: must be a list" in problems(examples={"compliant": "x"})
    assert "examples.good: unknown key" in problems(examples={"good": ["x"]})


def test_all_problems_are_reported_at_once() -> None:
    text = problems(severity="bad", title="", check={"must_exist": "("})

    assert text.count("\n") >= 2


# ------------------------------------------------------------------ directory


def write(path, text):
    path.write_text(text, encoding="utf-8")


RULE_YAML = """\
id: {id}
title: Test
severity: low
scope: global
check:
  must_exist: "^hostname "
rationale: Because.
remediation:
  recommended_change: [hostname R1]
  before_you_apply: [Check.]
references:
  stig: []
  nist_800_53: []
  cisco_guide: null
  cisa: false
"""


def test_load_rules_sorted_by_file_name(tmp_path) -> None:
    write(tmp_path / "B.yaml", RULE_YAML.format(id="IOS-TEST-002"))
    write(tmp_path / "A.yaml", RULE_YAML.format(id="IOS-TEST-001"))
    write(tmp_path / "notes.txt", "not a rule")

    assert [r.id for r in load_rules(tmp_path)] == ["IOS-TEST-001", "IOS-TEST-002"]


def test_load_rules_collects_errors_from_all_files(tmp_path) -> None:
    write(tmp_path / "a.yaml", RULE_YAML.format(id="IOS-TEST-001").replace("low", "hihg"))
    write(tmp_path / "b.yaml", "id: [unclosed")
    write(tmp_path / "c.yaml", RULE_YAML.format(id="IOS-TEST-003"))

    with pytest.raises(RuleLoadError) as exc:
        load_rules(tmp_path)

    errors = exc.value.errors
    assert any(e.startswith("a.yaml: severity:") for e in errors)
    assert any(e.startswith("b.yaml: not valid YAML") for e in errors)
    assert not any(e.startswith("c.yaml") for e in errors)


def test_duplicate_ids_are_rejected(tmp_path) -> None:
    write(tmp_path / "a.yaml", RULE_YAML.format(id="IOS-TEST-001"))
    write(tmp_path / "b.yaml", RULE_YAML.format(id="IOS-TEST-001"))

    with pytest.raises(RuleLoadError, match="already used by a.yaml"):
        load_rules(tmp_path)


def test_missing_directory(tmp_path) -> None:
    with pytest.raises(RuleLoadError, match="does not exist"):
        load_rules(tmp_path / "missing")


def test_empty_file(tmp_path) -> None:
    write(tmp_path / "a.yaml", "")

    with pytest.raises(RuleLoadError, match="YAML mapping"):
        load_rules(tmp_path)


def test_reference_unknown_placeholder_but_quantifiers_allowed() -> None:
    assert "unknown placeholder other" in problems(
        check={"reference": {"capture": "^a (?P<acl>\\S+)", "must_exist": "^b {acl} {other}"}}
    )
    rule = parse_rule(
        {
            **VALID,
            "check": {
                "reference": {"capture": "^a (?P<acl>\\S+)", "must_exist": "^b {acl} \\d{3}"}
            },
        }
    )
    assert rule.check.must_exist.endswith("\\d{3}")
