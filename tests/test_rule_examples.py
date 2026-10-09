"""Check every bundled rule against the examples written in its own YAML file.

``compliant`` examples must PASS, ``non_compliant`` ones must FAIL and
``not_applicable`` ones must be N/A, so a rule cannot hide behind "no
finding" when it actually checked nothing.
"""

import pytest

from guardian.core.models import Status
from guardian.core.platforms import PLATFORMS
from guardian.core.rules.engine import evaluate_rule
from guardian.core.rules.loader import load_rules

RULESETS = [(platform, load_rules(platform.rules_dir)) for platform in PLATFORMS.values()]
EXPECTED = {
    "compliant": Status.PASS,
    "non_compliant": Status.FAIL,
    "not_applicable": Status.NOT_APPLICABLE,
}


def _example_cases() -> list:
    """Turn every example of every rule of every platform into one pytest case."""
    cases = []
    for platform, rules in RULESETS:
        for rule in rules:
            for kind, status in EXPECTED.items():
                for number, text in enumerate(getattr(rule.examples, kind), start=1):
                    case_id = f"{rule.id}-{kind}-{number}"
                    cases.append(pytest.param(platform, rule, text, status, id=case_id))
    return cases


ALL_RULES = [pytest.param(rule, id=rule.id) for _, rules in RULESETS for rule in rules]


@pytest.mark.parametrize(("platform", "rule", "config_text", "expected"), _example_cases())
def test_rule_example(platform, rule, config_text: str, expected: Status) -> None:
    outcome = evaluate_rule(rule, platform.parse(config_text))

    assert outcome.status is expected, outcome.reason


@pytest.mark.parametrize("rule", ALL_RULES)
def test_rule_has_examples(rule) -> None:
    assert rule.examples.compliant, "add at least one compliant example (must PASS)"
    assert rule.examples.non_compliant, "add at least one non_compliant example"


def test_every_platform_has_rules() -> None:
    for platform, rules in RULESETS:
        assert rules, f"{platform.name} has no rules in {platform.rules_dir}"
