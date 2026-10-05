"""Check every bundled rule against the examples written in its own YAML file."""

import pytest

from guardian.core.platforms import PLATFORMS
from guardian.core.rules.engine import evaluate
from guardian.core.rules.loader import load_rules

RULESETS = [(platform, load_rules(platform.rules_dir)) for platform in PLATFORMS.values()]


def _example_cases() -> list:
    """Turn every example of every rule of every platform into one pytest case."""
    cases = []
    for platform, rules in RULESETS:
        for rule in rules:
            for kind, texts in (
                ("compliant", rule.examples.compliant),
                ("non_compliant", rule.examples.non_compliant),
            ):
                for number, text in enumerate(texts, start=1):
                    case_id = f"{rule.id}-{kind}-{number}"
                    cases.append(
                        pytest.param(platform, rule, text, kind == "compliant", id=case_id)
                    )
    return cases


ALL_RULES = [pytest.param(rule, id=rule.id) for _, rules in RULESETS for rule in rules]


@pytest.mark.parametrize(("platform", "rule", "config_text", "compliant"), _example_cases())
def test_rule_example(platform, rule, config_text: str, compliant: bool) -> None:
    findings = evaluate(rule, platform.parse(config_text))

    assert (findings == []) is compliant


@pytest.mark.parametrize("rule", ALL_RULES)
def test_rule_has_examples(rule) -> None:
    assert rule.examples.compliant, "add at least one compliant example"
    assert rule.examples.non_compliant, "add at least one non_compliant example"


def test_every_platform_has_rules() -> None:
    for platform, rules in RULESETS:
        assert rules, f"{platform.name} has no rules in {platform.rules_dir}"
