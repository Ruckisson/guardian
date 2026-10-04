"""Check every rule against the examples written in its own YAML file."""

from pathlib import Path

import pytest
import yaml

from guardian.core.parsers.cisco_ios import parse
from guardian.core.rules.engine import evaluate, load_rules

RULES_DIR = Path(__file__).parents[1] / "rules" / "cisco_ios"
RULE_FILES = sorted(RULES_DIR.glob("*.yaml"))
RULES = {rule.id: rule for rule in load_rules(RULES_DIR)}


def _read(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _example_cases() -> list:
    """Turn every example in every rule file into one pytest case."""
    cases = []
    for path in RULE_FILES:
        data = _read(path)
        examples = data.get("examples", {})
        for kind in ("compliant", "non_compliant"):
            for number, text in enumerate(examples.get(kind, []), start=1):
                case_id = f"{data['id']}-{kind}-{number}"
                cases.append(pytest.param(data["id"], text, kind == "compliant", id=case_id))
    return cases


@pytest.mark.parametrize(("rule_id", "config_text", "compliant"), _example_cases())
def test_rule_example(rule_id: str, config_text: str, compliant: bool) -> None:
    findings = evaluate(RULES[rule_id], parse(config_text))

    assert (findings == []) is compliant


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_has_examples(path: Path) -> None:
    examples = _read(path).get("examples", {})

    assert examples.get("compliant"), "add at least one compliant example"
    assert examples.get("non_compliant"), "add at least one non_compliant example"
