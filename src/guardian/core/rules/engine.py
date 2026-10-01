"""Load rules from YAML and evaluate them against a parsed config."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from guardian.core.models import ConfigLine, Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    block: str  # regex selecting top-level blocks, e.g. "^line vty "
    child_must_match: str  # regex; at least one child of the block must match
    rationale: str
    remediation: str


def load_rules(directory: Path) -> list[Rule]:
    """Load every ``*.yaml`` rule in ``directory``."""
    rules = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(
            Rule(
                id=data["id"],
                title=data["title"],
                severity=Severity(data["severity"]),
                block=data["match"]["block"],
                child_must_match=data["check"]["child_must_match"],
                rationale=data["rationale"],
                remediation=data["remediation"],
            )
        )
    return rules


def evaluate(rule: Rule, config: list[ConfigLine]) -> list[Finding]:
    """Return one finding for every matching block that fails the check."""
    block_re = re.compile(rule.block)
    child_re = re.compile(rule.child_must_match)

    findings = []
    for line in config:
        if not block_re.search(line.text):
            continue
        if not any(child_re.search(child.text) for child in line.children):
            findings.append(Finding(rule.id, rule.severity, line.text, rule.title))
    return findings
