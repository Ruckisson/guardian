"""Audit pipeline: config file -> parser -> rules -> findings."""

from pathlib import Path

from guardian.core.models import Finding
from guardian.core.parsers import cisco_ios
from guardian.core.rules.engine import evaluate, load_rules


def run_audit(config_path: Path, rules_dir: Path) -> list[Finding]:
    config = cisco_ios.parse(config_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for rule in load_rules(rules_dir):
        findings.extend(evaluate(rule, config))
    return findings
