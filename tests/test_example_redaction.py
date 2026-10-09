"""Lines that rules report verbatim must never show the secret they contain."""

import re

import pytest

from guardian.core.platforms import PLATFORMS
from guardian.core.redact import MASK
from guardian.core.rules.engine import evaluate
from guardian.core.rules.loader import load_rules
from guardian.core.rules.model import EachMustMatch, MustNotExist

# A line with one of these carries a secret value after the keyword.
SECRET_LINE = re.compile(
    r"\b(password|secret|key-string|pre-shared-key|wpa-psk|message-digest-key|"
    r"authentication-key)\b \S|^snmp-server community |^crypto isakmp key |://[^/\s]*:[^@\s]*@"
)

CASES = [
    pytest.param(platform, rule, text, id=f"{rule.id}-{n}")
    for platform in PLATFORMS.values()
    for rule in load_rules(platform.rules_dir)
    if rule.scope.is_global and isinstance(rule.check, MustNotExist | EachMustMatch)
    for n, text in enumerate(rule.examples.non_compliant, start=1)
]


@pytest.mark.parametrize(("platform", "rule", "text"), CASES)
def test_reported_lines_are_redacted(platform, rule, text) -> None:
    for finding in evaluate(rule, platform.parse(text)):
        if SECRET_LINE.search(finding.target):
            assert MASK in finding.target, finding.target
