"""Audit pipeline: config -> platform parser -> platform rules -> findings."""

from pathlib import Path

from guardian.core.models import Finding
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.rules.engine import evaluate_all
from guardian.core.rules.loader import load_rules
from guardian.core.rules.model import Rule


def audit_text(text: str, rules: list[Rule], platform: str = DEFAULT_PLATFORM) -> list[Finding]:
    """Parse ``text`` with the platform's parser and evaluate ``rules`` on it."""
    config = get_platform(platform).parse(text)
    return evaluate_all(rules, config)


def run_audit(
    config_path: Path,
    *,
    platform: str = DEFAULT_PLATFORM,
    rules_dir: Path | None = None,
) -> list[Finding]:
    """Audit one config file.

    Uses the platform's bundled rule set unless ``rules_dir`` points elsewhere.
    Raises ``UnknownPlatformError`` or ``RuleLoadError`` on bad input.
    """
    rules = load_rules(rules_dir or get_platform(platform).rules_dir)
    return audit_text(config_path.read_text(encoding="utf-8"), rules, platform)
