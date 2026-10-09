"""Audit pipeline: config -> platform parser -> platform rules -> findings."""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

from guardian import __version__
from guardian.core.models import AuditResult, ConfigLine, Finding, RuleResult
from guardian.core.platforms import DEFAULT_PLATFORM, get_platform
from guardian.core.rules.engine import evaluate_all, evaluate_rule
from guardian.core.rules.loader import load_rules
from guardian.core.rules.model import Rule

# Running configs are a few hundred kB at most; anything far bigger is not one.
MAX_CONFIG_BYTES = 50 * 1024 * 1024


class ConfigInputError(ValueError):
    """The input cannot be audited (not a usable configuration)."""


class EmptyConfigError(ConfigInputError):
    """The input has no configuration lines; auditing it would pass rules on no data."""


class ConfigTooLargeError(ConfigInputError):
    """The input is larger than MAX_CONFIG_BYTES."""


_HOSTNAME = re.compile(r"^hostname (\S+)$")
_VERSION = re.compile(r"^version (\S+)$")


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
    """Audit one config file and return only its findings.

    Kept for compatibility; ``audit_file`` returns the full ``AuditResult``.
    Raises ``UnknownPlatformError`` or ``RuleLoadError`` on bad input.
    """
    return audit_file(config_path, platform=platform, rules_dir=rules_dir).findings


def audit_file(
    config_path: Path,
    *,
    platform: str = DEFAULT_PLATFORM,
    rules_dir: Path | None = None,
    now: datetime | None = None,
) -> AuditResult:
    """Audit one config file: status of every rule, findings and input details.

    Uses the platform's bundled rule set unless ``rules_dir`` points elsewhere.
    Raises ``UnknownPlatformError`` or ``RuleLoadError`` on bad input,
    ``ConfigInputError`` when the file is empty or too large, and ``OSError`` /
    ``UnicodeDecodeError`` when the file cannot be read.
    """
    rules = load_rules(rules_dir or get_platform(platform).rules_dir)
    size = config_path.stat().st_size
    if size > MAX_CONFIG_BYTES:
        limit = MAX_CONFIG_BYTES // (1024 * 1024)
        raise ConfigTooLargeError(
            f"{config_path.name}: {size} bytes is more than the {limit} MB limit for a config"
        )
    data = config_path.read_bytes()
    return audit_bytes(data, rules, name=config_path.name, platform=platform, now=now)


def audit_bytes(
    data: bytes,
    rules: list[Rule],
    *,
    name: str,
    platform: str = DEFAULT_PLATFORM,
    now: datetime | None = None,
) -> AuditResult:
    """Audit config ``data`` (the raw file content) with ``rules``."""
    config = get_platform(platform).parse(data.decode("utf-8"))
    if not config:
        raise EmptyConfigError(f"{name}: no configuration lines found")

    results: list[RuleResult] = []
    findings: list[Finding] = []
    for rule in rules:
        outcome = evaluate_rule(rule, config)
        results.append(
            RuleResult(
                rule.id,
                rule.title,
                rule.severity,
                outcome.status,
                outcome.reason,
                rule.references,
            )
        )
        findings.extend(outcome.findings)

    timestamp = (now or datetime.now(UTC)).astimezone(UTC)
    return AuditResult(
        file=name,
        platform=platform,
        hostname=_top_level_value(config, _HOSTNAME),
        version=_top_level_value(config, _VERSION),
        sha256=hashlib.sha256(data).hexdigest(),
        generated_at=timestamp.isoformat(timespec="seconds").replace("+00:00", "Z"),
        guardian_version=__version__,
        rules=results,
        findings=findings,
    )


def _top_level_value(config: list[ConfigLine], pattern: re.Pattern[str]) -> str | None:
    for line in config:
        if m := pattern.match(line.text):
            return m.group(1)
    return None
