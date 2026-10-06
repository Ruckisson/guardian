"""Supported platforms: which parser and which rule set belong together.

Adding a platform means adding one entry here, a parser (or reusing one)
and a rule directory under ``guardian/rulesets/``. The engine never changes.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from guardian.core.models import ConfigLine
from guardian.core.parsers import cisco

RULESETS_DIR = Path(__file__).resolve().parent.parent / "rulesets"


@dataclass(frozen=True)
class Platform:
    name: str
    description: str
    parse: Callable[[str], list[ConfigLine]]
    rules_dir: Path


PLATFORMS: dict[str, Platform] = {
    "cisco_ios": Platform(
        name="cisco_ios",
        description="Cisco IOS and IOS-XE",
        parse=cisco.parse,
        rules_dir=RULESETS_DIR / "cisco_ios",
    ),
}

DEFAULT_PLATFORM = "cisco_ios"


class UnknownPlatformError(ValueError):
    """The requested platform is not in ``PLATFORMS``."""


def get_platform(name: str) -> Platform:
    """Return the platform called ``name`` or raise ``UnknownPlatformError``."""
    try:
        return PLATFORMS[name]
    except KeyError:
        known = ", ".join(sorted(PLATFORMS))
        raise UnknownPlatformError(f"unknown platform {name!r} (supported: {known})") from None
