"""Registry of Python checks for logic that YAML cannot express.

A YAML rule refers to a check by name (``check: {python: <name>}``); it can
never point at an arbitrary module, so rule files cannot execute code.

A check receives the selected block (or a virtual root for global scope)
and the whole parsed configuration, and returns True when compliant::

    @register("vty-count-matches-something")
    def _vty_count(block: ConfigLine, config: list[ConfigLine]) -> bool:
        ...
"""

from collections.abc import Callable

from guardian.core.models import ConfigLine

CustomCheck = Callable[[ConfigLine, list[ConfigLine]], bool]

CHECKS: dict[str, CustomCheck] = {}


def register(name: str) -> Callable[[CustomCheck], CustomCheck]:
    """Decorator that makes a function available to YAML rules under ``name``."""

    def decorator(func: CustomCheck) -> CustomCheck:
        if name in CHECKS:
            raise ValueError(f"custom check {name!r} is already registered")
        CHECKS[name] = func
        return func

    return decorator
