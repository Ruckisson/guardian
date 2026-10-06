"""Mask secrets in configuration lines before they leave the engine.

Findings can point at a single line (for example an SNMP community that
should not exist). That line must not leak the secret into reports, logs or
the terminal, so every finding target passes through ``redact``.

Covers the common Cisco forms; extend ``_PATTERNS`` when a new rule can
report a line containing another kind of secret.
"""

import re

MASK = "<redacted>"

# Each pattern has exactly one group: the secret value to mask.
_PATTERNS = [
    # snmp-server community <secret> ...
    re.compile(r"^snmp-server community (\S+)"),
    # snmp-server host <ip> [traps|informs] [version 1|2c] <community> ...
    re.compile(
        r"^snmp-server host \S+ (?:(?:traps|informs) )?(?:version (?:1|2c) )?(?!version\b)(\S+)"
    ),
    # ... password [type] <secret>   /   ... secret [type] <secret>
    re.compile(r"\b(?:password|secret)(?: \d{1,2})? (\S+)"),
    # key-string [type] <secret>
    re.compile(r"\bkey-string(?: \d)? (\S+)"),
    # tacacs-server key [type] <secret>, radius-server key ..., key <secret>
    re.compile(r"\bkey(?: \d)? (\S+)$"),
]


def _mask(match: re.Match[str]) -> str:
    whole = match.group(0)
    if match.group(1) == MASK:
        return whole
    start = match.start(1) - match.start(0)
    end = match.end(1) - match.start(0)
    return whole[:start] + MASK + whole[end:]


def redact(line: str) -> str:
    """Return ``line`` with known secret values replaced by ``<redacted>``."""
    for pattern in _PATTERNS:
        line = pattern.sub(_mask, line)
    return line
