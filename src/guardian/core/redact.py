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
    # snmp-server user <u> <g> v3 auth <alg> <secret> priv <alg> [bits] <secret>
    re.compile(r"^snmp-server user .*?\bauth (?:md5|sha\S*) (\S+)"),
    re.compile(r"^snmp-server user .*?\bpriv (?:des|3des|aes)(?: \d+)? (\S+)"),
    # ... password [type] <secret>   /   ... secret [type] <secret>
    re.compile(r"\b(?:password|secret)(?: \d{1,2})? (\S+)"),
    # URL with credentials: ftp://user:<secret>@host/... (boot network, archive path, ...)
    re.compile(r"://[^:/@\s]+:([^@\s]+)@"),
    # key-string [type] <secret>
    re.compile(r"\bkey-string(?: \d)? (\S+)"),
    # ntp authentication-key <n> <algorithm> <secret> [7]
    re.compile(r"^ntp authentication-key \d+ \S+ (\S+)"),
    # crypto isakmp key [0|6] <secret> address ...
    re.compile(r"^crypto isakmp key(?: [06])? (\S+)"),
    # standby [n] authentication [text] <secret>   (md5 uses a key chain or key-string)
    re.compile(r"^standby(?: \d+)? authentication (?:text )?(?!md5\b)(?!text\b)(\S+)"),
    # vrrp <n> authentication text <secret>
    re.compile(r"^vrrp \d+ authentication text (\S+)"),
    # ip ospf message-digest-key <n> md5 [type] <secret>
    re.compile(r"\bmessage-digest-key \d+ md5(?: \d)? (\S+)"),
    # pre-shared-key [local|remote] [type] <secret>, wpa-psk [ascii|hex] [type] <secret>
    re.compile(r"\bpre-shared-key(?: (?:local|remote))?(?: [06])? (\S+)"),
    re.compile(r"\bwpa-psk(?: (?:ascii|hex))?(?: [07])? (\S+)"),
    # ip ospf authentication-key [type] <secret>  (ipv6 ospf too)
    re.compile(r"\bauthentication-key(?: [07])? (\S+)$"),
    # key config-key password-encrypt <secret>
    re.compile(r"^key config-key password-encrypt (\S+)"),
    # tacacs-server key <type> <secret>, key <type> <secret> in a server block.
    # With a type the value is always a secret (NTP key IDs aside).
    re.compile(r"^(?!ntp (?:server|peer) ).*?(?<!\S)key [067] (\S+)"),
    # tacacs-server key <secret>, key <secret> in a server block. A number alone
    # is a key ID only in "key 1" (key chain) and "ntp server|peer ... key 1".
    re.compile(
        r"^(?!\s*key \d+$)(?!ntp (?:server|peer) .* key \d+$)(?!crypto key )"
        r".*?(?<!\S)key (?![067] )(\S+)$"
    ),
]


def _mask(match: re.Match[str]) -> str:
    whole = match.group(0)
    if match.group(1) == MASK:
        return whole
    start = match.start(1) - match.start(0)
    end = match.end(1) - match.start(0)
    return whole[:start] + MASK + whole[end:]


# "key <number>" alone is a key ID in a key chain, but a secret in a server
# block ("tacacs server ISE" / " key 123456"); only the block tells them apart.
_BLOCK_KEY = re.compile(r"^\s*key (\d+)$")
_KEY_CHAIN = re.compile(r"^key chain ")


def redact(line: str, block: str | None = None) -> str:
    """Return ``line`` with known secret values replaced by ``<redacted>``.

    ``block`` is the line's parent block, when known.
    """
    if block is not None and not _KEY_CHAIN.match(block):
        line = _BLOCK_KEY.sub(_mask, line)
    for pattern in _PATTERNS:
        line = pattern.sub(_mask, line)
    return line
