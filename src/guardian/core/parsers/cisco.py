"""Parser for Cisco configurations that use indentation for nesting.

Designed for the ``show running-config`` output of IOS, IOS-XE, NX-OS, ASA
and IOS-XR: all of them nest sub-commands by indenting them. Platform
differences live in the rule sets, not here. Tested with IOS configurations
and short samples of the other platforms' headers.

Handled specially:

* comments (``!``), output headers and ``end`` are skipped;
* multi-line ``banner`` text is kept as children of the banner line, so the
  banner's content can never be mistaken for configuration;
* tabs, Windows line endings and a byte-order mark are normalised (see
  ``_indent``).
"""

import re

from guardian.core.models import ConfigLine

# Whole lines that carry no configuration.
_SKIP = re.compile(
    r"^(?:"
    r"!.*"  # comment, also NX-OS "!Command:" and IOS-XR "!! ..." headers
    r"|Building configuration.*"
    r"|Current configuration.*"
    r"|:.*"  # ASA ": Saved" / ": Serial Number" header
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) .*"  # XR
    r"|end"
    r")$"
)

# "banner motd ^C" with the text starting on the same line or on the next ones.
# Running-config prints the delimiter as the two characters "^C"; a banner typed
# with another delimiter (e.g. "#") keeps that single character.
_BANNER = re.compile(r"^(banner \S+) (\^C|\S)(.*)$")


def parse(text: str) -> list[ConfigLine]:
    """Turn running-config text into a tree based on indentation.

    Returns the top-level lines; nested lines are in ``children``.
    """
    root: list[ConfigLine] = []
    stack: list[tuple[int, ConfigLine]] = []  # (indent, line) of open parents
    lines = text.lstrip("\ufeff").splitlines()

    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        stripped = raw.strip()
        if not stripped or _SKIP.match(stripped):
            continue

        indent = _indent(raw)
        node = ConfigLine(stripped)

        banner = _BANNER.match(stripped) if indent == 0 else None
        if banner:
            node.text = banner.group(1)
            i = _read_banner(banner.group(2), banner.group(3), lines, i, node)

        # Close every parent that is not shallower than this line.
        while stack and stack[-1][0] >= indent:
            stack.pop()

        if stack:
            stack[-1][1].children.append(node)
        else:
            root.append(node)
        stack.append((indent, node))

    return root


def _indent(raw: str) -> int:
    """Indentation level of a line.

    IOS writes the "quit" that closes a certificate as two spaces and a tab;
    tabs after spaces are ignored so that line stays at the certificate data
    level. A line indented with tabs only counts each tab as one space.
    """
    leading = raw[: len(raw) - len(raw.lstrip())]
    spaces = leading.count(" ")
    return spaces if spaces else leading.count("\t")


def _read_banner(delimiter: str, rest: str, lines: list[str], i: int, node: ConfigLine) -> int:
    """Store banner text as children of ``node``; return the index after the banner."""
    if delimiter in rest:  # whole banner on one line
        text_lines = [rest.split(delimiter, 1)[0]]
        end = i
    else:
        text_lines = [rest]
        end = None
        for j in range(i, len(lines)):
            if delimiter in lines[j]:
                text_lines.append(lines[j].split(delimiter, 1)[0])
                end = j + 1
                break
            text_lines.append(lines[j])
        if end is None:
            # No closing delimiter: do not swallow the rest of the config.
            text_lines = [rest]
            end = i
    node.children = [ConfigLine(t.strip()) for t in text_lines if t.strip()]
    return end
