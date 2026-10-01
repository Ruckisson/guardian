"""Parser for Cisco IOS ``show running-config`` output."""

from guardian.core.models import ConfigLine

# Lines that carry no configuration.
_SKIP_PREFIXES = ("!", "Building configuration", "Current configuration")


def parse(text: str) -> list[ConfigLine]:
    """Turn running-config text into a tree based on indentation.

    Returns the top-level lines; nested lines are in ``children``.
    Known limitation: multi-line banners are not handled yet.
    """
    root: list[ConfigLine] = []
    stack: list[tuple[int, ConfigLine]] = []  # (indent, line) of open parents

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped == "end" or stripped.startswith(_SKIP_PREFIXES):
            continue

        indent = len(raw) - len(raw.lstrip())
        node = ConfigLine(stripped)

        # Close every parent that is not shallower than this line.
        while stack and stack[-1][0] >= indent:
            stack.pop()

        if stack:
            stack[-1][1].children.append(node)
        else:
            root.append(node)
        stack.append((indent, node))

    return root
