"""Load rule files and validate them before anything is evaluated.

Every problem is reported with the file name and the key that caused it, and
all problems in a directory are collected before failing, so a typo never
turns into a rule that silently checks nothing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from guardian.core.models import Severity
from guardian.core.rules import custom
from guardian.core.rules.model import (
    Check,
    EachMustMatch,
    Examples,
    MustExist,
    MustNotExist,
    Python,
    Reference,
    Rule,
    Scope,
    Value,
)

ID_FORMAT = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
PLACEHOLDER = re.compile(r"\{(\w+)\}")

TOP_KEYS = {
    "id",
    "title",
    "severity",
    "scope",
    "check",
    "rationale",
    "remediation",
    "references",
    "examples",
}
REQUIRED_KEYS = ("id", "title", "severity", "scope", "check", "rationale", "remediation")
CHECK_TYPES = ("must_exist", "must_not_exist", "each_must_match", "value", "reference", "python")


class RuleError(Exception):
    """One rule file is invalid. ``problems`` lists every issue found in it."""

    def __init__(self, source: str, problems: list[str]) -> None:
        self.source = source
        self.problems = problems
        super().__init__("\n".join(f"{source}: {p}" for p in problems))


class RuleLoadError(Exception):
    """A rule directory could not be loaded. ``errors`` lists every problem."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("\n".join(errors))


class _Problems:
    """Collects validation messages for one rule file."""

    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, key: str, message: str) -> None:
        self.items.append(f"{key}: {message}")

    def regex(self, value: Any, key: str) -> re.Pattern[str] | None:
        if not isinstance(value, str) or not value:
            self.add(key, "must be a non-empty regex string")
            return None
        try:
            return re.compile(value)
        except re.error as exc:
            self.add(key, f"invalid regex ({exc})")
            return None

    def regex_list(self, value: Any, key: str) -> tuple[re.Pattern[str], ...]:
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or not values:
            self.add(key, "must be a regex or a non-empty list of regexes")
            return ()
        compiled = [self.regex(v, f"{key}[{i}]") for i, v in enumerate(values)]
        return tuple(c for c in compiled if c is not None)

    def text(self, value: Any, key: str) -> str:
        if not isinstance(value, str) or not value.strip():
            self.add(key, "must be non-empty text")
            return ""
        return value

    def mapping(self, value: Any, key: str, allowed: set[str]) -> dict[str, Any]:
        if not isinstance(value, dict):
            self.add(key, "must be a mapping")
            return {}
        for unknown in sorted(set(value) - allowed):
            self.add(f"{key}.{unknown}", f"unknown key (allowed: {', '.join(sorted(allowed))})")
        return value

    def integer(self, value: Any, key: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            self.add(key, "must be a whole number")
            return None
        return value


def parse_rule(data: Any, source: str = "<rule>") -> Rule:
    """Validate one rule (already parsed from YAML) and build a ``Rule``."""
    p = _Problems()
    if not isinstance(data, dict):
        raise RuleError(source, ["file must contain a YAML mapping (key: value pairs)"])

    if "match" in data:
        p.add("match", "old rule format; use 'scope: {path: [...]}' instead")
    for unknown in sorted(set(data) - TOP_KEYS - {"match"}):
        p.add(unknown, f"unknown key (allowed: {', '.join(sorted(TOP_KEYS))})")
    for key in REQUIRED_KEYS:
        if key not in data:
            p.add(key, "missing required key")
    if p.items:
        raise RuleError(source, p.items)

    rule_id = p.text(data["id"], "id")
    if rule_id and not ID_FORMAT.fullmatch(rule_id):
        p.add("id", f"{rule_id!r} does not look like PLATFORM-AREA-NNN (e.g. IOS-SNMP-001)")

    title = p.text(data["title"], "title")
    if "\n" in title.strip():
        p.add("title", "must be a single line")

    severity = None
    try:
        severity = Severity(data["severity"])
    except ValueError:
        allowed = ", ".join(s.value for s in Severity)
        p.add("severity", f"{data['severity']!r} is not one of: {allowed}")

    scope = _parse_scope(data["scope"], p)
    check = _parse_check(data["check"], p)
    rationale = p.text(data["rationale"], "rationale")
    remediation = p.text(data["remediation"], "remediation")
    references = _parse_strings(data.get("references", []), "references", p)
    examples = _parse_examples(data.get("examples", {}), p)

    if p.items:
        raise RuleError(source, p.items)
    assert severity is not None and scope is not None and check is not None
    return Rule(
        id=rule_id,
        title=title.strip(),
        severity=severity,
        scope=scope,
        check=check,
        rationale=rationale,
        remediation=remediation,
        references=references,
        examples=examples,
        source=Path(source) if source != "<rule>" else None,
    )


def _parse_scope(value: Any, p: _Problems) -> Scope | None:
    if value == "global":
        return Scope()
    if not isinstance(value, dict):
        p.add("scope", "must be 'global' or a mapping with 'path'")
        return None
    value = p.mapping(value, "scope", {"path", "has_child", "not_has_child"})
    if "path" not in value:
        p.add("scope.path", "missing; use 'scope: global' for top-level lines")
        return None
    return Scope(
        path=p.regex_list(value["path"], "scope.path"),
        has_child=p.regex_list(value["has_child"], "scope.has_child")
        if "has_child" in value
        else (),
        not_has_child=p.regex_list(value["not_has_child"], "scope.not_has_child")
        if "not_has_child" in value
        else (),
    )


def _parse_check(value: Any, p: _Problems) -> Check | None:
    if not isinstance(value, dict) or len(value) != 1:
        p.add("check", f"must contain exactly one of: {', '.join(CHECK_TYPES)}")
        return None
    ((kind, body),) = value.items()
    key = f"check.{kind}"

    if kind == "must_exist":
        pattern = p.regex(body, key)
        return MustExist(pattern) if pattern else None

    if kind == "must_not_exist":
        pattern = p.regex(body, key)
        return MustNotExist(pattern) if pattern else None

    if kind == "each_must_match":
        body = p.mapping(body, key, {"select", "pattern"})
        select = p.regex(body.get("select"), f"{key}.select")
        pattern = p.regex(body.get("pattern"), f"{key}.pattern")
        return EachMustMatch(select, pattern) if select and pattern else None

    if kind == "value":
        before = len(p.items)
        body = p.mapping(body, key, {"pattern", "min", "max", "if_missing"})
        pattern = p.regex(body.get("pattern"), f"{key}.pattern")
        if pattern is not None and pattern.groups < 1:
            p.add(f"{key}.pattern", "needs a capture group around the number, e.g. (\\d+)")
        low = p.integer(body.get("min"), f"{key}.min")
        high = p.integer(body.get("max"), f"{key}.max")
        if body.get("min") is None and body.get("max") is None:
            p.add(key, "needs 'min', 'max' or both")
        if low is not None and high is not None and low > high:
            p.add(key, f"min ({low}) is greater than max ({high})")
        if_missing = body.get("if_missing", "fail")
        if if_missing not in ("pass", "fail"):
            p.add(f"{key}.if_missing", "must be 'pass' or 'fail'")
        if pattern is None or len(p.items) > before:
            return None
        return Value(pattern, low, high, if_missing)

    if kind == "reference":
        body = p.mapping(body, key, {"capture", "must_exist"})
        capture = p.regex(body.get("capture"), f"{key}.capture")
        template = p.text(body.get("must_exist"), f"{key}.must_exist")
        if capture is None or not template:
            return None
        names = set(capture.groupindex)
        if not names:
            p.add(f"{key}.capture", "needs a named group, e.g. (?P<acl>\\S+)")
            return None
        placeholders = set(PLACEHOLDER.findall(template))
        # "{3}" or "{4,6}" are regex quantifiers, not placeholders.
        unknown = {n for n in placeholders - names if not n.isdigit()}
        if unknown:
            p.add(
                f"{key}.must_exist",
                f"unknown placeholder {', '.join(sorted(unknown))} (capture defines: "
                f"{', '.join(sorted(names))})",
            )
            return None
        if not placeholders & names:
            p.add(
                f"{key}.must_exist",
                f"must use a placeholder: {', '.join('{' + n + '}' for n in sorted(names))}",
            )
            return None
        try:
            re.compile(
                PLACEHOLDER.sub(lambda m: "x" if m.group(1) in names else m.group(0), template)
            )
        except re.error as exc:
            p.add(f"{key}.must_exist", f"invalid regex template ({exc})")
            return None
        return Reference(capture, template)

    if kind == "python":
        name = p.text(body, key)
        if name and name not in custom.CHECKS:
            known = ", ".join(sorted(custom.CHECKS)) or "none registered"
            p.add(key, f"unknown custom check {name!r} (known: {known})")
            return None
        return Python(name) if name else None

    p.add("check", f"unknown check type {kind!r} (allowed: {', '.join(CHECK_TYPES)})")
    return None


def _parse_strings(value: Any, key: str, p: _Problems) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        p.add(key, "must be a list of text items")
        return ()
    return tuple(value)


def _parse_examples(value: Any, p: _Problems) -> Examples:
    value = p.mapping(value, "examples", {"compliant", "non_compliant"})
    return Examples(
        compliant=_parse_strings(value.get("compliant", []), "examples.compliant", p),
        non_compliant=_parse_strings(value.get("non_compliant", []), "examples.non_compliant", p),
    )


def load_rules(directory: Path) -> list[Rule]:
    """Load and validate every ``*.yaml`` rule in ``directory``, sorted by file name.

    Raises ``RuleLoadError`` listing every problem in every file, including
    duplicate rule IDs.
    """
    if not directory.is_dir():
        raise RuleLoadError([f"{directory}: rule directory does not exist"])

    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            rule = parse_rule(data, str(path))
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: not valid YAML ({exc})".replace("\n", " "))
            continue
        except RuleError as exc:
            errors.extend(f"{path.name}: {problem}" for problem in exc.problems)
            continue
        if rule.id in seen:
            errors.append(f"{path.name}: id {rule.id} is already used by {seen[rule.id]}")
            continue
        seen[rule.id] = path.name
        rules.append(rule)

    if errors:
        raise RuleLoadError(errors)
    return rules
