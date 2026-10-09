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

from guardian.core.models import References, Severity, StigReference
from guardian.core.rules import custom
from guardian.core.rules.model import (
    AlternativeSpec,
    Check,
    EachMustMatch,
    Examples,
    MustExist,
    MustNotExist,
    Python,
    Reference,
    RemediationSpec,
    Rule,
    Scope,
    Skip,
    Value,
    Variant,
)
from guardian.core.rules.remediation import VARIABLE, VARIABLES

ID_FORMAT = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
PLACEHOLDER = re.compile(r"\{(\w+)\}")

# Remediation commands: "<NTP_SERVER_IP>" style placeholders, {variables} from
# guardian.core.rules.remediation, and commands a remediation must never contain.
COMMAND_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]*>")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Saving, reloading or wiping is never part of a suggested change ("do" runs
# an EXEC command from configuration mode).
FORBIDDEN_COMMAND = re.compile(
    r"^\s*(do\s+)?(wr(ite)?(\s+mem(ory)?)?|copy\s+run\S*\s+start\S*|reload|erase|delete"
    r"|format)(\s|$)",
    re.IGNORECASE,
)
REMEDIATION_KEYS = {
    "recommended_change",
    "before_you_apply",
    "notes",
    "if_service_needed",
    "may_cut_access",
    "change_both_ends",
}

TOP_KEYS = {
    "id",
    "title",
    "severity",
    "scope",
    "check",
    "rationale",
    "remediation",
    "references",
    "applies_to",
    "examples",
}
REQUIRED_KEYS = (
    "id",
    "title",
    "severity",
    "scope",
    "check",
    "rationale",
    "remediation",
    "references",
)

# references: official sources. Formats of DISA STIG and NIST SP 800-53 identifiers.
REFERENCE_KEYS = {"stig", "nist_800_53", "cisco_guide", "cisa"}
STIG_KEYS = {"id", "stig_id", "benchmark", "severity", "relation"}
STIG_VULN_ID = re.compile(r"^V-\d{6}$")
STIG_RULE_ID = re.compile(r"^CISC-(ND|RT|L2)-\d{6}$")
STIG_SEVERITIES = ("CAT I", "CAT II", "CAT III")
STIG_RELATIONS = ("satisfies", "related")
NIST_CONTROL = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")
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
    if "fix" in data:
        p.add("fix", "old rule format; use 'remediation: {recommended_change: [...]}' instead")
    for unknown in sorted(set(data) - TOP_KEYS - {"match", "fix"}):
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
    remediation = _parse_remediation(data["remediation"], scope, p)
    references = _parse_references(data["references"], p)
    applies_to = ""
    if "applies_to" in data:
        applies_to = p.text(data["applies_to"], "applies_to").strip()
        if scope is not None and scope.is_global:
            p.add("applies_to", "only for block scopes; a global rule always applies")
    examples = _parse_examples(data.get("examples", {}), p)

    if p.items:
        raise RuleError(source, p.items)
    assert severity is not None and scope is not None and check is not None
    assert remediation is not None
    return Rule(
        id=rule_id,
        title=title.strip(),
        severity=severity,
        scope=scope,
        check=check,
        rationale=rationale,
        remediation=remediation,
        references=references,
        applies_to=applies_to,
        examples=examples,
        source=Path(source) if source != "<rule>" else None,
    )


def _parse_scope(value: Any, p: _Problems) -> Scope | None:
    if value == "global":
        return Scope()
    if not isinstance(value, dict):
        p.add("scope", "must be 'global' or a mapping with 'path'")
        return None
    value = p.mapping(value, "scope", {"path", "has_child", "not_has_child", "skip_if"})
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
        skip_if=_parse_skips(value.get("skip_if", []), p),
    )


def _parse_skips(value: Any, p: _Problems) -> tuple[Skip, ...]:
    if not isinstance(value, list):
        p.add("scope.skip_if", "must be a list of {child, reason, block}")
        return ()
    skips = []
    for i, item in enumerate(value):
        key = f"scope.skip_if[{i}]"
        item = p.mapping(item, key, {"child", "reason", "block"})
        child = p.regex(item.get("child"), f"{key}.child")
        reason = p.text(item.get("reason"), f"{key}.reason")
        block = p.regex(item["block"], f"{key}.block") if "block" in item else None
        if child is not None and reason:
            skips.append(Skip(child, reason.strip(), block))
    return tuple(skips)


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


def _parse_remediation(value: Any, scope: Scope | None, p: _Problems) -> RemediationSpec | None:
    before = len(p.items)
    if isinstance(value, str):
        p.add("remediation", "must be a mapping with recommended_change and before_you_apply")
        return None
    value = p.mapping(value, "remediation", REMEDIATION_KEYS)
    key = "remediation"
    for required in ("recommended_change", "before_you_apply"):
        if required not in value:
            p.add(f"{key}.{required}", "missing required key")

    variants = _parse_variants(value.get("recommended_change", []), scope, p)
    before_you_apply = _parse_strings(
        value.get("before_you_apply", []), f"{key}.before_you_apply", p
    )
    if "before_you_apply" in value and not before_you_apply:
        p.add(f"{key}.before_you_apply", "needs at least one item")
    notes = _parse_strings(value.get("notes", []), f"{key}.notes", p)
    for name, texts in (("before_you_apply", before_you_apply), ("notes", notes)):
        for i, text in enumerate(texts):
            _check_variables(text, f"{key}.{name}[{i}]", scope, p)

    alternative = None
    if "if_service_needed" in value:
        body = p.mapping(
            value["if_service_needed"], f"{key}.if_service_needed", {"text", "commands"}
        )
        text = p.text(body.get("text"), f"{key}.if_service_needed.text")
        _check_variables(text, f"{key}.if_service_needed.text", scope, p)
        commands = _parse_commands(
            body.get("commands", []), f"{key}.if_service_needed.commands", scope, p, required=False
        )
        alternative = AlternativeSpec(" ".join(text.split()), commands)

    flags = {}
    for flag in ("may_cut_access", "change_both_ends"):
        flags[flag] = value.get(flag, False)
        if not isinstance(flags[flag], bool):
            p.add(f"{key}.{flag}", "must be true or false")

    if len(p.items) > before:
        return None
    return RemediationSpec(
        recommended_change=variants,
        before_you_apply=tuple(" ".join(t.split()) for t in before_you_apply),
        notes=tuple(" ".join(t.split()) for t in notes),
        if_service_needed=alternative,
        **flags,
    )


def _parse_variants(value: Any, scope: Scope | None, p: _Problems) -> tuple[Variant, ...]:
    """A list of commands, or a list of variants ({when_*, commands}), default last."""
    key = "remediation.recommended_change"
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        commands = _parse_commands(value, key, scope, p)
        return (Variant(commands),) if commands else ()
    if not isinstance(value, list) or not value:
        p.add(key, "must be a list of commands or a list of variants")
        return ()

    variants = []
    conditions = ("when_config", "when_block", "when_line")
    for i, item in enumerate(value):
        item_key = f"{key}[{i}]"
        body = p.mapping(item, item_key, {"commands", "notes", *conditions})
        patterns = {c: p.regex(body[c], f"{item_key}.{c}") for c in conditions if c in body}
        commands = _parse_commands(body.get("commands", []), f"{item_key}.commands", scope, p)
        notes = _parse_strings(body.get("notes", []), f"{item_key}.notes", p)
        for j, text in enumerate(notes):
            _check_variables(text, f"{item_key}.notes[{j}]", scope, p)
        is_last = i == len(value) - 1
        if is_last and patterns:
            p.add(item_key, "the last variant is the default and must not have conditions")
        if not is_last and not patterns:
            p.add(item_key, "only the last variant may be without conditions")
        if "when_block" in patterns and scope is not None and scope.is_global:
            p.add(f"{item_key}.when_block", "needs a block scope, the rule scope is global")
        notes = tuple(" ".join(t.split()) for t in notes)
        variants.append(Variant(commands, notes, **patterns))
    return tuple(variants)


def _parse_commands(
    value: Any, key: str, scope: Scope | None, p: _Problems, *, required: bool = True
) -> tuple[str, ...]:
    commands = _parse_strings(value, key, p)
    if required and not commands:
        p.add(key, "needs at least one command")
    for i, command in enumerate(commands):
        item = f"{key}[{i}]"
        if not command.strip():
            p.add(item, "must not be empty")
        if CONTROL.search(command):
            p.add(item, "must be a single line without control characters")
        if FORBIDDEN_COMMAND.search(command):
            p.add(item, "must not save, reload, erase or delete anything")
        for bracket in re.findall(r"<[^>]*>", command):
            if not COMMAND_PLACEHOLDER.fullmatch(bracket):
                p.add(item, f"placeholder {bracket} must look like <UPPER_CASE>")
        _check_variables(command, item, scope, p)
    return commands


def _check_variables(text: str, key: str, scope: Scope | None, p: _Problems) -> None:
    for name in VARIABLE.findall(text):
        variable = VARIABLES.get(name)
        if variable is None:
            p.add(key, f"unknown variable {{{name}}} (known: {', '.join(sorted(VARIABLES))})")
        elif scope is not None and variable.needs == "block" and scope.is_global:
            p.add(key, f"{{{name}}} needs a block scope, the rule scope is global")
        elif scope is not None and variable.needs == "line" and not scope.is_global:
            p.add(key, f"{{{name}}} needs a global scope (it comes from the offending line)")


def _parse_references(value: Any, p: _Problems) -> References:
    key = "references"
    value = p.mapping(value, key, REFERENCE_KEYS)
    for required in sorted(REFERENCE_KEYS):
        if required not in value:
            p.add(f"{key}.{required}", "missing required key (use [], null or false when empty)")

    stig = []
    items = value.get("stig", [])
    if not isinstance(items, list):
        p.add(f"{key}.stig", "must be a list (empty: [])")
        items = []
    for i, item in enumerate(items):
        item_key = f"{key}.stig[{i}]"
        item = p.mapping(item, item_key, STIG_KEYS)
        for missing in sorted(STIG_KEYS - set(item)):
            p.add(f"{item_key}.{missing}", "missing required key")
        if len(STIG_KEYS & set(item)) < len(STIG_KEYS):
            continue
        checks = (
            ("id", STIG_VULN_ID.fullmatch(str(item["id"])), "must look like V-215813"),
            (
                "stig_id",
                STIG_RULE_ID.fullmatch(str(item["stig_id"])),
                "must look like CISC-ND-000150",
            ),
            ("severity", item["severity"] in STIG_SEVERITIES, "must be CAT I, CAT II or CAT III"),
            ("relation", item["relation"] in STIG_RELATIONS, "must be satisfies or related"),
        )
        for name, ok, message in checks:
            if not ok:
                p.add(f"{item_key}.{name}", f"{item[name]!r} {message}")
        benchmark = p.text(item["benchmark"], f"{item_key}.benchmark")
        stig.append(
            StigReference(
                str(item["id"]), str(item["stig_id"]), benchmark, item["severity"], item["relation"]
            )
        )

    nist = _parse_strings(value.get("nist_800_53", []), f"{key}.nist_800_53", p)
    for control in nist:
        if not NIST_CONTROL.fullmatch(control):
            p.add(f"{key}.nist_800_53", f"{control!r} must look like AC-7 or IA-5(1)")

    guide = value.get("cisco_guide")
    if guide is not None:
        guide = p.text(guide, f"{key}.cisco_guide").strip()
    cisa = value.get("cisa", False)
    if not isinstance(cisa, bool):
        p.add(f"{key}.cisa", "must be true or false")
        cisa = False
    return References(tuple(stig), nist, guide or None, cisa)


def _parse_strings(value: Any, key: str, p: _Problems) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        p.add(key, "must be a list of text items")
        return ()
    return tuple(value)


def _parse_examples(value: Any, p: _Problems) -> Examples:
    value = p.mapping(value, "examples", {"compliant", "non_compliant", "not_applicable"})
    return Examples(
        compliant=_parse_strings(value.get("compliant", []), "examples.compliant", p),
        non_compliant=_parse_strings(value.get("non_compliant", []), "examples.non_compliant", p),
        not_applicable=_parse_strings(
            value.get("not_applicable", []), "examples.not_applicable", p
        ),
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
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{path.name}: cannot read the rule file ({exc})".replace("\n", " "))
            continue
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
