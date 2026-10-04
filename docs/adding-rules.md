# Adding a compliance rule

A rule is a single YAML file in `rules/<platform>/`. No Python is needed
as long as the rule engine supports the check you want.

## 1. Think it through first

Answer these before writing anything:

1. **Where** is it configured? (e.g. under `line vty` blocks)
2. **Which** blocks does it apply to, and which not? (most false positives come from here)
3. **What** must be true? Write the exact regex.
4. **ID and severity.** Format `IOS-<AREA>-<NNN>`; the ID never changes once published.
5. **Why and how to fix**, in your own words. Do not copy benchmark text.

One rule checks one thing.

## 2. Write the rule

`rules/cisco_ios/IOS-MGMT-002_vty-access-class.yaml`:

```yaml
id: IOS-MGMT-002
title: VTY lines must restrict source addresses with an access-class
severity: medium            # low | medium | high | critical

match:
  block: "^line vty "       # regex selecting top-level blocks

check:
  child_must_match: "^access-class \\S+ in( vrf-also)?$"   # at least one child must match

rationale: >
  Why the rule exists.

remediation: |
  Commands that fix the finding.

examples:
  compliant:                # must produce no finding
    - |
      line vty 0 4
       access-class MGMT-ACCESS in
  non_compliant:            # must produce at least one finding
    - |
      line vty 0 4
       access-class MGMT-ACCESS out
```

Notes:

- Inside double quotes in YAML, write `\\` to get one backslash in the regex.
- In examples, keep one extra space before child lines; that space is the
  config indentation the parser relies on.
- Every rule needs at least one compliant and one non-compliant example;
  the test suite enforces it.

## 3. Test

```bash
pytest
```

- `tests/test_rule_examples.py` runs every example of every rule automatically.
- `tests/test_audit.py` runs all rules on the configs in `tests/fixtures/configs/`.
  If your rule finds something there, the test fails on purpose: review the new
  finding and add it to the expected set.

Try the rule by hand:

```bash
guardian audit tests/fixtures/configs/<config>.cfg
```

## 4. Ship it

```bash
ruff check . && ruff format .
git switch -c feat/rule-<name>
git add -A && git commit -m "Add rule <ID>: <summary>"
git push -u origin feat/rule-<name>
gh pr create --fill
```

Merge after CI is green.

## When the engine is not enough

The engine currently supports one check type: blocks selected by their own
text must contain a child line matching a regex. Rules that need more (for
example filtering blocks by their children, forbidding a line, or comparing
values) require extending `src/guardian/core/rules/engine.py` first.