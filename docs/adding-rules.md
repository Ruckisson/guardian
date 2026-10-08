# Adding a compliance rule

A rule is a single YAML file in `src/guardian/rulesets/<platform>/`. No Python
is needed as long as one of the check types below fits.

## 1. Think it through first

Answer these before writing anything:

1. **Where** is it configured? Global line, or inside a block (`line vty`, `interface`)?
2. **Which** blocks does it apply to, and which not? (most false positives come from here)
3. **What** must be true? Pick a check type and write the exact regex.
4. **ID and severity.** Format `<PLATFORM>-<AREA>-<NNN>`, e.g. `IOS-SNMP-001`;
   the ID never changes once published.
   `guardian rules` groups rules by AREA. When you start a new area, add a short
   description for it to `AREA_DESCRIPTIONS` in `src/guardian/core/rules/model.py`.
5. **Why and how to fix**, in your own words. Do not copy benchmark text.

One rule checks one thing.

## 2. Rule file structure

```yaml
id: IOS-SNMP-001                 # PLATFORM-AREA-NNN, unique
title: SNMP must not use the default communities public or private
severity: high                   # low | medium | high | critical

scope: global                    # where to look (see below)

check:                           # exactly one check type (see below)
  must_not_exist: "^snmp-server community (?i:public|private)( |$)"

rationale: >                     # why the rule exists
  ...
remediation: |                   # commands that fix it
  ...
references:                      # optional: control IDs, documents
  - "Cisco IOS hardening guide: SNMP"

examples:                        # required by the test suite
  compliant:                     # must produce no finding
    - |
      snmp-server community Xq7-lab-monitoring RO 10
  non_compliant:                 # must produce at least one finding
    - |
      snmp-server community public RO
```

The loader rejects unknown keys, missing keys, invalid regexes and duplicate
IDs with a message naming the file and the key, so typos cannot turn into a
rule that silently checks nothing.

YAML notes:

- Inside double quotes write `\\` to get one backslash in the regex (`\\S+` → `\S+`).
- In examples keep one extra space before child lines; that space is the
  config indentation the parser relies on.

## 3. Scope: where to look

| Scope | Selects |
| --- | --- |
| `scope: global` | the top-level lines of the configuration |
| `scope: {path: "^line vty "}` | every top-level block whose line matches |
| `scope: {path: ["^router bgp ", "^address-family "]}` | nested blocks, one regex per level |
| `has_child: <regex or list>` | keep only blocks that contain matching child lines (all of them) |
| `not_has_child: <regex or list>` | drop blocks that contain any matching child line |

Example, active access ports only:

```yaml
scope:
  path: "^interface "
  has_child: "^switchport mode access$"
  not_has_child: "^shutdown$"
```

## 4. Check types: what must be true

Every check looks at the lines **inside** each selected place (for
`global`, the top-level lines).

| Check | Meaning | Finding target |
| --- | --- | --- |
| `must_exist: <regex>` | at least one line matches | the block, or `(global)` |
| `must_not_exist: <regex>` | no line matches | the block; for `global` each offending line |
| `each_must_match: {select, pattern}` | every line matching `select` also matches `pattern` | as above |
| `value: {pattern, min, max, if_missing}` | the number in group 1 is within limits | the block, or `(global)` |
| `reference: {capture, must_exist}` | what `capture` names is defined at top level | the block, or `(global)` |
| `python: <name>` | a function registered in `guardian/core/rules/custom.py` returns True | the block, or `(global)` |

`value` details: `pattern` needs a capture group around the number; give
`min`, `max` or both; `if_missing: pass` when the platform default is
compliant, otherwise leave the default `fail`. A captured value that is not a
number counts as out of range.

`reference` details: `capture` needs a named group such as `(?P<acl>\S+)`;
`must_exist` uses it as `{acl}` (the value is regex-escaped). Regex
quantifiers like `\d{3}` are left alone.

Secrets in targets (SNMP communities, passwords, keys) are replaced by
`<redacted>` automatically.

## 5. Test

```bash
pytest
```

- `tests/test_rule_examples.py` runs every example of every rule automatically
  and fails if a rule has no compliant or no non-compliant example.
- `tests/test_audit.py` runs all rules on the configs in `tests/fixtures/configs/`.
  If your rule finds something there, the test fails on purpose: review the new
  finding and add it to the expected set.

Try the rule by hand:

```bash
guardian rules
guardian audit tests/fixtures/configs/insecure_switch.cfg
```

## 6. Ship it

```bash
ruff check . && ruff format .
git switch -c feat/rule-<name>
git add -A && git commit -m "Add rule <ID>: <summary>"
git push -u origin feat/rule-<name>
gh pr create --fill
```

Merge after CI is green.
