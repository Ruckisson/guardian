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
severity: high                   # low | medium | high | critical (from the STIG CAT, see section 6)

scope: global                    # where to look (see below)

check:                           # exactly one check type (see below)
  must_not_exist: "^snmp-server community (?i:public|private)( |$)"

rationale: >                     # why the rule exists
  ...
remediation:                     # how to fix it (see section 5)
  recommended_change:
    - "no snmp-server community public"
  before_you_apply:
    - "Move the monitoring system to a new community or SNMPv3 first."
references:                      # required: official sources (see section 6)
  stig: []
  nist_800_53: []
  cisco_guide: "SNMP Community Strings"
  cisa: false

examples:                        # required by the test suite
  compliant:                     # must PASS
    - |
      snmp-server community Xq7-lab-monitoring RO 10
  not_applicable: []             # optional: must be N/A (nothing to check)
  non_compliant:                 # must FAIL (at least one finding)
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
| `skip_if: [{block, child, reason}]` | a selected block whose header matches `block` and that has a `child` line is N/A with `reason` |

Example, active access ports only:

```yaml
scope:
  path: "^interface "
  has_child: "^switchport mode access$"
  not_has_child: "^shutdown$"
```

Example, VTY lines that accept no connections are N/A:

```yaml
scope:
  path: "^line vty "
  skip_if:
    - block: "^line vty "
      child: "^transport input none$"
      reason: the line accepts no connections (transport input none)
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

### PASS, FAIL and N/A

A rule is FAIL with any finding, PASS when it checked at least one place,
and N/A when there was nothing to check: the scope selected no block, or a
custom check returned `NotApplicable("reason")` (for example "the device is
not a switch"). For block scopes add `applies_to` so the N/A reason is
readable:

```yaml
applies_to: VTY lines        # report says "the config has no VTY lines"
```

Secrets in reported lines are masked by `guardian/core/redact.py`. When a rule
reports a line that holds another kind of secret, extend `_PATTERNS` there;
`tests/test_example_redaction.py` checks the `non_compliant` examples of
global rules.

## 5. Remediation: how to fix a finding

Written by hand in the YAML, in English. Guardian never builds a fix by
putting `no` in front of the offending line (`no username admin` would delete
the user). Nothing in a remediation saves the config or reloads the device.

```yaml
remediation:
  recommended_change:            # required: config commands, one per item
    - "{block}"                  # a leading space marks a sub-command
    - " access-class <MGMT_ACL> in vrf-also"
  before_you_apply:              # required: show commands and checks
    - "Your own source address is permitted: `show users`."
  notes:                         # optional: version differences, caveats
    - "Older IOS: ..."
  if_service_needed:             # optional: restrict instead of disable
    text: Keep it, but only for management addresses.
    commands:
      - "ip http access-class ipv4 <MGMT_ACL>"
  may_cut_access: true           # optional warning: can lock out the operator
  change_both_ends: false        # optional warning: change the neighbour too
```

`recommended_change` can also be a list of variants; the first one whose
conditions hold is used, the last one has no conditions:

```yaml
  recommended_change:
    - when_config: "^aaa new-model$"   # a top-level line matches
      commands: ["{block}", " login authentication default"]
    - commands: ["{block}", " login local"]
```

Other conditions: `when_block` (a line in the failing block) and `when_line`
(the offending line of a global rule). A variant can have its own `notes`,
shown before the rule's notes.

**Placeholders** like `<NEW_PASSWORD>`, `<SNMP_COMMUNITY>`, `<NTP_SERVER_IP>`
are filled in by a person. Secrets are always placeholders, never values from
the config.

**Variables** are filled from the config. Each value must pass a whitelist;
one that does not (spaces, control characters, unexpected names) is shown as
its placeholder with a note.

| Variable | Value | Rules with |
| --- | --- | --- |
| `{block}` | failing block (`interface Gi1/0/1`, `line vty 0 4`) | block scope |
| `{interface}` | interface name of the failing block | block scope |
| `{switchport_mode}` | `access` / `trunk` guessed from the port's lines | block scope |
| `{acl_name}` | ACL of the block's `access-class` | block scope |
| `{fhrp_group}` | HSRP/VRRP groups without MD5 as `standby 1`, `vrrp 2` or `standby` for group 0 (command repeated per group) | block scope |
| `{username}` | user name from the offending `username` line | global scope |
| `{snmp_group}`, `{snmp_level}` | SNMPv3 group and level from the offending line | global scope |
| `{vty_acl}` | ACL used by the VTY access-class, else `<MGMT_ACL>` | any |
| `{http_auth}` | the configured `ip http authentication` method, else `local` | any |
| `{ntp_source}` | `server`/`peer`, vrf, address and options without the key (command repeated per line) | any |

The loader refuses `write memory`, `copy run start`, `reload`, `erase`,
`delete`, `format` (also with `do`), line breaks
and control characters, unknown variables and variables the scope cannot
provide.

## 6. References and severity

Every rule names its official sources. All four keys are required; use
`[]`, `null` or `false` when there is nothing.

```yaml
references:
  stig:
    - id: V-215813                 # V- and six digits
      stig_id: CISC-ND-000150      # CISC-ND-, CISC-RT- or CISC-L2- and six digits
      benchmark: Cisco IOS XE Router NDM V3R7
      severity: CAT II             # CAT I | CAT II | CAT III
      relation: satisfies          # satisfies: the rule checks the requirement
                                   # related: the rule covers part of it
  nist_800_53: [AC-7]              # e.g. AC-7, IA-5(1)
  cisco_guide: "Login Password Retry Lockout"   # section of the Cisco IOS XE Hardening Guide, or null
  cisa: false                      # true if CISA's 2024 hardening guidance asks for it
```

Severity follows the STIG CAT only when the rule satisfies the STIG requirement. Rules that are only related to a STIG requirement, or have none, keep their own severity. Four rules with direct remote takeover risk are critical.
The highest CAT among the `satisfies` references counts: CAT I high, CAT II
medium, CAT III low. The critical rules are IOS-MGMT-001, IOS-MGMT-010,
IOS-SNMP-001 and IOS-SNMP-002. `tests/test_references.py` checks this.

Reports show the references as tags; the mapping is informative, Guardian is
not an official STIG scanner.

## 7. Test

```bash
pytest
```

- `tests/test_rule_examples.py` runs every example of every rule automatically:
  `compliant` must PASS, `non_compliant` must FAIL, `not_applicable` must be
  N/A. It fails if a rule has no compliant or no non-compliant example.
- `tests/test_audit.py` runs all rules on the configs in `tests/fixtures/configs/`.
  If your rule finds something there, the test fails on purpose: review the new
  finding and add it to the expected set.

Try the rule by hand:

```bash
guardian rules
guardian audit tests/fixtures/configs/insecure_switch.cfg
```

## 8. Ship it

```bash
ruff check . && ruff format .
git switch -c feat/rule-<name>
git add src/guardian/rulesets/cisco_ios/<ID>_<name>.yaml <other files you changed>
git status                       # check that only your files are staged
git commit -m "Add rule <ID>: <summary>"
git push -u origin feat/rule-<name>
gh pr create --fill
```

Merge after CI is green.
