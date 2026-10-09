# Guardian

Compliance auditing for network device configurations. Backups and drift
tracking are planned.

I'm moving towards network security from NOC background. Guardian is
my learning and portfolio project. It's in early development: right now it
audits a saved Cisco IOS config against a set of rules. Everything else in the
roadmap is planned and not done yet.

## What works today

- Auditing a Cisco IOS / IOS-XE `show running-config` saved to a file.
- 60 rules in 9 areas, listed below: passwords, management access, AAA, SNMP,
  unneeded services, interfaces, layer 2, logging and NTP.
- Rules are plain YAML files. The loader validates every rule and refuses a
  broken one instead of skipping it, so a typo can't turn into a rule that
  checks nothing.
- Supported checks:
  - a line must exist / must not exist
  - every matching line must also match a pattern
  - a number must be within limits
  - a reference must be defined (e.g. the ACL used by a VTY line has to exist)
  - a custom Python check, for cases YAML can't express
- Every rule ends as pass, fail or na (`status` in the JSON report). Rules
  that only make sense when a feature is configured (HTTPS server,
  HSRP/VRRP, NTP, IPv6, switch-only features) are na with the reason when the
  feature isn't there. Missing data never passes: a file without any
  configuration lines is refused.
- Every rule has a remediation: the recommended change (config commands),
  what to check before you apply it, and where it makes sense a milder option
  if the service is needed (restrict instead of disable). Changes that can cut
  your access or must be made on both ends of a link are marked. Remediations
  never save the config and never contain secrets from the config; values
  taken from the config (interface, ACL or user names, NTP servers) must pass
  a whitelist first.
- Passwords, SNMP communities, keys and credentials in URLs are masked in the
  output.
- `guardian audit` groups findings by rule, most severe first: each rule once
  with its title, every failing place in the config below it, and a summary
  per severity. `guardian rules` lists the rules grouped by area.
- Reports: `--format json` (machine-readable, `schema_version`, stable keys and
  order) and `--format html` (one offline file, no scripts or external
  resources). Both include the file's SHA-256, hostname, version, time (UTC),
  the status of every rule and each finding with its rationale and remediation.
  `-o` writes the report to a file readable only by you (0600).
- Exit codes: 0 no findings at or above `--fail-on` (default `low`, so any
  finding counts), 1 such findings, 2 Guardian couldn't run (missing or
  unreadable file, a file with no configuration lines, broken rule). This
  makes it usable in scripts and CI.

```bash
guardian rules                                       # list rules
guardian audit running-config.txt                    # audit a config file
guardian audit running-config.txt --rules ./my-rules # use your own rules
guardian audit running-config.txt -f json -o audit.json  # JSON report
guardian audit running-config.txt -f html -o audit.html  # HTML report
guardian audit running-config.txt --fail-on high     # fail CI on high only
```

## Rules

| ID | Severity | What it checks |
| --- | --- | --- |
| IOS-PASS-001 | high | Enable password must not be used, use enable secret |
| IOS-PASS-002 | high | Local users must use secret, not password |
| IOS-PASS-003 | high | Console, AUX and VTY lines must not use a line password |
| IOS-PASS-004 | low | Password encryption service must be enabled |
| IOS-PASS-005 | medium | Enable and user secrets must not use weak hash types 4 or 5 |
| IOS-PASS-006 | medium | Minimum password length must be at least 15 characters |
| IOS-PASS-007 | medium | Minimum password length must be at least 15 (clear text passwords present) |
| IOS-PASS-008 | high | Enable secret must be configured |
| IOS-PASS-009 | high | Local users must not be configured without a password |
| IOS-PASS-010 | medium | Login attempts must be rate limited with login block-for and a quiet-mode exception |
| IOS-PASS-011 | low | Local accounts must lock after 3 or fewer failed logins |
| IOS-MGMT-001 | critical | VTY lines must accept SSH only |
| IOS-MGMT-002 | medium | VTY lines must restrict source addresses with an access-class |
| IOS-MGMT-003 | medium | ACL used by a VTY access-class must be defined |
| IOS-MGMT-004 | high | Console and VTY sessions must not have timeouts disabled |
| IOS-MGMT-005 | high | Console and VTY session timeouts must be 5 minutes or less |
| IOS-MGMT-006 | high | HTTP server must be disabled, use HTTPS instead |
| IOS-MGMT-007 | medium | SSH must be limited to version 2 |
| IOS-MGMT-008 | low | AUX port must not start an EXEC session |
| IOS-MGMT-009 | low | AUX and TTY lines must not accept incoming connections |
| IOS-MGMT-010 | critical | Console and VTY lines must require login |
| IOS-MGMT-011 | high | HTTPS server must have an access-class and authentication |
| IOS-MGMT-012 | low | SSH negotiation timeout must be 60 seconds or less |
| IOS-MGMT-013 | low | SSH must allow at most 3 authentication retries per connection |
| IOS-MGMT-014 | low | A login banner must be configured |
| IOS-MGMT-015 | medium | VTY lines must restrict IPv6 sources when IPv6 is enabled |
| IOS-AAA-001 | medium | AAA must be enabled with aaa new-model |
| IOS-SNMP-001 | critical | SNMP must not use the default communities public or private |
| IOS-SNMP-002 | critical | SNMP communities must be read-only |
| IOS-SNMP-003 | medium | Every SNMP community must be limited by an ACL |
| IOS-SNMP-004 | medium | SNMPv3 groups must use authentication and encryption (priv) |
| IOS-SNMP-005 | high | SNMP must not be allowed to reload the device |
| IOS-SVC-001 | high | TCP and UDP small servers must be disabled |
| IOS-SVC-002 | high | Finger service must be disabled |
| IOS-SVC-003 | high | Loading configuration from the network at boot must be disabled |
| IOS-SVC-004 | high | rcp and rsh services must be disabled |
| IOS-SVC-005 | medium | IOx application hosting must be disabled when not used |
| IOS-SVC-006 | high | Smart Install must be disabled on switches |
| IOS-SVC-007 | medium | IP source routing must be disabled |
| IOS-SVC-008 | low | TCP keepalives must be enabled for incoming sessions |
| IOS-SVC-009 | low | CDP must be disabled on interfaces that face another network |
| IOS-IF-001 | low | Packets with IP options must be dropped |
| IOS-IF-002 | medium | Proxy ARP must be disabled on routed interfaces |
| IOS-IF-003 | medium | ICMP redirects must be disabled on routed interfaces |
| IOS-L2-001 | medium | Active access ports must have port security or 802.1X/MAB |
| IOS-L2-002 | medium | Switch ports must have an explicit switchport mode |
| IOS-L2-003 | medium | Trunk ports must not negotiate with DTP |
| IOS-L2-004 | medium | HSRP and VRRP groups must use MD5 authentication |
| IOS-L2-005 | medium | Active access ports must be protected by BPDU guard |
| IOS-L2-006 | medium | Trunk native VLAN must not be VLAN 1 |
| IOS-L2-007 | medium | DHCP snooping must be enabled on switches |
| IOS-LOG-001 | medium | Log messages must carry date and time stamps |
| IOS-LOG-002 | high | Logs must be sent to at least two remote syslog servers |
| IOS-LOG-003 | medium | Configuration changes must be logged |
| IOS-LOG-004 | medium | Configuration change log must hide passwords |
| IOS-LOG-005 | medium | Failed logins must be logged |
| IOS-LOG-006 | low | Successful logins should be logged |
| IOS-NTP-001 | medium | At least two NTP servers or peers must be configured |
| IOS-NTP-002 | low | NTP control messages (mode 6) must be disabled |
| IOS-NTP-003 | medium | NTP servers and peers must be authenticated |

Thresholds follow the DISA STIG for Cisco IOS XE: passwords of at least 15
characters, session timeouts of at most 5 minutes, two syslog servers, two
NTP servers, lockout after 3 failed logins, and `login block-for 900
attempts 3 within 120` together with a quiet-mode access-class.

Severity follows the STIG CAT only when the rule satisfies the STIG requirement. Rules that are only related to a STIG requirement, or have none, keep their own severity. Four rules with direct remote takeover risk are critical.
Every rule
lists its sources (`references`: DISA STIG, NIST SP 800-53, Cisco IOS XE
Hardening Guide, CISA hardening guidance); the reports show them. Guardian is
not an official STIG scanner, the mapping is informative.

See [docs/adding-rules.md](docs/adding-rules.md) for how to write a new rule.

## Roadmap

| Version | Scope | Status |
| --- | --- | --- |
| v0.1 | Cisco IOS config from file, core hardening rules, HTML/JSON report | done |
| v0.2 | SSH collection (Netmiko), git backup, `collect` command | planned |
| v0.3 | Scheduler, compliance drift between runs | planned |
| v0.4 | Waivers (accepted risk with owner and expiry), MikroTik | planned |
| v0.5 | Collection triggered by syslog | planned |

## Known limitations

- Switch ports with no switchport line at all (left at the default dynamic
  auto mode) are not checked yet.
- A router with a switch module counts as a switch (IOS-SVC-006, IOS-L2-007).
- Some IOS defaults are not shown in the running config (for example AUX
  `transport input`, NTP mode 6). Where a rule needs the explicit line, a
  device that is safe by default can get a false FAIL.
- SSH ciphers and MACs and SNMPv3 algorithms are checked from v0.2 on (they
  need `show ip ssh` and `show snmp user`).

## Project layout

```
src/guardian/
├── cli/            # command-line layer only, no logic
├── core/           # everything else, independent of the CLI (a GUI/web UI can reuse it)
│   ├── models.py   # ConfigLine, Severity, Finding, Remediation, AuditResult
│   ├── platforms.py  # platform -> parser + rule set
│   ├── audit.py    # parse -> load rules -> evaluate -> AuditResult
│   ├── redact.py   # masks secrets in findings
│   ├── parsers/    # config parsers (cisco.py)
│   ├── reporting/  # JSON and HTML reports
│   └── rules/      # rule model, loader, engine, remediations, custom checks
└── rulesets/       # YAML rules, one directory per platform
docs/               # adding-rules.md, design/ (approved HTML report design)
tests/              # pytest suite and sample configs
```

## Development

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

guardian version   # quick check
pytest             # tests
ruff check .       # lint
ruff format .      # format
```

## Security notes

- No credentials are stored in this repository.
- Device configs contain secrets (SNMP communities, password hashes), so
  backups and run history are kept outside this repository.
- Test configs are made-up lab configs, never taken from a production network.
  All passwords, hashes and keys in them are fake.
- Rule texts are original wording, not copied from benchmarks. Where a rule
  follows a benchmark, it references the control ID only.

## Use of AI

I use Claude (Anthropic's AI assistant) while building Guardian, mainly as a
tutor and a pair programmer:

- It explains Python and Cisco topics.
- It reviews the rules I write.
- It wrote larger parts of the code, for example the rule engine, the config
  parser and the custom Python checks.
- It wrote most of the rules: I wrote IOS-PASS-001 to IOS-PASS-003 myself,
  the other rules were written by Claude from a list of hardening topics I
  chose, together with their test configs.

I read through the code until I understand it, test it, and decide what gets
merged.

## License

Apache License 2.0, see [LICENSE](LICENSE).
