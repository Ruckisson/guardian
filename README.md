# Guardian

Compliance auditing for network device configurations. Backups and drift
tracking are planned.

I work as a NOC operator and I'm moving towards network security. Guardian is
my learning and portfolio project. It's in early development: right now it
audits a saved Cisco IOS config against a set of rules. Everything else in the
roadmap is planned and not done yet.

## What works today

- Auditing a Cisco IOS / IOS-XE `show running-config` saved to a file.
- 15 rules, listed below.
- Rules are plain YAML files. The loader validates every rule and refuses a
  broken one instead of skipping it, so a typo can't turn into a rule that
  checks nothing.
- Supported checks:
  - a line must exist / must not exist
  - every matching line must also match a pattern
  - a number must be within limits
  - a reference must be defined (e.g. the ACL used by a VTY line has to exist)
  - a custom Python check, for cases YAML can't express
- Passwords, SNMP communities and keys are masked in the output.
- Exit codes: 0 compliant, 1 findings, 2 Guardian couldn't run (missing file,
  broken rule). This makes it usable in scripts and CI.

```bash
guardian rules                                       # list rules
guardian audit running-config.txt                    # audit a config file
guardian audit running-config.txt --rules ./my-rules # use your own rules
```

## Rules

| ID | What it checks |
| --- | --- |
| IOS-MGMT-001 | VTY lines accept SSH only |
| IOS-MGMT-002 | VTY lines have an access-class |
| IOS-MGMT-003 | the ACL used by the access-class is defined |
| IOS-MGMT-004 | console and VTY timeouts are not disabled |
| IOS-MGMT-005 | console and VTY timeouts are 10 minutes or less |
| IOS-MGMT-006 | the HTTP server (`ip http server`) is disabled |
| IOS-SNMP-001 | no `public` / `private` communities |
| IOS-SNMP-002 | no read-write communities |
| IOS-SNMP-003 | every community is limited by an ACL |
| IOS-SNMP-004 | SNMPv3 groups use authentication and encryption |
| IOS-PASS-001 | `enable secret` is used instead of `enable password` |
| IOS-PASS-002 | local users have `secret`, not `password` |
| IOS-PASS-003 | console, AUX and VTY lines don't use a line password |
| IOS-L2-001 | active access ports have port security |
| IOS-LOG-001 | log messages have date and time stamps |

See [docs/adding-rules.md](docs/adding-rules.md) for how to write a new rule.

## Roadmap

| Version | Scope | Status |
| --- | --- | --- |
| v0.1 | Cisco IOS config from file, 15–20 rules, HTML/JSON report | in progress (engine and 15 rules done, reports to do) |
| v0.2 | SSH collection (Netmiko), git backup, `collect` command | planned |
| v0.3 | Scheduler, compliance drift between runs | planned |
| v0.4 | Waivers (accepted risk with owner and expiry), MikroTik | planned |
| v0.5 | Collection triggered by syslog | planned |

## Project layout

```
src/guardian/
├── cli/            # command-line layer only, no logic
├── core/           # everything else, independent of the CLI (a GUI/web UI can reuse it)
│   ├── models.py   # ConfigLine, Severity, Finding
│   ├── platforms.py  # platform -> parser + rule set
│   ├── audit.py    # parse -> load rules -> evaluate
│   ├── redact.py   # masks secrets in findings
│   ├── parsers/    # config parsers (cisco.py)
│   └── rules/      # rule model, loader, engine, custom checks
└── rulesets/       # YAML rules, one directory per platform
docs/               # adding-rules.md
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
- Test configs come from my lab only, never from a production network.
- Rules are written in my own words. Where a rule follows a benchmark, it
  references the control ID only and doesn't copy its text.

## Use of AI

I use Claude (Anthropic's AI assistant) while building Guardian, mainly as a
tutor and a pair programmer:

- It explains Python and Cisco topics.
- It reviews the rules I write.
- It wrote larger parts of the code, for example the rule engine and the
  config parser.

I read through the code until I understand it, test it, and decide what gets
merged. The newer rules are written by me, with Claude doing the review.

## License

Apache License 2.0, see [LICENSE](LICENSE).
