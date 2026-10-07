# Guardian

Network configuration backup, compliance auditing and drift tracking.

> **Status: early development (pre-v0.1).** Auditing a Cisco IOS config file works;
> collection, backups, drift and reports are planned. This README lists only what
> actually works; planned features are marked as such.

## What works today

- Audit a Cisco IOS / IOS-XE `show running-config` saved to a file.
- 12 bundled rules: SSH-only and ACL-restricted VTY access, session timeouts,
  SNMP communities and SNMPv3, port security on access ports, log timestamps.
- Rules are YAML data with a validated schema; the engine supports global and
  nested block scopes, block filters, required/forbidden lines, per-line checks,
  numeric limits with platform defaults and cross-references (e.g. ACL defined).
- Secrets in findings (SNMP communities, passwords, keys) are redacted.
- Exit code 0 = compliant, 1 = findings, 2 = Guardian could not run.

```bash
guardian rules                              # list bundled rules
guardian audit running-config.txt           # audit a config file
guardian audit running-config.txt --rules ./my-rules
```

## What it will do

- Collect running configs from network devices and back them up to git.
- Audit configs against data-defined compliance rules, one rule set per platform.
- Track **compliance drift**: which findings appeared or disappeared between runs.
- Support **waivers** (accepted risk with reason, owner and expiry), so reports split into
  *fix*, *accepted* and *waiver expiring soon*.
- Produce HTML and JSON reports.

## Roadmap

| Version | Scope | Status |
| --- | --- | --- |
| v0.1 | Cisco IOS config from file, 15–20 rules, HTML/JSON report | in progress (engine + 11 rules done, reports planned) |
| v0.2 | SSH collection (Netmiko), git backup, `collect` command | planned |
| v0.3 | Scheduler with separate backup/compliance intervals, compliance drift | planned |
| v0.4 | Waivers, MikroTik plugin | planned |
| v0.5 | Syslog-triggered collection | planned |

## Project layout

```
src/guardian/
├── cli/            # thin command-line layer, no business logic
├── core/           # UI-independent core (reusable by a future GUI/web)
│   ├── models.py   # ConfigLine, Severity, Finding
│   ├── platforms.py  # platform -> parser + rule set
│   ├── audit.py    # pipeline: parse -> load rules -> evaluate
│   ├── redact.py   # masks secrets in findings
│   ├── parsers/    # per-syntax config parsers (cisco.py)
│   ├── rules/      # rule model, loader/validator, engine, custom checks
│   └── inventory/ collectors/ storage/ reporting/ scheduler/   # planned
└── rulesets/       # rule definitions (YAML), one directory per platform
docs/               # adding-rules.md: rule format reference
tests/              # pytest suite and sample configs
```

## Development

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

guardian version   # smoke check
pytest             # tests
ruff check .       # lint
ruff format .      # format
```

## Security notes

- Credentials are never stored in this repository.
- Collected configs contain secrets (SNMP communities, password hashes). Backups and
  run history live outside this repository (see `.gitignore`).
- Only lab configs are used as test fixtures.
- Rules are written in the author's own words and reference control IDs only;
  no third-party benchmark text is reproduced.

## License

Apache License 2.0, see [LICENSE](LICENSE).
