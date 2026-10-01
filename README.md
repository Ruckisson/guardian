# Guardian

Network configuration backup, compliance auditing and drift tracking.

> **Status: early development (pre-v0.1).** Only the project skeleton exists so far.
> This README lists only what actually works; planned features are marked as such.

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
| v0.1 | Cisco IOS config from file, 15–20 rules, HTML/JSON report | planned |
| v0.2 | SSH collection (Netmiko), git backup, `collect` command | planned |
| v0.3 | Scheduler with separate backup/compliance intervals, compliance drift | planned |
| v0.4 | Waivers, MikroTik plugin | planned |
| v0.5 | Syslog-triggered collection | planned |

## Project layout

```
src/guardian/
├── cli/            # thin command-line layer, no business logic
└── core/           # UI-independent core (reusable by a future GUI/web)
    ├── inventory/  # devices from YAML
    ├── collectors/ # per-vendor config collection
    ├── parsers/    # per-vendor config parsing
    ├── rules/      # data-driven rule engine
    ├── storage/    # git backups + SQLite history
    ├── reporting/  # HTML / JSON output
    └── scheduler/  # backup and compliance intervals
rules/              # rule definitions (YAML), one directory per platform
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
