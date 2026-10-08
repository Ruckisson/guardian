"""Guardian CLI entry point."""

from collections import Counter
from itertools import groupby
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from guardian import __version__
from guardian.core.audit import run_audit
from guardian.core.models import Severity
from guardian.core.platforms import DEFAULT_PLATFORM, UnknownPlatformError, get_platform
from guardian.core.rules.loader import RuleLoadError, load_rules
from guardian.core.rules.model import AREA_DESCRIPTIONS

console = Console()
errors = Console(stderr=True)

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}

# Exit codes: 0 compliant, 1 findings, 2 Guardian could not run (bad input).
EXIT_FINDINGS = 1
EXIT_ERROR = 2

PlatformOption = Annotated[
    str, typer.Option("--platform", "-p", help="Platform of the config (e.g. cisco_ios).")
]
RulesOption = Annotated[
    Path | None,
    typer.Option(
        exists=True,
        file_okay=False,
        help="Use rules from this directory instead of the bundled set.",
    ),
]

app = typer.Typer(
    name="guardian",
    help="Network configuration backup, compliance auditing and drift tracking.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """Guardian command-line interface."""


@app.command()
def version() -> None:
    """Print the Guardian version."""
    typer.echo(f"guardian {__version__}")


@app.command()
def audit(
    config: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Config file to audit.")
    ],
    platform: PlatformOption = DEFAULT_PLATFORM,
    rules: RulesOption = None,
) -> None:
    """Audit a config file against compliance rules."""
    try:
        findings = run_audit(config, platform=platform, rules_dir=rules)
    except (UnknownPlatformError, RuleLoadError) as exc:
        _fail(exc)

    if not findings:
        console.print("[bold green]✔ No findings. Config is compliant.[/]")
        return

    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.target))

    # One block per rule: severity, id and title once, then every place in the
    # config that fails it. A borderless grid keeps wrapped text in its column.
    console.print(f"[bold]Audit: {config.name}[/]\n")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_column()
    for rule_id, group in groupby(findings, key=lambda f: f.rule_id):
        group = list(group)
        severity = group[0].severity
        style = SEVERITY_STYLE[severity]
        grid.add_row(f"[{style}]{severity.upper()}[/]", rule_id, f"[bold]{group[0].message}[/]")
        for f in group:
            grid.add_row("", "", Text(f"→ {f.target}", style="dim"))
        grid.add_row("", "", "")
    console.print(grid)

    counts = Counter(f.severity for f in findings)
    by_severity = ", ".join(
        f"[{SEVERITY_STYLE[s]}]{counts[s]} {s}[/]" for s in reversed(Severity) if counts[s]
    )
    rules_hit = len({f.rule_id for f in findings})
    summary = f"[bold red]✘ {len(findings)} finding(s)[/] in {rules_hit} rule(s)"
    console.print(f"{summary}: {by_severity}")
    raise typer.Exit(code=EXIT_FINDINGS)


@app.command("rules")
def list_rules(
    platform: PlatformOption = DEFAULT_PLATFORM,
    rules: RulesOption = None,
) -> None:
    """List the rules that an audit would apply."""
    try:
        loaded = load_rules(rules or get_platform(platform).rules_dir)
    except (UnknownPlatformError, RuleLoadError) as exc:
        _fail(exc)

    console.print(f"[bold]Rules: {platform if rules is None else rules}[/]")

    # One table per area (L2, LOG, MGMT, ...), most severe rules first.
    loaded.sort(key=lambda r: (r.area, -r.severity.rank, r.id))
    title_width = max((len(r.title) for r in loaded), default=0)  # same width in every table
    for area, group in groupby(loaded, key=lambda r: r.area):
        description = AREA_DESCRIPTIONS.get(area)
        title = f"{area}: {description}" if description else area
        table = Table(title=title, title_justify="left", title_style="bold")
        table.add_column("Rule", min_width=12)
        table.add_column("Severity", min_width=8)
        table.add_column("Title", min_width=title_width)
        for rule in group:
            style = SEVERITY_STYLE[rule.severity]
            table.add_row(rule.id, f"[{style}]{rule.severity}[/]", rule.title)
        console.print(table)

    console.print(f"{len(loaded)} rule(s).")


def _fail(exc: Exception) -> NoReturn:
    """Print why Guardian cannot run and exit with EXIT_ERROR."""
    messages = exc.errors if isinstance(exc, RuleLoadError) else [str(exc)]
    errors.print("[bold red]✘ Guardian cannot run:[/]")
    for message in messages:
        errors.print(f"  {message}", markup=False, highlight=False)
    raise typer.Exit(code=EXIT_ERROR)
