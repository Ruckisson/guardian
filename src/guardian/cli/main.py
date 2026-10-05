"""Guardian CLI entry point."""

from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from guardian import __version__
from guardian.core.audit import run_audit
from guardian.core.platforms import DEFAULT_PLATFORM, UnknownPlatformError, get_platform
from guardian.core.rules.loader import RuleLoadError, load_rules

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

    table = Table(title=f"Audit: {config.name}")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Target")
    table.add_column("Finding")

    for f in findings:
        style = SEVERITY_STYLE[f.severity]
        table.add_row(f"[{style}]{f.severity.upper()}[/]", f.rule_id, f.target, f.message)

    console.print(table)
    console.print(f"[bold red]✘ {len(findings)} finding(s).[/]")
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

    table = Table(title=f"Rules: {platform if rules is None else rules}")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Title")
    for rule in loaded:
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
