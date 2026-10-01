"""Guardian CLI entry point."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from guardian import __version__
from guardian.core.audit import run_audit

console = Console()

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}

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
    rules: Annotated[
        Path, typer.Option(exists=True, file_okay=False, help="Directory with rule files.")
    ] = Path("rules/cisco_ios"),
) -> None:
    """Audit a config file against compliance rules."""
    findings = run_audit(config, rules)

    if not findings:
        console.print("[bold green]✔ No findings. Config is compliant.[/]")
        return

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
    raise typer.Exit(code=1)
