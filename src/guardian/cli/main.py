"""Guardian CLI entry point."""

import io
import sys
from collections import Counter
from enum import StrEnum
from itertools import groupby
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from guardian import __version__
from guardian.core.audit import ConfigInputError, audit_file
from guardian.core.models import AuditResult, Finding, Severity, Status
from guardian.core.platforms import DEFAULT_PLATFORM, UnknownPlatformError, get_platform
from guardian.core.reporting import html as html_report
from guardian.core.reporting import json as json_report
from guardian.core.reporting import write_private
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

# Exit codes: 0 no findings at or above --fail-on, 1 such findings,
# 2 Guardian could not run (bad input).
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class ReportFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"


class FailOn(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    report_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", help="Output format.")
    ] = ReportFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", dir_okay=False, help="Write the report to this file (mode 0600)."
        ),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(help="Exit with 1 only for findings of this severity or higher."),
    ] = FailOn.LOW,
) -> None:
    """Audit a config file against compliance rules."""
    if output is not None and _same_file(output, config):
        _fail(f"refusing to write the report over the input file {config}")
    try:
        result = audit_file(config, platform=platform, rules_dir=rules)
    except (UnknownPlatformError, RuleLoadError, ConfigInputError) as exc:
        _fail(exc)
    except (OSError, UnicodeDecodeError) as exc:
        _fail(f"cannot read {config}: {exc}")

    if report_format is ReportFormat.TEXT:
        if output is None:
            _print_text(result, console)
        else:
            buffer = io.StringIO()
            _print_text(result, Console(file=buffer, width=120, color_system=None))
            _write(output, buffer.getvalue())
    else:
        render = json_report.render if report_format is ReportFormat.JSON else html_report.render
        text = render(result)
        if output is None:
            sys.stdout.write(text)
        else:
            _write(output, text)

    if _fails(result.findings, Severity(fail_on.value)):
        raise typer.Exit(code=EXIT_FINDINGS)


def _fails(findings: list[Finding], threshold: Severity) -> bool:
    """True if any finding is at least as severe as ``threshold``."""
    return any(f.severity.rank >= threshold.rank for f in findings)


def _same_file(output: Path, config: Path) -> bool:
    """True if ``output`` is the config itself (also through symlinks or ``..``)."""
    try:
        return output.resolve() == config.resolve() or (output.exists() and output.samefile(config))
    except OSError:
        return False


def _write(path: Path, text: str) -> None:
    try:
        write_private(path, text)
    except OSError as exc:
        _fail(f"cannot write {path}: {exc}")
    errors.print(f"Report written to {path}", markup=False, highlight=False, soft_wrap=True)


def _print_text(result: AuditResult, out: Console) -> None:
    """Human-readable report: findings grouped by rule, most severe first.

    Everything that comes from the config, the file name or a rule file is
    printed as ``Text`` (or escaped), never as Rich markup, so a file called
    "[red]x.cfg" shows up literally.
    """
    findings = sorted(result.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.target))
    statuses = Counter(r.status for r in result.rules)
    counts_line = (
        f"Rules: {statuses[Status.PASS]} pass, {statuses[Status.FAIL]} fail, "
        f"{statuses[Status.NOT_APPLICABLE]} N/A"
    )
    if statuses[Status.PASS] + statuses[Status.FAIL] == 0:
        out.print("[bold yellow]! Nothing was checked: no rule applies to this config.[/]")
        out.print(counts_line)
        return
    if not findings:
        out.print("[bold green]✔ No findings. Config is compliant.[/]")
        out.print(counts_line)
        return

    # One block per rule: severity, id and title once, then every place in the
    # config that fails it. A borderless grid keeps wrapped text in its column.
    out.print(Text.assemble(("Audit: ", "bold"), (result.file, "bold"), "\n"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_column()
    for rule_id, group in groupby(findings, key=lambda f: f.rule_id):
        group = list(group)
        severity = group[0].severity
        style = SEVERITY_STYLE[severity]
        grid.add_row(
            Text(severity.upper(), style=style), Text(rule_id), Text(group[0].title, style="bold")
        )
        for f in group:
            grid.add_row("", "", Text(f"→ {f.target}", style="dim"))
        grid.add_row("", "", "")
    out.print(grid)

    counts = Counter(f.severity for f in findings)
    by_severity = ", ".join(
        f"[{SEVERITY_STYLE[s]}]{counts[s]} {s}[/]" for s in reversed(Severity) if counts[s]
    )
    rules_hit = len({f.rule_id for f in findings})
    summary = f"[bold red]✘ {len(findings)} finding(s)[/] in {rules_hit} rule(s)"
    out.print(f"{summary}: {by_severity}")
    out.print(counts_line)


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

    console.print(Text(f"Rules: {platform if rules is None else rules}", style="bold"))

    # One table per area (L2, LOG, MGMT, ...), most severe rules first.
    loaded.sort(key=lambda r: (r.area, -r.severity.rank, r.id))
    title_width = max((len(r.title) for r in loaded), default=0)  # same width in every table
    for area, group in groupby(loaded, key=lambda r: r.area):
        description = AREA_DESCRIPTIONS.get(area)
        title = f"{area}: {description}" if description else area
        table = Table(title=escape(title), title_justify="left", title_style="bold")
        table.add_column("Rule", min_width=12)
        table.add_column("Severity", min_width=8)
        table.add_column("Title", min_width=title_width)
        for rule in group:
            style = SEVERITY_STYLE[rule.severity]
            table.add_row(Text(rule.id), Text(rule.severity, style=style), Text(rule.title))
        console.print(table)

    console.print(f"{len(loaded)} rule(s).")


def _fail(exc: Exception | str) -> NoReturn:
    """Print why Guardian cannot run and exit with EXIT_ERROR."""
    messages = exc.errors if isinstance(exc, RuleLoadError) else [str(exc)]
    errors.print("[bold red]✘ Guardian cannot run:[/]")
    for message in messages:
        errors.print(f"  {message}", markup=False, highlight=False)
    raise typer.Exit(code=EXIT_ERROR)
