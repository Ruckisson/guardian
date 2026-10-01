"""Guardian CLI entry point."""

import typer

from guardian import __version__

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
