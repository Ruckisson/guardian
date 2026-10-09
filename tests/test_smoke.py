"""Smoke tests for the project skeleton."""

import ast
from pathlib import Path

from typer.testing import CliRunner

import guardian
from guardian.cli.main import app

CORE_DIR = Path(guardian.__file__).parent / "core"
FORBIDDEN_IN_CORE = ("guardian.cli", "typer", "click")

runner = CliRunner()


def test_version_is_set() -> None:
    assert guardian.__version__


def test_cli_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert guardian.__version__ in result.output


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.output


def test_core_does_not_import_ui_layer() -> None:
    """The core must stay usable from a future GUI or web front end."""
    offenders = []
    for path in CORE_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                if any(name == f or name.startswith(f + ".") for f in FORBIDDEN_IN_CORE):
                    offenders.append(f"{path.relative_to(CORE_DIR)}: {name}")
    assert not offenders, f"core imports UI code: {offenders}"


def test_version_matches_pyproject() -> None:
    pyproject = Path(guardian.__file__).parents[2] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    assert f'version = "{guardian.__version__}"' in text
    assert guardian.__version__ == "0.1.0"
