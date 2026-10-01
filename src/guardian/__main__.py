"""Allow running Guardian as ``python -m guardian``."""

from guardian.cli.main import app

if __name__ == "__main__":
    app()
