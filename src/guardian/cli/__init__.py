"""Command-line interface.

A thin layer over ``guardian.core``. It parses arguments, calls the core and
prints results. No business logic lives here, so a GUI or web front end can
later reuse the core unchanged.
"""
