"""Core of Guardian, independent of any user interface.

Rule: nothing under ``guardian.core`` may import ``guardian.cli`` or any
UI framework. The test suite enforces this.
"""
