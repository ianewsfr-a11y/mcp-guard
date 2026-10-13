"""Test collection settings."""

import importlib.util

# The TUI tests need the optional `ui` extra (Textual); the rest must pass
# without it, so a base install can run the suite.
collect_ignore = [] if importlib.util.find_spec("textual") else ["test_ui.py"]
