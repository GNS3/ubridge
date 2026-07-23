"""Shared helpers for the delay test suite.

Loads the brctl common helpers (Ubridge/Client/Results) by file path, like
tests/link/helpers.py, so the test trees stay independent.
"""
import importlib.util
import os

_brctl_common = os.path.join(
    os.path.dirname(__file__), "..", "brctl", "common.py"
)
_spec = importlib.util.spec_from_file_location("brctl_common", _brctl_common)
_brctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_brctl)

Ubridge = _brctl.Ubridge
Client = _brctl.Client
Results = _brctl.Results
