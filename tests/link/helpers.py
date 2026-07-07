"""Shared helpers for the link test suite.

Loads the brctl common helpers (Ubridge/Client/Results) by file path so the
two test trees can live side by side without a shared package.
"""
import importlib.util
import os
import subprocess

_brctl_common = os.path.join(
    os.path.dirname(__file__), "..", "brctl", "common.py"
)
_spec = importlib.util.spec_from_file_location("brctl_common", _brctl_common)
_brctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_brctl)

Ubridge = _brctl.Ubridge
Client = _brctl.Client
Results = _brctl.Results


def _run(*args, **kw):
    if "text" not in kw and "capture_output" not in kw:
        kw["text"] = True
    return subprocess.run(args, **kw)


def iface_exists(name):
    return _run("ip", "-o", "link", "show", name,
                capture_output=True, check=False).returncode == 0


def link_flags(name):
    """Return the <flags> substring of an interface, or '' if absent."""
    out = _run("ip", "-o", "link", "show", name,
               capture_output=True, text=True).stdout
    return out.split("<")[1].split(">")[0] if "<" in out else ""


def has_ipv4(name, cidr):
    out = _run("ip", "-o", "addr", "show", name,
               capture_output=True, text=True).stdout
    return cidr in out


def no_residual_link(prefix="ltest"):
    """True if no interface whose name starts with `prefix` remains."""
    out = _run("ip", "-o", "link", "show",
               capture_output=True, text=True).stdout
    return not any(line.split(":")[1].strip().split("@")[0].startswith(prefix)
                   or line.split(":")[1].strip().split("@")[0].startswith(prefix + "-")
                   for line in out.splitlines())
