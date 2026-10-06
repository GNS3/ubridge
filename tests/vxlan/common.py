"""Shared helpers for the vxlan test suite.

Ubridge / Client / Results / ubridge_binary come from the brctl suite's
common.py, loaded by file path like tests/bridge/helpers.py does — the
suites share one implementation (this module used to carry a near-verbatim
copy of it, and the copies had already drifted).  Only the vxlan-specific
helpers live here.
"""
import importlib.util
import os
import subprocess

_brctl_common = os.path.join(os.path.dirname(__file__), "..", "brctl", "common.py")
_spec = importlib.util.spec_from_file_location("brctl_common", _brctl_common)
_brctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_brctl)

Ubridge = _brctl.Ubridge
Client = _brctl.Client
Results = _brctl.Results
ubridge_binary = _brctl.ubridge_binary


def kernel_vxlan_attr(name, *keys):
    """Return a dict of {key: value} for keys found in `ip -d link show <name>`.

    Scans the `vxlan ...` section for `key value` token pairs, so a test can
    verify a parameter actually took effect in the kernel rather than only in
    `vxlan show` output.
    """
    out = subprocess.run(
        ["ip", "-d", "link", "show", name], capture_output=True, text=True
    ).stdout
    if " vxlan " not in out:
        return {}
    section = out.split(" vxlan ", 1)[1]
    toks = section.split()
    result = {}
    for i, tok in enumerate(toks):
        if tok in keys and i + 1 < len(toks):
            result[tok] = toks[i + 1]
    return result


def no_residual(prefix="vxt"):
    """True if no vxlan device whose name starts with `prefix` remains."""
    out = subprocess.run(
        ["ip", "-o", "link", "show", "type", "vxlan"], capture_output=True, text=True
    ).stdout
    return not any(prefix in line for line in out.splitlines())
