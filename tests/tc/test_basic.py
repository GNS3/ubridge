"""Basic regression for the tc module (kernel netem qdisc).

Attaches netem (delay/jitter/loss/dup) to a throwaway dummy interface and
reads it back with `tc qdisc show` to confirm the netlink ABI and unit
conversions are correct. Stdlib only. Requires CAP_NET_ADMIN — run under
sudo. Self-skips when the `tc` binary is missing (a TEST dependency only —
ubridge itself talks netlink directly and needs no iproute2 tools).

Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import sys
import shutil
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubtc-"
PORT = 13040
IFC = PREFIX + "dummy0"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))


def _find_tc():
    """Locate the tc tool. shutil.which() alone is not enough: tc lives in
    /usr/sbin on several distros, which a non-root PATH (and the PATH
    inherited into `unshare`) may not include."""
    path = shutil.which("tc")
    if path:
        return path
    for path in ("/usr/sbin/tc", "/sbin/tc"):
        if os.access(path, os.X_OK):
            return path
    return None


_TC = _find_tc()


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _tc(args):
    return subprocess.run([_TC] + args, capture_output=True, text=True)


def _qdisc(ifname):
    return _tc(["qdisc", "show", "dev", ifname]).stdout


def main():
    r = Results()

    if _TC is None:
        # CI installs iproute2, which ships tc; a skip here means the local
        # host truly lacks the test-only verification tool.
        print("  [SKIP] needs the `tc` tool (ships with iproute2) to verify")
        print("         kernel qdisc state; not in PATH, /usr/sbin or /sbin")
        return 0

    # throwaway dummy interface to hang the qdisc on
    _ip(["link", "add", IFC, "type", "dummy"])
    _ip(["link", "set", IFC, "up"])

    try:
        # in-repo build: the installed binary may be older than the tree
        # (same convention as the marker suite)
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                # --- netem set: delay + loss, read back from the kernel ---
                res = c.send("tc netem set %s delay 100 loss 50" % IFC)
                r.check("netem set delay+loss", res.startswith("100-"), res)
                q = _qdisc(IFC)
                r.check("kernel: netem attached", "netem" in q, q.strip()[:120])
                r.check("kernel: delay applied", "delay" in q, q.strip()[:120])
                r.check("kernel: loss applied", "loss" in q, q.strip()[:120])

                # --- netem set: delay + jitter + dup ---
                r.check("netem set jitter+dup",
                        c.send("tc netem set %s delay 50 jitter 10 dup 20" % IFC).startswith("100-"))
                q = _qdisc(IFC)
                # tc prints jitter as a bare value after delay: "delay 50ms 10ms"
                # (not the word "jitter"), so assert the jitter value is present.
                r.check("kernel: jitter applied", "10ms" in q, q.strip()[:120])

                # --- netem set: corrupt ---
                r.check("netem set corrupt",
                        c.send("tc netem set %s corrupt 30" % IFC).startswith("100-"))
                r.check("kernel: corrupt applied", "corrupt 30%" in _qdisc(IFC), _qdisc(IFC).strip()[:120])

                # --- reset removes the qdisc ---
                r.check("reset", c.send("tc reset %s" % IFC).startswith("100-"))
                r.check("kernel: netem gone after reset", "netem" not in _qdisc(IFC))
                # idempotent: no qdisc is already the target state
                r.check("reset with no qdisc -> 100 (idempotent)",
                        c.send("tc reset %s" % IFC).startswith("100-"))

                # --- error paths ---
                r.check("netem missing iface -> 207",
                        c.send("tc netem set %s-nope delay 10" % PREFIX).startswith("207-"))
                r.check("netem too few params -> 203",
                        c.send("tc netem set %s" % IFC).startswith("203-"))
                r.check("netem negative delay -> 204",
                        c.send("tc netem set %s delay -5" % IFC).startswith("204-"))
                r.check("netem bad keyword -> 204",
                        c.send("tc netem set %s bogus 5" % IFC).startswith("204-"))
                r.check("netem loss out of range -> 204",
                        c.send("tc netem set %s loss 150" % IFC).startswith("204-"))
                r.check("netem bad delay value -> 204",
                        c.send("tc netem set %s delay abc" % IFC).startswith("204-"))
                r.check("reset missing iface -> 207",
                        c.send("tc reset %s-nope" % PREFIX).startswith("207-"))
            finally:
                # leave the interface clean
                c.send("tc reset %s" % IFC)
                c.close()
    finally:
        _ip(["link", "del", IFC])

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
