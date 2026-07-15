"""Basic lifecycle + error-path regression for the tap module.

Covers persistent-TAP create / set_owner / delete, common error paths
(duplicate create, missing delete, overlong name, bad uid), and the brctl
integration that wires a persistent TAP into a kernel bridge. Stdlib only —
no third-party dependencies. Requires CAP_NET_ADMIN, so run under sudo.

Reuses Ubridge / Client / Results from tests/brctl/common.py.
"""
import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubtapt-"
PORT = 13030
OWNER_UID = "1000"  # representative non-root uid for the set_owner check


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _exists(name):
    return _ip(["-o", "link", "show", name]).returncode == 0


def _no_residual():
    """True if no tuntap device whose name starts with PREFIX remains."""
    out = _ip(["-o", "tuntap", "show"]).stdout
    return not any(PREFIX in line for line in out.splitlines())


def _force_delete(name):
    """Best-effort kernel-side cleanup if a test leaves a tap behind."""
    _ip(["tuntap", "del", "mode", "tap", "dev", name])


def main():
    r = Results()
    t0 = PREFIX + "t0"
    t1 = PREFIX + "t1"
    br = PREFIX + "br0"

    with Ubridge(port=PORT) as ub:
        c = ub.connect()
        try:
            # --- lifecycle ---
            r.check("create t0", c.code("tap create %s" % t0) == "100")
            r.check("kernel sees t0", _exists(t0))
            r.check("dup create -> 206/EBUSY",
                    c.code("tap create %s" % t0) == "206",
                    c.send("tap create %s" % t0))
            r.check("overlong name -> 204",
                    c.code("tap create %s" % ("x" * 16)) == "204")
            r.check("set_owner ok",
                    c.code("tap set_owner %s %s" % (t0, OWNER_UID)) == "100")
            r.check("set_owner bad uid -> 204",
                    c.code("tap set_owner %s abc" % t0) == "204")
            r.check("set_owner on missing tap -> 206",
                    c.code("tap set_owner %s-nope %s" % (t0, OWNER_UID)) == "206")
            r.check("delete t0", c.code("tap delete %s" % t0) == "100")
            r.check("kernel t0 gone", not _exists(t0))
            r.check("delete again -> 207/ENODEV",
                    c.code("tap delete %s" % t0) == "207")

            # --- brctl integration: persistent TAP enslaved to a kernel bridge ---
            r.check("create t1", c.code("tap create %s" % t1) == "100")
            r.check("brctl create br0", c.code("brctl create %s" % br) == "100")
            r.check("brctl addif br0 t1",
                    c.code("brctl addif %s %s" % (br, t1)) == "100",
                    c.send("brctl addif %s %s" % (br, t1)))
            # the tap should now be a port of the bridge in the kernel
            link = _ip(["-d", "link", "show", t1]).stdout
            r.check("kernel: t1 enslaved to br0", br in link and "master" in link, link.strip()[:80])
        finally:
            # --- cleanup (tolerant) ---
            c.send("brctl delif %s %s" % (br, t1))
            c.send("brctl delete %s" % br)
            c.send("tap delete %s" % t1)
            c.send("tap delete %s" % t0)
            c.close()
            for name in (t0, t1):
                if _exists(name):
                    _force_delete(name)
            if _exists(br):
                _ip(["link", "del", br])

        r.check("no residual taps", _no_residual())

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
