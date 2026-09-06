"""Regression tests for TAP carrier control. Requires CAP_NET_ADMIN."""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13031
BRIDGE = "carrier-test"
TAP = "ubcarrier0"
DEFAULT_BRIDGE = "carrier-default-test"
DEFAULT_TAP = "ubcarrier1"


def _ip(*args):
    return subprocess.run(["ip"] + list(args), capture_output=True, text=True)


def _carrier_for(tap=TAP):
    try:
        with open("/sys/class/net/%s/carrier" % tap, encoding="ascii") as stream:
            return stream.read().strip()
    except OSError:
        return None


def main():
    r = Results()

    with Ubridge(port=PORT) as ub:
        c = ub.connect()
        try:
            r.check("create bridge", c.code("bridge create %s" % BRIDGE) == "100")
            r.check("set carrier without TAP rejected",
                    c.code("bridge set_nio_tap_carrier %s off" % BRIDGE) == "214")
            r.check("invalid initial state rejected",
                    c.code("bridge add_nio_tap %s %s invalid" % (BRIDGE, TAP)) == "204")
            r.check("add TAP with carrier off",
                    c.code("bridge add_nio_tap %s %s off" % (BRIDGE, TAP)) == "100")
            r.check("bring TAP administratively up",
                    c.code("link set %s up" % TAP) == "100")
            carrier = _carrier_for()
            r.check("initial carrier is off", carrier == "0", "carrier=%r" % carrier)
            r.check("set carrier on",
                    c.code("bridge set_nio_tap_carrier %s on" % BRIDGE) == "100")
            carrier = _carrier_for()
            r.check("carrier is on", carrier == "1", "carrier=%r" % carrier)
            r.check("set carrier off",
                    c.code("bridge set_nio_tap_carrier %s off" % BRIDGE) == "100")
            carrier = _carrier_for()
            r.check("carrier is off", carrier == "0", "carrier=%r" % carrier)
            r.check("invalid state rejected",
                    c.code("bridge set_nio_tap_carrier %s invalid" % BRIDGE) == "204")

            r.check("create default bridge",
                    c.code("bridge create %s" % DEFAULT_BRIDGE) == "100")
            r.check("legacy add TAP defaults carrier on",
                    c.code("bridge add_nio_tap %s %s" % (DEFAULT_BRIDGE, DEFAULT_TAP)) == "100")
            r.check("bring default TAP administratively up",
                    c.code("link set %s up" % DEFAULT_TAP) == "100")
            default_carrier = _carrier_for(DEFAULT_TAP)
            r.check("default carrier is on", default_carrier == "1",
                    "carrier=%r" % default_carrier)
        finally:
            c.send("bridge delete %s" % BRIDGE)
            c.send("bridge delete %s" % DEFAULT_BRIDGE)
            c.close()
            _ip("link", "delete", TAP)
            _ip("link", "delete", DEFAULT_TAP)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
