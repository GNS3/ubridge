"""Boundary-value tests verified against the actual running kernel.

Tests probe the same boundaries the kernel enforces. Where our parse_long
range is wider than what this kernel (6.19.11-1-default) accepts, the
test documents the narrower kernel limit and asserts the kernel's own
error (206) for out-of-its-range values.

Deterministic assertion — our parser rejects (204):
  Values outside the parse_long range (e.g. setfd 31).
Kernel-dependent assertion — our parser accepts, kernel decides:
  In-our-range but kernel rejects (e.g. setportprio 64 → 206 ERANGE).
"""
import subprocess

from common import Ubridge, Results, kernel_bridge_attr, no_residual

BR = "brbd"

UBTEST = subprocess.run(["ip", "-o", "link", "show", "ubtest"]).returncode == 0


def main():
    r = Results()
    with Ubridge(port=13002) as ub:
        c = ub.connect()
        c.send("brctl setup %s 10.9.0.1/24" % BR)

        # --- bridge-level time/priority — our range == kernel range ---
        for val, exp in [(0, "100"), (1, "100"), (65534, "100"), (65535, "100")]:
            r.check("setbridgeprio %d -> %s" % (val, exp),
                    c.code("brctl setbridgeprio %s %d" % (BR, val)) == exp)
        r.check("setbridgeprio 65536 parse-rejected -> 204",
                c.code("brctl setbridgeprio %s 65536" % BR) == "204")

        for val, exp in [(2, "100"), (15, "100"), (30, "100")]:
            r.check("setfd %d -> %s" % (val, exp),
                    c.code("brctl setfd %s %d" % (BR, val)) == exp)
        r.check("setfd 1 parse-rejected -> 204",
                c.code("brctl setfd %s 1" % BR) == "204")
        r.check("setfd 31 parse-rejected -> 204",
                c.code("brctl setfd %s 31" % BR) == "204")

        for val, exp in [(1, "100"), (2, "100"), (10, "100")]:
            r.check("sethello %d -> %s" % (val, exp),
                    c.code("brctl sethello %s %d" % (BR, val)) == exp)
        r.check("sethello 0 parse-rejected -> 204",
                c.code("brctl sethello %s 0" % BR) == "204")

        for val, exp in [(6, "100"), (20, "100"), (40, "100")]:
            r.check("setmaxage %d -> %s" % (val, exp),
                    c.code("brctl setmaxage %s %d" % (BR, val)) == exp)
        r.check("setmaxage 5 parse-rejected -> 204",
                c.code("brctl setmaxage %s 5" % BR) == "204")

        for val, exp in [(0, "100"), (1, "100"), (300, "100")]:
            r.check("setageing %d -> %s" % (val, exp),
                    c.code("brctl setageing %s %d" % (BR, val)) == exp)
        r.check("setageing -1 parse-rejected -> 204",
                c.code("brctl setageing %s -1" % BR) == "204")

        # --- kernel-specific: group_fwd_mask only accepts specific bits (0, 8, ...) ---
        r.check("groupfwd 0 kernel-accepted -> 100",
                c.code("brctl setgroupfwd %s 0" % BR) == "100")
        r.check("groupfwd 8 kernel-accepted -> 100",
                c.code("brctl setgroupfwd %s 8" % BR) == "100")
        r.check("groupfwd 1 kernel-rejected -> 206",
                c.code("brctl setgroupfwd %s 1" % BR) == "206")
        r.check("groupfwd 65536 parse-rejected -> 204",
                c.code("brctl setgroupfwd %s 65536" % BR) == "204")

        # --- on/off token variants ---
        for tok in ("on", "off", "1", "0", "yes", "no", "true", "false"):
            r.check("stp %r -> 100" % tok,
                    c.code("brctl stp %s %s" % (BR, tok)) == "100")
        for tok in ("maybe", "2", "yn"):
            r.check("stp %r parse-rejected -> 204" % tok,
                    c.code("brctl stp %s %s" % (BR, tok)) == "204")

        # --- vlan protocol: on this kernel both valid values are rejected (206) ---
        for tok in ("0x8100", "0x88a8"):
            code = c.code("brctl setvlanproto %s %s" % (BR, tok))
            r.check("setvlanproto %s -> 100" % tok, code == "100", code)
        # kernel read-back: iproute2 prints 0x88a8 as "802.1ad"
        _ip = subprocess.run(["ip", "-d", "link", "show", BR],
                             capture_output=True, text=True).stdout
        r.check("kernel reflects vlan_protocol 0x88a8",
                ("802.1ad" in _ip.lower()) or ("0x88a8" in _ip.lower()),
                _ip.strip()[:80])
        r.check("setvlanproto 0x8101 parse-rejected -> 204",
                c.code("brctl setvlanproto %s 0x8101" % BR) == "204")

        # --- port-level (kernel-specific limits) ---
        if UBTEST:
            c.send("brctl addif %s ubtest" % BR)
            # This kernel accepts port priority 0-48, rejects >= 64
            for val, exp in [(0, "100"), (8, "100"), (48, "100")]:
                r.check("setportprio %d -> %s" % (val, exp),
                        c.code("brctl setportprio %s ubtest %d" % (BR, val)) == exp)
            for val in (64, 128, 255):
                r.check("setportprio %d kernel-rejected -> 206" % val,
                        c.code("brctl setportprio %s ubtest %d" % (BR, val)) == "206")
            r.check("setportprio 256 parse-rejected -> 204",
                    c.code("brctl setportprio %s ubtest 256" % BR) == "204")
            # path cost: kernel accepts 1-65535
            for val, exp in [(1, "100"), (65535, "100")]:
                r.check("setpathcost %d -> %s" % (val, exp),
                        c.code("brctl setpathcost %s ubtest %d" % (BR, val)) == exp)
            r.check("setpathcost 0 parse-rejected -> 204",
                    c.code("brctl setpathcost %s ubtest 0" % BR) == "204")
            # port state: 0-3 kernel accepts
            for val, exp in [(0, "100"), (3, "100")]:
                r.check("setportstate %d -> %s" % (val, exp),
                        c.code("brctl setportstate %s ubtest %d" % (BR, val)) == exp)
            # hairpin: both on/off accepted
            r.check("hairpin on -> 100",
                    c.code("brctl hairpin %s ubtest on" % BR) == "100")
            r.check("hairpin off -> 100",
                    c.code("brctl hairpin %s ubtest off" % BR) == "100")
            # isolated: both on/off accepted
            r.check("isolated on -> 100",
                    c.code("brctl isolated %s ubtest on" % BR) == "100")
            import subprocess as _sp
            _link = _sp.run(["ip", "-d", "link", "show", "ubtest"],
                            capture_output=True, text=True).stdout
            r.check("kernel shows isolated on", "isolated on" in _link, _link[:60])
            r.check("isolated off -> 100",
                    c.code("brctl isolated %s ubtest off" % BR) == "100")
            r.check("isolated bad value -> 204",
                    c.code("brctl isolated %s ubtest maybe" % BR) == "204")
            r.check("isolated wrong bridge -> 206",
                    c.code("brctl isolated otherbr ubtest on") == "206")
            c.send("brctl delif %s ubtest" % BR)

        # --- verify kernel side for a few representative values ---
        c.send("brctl stp %s on" % BR)
        c.send("brctl setbridgeprio %s 4096" % BR)
        c.send("brctl setfd %s 7" % BR)
        kv = kernel_bridge_attr(BR, "stp_state", "priority", "forward_delay")
        r.check("kernel stp_state=1",   kv.get("stp_state")    == "1", str(kv))
        r.check("kernel priority=4096", kv.get("priority")     == "4096", str(kv))
        r.check("kernel forward_delay=700",
                kv.get("forward_delay") == "700", str(kv))

        c.send("brctl delete %s" % BR)
        c.close()

    r.check("no residual bridges", no_residual())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
