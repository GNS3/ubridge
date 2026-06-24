"""Robustness tests: malformed and hostile inputs must be rejected gracefully,
never crash ubridge or leave inconsistent state.
"""
import subprocess

from common import Ubridge, Results, no_residual


def main():
    r = Results()
    with Ubridge(port=13004) as ub:
        c = ub.connect()
        c.send("brctl create robtest")

        # --- number expected, garbage given ---
        r.check("setbridgeprio non-numeric -> 204",
                c.code("brctl setbridgeprio robtest abc") == "204")
        r.check("setbridgeprio negative -> 204",
                c.code("brctl setbridgeprio robtest -5") == "204")
        r.check("setfd with trailing text -> 204",
                c.code("brctl setfd robtest 7s") == "204")
        r.check("setportprio non-numeric -> 204",
                c.code("brctl setportprio robtest ubtest xyz") == "204")

        # --- on/off expected, garbage given ---
        r.check("stp garbage -> 204", c.code("brctl stp robtest yesno") == "204")

        # --- addip with various bad CIDRs ---
        for bad in ("not-an-ip/24", "10.0.0/24", "10.0.0.0.0/24",
                    "256.1.1.1/24", "10.0.0.1/", "10.0.0.1/0x10"):
            r.check("addip %r -> 204" % bad, c.code("brctl addip robtest %s" % bad) == "204",
                    c.send("brctl addip robtest %s" % bad))

        # --- IPv6 is rejected (module is IPv4-only) ---
        r.check("addip IPv6 -> 204",
                c.code("brctl addip robtest 2001:db8::1/64") == "204")

        # --- overlong CIDR rejected, not truncated (parse_cidr length check) ---
        r.check("addip overlong -> 204",
                c.code("brctl addip robtest %s/24" % ("9" * 80)) == "204")

        # --- bad vlan protocol ---
        r.check("setvlanproto out-of-set -> 204",
                c.code("brctl setvlanproto robtest 0x1234") == "204")

        # --- bridge / port name edge cases ---
        # Names longer than IFNAMSIZ (15): kernel rejects the create.
        longname = "b" * 20
        r.check("overlong bridge name rejected by kernel (206)",
                c.code("brctl create %s" % longname) == "206",
                c.send("brctl create %s" % longname)[:50])

        # Non-existent port on addif -> 206/ENODEV, no crash
        r.check("addif missing port -> 206",
                c.code("brctl addif robtest nosuchport0") == "206")

        # ubtest must still respond (ubridge did not crash)
        if subprocess.run(["ip", "-o", "link", "show", "ubtest"]).returncode == 0:
            r.check("addif ubtest still works (no crash)", c.code("brctl addif robtest ubtest") == "100")
            r.check("delif ubtest", c.code("brctl delif robtest ubtest") == "100")

        c.send("brctl delete robtest")

        # --- the connection itself is still alive after all that abuse ---
        r.check("connection still alive", c.code("brctl list").startswith("100"))

        c.close()

    r.check("no residual bridges", no_residual(prefix="robtest"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
