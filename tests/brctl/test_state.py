"""State-transition tests: how operations interact with existing kernel state.

Covers: enslave a port twice, re-add the same IP, delete a bridge that still
has ports, operations on UP vs DOWN bridges, and idempotency.
"""
import subprocess

from common import Ubridge, Results, no_residual


def ubtest_present():
    return subprocess.run(["ip", "-o", "link", "show", "ubtest"]).returncode == 0


def main():
    r = Results()
    with Ubridge(port=13005) as ub:
        c = ub.connect()
        c.send("brctl create sttest")

        # --- addif twice (second is a no-op-ish; kernel returns success/EBUSY) ---
        if ubtest_present():
            r.check("first addif -> 100", c.code("brctl addif sttest ubtest") == "100")
            second = c.code("brctl addif sttest ubtest")
            # kernel reports EBUSY (206) or success — either is acceptable, must not crash
            r.check("second addif -> 206 or 100 (no crash)", second in ("206", "100"), second)
            r.check("delif ubtest", c.code("brctl delif sttest ubtest") == "100")
            # delif when no longer on the bridge -> rejected
            r.check("delif again -> 207", c.code("brctl delif sttest ubtest") == "207")

        # --- addip twice (replace semantics) ---
        r.check("first addip -> 100", c.code("brctl addip sttest 10.20.0.1/24") == "100")
        # NLM_F_REPLACE adds a secondary address rather than replacing
        # when the new IP differs; verify both exist via `ip addr show`.
        r.check("second addip -> 100", c.code("brctl addip sttest 10.20.0.2/24") == "100")
        import subprocess as sp
        addr_out = sp.run(["ip", "-o", "addr", "show", "sttest"], capture_output=True, text=True).stdout
        r.check("second IP visible via ip addr", "10.20.0.2/24" in addr_out, addr_out[:80])

        # --- delete a bridge that still has a port (kernel auto-releases the port) ---
        if ubtest_present():
            c.send("brctl addif sttest ubtest")
            # ubtest is now enslaved; deleting the bridge should still succeed
            # (the kernel detaches all ports).
            r.check("delete bridge with port attached -> 100",
                    c.code("brctl delete sttest") == "100")
            # ubtest should no longer have a master
            link = subprocess.run(["ip", "-o", "link", "show", "ubtest"],
                                  capture_output=True, text=True).stdout
            r.check("ubtest released after bridge delete", "master" not in link, link[:60])
        else:
            c.send("brctl delete sttest")

        # --- operations on a DOWN (no IP) bridge vs UP bridge ---
        c.send("brctl create updown")
        r.check("stp on DOWN bridge -> 100", c.code("brctl stp updown on") == "100")
        c.send("brctl setup updown2 10.30.0.1/24")  # this one is UP
        r.check("stp on UP bridge -> 100", c.code("brctl stp updown2 on") == "100")
        c.send("brctl delete updown")
        c.send("brctl delete updown2")

        c.close()

    r.check("no residual bridges", no_residual(prefix="sttest") and no_residual(prefix="updown"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
