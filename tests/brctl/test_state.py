"""State-transition tests: how operations interact with existing kernel state.

Covers: enslave a port twice, re-add the same IP, refuse to delete a bridge
that still has ports, operations on UP vs DOWN bridges, and idempotency.
"""
import os
import subprocess

from common import Ubridge, Results, no_residual


def ubtest_present():
    return subprocess.run(["ip", "-o", "link", "show", "ubtest"]).returncode == 0


def ports_of(bridge):
    """Sorted names of the ports currently enslaved to `bridge`."""
    out = subprocess.run(["ip", "-o", "link", "show", "master", bridge],
                         capture_output=True, text=True).stdout
    return sorted(line.split(":")[1].strip().split("@")[0]
                  for line in out.splitlines() if line.strip())


def scratch_port(name):
    """Create a throwaway dummy port; None when we lack the privileges.

    Unlike `ubtest` this is not a shared fixture — it is removed again by
    release_scratch() so the suite leaves nothing behind.
    """
    if subprocess.run(["ip", "-o", "link", "show", name],
                      capture_output=True).returncode == 0:
        return name
    if os.geteuid() != 0:
        return None
    if subprocess.run(["ip", "link", "add", name, "type", "dummy"],
                      capture_output=True).returncode != 0:
        return None
    return name


def release_scratch(name):
    subprocess.run(["ip", "link", "delete", name], capture_output=True)


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

        # --- delete a bridge that still has a port: refused, bridge survives ---
        # RTM_DELLINK does not refuse this by itself — the kernel's
        # br_dev_delete() detaches every port and unregisters the bridge, which
        # silently strands a peer that still has a port enslaved. br_delbr
        # refuses with EBUSY so the bridge outlives whoever released a port
        # first, and the peer re-attaches to the bridge it still finds.
        if ubtest_present():
            c.send("brctl addif sttest ubtest")
            r.check("delete bridge with port attached -> 207",
                    c.code("brctl delete sttest") == "207")
            # the port is still enslaved: the refused delete detached nothing
            link = subprocess.run(["ip", "-o", "link", "show", "ubtest"],
                                  capture_output=True, text=True).stdout
            r.check("ubtest still enslaved after refused delete",
                    "master sttest" in link, link[:60])
            # last one out: releasing the port lets the delete through
            r.check("delif ubtest", c.code("brctl delif sttest ubtest") == "100")
            r.check("delete once empty -> 100", c.code("brctl delete sttest") == "100")
        else:
            c.send("brctl delete sttest")

        # --- the two-sided case: a peer holds the bridge open ---
        # Models the single-sided node stop/start that used to orphan the
        # peer's port: one side releases its port (its veth disappears on
        # stop) and its delete is refused, so the bridge survives carrying the
        # peer's port; on restart that side re-attaches to the bridge it finds
        # instead of building a new one next to an orphaned peer.
        peer = scratch_port("ubtest2")
        try:
            if ubtest_present() and peer:
                c.send("brctl create sttest2")
                c.send("brctl addif sttest2 ubtest")    # the peer that stays
                c.send("brctl addif sttest2 ubtest2")   # the side that restarts
                c.send("brctl delif sttest2 ubtest2")   # ... it stops
                r.check("peer-only bridge refuses delete -> 207",
                        c.code("brctl delete sttest2") == "207")
                r.check("peer port still on the surviving bridge",
                        ports_of("sttest2") == ["ubtest"], str(ports_of("sttest2")))
                c.send("brctl addif sttest2 ubtest2")   # ... and starts again
                r.check("reunited on the surviving bridge",
                        ports_of("sttest2") == ["ubtest", "ubtest2"],
                        str(ports_of("sttest2")))
                c.send("brctl delif sttest2 ubtest")
                c.send("brctl delif sttest2 ubtest2")
                r.check("delete once both released -> 100",
                        c.code("brctl delete sttest2") == "100")
            else:
                print("  [NOTE] no second port available (root?) — reunion checks skipped")
        finally:
            if peer:
                release_scratch(peer)

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
