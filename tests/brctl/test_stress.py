"""Stress / leak test: many create/delete cycles and many bridges in `list`.

Checks that:
- the hypervisor process stays alive and responsive,
- file-descriptor usage of the ubridge process does not grow unboundedly,
- no bridges leak after the run,
- `list` reports the correct count (dump coalescing stays correct at scale).
"""
import subprocess
import time

from common import Ubridge, Results, no_residual

CYCLES = 40000    # create/delete iterations (~2-3 min)
FD_CYCLES = 10000 # fd-leak check iterations
MANY = 7000       # bridges created simultaneously for list-count check
# Note: 7000 bridges is within the default kernel max_net_devices (8192)
# and consumes ~14 MB of slab memory.  Creating 7000 bridges + one list +
# deleting 7000 bridges takes about 15 seconds.


def count_fds(pid):
    try:
        return len(subprocess.run(["ls", "/proc/%d/fd" % pid],
                                  capture_output=True, text=True).stdout.split())
    except Exception:
        return -1


def main():
    r = Results()
    with Ubridge(port=13006) as ub:
        c = ub.connect()

        # --- churn: create+delete the same name many times ---
        ok = True
        for i in range(CYCLES):
            if c.code("brctl create churn%d" % (i % 3)) != "100":
                ok = False
                if i == 0 or c.code("brctl create churn%d" % (i % 3)) != "206":
                    # only a real failure if not the expected EEXIST on a stale name
                    pass
            c.send("brctl delete churn%d" % (i % 3))
        r.check("%d create/delete cycles completed" % CYCLES, ok)

        # --- fd usage stable before/after churn ---
        # (do another batch and confirm fds don't climb)
        fds_before = count_fds(ub.proc.pid)
        for i in range(FD_CYCLES):
            c.send("brctl create fdleak")
            c.send("brctl delete fdleak")
        fds_after = count_fds(ub.proc.pid)
        r.check("fd count did not grow (before=%d after=%d)" % (fds_before, fds_after),
                fds_after >= 0 and fds_after <= fds_before + 2,
                "fds %d -> %d" % (fds_before, fds_after))

        # --- many bridges, then verify list count ---
        for i in range(MANY):
            c.send("brctl create scale%d" % i)
        list_out = c.send("brctl list")
        # count how many scaleN entries appear (each line is "NNN scaleN"[ ...])
        lines = list_out.splitlines()
        seen = sum(1 for i in range(MANY) if any("scale%d" % i in ln for ln in lines))
        r.check("list saw all %d bridges (dump coalescing)" % MANY, seen == MANY,
                "saw %d/%d" % (seen, MANY))
        for i in range(MANY):
            c.send("brctl delete scale%d" % i)

        # --- still responsive ---
        r.check("still responsive after stress", c.code("brctl list").startswith("100"))

        c.close()

    r.check("no residual bridges", no_residual(prefix="churn")
            and no_residual(prefix="scale") and no_residual(prefix="fdleak"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
