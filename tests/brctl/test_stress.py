"""Scale test: 7000 bridges + fd-leak check.

Sequential create/delete cycles test single-client latency (~5-10 ms per
pair through the text protocol), not meaningful stress.  Parallel stress
is covered by test_concurrency.py; lifecycle by test_basic.py.

The key test here is verifying that `list` dumps 7000 bridges correctly
(kernel message coalescing at scale).  A short fd-leak check ensures the
process doesn't grow descriptors after moderate use.
"""
import subprocess

from common import Ubridge, Results, no_residual

MANY = 7000  # bridges created for dump-coalescing verification.
             # Within default kernel max_net_devices (8192); ~14 MB slab.


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

        # --- fd-leak check ---
        fd_before = count_fds(ub.proc.pid)
        for i in range(500):
            c.send("brctl create fdleak")
            c.send("brctl delete fdleak")
        fd_after = count_fds(ub.proc.pid)
        r.check("fd count stable (before=%d after=%d)" % (fd_before, fd_after),
                fd_after >= 0 and fd_after <= fd_before + 2,
                "fds %d -> %d" % (fd_before, fd_after))

        # --- many bridges, then verify list count ---
        for i in range(MANY):
            c.send("brctl create scale%d" % i)
        list_out = c.send("brctl list")
        lines = list_out.splitlines()
        seen = sum(1 for i in range(MANY) if any("scale%d" % i in ln for ln in lines))
        r.check("list saw all %d bridges (dump coalescing)" % MANY,
                seen == MANY, "saw %d/%d" % (seen, MANY))
        for i in range(MANY):
            c.send("brctl delete scale%d" % i)

        r.check("still responsive after stress", c.code("brctl list").startswith("100"))
        c.close()

    r.check("no residual bridges",
            no_residual(prefix="scale") and no_residual(prefix="fdleak"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
