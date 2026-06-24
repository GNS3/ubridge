"""Stress test: fd stability under repeated create/delete.

The brctl list command was removed (it couldn't reliably dump thousands
of bridges).  This suite now focuses on fd/leak stability: many
create/delete cycles, verifying the process descriptor count stays flat
and the process stays responsive.
"""
import subprocess

from common import Ubridge, Results, no_residual

CYCLES = 500


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

        # --- fd-leak check: many create/delete cycles ---
        fd_before = count_fds(ub.proc.pid)
        for i in range(CYCLES):
            c.send("brctl create fdleak")
            c.send("brctl delete fdleak")
        fd_after = count_fds(ub.proc.pid)
        r.check("fd count stable over %d cycles (before=%d after=%d)" % (CYCLES, fd_before, fd_after),
                fd_after >= 0 and fd_after <= fd_before + 2,
                "fds %d -> %d" % (fd_before, fd_after))

        r.check("still responsive after stress", c.code("brctl show docker0").startswith("100"))
        c.close()

    r.check("no residual bridges", no_residual(prefix="fdleak"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
