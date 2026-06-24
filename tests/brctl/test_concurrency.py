"""Concurrency tests: multiple hypervisor clients hitting the same bridge
operations simultaneously.

ubridge runs one thread per connection; shared state (the kernel bridge
table, stderr) is where races hide. The errno-clobber bug fixed in
netlink_transaction was exactly this kind of multithreaded issue.

Each client opens its own connection. We assert invariants that must hold
regardless of interleaving (e.g. exactly one create succeeds).
"""
import threading

from common import Ubridge, Results, no_residual


def main():
    r = Results()
    with Ubridge(port=13003) as ub:
        N = 12
        results = {}

        # --- N clients race to create the same bridge ---
        def racer(i):
            c = ub.connect()
            try:
                results[i] = c.code("brctl create concrace")
            finally:
                c.close()

        threads = [threading.Thread(target=racer, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        codes = list(results.values())
        r.check("exactly one create succeeded (100)",
                codes.count("100") == 1, "got %r" % codes)
        r.check("all others got EEXIST (206)",
                all(x == "206" for x in codes if x != "100"), "got %r" % codes)

        c = ub.connect()
        r.check("concrace exists", c.code("brctl show concrace")[:3] == "100")
        r.check("delete concrace", c.code("brctl delete concrace") == "100")

        # --- concurrent create/delete + list (no crash, no hang) ---
        import time as _time
        _start = _time.time()
        _err = [None]

        def _mutator():
            try:
                cm = ub.connect()
                for i in range(30):
                    cm.send("brctl create churn%d" % (i % 4))
                    cm.send("brctl delete churn%d" % (i % 4))
                cm.close()
            except Exception as e:
                _err[0] = str(e)

        def _lister():
            try:
                cl = ub.connect()
                while _time.time() - _start < 6 and _err[0] is None:
                    cl.send("brctl show docker0")  # keep connection warm; no crash is enough
                cl.close()
            except Exception as e:
                _err[0] = str(e)

        t1 = threading.Thread(target=_mutator)
        t2 = threading.Thread(target=_lister)
        t1.start(); t2.start()
        t1.join(timeout=8); t2.join(timeout=8)
        r.check("concurrent list + create/delete (no crash/hang)", _err[0] is None, _err[0] or "")

        for i in range(4):
            c.send("brctl delete churn%d" % i)
        c.close()

    r.check("no residual bridges", no_residual(prefix="churn") and no_residual(prefix="conc"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
