"""Performance test: vlan_show over a port carrying the full VID range (1-4094).

Sets up all 4094 VLANs on one port with a single bulk range add, then exercises
`vlan_show` end to end — stressing the RTM_GETLINK dump (the 4094 VLAN_INFO
entries span several datagrams), the per-VID parse, the multi-line reply, and
the client recv loop — and checks it completes correctly and quickly.

Run as root (needs the ubtest dummy + cap_net_admin).
"""
import time
from common import Ubridge, Results, no_residual, ensure_ubtest

PORT = 13008
BR = "regperf0"
N = 4094  # full 802.1Q VID range (1-4094; 4095 is reserved)


def main():
    r = Results()
    with Ubridge(port=PORT) as ub:
        c = ub.connect()

        has_port = ensure_ubtest()
        if not has_port:
            print("  [NOTE] no ubtest dummy and not root — perf test skipped")

        r.check("create %s" % BR, c.code("brctl create %s" % BR) == "100")
        r.check("vlanfiltering on %s" % BR,
                c.code("brctl vlanfiltering %s on" % BR) == "100")

        if has_port:
            r.check("addif %s ubtest" % BR,
                    c.code("brctl addif %s ubtest" % BR) == "100")

            # Drop the default PVID 1, then add the full range 1-4094 in one
            # bulk command (RANGE_BEGIN/RANGE_END) so the port carries exactly N.
            c.send("brctl vlan_del %s ubtest 1" % BR)
            t0 = time.time()
            add_rc = c.code("brctl vlan_add %s ubtest 1 vid %d" % (BR, N))
            t_add = time.time() - t0
            r.check("range-add 1-%d -> 100 (%.2fs)" % (N, t_add), add_rc == "100")

            # --- the performance target: list all N VLANs back ---
            t0 = time.time()
            show = c.send("brctl vlan_show %s ubtest" % BR)
            t_show = time.time() - t0
            lines = show.splitlines()
            toks = show.split()

            r.check("vlan_show final code 100", lines[-1].startswith("100"))
            r.check("vlan_show reports %d entries" % N,
                    ("%d" % N) in lines[-1], lines[-1])
            r.check("vlan_show completed under 10s (%.2fs)" % t_show, t_show < 10.0)
            r.check("vlan_show lists endpoints + mid (1, 2048, %d)" % N,
                    all(str(v) in toks for v in (1, 2048, N)))
            print("  [perf] add=%.2fs  vlan_show=%0.2fs  (%d VLANs)" % (t_add, t_show, N))

        r.check("delete %s" % BR, c.code("brctl delete %s" % BR) == "100")
        c.close()

    r.check("no residual bridges", no_residual(prefix="regperf"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
