"""Performance regression for the delay filter (GNS3/ubridge#114).

The #114 failure mode was structural collapse under load: the old inline
nanosleep serialized each direction to ~1000/latency pps, so a burst took
~N*latency to drain and latency ballooned without bound. These check the delay
line sustains throughput and keeps latency bounded at scale, that delay is
accurate across magnitudes, and that the no-filter fast path isn't regressed.

No privileges required (UDP only). Stdlib only.
"""
from helpers import (Ubridge, Results, HOST, ubridge_binary, bound_udp,
                     send_burst, recv_count, one_way, build_bridge)

PORT = 14200


def main():
    r = Results()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # ---- 1. large burst drains in bounded time (anti-#114 at scale) ----
            # 400 pkts @50ms: the serial-sleep bug drained in ~400*50ms = 20s;
            # the delay line drains in ~50ms (recv never blocks).
            l1, r1, l2, r2 = build_bridge(c, "p1", 14210, ["delay 50"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            t0 = send_burst(tx, (HOST, l1), 400)
            count, t_last = recv_count(rx, 400, timeout=5.0)
            drain = (t_last - t0) if t_last else 999.0
            r.check("perf: 400-pkt burst @50ms drains < 2s",
                    drain < 2.0, "drain=%.0fms" % (drain * 1000))
            r.check("perf: burst delivered with little loss", count >= 380, "%d/400" % count)
            tx.close()
            rx.close()
            assert c.code("bridge stop p1") == "100"
            assert c.code("bridge delete p1") == "100"

            # ---- 2. delay accuracy across magnitudes ----
            for k, cfg in enumerate((10, 100, 500)):
                name = "p2_%d" % cfg
                l1, r1, l2, r2 = build_bridge(c, name, 14240 + k * 10, ["delay %d" % cfg])
                tx = bound_udp(r1)
                rx = bound_udp(r2)
                send_burst(tx, (HOST, l1), 2)
                recv_count(rx, 2, timeout=2.0)  # prime the lazy delay line
                ows = sorted(o * 1000 for o in (one_way(tx, (HOST, l1), rx) for _ in range(3)) if o)
                med = ows[len(ows) // 2] if ows else -1.0
                r.check("perf: delay %dms ~= measured" % cfg,
                        0.6 * cfg < med < 1.6 * cfg, "med=%.0fms" % med)
                tx.close()
                rx.close()
                assert c.code("bridge stop %s" % name) == "100"
                assert c.code("bridge delete %s" % name) == "100"

            # ---- 3. no-delay forwarding throughput baseline (regression guard) ----
            # Sized to fit the kernel UDP receive buffer -- an instant 1000-pkt
            # burst overflows it regardless of ubridge (the delay path actually
            # drains faster, since enqueue is cheaper than inline send()).
            l1, r1, l2, r2 = build_bridge(c, "p3", 14300)
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            t0 = send_burst(tx, (HOST, l1), 100)
            count, t_last = recv_count(rx, 100, timeout=3.0)
            dt = (t_last - t0) if t_last else 999.0
            r.check("perf: no-delay forwards a burst fast (< 0.5s)",
                    count >= 90 and dt < 0.5, "%d/100 in %.0fms" % (count, dt * 1000))
            tx.close()
            rx.close()
            assert c.code("bridge stop p3") == "100"
            assert c.code("bridge delete p3") == "100"
        finally:
            c.close()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
