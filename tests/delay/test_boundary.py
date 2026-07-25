"""Boundary tests for the delay filter: minimum/edge configs, packet sizes,
and teardown while packets are still queued.

No privileges required (UDP only). Stdlib only.
"""
import os
import socket
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, bound_udp,
                     send_burst, recv_count, one_way, build_bridge)

PORT = 14400


def main():
    r = Results()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # ---- 1. minimum latency (1ms; delay_setup rejects <= 0) ----
            l1, r1, l2, r2 = build_bridge(c, "b1", 14410, ["delay 1"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            ow = one_way(tx, (HOST, l1), rx)
            r.check("boundary: min latency 1ms works (< 50ms)",
                    ow is not None and ow < 0.050, "%.0fms" % ((ow or -1) * 1000))
            tx.close()
            rx.close()
            assert c.code("bridge stop b1") == "100"
            assert c.code("bridge delete b1") == "100"

            # ---- 2. jitter > latency (negatives clamp to 0, no crash) ----
            l1, r1, l2, r2 = build_bridge(c, "b2", 14420, ["delay 50 100"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            send_burst(tx, (HOST, l1), 2)
            recv_count(rx, 2, timeout=2.0)
            samples = [s * 1000 for s in (one_way(tx, (HOST, l1), rx) for _ in range(12)) if s]
            # no crash / all clamped into range; and jitter does throw positive
            # samples too (not every packet clamps to 0).
            r.check("boundary: jitter>latency no crash, all in [0,600]ms",
                    len(samples) >= 8 and all(0 <= s < 600 for s in samples),
                    "n=%d max=%.0fms" % (len(samples), max(samples) if samples else -1))
            r.check("boundary: jitter>latency shows positive delays",
                    max(samples) > 10 if samples else False,
                    "max=%.0fms" % (max(samples) if samples else -1))
            tx.close()
            rx.close()
            assert c.code("bridge stop b2") == "100"
            assert c.code("bridge delete b2") == "100"

            # ---- 3. packet-size boundaries through delay (1 byte and ~60 KB) ----
            l1, r1, l2, r2 = build_bridge(c, "b3", 14430, ["delay 30"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            rx.settimeout(3.0)
            tx.sendto(b"z", (HOST, l1))
            got_tiny = False
            try:
                got_tiny = (rx.recv(70000) == b"z")
            except socket.timeout:
                pass
            big = b"Q" * 60000
            tx.sendto(big, (HOST, l1))
            got_big = False
            try:
                got_big = (len(rx.recv(70000)) == 60000)
            except socket.timeout:
                pass
            r.check("boundary: 1-byte packet through delay", got_tiny)
            r.check("boundary: 60KB packet through delay", got_big)
            tx.close()
            rx.close()
            assert c.code("bridge stop b3") == "100"
            assert c.code("bridge delete b3") == "100"

            # ---- 4. stop the bridge while packets are still queued (no hang) ----
            l1, r1, l2, r2 = build_bridge(c, "b4", 14440, ["delay 2000"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            send_burst(tx, (HOST, l1), 20)   # queued, not due for 2s
            time.sleep(0.1)
            t0 = time.monotonic()
            assert c.code("bridge stop b4") == "100"   # joins release thread, frees queue
            assert c.code("bridge delete b4") == "100"
            dt = (time.monotonic() - t0) * 1000
            r.check("boundary: stop with queued pkts < 1s (no hang)",
                    dt < 1000.0, "stop+delete=%.0fms" % dt)
            tx.close()
            rx.close()
            # ubridge is still responsive after cancel-with-queued-packets
            l1, r1, l2, r2 = build_bridge(c, "b4b", 14450, ["delay 10"])
            tx = bound_udp(r1)
            rx = bound_udp(r2)
            ow = one_way(tx, (HOST, l1), rx)
            r.check("boundary: responsive after cancel-with-queue",
                    ow is not None and ow < 0.100, "%.0fms" % ((ow or -1) * 1000))
            tx.close()
            rx.close()
            assert c.code("bridge stop b4b") == "100"
            assert c.code("bridge delete b4b") == "100"
        finally:
            c.close()

    # ---- 5. queue-limit boundary (separate session, UBRIDGE_DELAY_LIMIT=10) ----
    os.environ["UBRIDGE_DELAY_LIMIT"] = "10"
    try:
        with Ubridge(port=14460, binary=ubridge_binary()) as ub:
            c = ub.connect()
            try:
                l1, r1, l2, r2 = build_bridge(c, "b5", 14470, ["delay 100"])
                tx = bound_udp(r1)
                rx = bound_udp(r2)
                # exactly the limit: all delivered
                send_burst(tx, (HOST, l1), 10)
                n_at, _ = recv_count(rx, 10, timeout=2.0)
                # one over the limit: still 10 (1 tail-dropped)
                send_burst(tx, (HOST, l1), 11)
                n_over, _ = recv_count(rx, 11, timeout=0.8)
                r.check("boundary: limit==delivered (10/10)", n_at == 10, "%d/10" % n_at)
                r.check("boundary: limit caps delivery at 10 (11 sent)",
                        n_over == 10, "%d/11" % n_over)
                tx.close()
                rx.close()
                assert c.code("bridge stop b5") == "100"
                assert c.code("bridge delete b5") == "100"
            finally:
                c.close()
    finally:
        os.environ.pop("UBRIDGE_DELAY_LIMIT", None)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
