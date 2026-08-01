"""Regression for the delay packet filter (GNS3/ubridge#114).

The old delay filter slept inline in the per-direction bridge thread
(nanosleep), so each direction serviced at most ~1000/latency pps and the link
collapsed under any heavier load (latency ballooned, then packet loss). The
fix routes delayed sends through a real delay line with a dedicated release
thread, so the recv loop never blocks and per-packet latency stays bounded.

This drives ubridge's hypervisor protocol directly. ubridge's UDP NIO is a
*connected* point-to-point tunnel: a NIO on local port L connected to remote
port R only accepts datagrams from R (and sends to R). So to feed a bridge we
send from a socket bound to the NIO's remote port, and we observe on the peer
NIO's remote port. No privileges required (high UDP ports only). Stdlib only.

Topology (all on 127.0.0.1), one bridge "B" with two NIOs:

  source_nio: L1 <--> R1      dest_nio: L2 <--> R2

  forward (inject at source, observe at dest):
    bound-R1 socket --sendto--> L1  ==> bridge[delay] ==> dest_nio --sendto--> R2 (rx)
  reverse (inject at dest, observe at source):
    bound-R2 socket --sendto--> L2  ==> bridge[delay] ==> source_nio --sendto--> R1 (rx)
"""
import os
import socket
import struct
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary as _binary,
                     bound_udp as _udp_bound, send_burst as _send_burst,
                     recv_count as _recv_count, one_way as _one_way)


def _build_bridge(c, name, delay_ms=None, jitter_ms=None, base=13060):
    """Create a started bridge with two connected UDP NIOs and an optional
    delay filter. Returns (L1, R1, L2, R2)."""
    if delay_ms is not None:
        spec = "delay %d" % delay_ms if jitter_ms is None else "delay %d %d" % (delay_ms, jitter_ms)
        filters = [spec]
    else:
        filters = None
    from helpers import build_bridge
    return build_bridge(c, name, base, filters)


def main():
    r = Results()

    with Ubridge(port=13099, binary=_binary()) as ub:
        c = ub.connect()
        try:
            # ---- 1. single-packet one-way latency ~= configured delay ----
            l1, r1, l2, r2 = _build_bridge(c, "d1", delay_ms=100)
            tx = _udp_bound(r1)          # inject forward: source addr = R1
            rx = _udp_bound(r2)          # observe forward out at R2
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("fwd one-packet ~delay (100ms)",
                    ow is not None and 0.060 < ow < 0.450,
                    "%.0f ms" % (ow * 1000) if ow else "lost")

            # ---- 2. burst drains in bounded time (the #114 regression) ----
            # 30 pkts at 100ms: serial-sleep bug ~ 3.0s; delay-line fix ~ 0.12s.
            n = 30
            t0 = _send_burst(tx, (HOST, l1), n)
            count, t_last = _recv_count(rx, n, timeout=4.0)
            drain = (t_last - t0) if t_last else float("inf")
            r.check("burst: no loss under load", count == n, "%d/%d" % (count, n))
            r.check("burst: latency stays bounded (drain < 1.2s)",
                    drain < 1.2, "drain=%.0fms" % (drain * 1000))
            tx.close()
            rx.close()

            # ---- 3. reverse direction is bounded too (each dir has its line) ----
            tx = _udp_bound(r2)          # inject reverse: source addr = R2
            rx = _udp_bound(r1)          # observe reverse out at R1
            t0 = _send_burst(tx, (HOST, l2), n)
            count, t_last = _recv_count(rx, n, timeout=4.0)
            drain_r = (t_last - t0) if t_last else float("inf")
            r.check("reverse burst: no loss", count == n, "%d/%d" % (count, n))
            r.check("reverse burst: bounded (drain < 1.2s)",
                    drain_r < 1.2, "drain=%.0fms" % (drain_r * 1000))
            tx.close()
            rx.close()

            assert c.code("bridge stop d1") == "100"
            assert c.code("bridge delete d1") == "100"

            # ---- 4. jitter is Gaussian, centred on the delay ----
            # With jitter the per-packet delay is N(latency, jitter^2), so check
            # the sample mean and spread rather than each sample being in a fixed
            # band (a normal distribution legitimately throws low-tail samples).
            l1, r1, l2, r2 = _build_bridge(c, "d2", delay_ms=50, jitter_ms=30, base=13070)
            tx = _udp_bound(r1)
            rx = _udp_bound(r2)
            samples = []
            for _ in range(20):
                ow = _one_way(tx, (HOST, l1), rx)
                if ow is not None:
                    samples.append(ow * 1000.0)   # ms
            mean = sum(samples) / len(samples) if samples else -1.0
            spread = (max(samples) - min(samples)) if samples else -1.0
            r.check("jitter: mean ~50ms (Gaussian)", len(samples) >= 15 and 30 < mean < 80,
                    "mean=%.0fms n=%d" % (mean, len(samples)))
            r.check("jitter: spread present (>15ms)", spread > 15,
                    "spread=%.0fms" % spread)
            r.check("jitter: samples bounded (<200ms)",
                    all(s < 200 for s in samples), "max=%.0fms" % (max(samples) if samples else -1))
            tx.close()
            rx.close()
            assert c.code("bridge stop d2") == "100"
            assert c.code("bridge delete d2") == "100"

            # ---- 5. no delay filter: forwarding still fast (sanity) ----
            l1, r1, l2, r2 = _build_bridge(c, "d3", base=13080)
            tx = _udp_bound(r1)
            rx = _udp_bound(r2)
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("no-filter one-way < 50ms",
                    ow is not None and ow < 0.050,
                    "%.0f ms" % (ow * 1000) if ow else "lost")
            tx.close()
            rx.close()
            assert c.code("bridge stop d3") == "100"
            assert c.code("bridge delete d3") == "100"

            # ---- 6. stats reflect the traffic ----
            l1, r1, l2, r2 = _build_bridge(c, "d4", delay_ms=20, base=13090)
            tx = _udp_bound(r1)
            rx = _udp_bound(r2)
            _send_burst(tx, (HOST, l1), 5)
            _recv_count(rx, 5, timeout=2.0)
            stats = c.send("bridge get_stats d4")
            r.check("get_stats shows traffic after burst",
                    "IN: 5 packets" in stats or "IN:      5" in stats,
                    stats.replace("\r", " | ").strip()[:90])
            tx.close()
            rx.close()
            assert c.code("bridge stop d4") == "100"
            assert c.code("bridge delete d4") == "100"

            # ---- 7. runtime filter management (GNS3 starts, then applies) ----
            # gns3-server does `bridge start` THEN `_ubridge_apply_filters`, and
            # re-applies on link update — so a delay filter added/changed/removed
            # on a RUNNING bridge must take effect immediately (the old one-shot
            # read at start left it silently inert; the regression behind
            # "configured 100ms but no effect").
            l1, r1, l2, r2 = (13110, 13111, 13112, 13113)
            assert c.code("bridge create d6") == "100"
            assert c.code("bridge add_nio_udp d6 %d %s %d" % (l1, HOST, r1)) == "100"
            assert c.code("bridge add_nio_udp d6 %d %s %d" % (l2, HOST, r2)) == "100"
            assert c.code("bridge start d6") == "100"
            time.sleep(0.2)
            tx = _udp_bound(r1)
            rx = _udp_bound(r2)
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("runtime: no filter -> ~0ms", ow is not None and ow < 0.050,
                    "%.0f ms" % (ow * 1000) if ow else "lost")
            r.check("runtime: add delay 80 after start -> 100",
                    c.code("bridge add_packet_filter d6 d1 delay 80") == "100")
            time.sleep(0.2)
            # prime the lazy delay-line creation, then measure (avoids measuring
            # the very first packet that races the filter-becoming-visible)
            _send_burst(tx, (HOST, l1), 2)
            _recv_count(rx, 2, timeout=1.0)
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("runtime: delay 80 takes effect",
                    ow is not None and 0.050 < ow < 0.250,
                    "%.0f ms" % (ow * 1000) if ow else "lost")
            # change params: reset + re-add at 150
            assert c.code("bridge reset_packet_filters d6") == "100"
            assert c.code("bridge add_packet_filter d6 d1 delay 150") == "100"
            time.sleep(0.2)
            _send_burst(tx, (HOST, l1), 2)
            _recv_count(rx, 2, timeout=1.0)
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("runtime: change to delay 150 takes effect",
                    ow is not None and 0.110 < ow < 0.350,
                    "%.0f ms" % (ow * 1000) if ow else "lost")
            # remove
            assert c.code("bridge reset_packet_filters d6") == "100"
            time.sleep(0.2)
            ow = _one_way(tx, (HOST, l1), rx)
            r.check("runtime: remove filter -> back to ~0ms",
                    ow is not None and ow < 0.050,
                    "%.0f ms" % (ow * 1000) if ow else "lost")
            tx.close()
            rx.close()
            assert c.code("bridge stop d6") == "100"
            assert c.code("bridge delete d6") == "100"

            # ---- 8. composition: delay + packet_loss (filters combine) ----
            # Only delay was special-cased (moved to the delay line); loss and
            # corrupt stay inline. Dropped packets never enter the delay line,
            # survivors are delayed -- so ~50% delivered, each by ~delay.
            l1, r1, l2, r2 = (13120, 13121, 13122, 13123)
            assert c.code("bridge create d7") == "100"
            assert c.code("bridge add_nio_udp d7 %d %s %d" % (l1, HOST, r1)) == "100"
            assert c.code("bridge add_nio_udp d7 %d %s %d" % (l2, HOST, r2)) == "100"
            assert c.code("bridge add_packet_filter d7 f0 delay 60") == "100"
            assert c.code("bridge add_packet_filter d7 f1 packet_loss 50") == "100"
            assert c.code("bridge start d7") == "100"
            time.sleep(0.2)
            tx = _udp_bound(r1)
            rx = _udp_bound(r2)
            t0 = _send_burst(tx, (HOST, l1), 200)
            count, t_last = _recv_count(rx, 200, timeout=3.0)
            drain = (t_last - t0) if t_last else float("inf")
            r.check("combo delay+loss: ~50% delivered", 60 <= count <= 140, "%d/200" % count)
            r.check("combo delay+loss: survivors delayed ~60ms",
                    0.030 < drain < 0.200, "drain=%.0fms" % (drain * 1000))
            tx.close()
            rx.close()
            assert c.code("bridge stop d7") == "100"
            assert c.code("bridge delete d7") == "100"
        finally:
            c.close()

    # ---- 7. queue limit: overload is tail-dropped, delivery is bounded ----
    # A separate session with a tiny limit (UBRIDGE_DELAY_LIMIT=20) so the
    # user-space drop path is hit deterministically. Every delivered packet
    # transits the queue, so delivery is capped at the limit; without the cap
    # an offered burst is buffered without bound (the memory side of #114).
    os.environ["UBRIDGE_DELAY_LIMIT"] = "20"
    try:
        with Ubridge(port=13098, binary=_binary()) as ub:
            c = ub.connect()
            try:
                l1, r1, l2, r2 = _build_bridge(c, "d5", delay_ms=100, base=13100)
                tx = _udp_bound(r1)
                rx = _udp_bound(r2)
                t0 = _send_burst(tx, (HOST, l1), 200)        # 200 >> limit(20)
                count, t_last = _recv_count(rx, 200, timeout=3.0)
                drain = (t_last - t0) if t_last else float("inf")
                r.check("limit: delivery capped at <=20",
                        0 < count <= 20, "%d/200 delivered" % count)
                r.check("limit: latency still bounded (drain < 1.5s)",
                        drain < 1.5, "drain=%.0fms" % (drain * 1000))
                tx.close()
                rx.close()
                assert c.code("bridge stop d5") == "100"
                assert c.code("bridge delete d5") == "100"
            finally:
                c.close()
    finally:
        os.environ.pop("UBRIDGE_DELAY_LIMIT", None)

    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
