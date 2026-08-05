"""Regression for the `frequency_drop` packet filter (deterministic 1-in-N drop).

frequency_drop N drops exactly every Nth packet (a counter increments per
packet; on reaching N it resets and drops):

  N > 0  : drop 1 of every N  (positions N, 2N, 3N, ...)
  N == 0 : pass all           (sentinel for "off")
  N == -1: drop all           (sentinel for "blackhole")

It is fully deterministic (no RNG), so delivered counts are exact. We feed a
2-NIO UDP bridge and count what exits the peer NIO. Pure user-space; no
CAP_NET_ADMIN, no sudo.

Topology (all 127.0.0.1), bridge B with two NIOs:
  source_nio L1<->R1   dest_nio L2<->R2
  bound-R1 socket --sendto L1--> bridge[filter] --> dest_nio --sendto R2 (rx)
"""
from helpers import (Ubridge, Results, HOST, ubridge_binary,
                     bound_udp, send_burst, recv_count, build_bridge)

PORT = 13190


def _delivered(c, name, base, spec, n):
    """Bridge with one filter, send n, return how many exit the peer NIO."""
    l1, r1, l2, r2 = build_bridge(c, name, base, filters=[spec])
    tx, rx = bound_udp(r1), bound_udp(r2)
    send_burst(tx, (HOST, l1), n)
    got = recv_count(rx, n, timeout=2.0)[0]
    tx.close()
    rx.close()
    return got


def main():
    r = Results()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # N=3 on 9 pkts -> drop positions 3,6,9 -> exactly 6 delivered
            got = _delivered(c, "fd3", 13200, "frequency_drop 3", 9)
            r.check("freq 3 drops every 3rd (9->6)", got == 6, "%d/9" % got)

            # N=1 -> drop every packet
            got = _delivered(c, "fd1", 13210, "frequency_drop 1", 5)
            r.check("freq 1 drops all (5->0)", got == 0, "%d/5" % got)

            # N=0 -> pass all
            got = _delivered(c, "fd0", 13220, "frequency_drop 0", 5)
            r.check("freq 0 passes all (5->5)", got == 5, "%d/5" % got)

            # N=-1 -> blackhole
            got = _delivered(c, "fdb", 13230, "frequency_drop -1", 5)
            r.check("freq -1 blackhole (5->0)", got == 0, "%d/5" % got)

            # determinism: two identical runs deliver the same count
            counts = [
                _delivered(c, "fdd%d" % i, base, "frequency_drop 4", 12)
                for i, base in enumerate((13240, 13250))
            ]
            r.check("deterministic (12->9 twice)", counts == [9, 9], str(counts))

            # error: type present, value missing -> setup argc!=1 -> 206
            # (needs an existing bridge; create one without starting it so no
            #  traffic ever hits the half-initialised failed filter)
            assert c.code("bridge create fde") == "100"
            r.check("missing value rejected (206)",
                    c.code("bridge add_packet_filter fde f frequency_drop") == "206")
            assert c.code("bridge delete fde") == "100"
        finally:
            c.close()
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
