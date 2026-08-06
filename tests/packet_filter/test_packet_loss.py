"""Regression for the `packet_loss` packet filter (random %-based drop).

Drops a packet when `random() % 100 <= percentage`. NOTE the off-by-one: the
comparison is <=, so percentage=0 still drops ~1% (value 0) and percentage=50
drops ~51% of packets (values 0..50). Bounds are validated: percentage must be
0..100, else setup returns -1 and the command replies 206.

Because it is random, counts are statistical: we send many packets and assert
the delivered count falls in a band that rules out "no loss" and "total loss"
while tolerating RNG variance. Pure user-space; no CAP_NET_ADMIN, no sudo.
"""
from helpers import (Ubridge, Results, HOST, ubridge_binary,
                     bound_udp, send_burst, recv_count, build_bridge)

PORT = 13191


def _delivered(c, name, base, spec, n, timeout=4.0):
    l1, r1, l2, r2 = build_bridge(c, name, base, filters=[spec])
    tx, rx = bound_udp(r1), bound_udp(r2)
    send_burst(tx, (HOST, l1), n)
    got = recv_count(rx, n, timeout=timeout)[0]
    tx.close()
    rx.close()
    return got


def main():
    r = Results()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # 100% -> all dropped (random()%100 <= 100 always)
            got = _delivered(c, "pl100", 13300, "packet_loss 100", 30)
            r.check("loss 100 drops all (30->0)", got == 0, "%d/30" % got)

            # 50% -> roughly half. 200 pkts, band [60,140] = 30%..70%: tight
            # enough to catch "no loss"/"total loss", loose enough for RNG.
            got = _delivered(c, "pl50", 13310, "packet_loss 50", 200)
            r.check("loss 50 ~halves (200 in [60,140])", 60 <= got <= 140, "%d/200" % got)

            # 0% -> the <=0 quirk drops ~1%, so almost all delivered
            got = _delivered(c, "pl0", 13320, "packet_loss 0", 200)
            r.check("loss 0 ~passes all (>=190 of 200)", got >= 190, "%d/200" % got)

            # monotonic: higher loss -> fewer delivered (25% vs 75%)
            g25 = _delivered(c, "pl25", 13330, "packet_loss 25", 200)
            g75 = _delivered(c, "pl75", 13340, "packet_loss 75", 200)
            r.check("loss monotonic (25%% delivers >= 75%%)", g25 > g75, "%d vs %d" % (g25, g75))

            # error: out-of-range percentage -> 206 (bridge must exist)
            assert c.code("bridge create ple") == "100"
            r.check("loss 101 rejected (206)",
                    c.code("bridge add_packet_filter ple f packet_loss 101") == "206")
            r.check("loss -1 rejected (206)",
                    c.code("bridge add_packet_filter ple f2 packet_loss -1") == "206")
            assert c.code("bridge delete ple") == "100"
        finally:
            c.close()
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
