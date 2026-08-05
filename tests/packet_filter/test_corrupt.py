"""Regression for the `corrupt` packet filter (random %-based bit damage).

When `random() % 100 <= percentage`, corrupt XORs a middle slice of the packet
against a cycling 8-byte pattern:

    length = len / 4
    offset = len/2 - length/2 + 1        # bytes [offset, offset+length)

Crucially the packet is still FORWARDED — corrupt never drops, it only damages
bytes. Same <= off-by-one as packet_loss (0 still hits ~1%). Bounds 0..100 are
validated; out-of-range -> 206.

At 100% every packet is damaged, so the content checks are deterministic: the
frame arrives, differs from what was sent, the leading bytes (outside the
damage slice) are intact, and the delivered count equals the sent count. Pure
user-space; no CAP_NET_ADMIN, no sudo.
"""
import socket
import struct

from helpers import (Ubridge, Results, HOST, ubridge_binary,
                     bound_udp, send_burst, recv_count, build_bridge)

PORT = 13192

# 4B seq + 40B of 0xAA -> L = 44. corrupt slice: length = 11, offset = 18,
# i.e. bytes [18, 29). So [0,18) and [29,44) must come through untouched.
PAYLOAD = b"\xaa" * 40


def _delivered(c, name, base, spec, n, timeout=3.0):
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
            # ---- 100%: one packet, detailed content check ----
            l1, r1, l2, r2 = build_bridge(c, "co100", 13400, filters=["corrupt 100"])
            tx, rx = bound_udp(r1), bound_udp(r2)
            sent = struct.pack("!I", 0) + PAYLOAD
            tx.sendto(sent, (HOST, l1))
            rx.settimeout(3.0)
            try:
                got, _ = rx.recvfrom(2048)
                arrived = True
            except socket.timeout:
                got, arrived = b"", False
            r.check("corrupt 100 still delivered", arrived, "timeout" if not arrived else "len=%d" % len(got))
            if arrived:
                ndiff = sum(a != b for a, b in zip(got, sent))
                r.check("frame changed", got != sent, "%d/%d bytes differ" % (ndiff, len(sent)))
                r.check("length unchanged", len(got) == len(sent), "%d vs %d" % (len(got), len(sent)))
                first = next((i for i in range(min(len(got), len(sent))) if got[i] != sent[i]), -1)
                r.check("leading bytes intact", got[:18] == sent[:18], "first diff@%d" % first)
                r.check("damage slice changed", got[18:29] != sent[18:29],
                        "%d/11 slice bytes differ" % sum(a != b for a, b in zip(got[18:29], sent[18:29])))
                r.check("trailing bytes intact", got[29:] == sent[29:], "ok")
            tx.close()
            rx.close()

            # ---- corrupt never drops, at any percentage ----
            got = _delivered(c, "co100b", 13410, "corrupt 100", 10)
            r.check("corrupt 100 delivers all (10/10)", got == 10, "%d/10" % got)
            got = _delivered(c, "co50", 13420, "corrupt 50", 10)
            r.check("corrupt 50 delivers all (10/10)", got == 10, "%d/10" % got)

            # ---- error: out-of-range percentage -> 206 ----
            assert c.code("bridge create coe") == "100"
            r.check("corrupt 101 rejected (206)",
                    c.code("bridge add_packet_filter coe f corrupt 101") == "206")
            r.check("corrupt -1 rejected (206)",
                    c.code("bridge add_packet_filter coe f2 corrupt -1") == "206")
            assert c.code("bridge delete coe") == "100"
        finally:
            c.close()
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
