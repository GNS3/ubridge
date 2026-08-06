"""Regression for the `nio_linux_raw` backend (AF_PACKET SOCK_RAW L2 attach).

Same veth-pair topology as test_ethernet but via nio_linux_raw: raw L2 frames
round-trip intact both ways, plus the two command error paths nio_linux_raw
uniquely has (bad iface, and device name > NIO_DEV_MAXLEN=64 -> 206).

NOTE on VLAN: nio_linux_raw reconstructs an offloaded VLAN tag from
PACKET_AUXDATA (tp_vlan_tci). That path only fires when the NIC hardware-
offloads VLAN stripping; veth does not, so it can't be exercised here and is
left as a documented gap. We send a plain tagged frame only to confirm the
recvmsg+auxdata path passes non-offloaded frames through uncorrupted.

Run under sudo (or `unshare -Urn`) — AF_PACKET + veth + promisc need caps.
"""
import socket
import struct
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, veth_up, veth_del,
                     raw_sock, eth_frame, free_udp_port, drain, recv_match)

PORT = 13181

# device name >= NIO_DEV_MAXLEN(64) is rejected by create_nio_linux_raw
LONG_NAME = "x" * 64


def main():
    r = Results()
    veth_up("vnio1a", "vnio1b")
    try:
        with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
            c = ub.connect()
            try:
                lp, rp = free_udp_port(), free_udp_port()
                assert c.code("bridge create nrl") == "100"
                assert c.code("bridge add_nio_linux_raw nrl vnio1a") == "100"
                assert c.code("bridge add_nio_udp nrl %d %s %d" % (lp, HOST, rp)) == "100"
                assert c.code("bridge start nrl") == "100"
                time.sleep(0.3)

                frame = eth_frame()

                # ---- veth -> NIO ----
                raw = raw_sock("vnio1b")
                rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.bind((HOST, rp)); rx.settimeout(2.0)
                raw.send(frame); drain(rx)
                raw.send(frame)
                got = recv_match(rx, frame)
                r.check("raw veth->NIO relay intact", got == frame,
                        "len %d vs %d" % (len(got) if got else 0, len(frame)))
                raw.close(); rx.close()

                # ---- NIO -> veth ----
                tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tx.bind((HOST, rp))
                raw = raw_sock("vnio1b")
                tx.sendto(frame, (HOST, lp)); drain(raw)
                tx.sendto(frame, (HOST, lp))
                got = recv_match(raw, frame)
                r.check("raw NIO->veth relay intact", got == frame,
                        "len %d vs %d" % (len(got) if got else 0, len(frame)))
                tx.close(); raw.close()

                # ---- tagged frame passes through uncorrupted ----
                # (veth doesn't HW-offload VLAN, so this is the passthrough path,
                #  not the auxdata-reconstruction path.)
                tagged = (b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55"
                          + struct.pack("!HHH", 0x8100, 0x0064, 0x0800) + b"VL")
                tagged += b"\x00" * (60 - len(tagged))
                raw = raw_sock("vnio1b")
                rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.bind((HOST, rp)); rx.settimeout(2.0)
                raw.send(tagged); drain(rx)
                raw.send(tagged)
                got = recv_match(rx, tagged)
                r.check("tagged frame passthrough intact", got == tagged,
                        "len %d vs %d" % (len(got) if got else 0, len(tagged)))
                raw.close(); rx.close()

                c.send("bridge stop nrl"); c.send("bridge delete nrl")

                # ---- error paths ----
                assert c.code("bridge create nrl_e") == "100"
                r.check("raw missing bridge -> 214",
                        c.code("bridge add_nio_linux_raw nope vnio1a") == "214")
                r.check("raw bad iface -> 206",
                        c.code("bridge add_nio_linux_raw nrl_e dev_does_not_exist") == "206")
                r.check("raw name too long -> 206",
                        c.code("bridge add_nio_linux_raw nrl_e %s" % LONG_NAME) == "206")
                assert c.code("bridge delete nrl_e") == "100"
            finally:
                c.close()
    finally:
        veth_del("vnio1a")
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
