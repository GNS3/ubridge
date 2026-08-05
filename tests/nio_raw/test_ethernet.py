"""Regression for the `nio_ethernet` backend (libpcap L2 attach).

Bridges a veth end (vnio0, via nio_ethernet) to a UDP NIO and checks raw L2
frames round-trip intact in both directions, plus the command error paths.
Run under sudo (or `unshare -Urn`) — pcap promisc + veth need CAP_NET_ADMIN.

Topology (bridge "nre", 2 NIOs):
  nio_ethernet vnio0  <-->  nio_udp lp<-->rp

  veth->NIO:  raw(vnio1).send(frame) -> vnio0 -> bridge -> UDP -> bound rp
  NIO->veth:  bound rp.sendto(frame, lp) -> bridge -> pcap_sendpacket vnio0 -> vnio1
"""
import socket
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, veth_up, veth_del,
                     raw_sock, eth_frame, free_udp_port, drain, recv_match)

PORT = 13180


def main():
    r = Results()
    veth_up("vnio0", "vnio1")
    try:
        with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
            c = ub.connect()
            try:
                lp, rp = free_udp_port(), free_udp_port()
                assert c.code("bridge create nre") == "100"
                assert c.code("bridge add_nio_ethernet nre vnio0") == "100"
                assert c.code("bridge add_nio_udp nre %d %s %d" % (lp, HOST, rp)) == "100"
                assert c.code("bridge start nre") == "100"
                time.sleep(0.3)

                frame = eth_frame()

                # ---- veth -> NIO: inject on vnio1, observe at UDP rp ----
                raw = raw_sock("vnio1")
                rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.bind((HOST, rp)); rx.settimeout(2.0)
                raw.send(frame); drain(rx)          # prime
                raw.send(frame)
                got = recv_match(rx, frame)
                r.check("veth->NIO relay intact", got == frame,
                        "len %d vs %d" % (len(got) if got else 0, len(frame)))
                raw.close(); rx.close()

                # ---- NIO -> veth: inject UDP (src rp -> lp), sniff vnio1 ----
                tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tx.bind((HOST, rp))
                raw = raw_sock("vnio1")
                tx.sendto(frame, (HOST, lp)); drain(raw)   # prime
                tx.sendto(frame, (HOST, lp))
                got = recv_match(raw, frame)
                r.check("NIO->veth relay intact", got == frame,
                        "len %d vs %d" % (len(got) if got else 0, len(frame)))
                tx.close(); raw.close()

                c.send("bridge stop nre"); c.send("bridge delete nre")

                # ---- error paths ----
                assert c.code("bridge create nre_e") == "100"
                r.check("ethernet missing bridge -> 214",
                        c.code("bridge add_nio_ethernet nope vnio0") == "214")
                r.check("ethernet bad iface -> 206",
                        c.code("bridge add_nio_ethernet nre_e dev_does_not_exist") == "206")
                assert c.code("bridge delete nre_e") == "100"
            finally:
                c.close()
    finally:
        veth_del("vnio0")
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
