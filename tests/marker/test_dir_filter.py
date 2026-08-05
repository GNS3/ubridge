"""Regression for the `mark` filter's directional keyword (dir tx|rx).

Guards against a sentinel-value collision: dir_match was zero-initialised by
memset with 0 meaning "both directions", but PKT_DIR_RX is *also* 0 — so
`dir rx` stored dir_match=0 and the handler's fast-path (`dir_match == 0`)
treated it as "both", letting tx-side traffic through. The fix decouples the
match state (MARK_DIR_*) from the runtime direction (PKT_DIR_*); this test
injects from each side of a UDP-NIO bridge and asserts the right one fires.

Direction mapping (see src/ubridge.c bridge_nios):
  NIO-A = source_nio      -> injecting into it is device-side ingress (tx)
  NIO-B = destination_nio -> injecting into it is link-side ingress  (rx)
Pure user-space (UDP + libpcap cBPF) — no CAP_NET_ADMIN, no sudo.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13070
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip_frame():
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()      # NIO listen ports (ubridge binds)
    ra, rb = _free_udp(), _free_udp()      # NIO remote ports (injectors bind)

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(1.0); ms.bind(("127.0.0.1", marker_port))
    # nio_udp connect()s to its remote, so it only accepts packets whose source
    # is that remote — bind each injector to the matching NIO's remote port.
    inj_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj_a.bind(("127.0.0.1", ra))   # => tx
    inj_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj_b.bind(("127.0.0.1", rb))   # => rx

    frame = _ip_frame()

    def drain():
        n = 0
        while True:
            try:
                ms.recvfrom(4096); n += 1
            except socket.timeout:
                return n

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node dirtest")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A = source_nio
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B = destination_nio
                c.send("bridge start br0")
                time.sleep(0.2)

                def trial(fdir):
                    """Add a mark filter with the given dir, inject from both
                    sides, return (tx_hits, rx_hits)."""
                    r.check("add mark dir %s" % fdir,
                            c.send("bridge add_packet_filter br0 f mark ip dir %s" % fdir).startswith("100-"))
                    drain()  # settle
                    inj_a.sendto(frame, ("127.0.0.1", la)); time.sleep(0.3)
                    tx_hits = drain()
                    inj_b.sendto(frame, ("127.0.0.1", lb)); time.sleep(0.3)
                    rx_hits = drain()
                    c.send("bridge delete_packet_filter br0 f")
                    return tx_hits, rx_hits

                tx_only = trial("tx")
                r.check("dir tx fires only on tx (1,0)", tx_only == (1, 0),
                        "got %s" % (tx_only,))

                rx_only = trial("rx")
                r.check("dir rx fires only on rx (0,1)", rx_only == (0, 1),
                        "got %s — collision regression?" % (rx_only,))
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, inj_a, inj_b):
            s.close()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
