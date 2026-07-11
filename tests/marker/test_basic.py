"""Basic regression for the marker feature (mark filter + UDP signal push).

A `mark` packet filter signals matches by pushing a UDP datagram to a
configured sink (gns3server). This test stands up a UDP listener as the sink,
injects an IP frame into a UDP-NIO bridge, and asserts the signal arrives and
the frame is still relayed (passive tap). Pure user-space (UDP + libpcap cBPF)
— no CAP_NET_ADMIN needed, no sudo. Uses the in-repo ./ubridge (the installed
binary may lack the marker module).
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13060
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip_frame():
    """Minimal Ethernet + IPv4 frame (matches BPF `ip`)."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()      # NIO listen ports (ubridge binds these)
    ra, rb = _free_udp(), _free_udp()      # NIO remote ports (listeners here)

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(2.0); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(2.0); rbs.bind(("127.0.0.1", rb))
    # nio_udp connect()s to the remote, so it only accepts packets whose source
    # is the configured remote — bind the injector to NIO-A's remote port (ra).
    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inj.bind(("127.0.0.1", ra))

    frame = _ip_frame()
    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node testnode")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B
                r.check("add mark filter",
                        c.send("bridge add_packet_filter br0 f1 mark ip tag 7").startswith("100-"))
                r.check("bridge start", c.send("bridge start br0").startswith("100-"))

                # inject an IP frame into NIO-A's listen port
                inj.sendto(frame, ("127.0.0.1", la))
                time.sleep(0.3)

                # marker signal arrived at the sink?
                try:
                    data, _ = ms.recvfrom(4096)
                    sig = data.decode(errors="replace")
                    r.check("marker signal received", sig.startswith("MARK "), sig.strip())
                    r.check("signal node/filter/tag", all(x in sig for x in
                            ("node=testnode", "filter=f1", "tag=7")), sig.strip())
                    r.check("signal len", ("len=%d" % len(frame)) in sig, sig.strip())
                except socket.timeout:
                    r.check("marker signal received", False, "timeout")

                # passive: the frame was still relayed to NIO-B's remote
                try:
                    rel, _ = rbs.recvfrom(4096)
                    r.check("frame relayed (passive)", rel == frame, "len=%d" % len(rel))
                except socket.timeout:
                    r.check("frame relayed (passive)", False, "timeout")

                # marker off -> no more signals
                c.send("marker off")
                inj.sendto(frame, ("127.0.0.1", la))
                time.sleep(0.3)
                try:
                    ms.recvfrom(4096)
                    r.check("no signal after marker off", False, "got signal after off")
                except socket.timeout:
                    r.check("no signal after marker off", True)

                # mark filter with pcap: matched packets are appended to a pcap
                PCAP = "/tmp/ubmark_test.pcap"
                if os.path.exists(PCAP):
                    os.remove(PCAP)
                r.check("add mark+pcap filter",
                        c.send("bridge add_packet_filter br0 f2 mark ip pcap %s" % PCAP).startswith("100-"))
                inj.sendto(frame, ("127.0.0.1", la))
                time.sleep(0.3)
                c.send("bridge delete_packet_filter br0 f2")   # closes/flushes the pcap
                time.sleep(0.1)
                r.check("pcap file created", os.path.exists(PCAP))
                if os.path.exists(PCAP):
                    blob = open(PCAP, "rb").read()
                    # 24B global header + 16B record header + frame bytes; frame must be present
                    r.check("pcap captured the frame", frame in blob and len(blob) > 24 + 16,
                            "size=%d" % len(blob))
                if os.path.exists(PCAP):
                    os.remove(PCAP)

                # status reports an emitted count
                st = c.send("marker status")
                r.check("status reports emitted", "emitted=" in st, st.replace("\n", " | "))
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj):
            s.close()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
