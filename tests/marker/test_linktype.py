"""linktype support for the `mark` packet filter.

The mark filter compiles its BPF against a link-layer DLT (default EN10MB).
`linktype <name>` overrides it, fixing both the BPF field offsets and the pcap
file header. This verifies:

  * accepted names: C_HDLC / PPP / FRELAY / ATM_RFC1483
  * linktype actually changes BPF offsets — a Cisco-HDLC frame matches `ip`
    only when compiled under DLT_C_HDLC, not under the default EN10MB
  * the default (EN10MB) still matches an Ethernet frame (no regression)
  * an unknown name falls back to EN10MB (filter still installs)
  * the chosen DLT is written into the pcap global header

Pure user-space (UDP NIO + libpcap cBPF) — no CAP_NET_ADMIN, no sudo.
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

# DLT values (the programming values passed to pcap_open_dead). The pcap *file*
# stores LINKTYPE, which equals the DLT for these layers — except ATM_RFC1483,
# which is DLT 11 but LINKTYPE 100 in the file (libpcap maps it on write).
DLT_EN10MB = 1
DLT_CHDLC = 104
DLT_FRELAY = 107


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ipv4():
    """Minimal IPv4 header (20 bytes, no options, proto=UDP)."""
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))


def _eth_ip_frame():
    """Ethernet + IPv4 — matches BPF `ip` under DLT_EN10MB."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    return eth + _ipv4()


def _chdlc_ip_frame():
    """Cisco-HDLC + IPv4 (Address 0x0F, Control 0x00, Type 0x0800).

    Matches BPF `ip` under DLT_C_HDLC (proto at offset 2 == 0x0800), but NOT
    under DLT_EN10MB (ether proto at offset 12 reads 0x4011, not 0x0800).
    """
    return b"\x0f\x00" + struct.pack("!H", 0x0800) + _ipv4()


def _pcap_network(path):
    """Read the link-layer type (network) field from a pcap global header."""
    with open(path, "rb") as f:
        gh = f.read(24)
    if len(gh) < 24:
        return None
    magic = struct.unpack("<I", gh[:4])[0]
    endian = "<" if magic == 0xA1B2C3D4 else ">"   # pcap is host-endian
    return struct.unpack(endian + "I", gh[20:24])[0]


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()      # NIO listen ports (ubridge binds these)
    ra, rb = _free_udp(), _free_udp()      # NIO remote ports (listeners here)

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(2.0); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(2.0); rbs.bind(("127.0.0.1", rb))
    # nio_udp connect()s to the remote, so bind the injector to NIO-A's remote port.
    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inj.bind(("127.0.0.1", ra))

    eth_frame = _eth_ip_frame()
    chdlc_frame = _chdlc_ip_frame()

    def drain():
        """Drop any stale marker signals before the next injection."""
        ms.settimeout(0)
        try:
            while True:
                ms.recvfrom(4096)
        except (BlockingIOError, OSError):
            pass
        finally:
            ms.settimeout(2.0)

    def add_mark(name, expr, *kw):
        cmd = "bridge add_packet_filter br0 %s mark %s" % (name, expr)
        if kw:
            cmd += " " + " ".join(kw)
        return c.send(cmd)

    def inject_expect(frame, expect_signal, label):
        drain()
        inj.sendto(frame, ("127.0.0.1", la))
        time.sleep(0.3)
        try:
            ms.recvfrom(4096)
            got = True
        except socket.timeout:
            got = False
        r.check(label, got == expect_signal, "got=%s expect=%s" % (got, expect_signal))

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node lt-node")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B
                c.send("bridge start br0")

                # --- A. accepted linktype names ---------------------------------
                for lt in ("C_HDLC", "PPP_SERIAL", "FRELAY", "ATM_RFC1483"):
                    r.check("accept linktype %s" % lt,
                            add_mark("fa", "ip", "linktype", lt).startswith("100-"))
                    c.send("bridge delete_packet_filter br0 fa")

                # --- B. linktype changes BPF field offsets ----------------------
                # C_HDLC frame + `ip` compiled under DLT_C_HDLC -> match
                add_mark("fb", "ip", "linktype", "C_HDLC")
                inject_expect(chdlc_frame, True, "C_HDLC frame matches under linktype C_HDLC")
                c.send("bridge delete_packet_filter br0 fb")

                # same frame + `ip` under default EN10MB -> no match (offset 12 != 0x0800)
                add_mark("fc", "ip")
                inject_expect(chdlc_frame, False, "C_HDLC frame does NOT match under default EN10MB")

                # --- C. default still matches Ethernet (no regression) ----------
                inject_expect(eth_frame, True, "Ethernet frame matches under default EN10MB")
                c.send("bridge delete_packet_filter br0 fc")

                # --- D. unknown linktype falls back to EN10MB -------------------
                r.check("accept unknown linktype (fallback)",
                        add_mark("fd", "ip", "linktype", "BOGUS").startswith("100-"))
                inject_expect(eth_frame, True, "unknown linktype falls back to EN10MB (eth match)")
                c.send("bridge delete_packet_filter br0 fd")

                # --- E. chosen linktype written into the pcap global header -----
                # create_pcap_capture() writes the header at add time; deleting the
                # filter flushes it. Header is written even with no matched packet.
                # pcap stores LINKTYPE (== DLT except ATM_RFC1483: DLT 11 / LINK 100).
                file_linktype = {"C_HDLC": DLT_CHDLC, "PPP_SERIAL": 50, "FRELAY": DLT_FRELAY,
                                 "ATM_RFC1483": 100, "EN10MB": DLT_EN10MB}
                for lt in ("C_HDLC", "PPP_SERIAL", "FRELAY", "ATM_RFC1483", "EN10MB"):
                    PCAP = "/tmp/ubmark_linktype.pcap"
                    if os.path.exists(PCAP):
                        os.remove(PCAP)
                    add_mark("fe", "ip", "linktype", lt, "pcap", PCAP)
                    time.sleep(0.1)
                    c.send("bridge delete_packet_filter br0 fe")   # close/flush the pcap
                    time.sleep(0.1)
                    net = _pcap_network(PCAP) if os.path.exists(PCAP) else None
                    r.check("pcap linktype for %s" % lt,
                            os.path.exists(PCAP) and net == file_linktype[lt],
                            "network=%s expect=%d" % (net, file_linktype[lt]))
                    if os.path.exists(PCAP):
                        os.remove(PCAP)

                # status sanity
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
