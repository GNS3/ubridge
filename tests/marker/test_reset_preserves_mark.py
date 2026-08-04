"""Regression: reset_packet_filters must preserve `mark` filters.

`mark` is a passive observability tap holding an open pcap. reset_packet_filters
is driven by impairment reapply (gns3server tears down + re-adds drop/loss/
delay/corrupt/bpf on filter changes), so it must drop impairment filters but
LEAVE mark filters — and their pcap handle — intact (the day-1 design intent
that reset_impairment_filters finally implements).

Stands up a mark filter (with pcap) + a frequency_drop(-1, drops all), then
issues reset_packet_filters and asserts:
  - the mark filter survives (bridge show still lists it; the impairment is gone)
  - the mark filter still signals after reset (same filter, still enabled)
  - its pcap handle was NOT closed/reopened: both pre- and post-reset captures
    land in ONE file (2 records, single 24-byte global header)
  - the impairment is actually gone: a frame that was dropped before reset is
    forwarded after it.

Walk order is add order ([f1 mark, f2 drop]): mark signals/captures BEFORE the
drop, so a signal fires and the frame is still dropped pre-reset. Pure
user-space (UDP + libpcap cBPF) — no CAP_NET_ADMIN, no sudo.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13063
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


def _pcap_record_lens(path):
    """Walk a classic (little-endian) pcap and return per-record captured lengths.

    Global header is 24 bytes; each record is a 16-byte header (ts_sec, ts_usec,
    incl_len, orig_len) followed by incl_len bytes. Returns [] if the file is
    absent or shorter than a global header.
    """
    try:
        blob = open(path, "rb").read()
    except FileNotFoundError:
        return []
    if len(blob) < 24:
        return []
    lens = []
    off = 24
    while off + 16 <= len(blob):
        incl = struct.unpack_from("<I", blob, off + 8)[0]
        lens.append(incl)
        off += 16 + incl
    return lens


def _recv_or_timeout(sock):
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()      # NIO listen ports (ubridge binds these)
    ra, rb = _free_udp(), _free_udp()      # NIO remote ports (listeners here)

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(1.0); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(0.5); rbs.bind(("127.0.0.1", rb))
    # nio_udp connect()s to the remote, so it only accepts packets whose source
    # is the configured remote — bind the injector to NIO-A's remote port (ra).
    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj.bind(("127.0.0.1", ra))

    frame = _ip_frame()
    PCAP = "/tmp/ubmark_reset_test.pcap"
    if os.path.exists(PCAP):
        os.remove(PCAP)

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node resetnode")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A (inject here)
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B (relay arrives here)
                # add order => walk order [f1, f2]: mark signals/captures BEFORE the drop.
                r.check("add mark filter (f1, +pcap)",
                        c.send("bridge add_packet_filter br0 f1 mark ip pcap %s" % PCAP).startswith("100-"))
                r.check("add frequency_drop -1 (f2)",
                        c.send("bridge add_packet_filter br0 f2 frequency_drop -1").startswith("100-"))
                r.check("bridge start", c.send("bridge start br0").startswith("100-"))

                show0 = c.send("bridge show br0")
                r.check("show lists both filters pre-reset",
                        ("Filter 'f1'" in show0 and "Filter 'f2'" in show0), show0.replace("\n", " | "))

                # --- pre-reset: mark fires (before the drop), frame is dropped ---
                inj.sendto(frame, ("127.0.0.1", la)); time.sleep(0.3)
                sig1 = _recv_or_timeout(ms)
                r.check("pre-reset: mark signaled", sig1 is not None, (sig1 or b"").decode(errors="replace").strip() or "timeout")
                relayed0 = _recv_or_timeout(rbs)
                r.check("pre-reset: frame dropped by f2 (not relayed)",
                        relayed0 is None, "got relay before reset => f2 didn't drop")

                # --- reset: must drop f2, preserve f1 ---
                r.check("reset_packet_filters ok",
                        c.send("bridge reset_packet_filters br0").startswith("100-"))

                show1 = c.send("bridge show br0")
                r.check("post-reset: mark filter (f1) survived",
                        "Filter 'f1'" in show1, show1.replace("\n", " | "))
                r.check("post-reset: impairment (f2) removed",
                        "Filter 'f2'" not in show1, show1.replace("\n", " | "))

                # --- post-reset: mark still fires (same filter/handle), frame forwarded ---
                inj.sendto(frame, ("127.0.0.1", la)); time.sleep(0.3)
                sig2 = _recv_or_timeout(ms)
                r.check("post-reset: mark still signals (survived)",
                        sig2 is not None, (sig2 or b"").decode(errors="replace").strip() or "timeout")
                relayed1 = _recv_or_timeout(rbs)
                r.check("post-reset: frame forwarded (f2 gone)",
                        relayed1 == frame, "len=%d" % (len(relayed1) if relayed1 else 0))

                # --- pcap handle was NOT closed/reopened: flush via delete, then
                # both captures must be in ONE file (2 records, 1 global header) ---
                c.send("bridge delete_packet_filter br0 f1")
                time.sleep(0.1)
                lens = _pcap_record_lens(PCAP)
                r.check("pcap has both captures (2 records, one handle)",
                        lens == [len(frame), len(frame)], "records=%s" % lens)
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj):
            s.close()
        if os.path.exists(PCAP):
            os.remove(PCAP)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
