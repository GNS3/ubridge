"""Regression for marker pause/resume — two independent levers:

  * per-filter: `bridge enable_packet_filter <br> <name> on|off` flips a filter's
    `enabled` flag. A paused filter is bypassed by the relay loop (no signal,
    no pcap) but the frame is still relayed (passive tap, paused ≠ drop).
  * global: `marker pause` / `marker resume` toggles a g_paused gate inside
    marker_emit(), suppressing *all* signal emission while keeping the sink
    socket open (unlike `marker off`, which tears the sink down).

Global pause overrides per-filter: even with the filter enabled, a paused
marker emits nothing. Pure user-space (UDP + libpcap cBPF) — no sudo.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13080
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
    ra, rb = _free_udp(), _free_udp()      # NIO remote ports (injector / receiver bind)

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(1.0); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(1.0); rbs.bind(("127.0.0.1", rb))
    inj_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj_a.bind(("127.0.0.1", ra))   # inject into la

    frame = _ip_frame()

    def drain():
        n = 0
        while True:
            try:
                ms.recvfrom(4096); n += 1
            except socket.timeout:
                return n

    def inject(label, want_signals, want_relay=True):
        """Inject one frame; assert signal count and (optionally) that it relayed."""
        drain()                                               # clear stale signals
        try:                                                  # clear stale relayed frames
            while True:
                rbs.recvfrom(4096)
        except socket.timeout:
            pass
        inj_a.sendto(frame, ("127.0.0.1", la)); time.sleep(0.3)
        signals = drain()
        r.check(label + " (signals)", signals == want_signals,
                "got %d, want %d" % (signals, want_signals))
        if want_relay:
            try:
                rel, _ = rbs.recvfrom(4096)
                r.check(label + " (relay unaffected)", rel == frame, "paused must still relay")
            except socket.timeout:
                r.check(label + " (relay unaffected)", False, "timeout — pause broke relay?")

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node pausenode")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A = source
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B = dest
                c.send("bridge add_packet_filter br0 f mark ip")
                c.send("bridge start br0")
                time.sleep(0.2)

                inject("baseline filter enabled", want_signals=1)

                # ---- per-filter pause/resume ----
                r.check("pause filter off", c.send("bridge enable_packet_filter br0 f off").startswith("100-"))
                inject("per-filter paused", want_signals=0)          # no signal…
                # …but the frame is still relayed (checked inside inject)

                r.check("resume filter on", c.send("bridge enable_packet_filter br0 f on").startswith("100-"))
                inject("per-filter resumed", want_signals=1)

                # ---- global pause/resume (filter still enabled) ----
                r.check("marker pause", c.send("marker pause").startswith("100-"))
                inject("global paused overrides enabled filter", want_signals=0)

                r.check("marker resume", c.send("marker resume").startswith("100-"))
                inject("global resumed", want_signals=1)

                # ---- error handling ----
                r.check("bad on/off rejected",
                        c.send("bridge enable_packet_filter br0 f maybe").startswith("2"),
                        "expected 2xx error")
                r.check("unknown filter rejected",
                        c.send("bridge enable_packet_filter br0 nope on").startswith("2"),
                        "expected 2xx error")

                # status surfaces the paused flag
                st = c.send("marker status")
                r.check("status reports paused=", "paused=" in st, st.replace("\n", " | "))
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj_a):
            s.close()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
