"""TAP anchor ports for the IOL bridge (iol_bridge add_nio_tap/delete_nio_tap).

Spec: gns3-server's frozen ubridge-iol-tap-anchor-spec.md — a port's second
destination NIO type, a persistent TAP created by the server (`tap create`,
hardened per the L2-only spec) and opened by name here. uBridge plays, on
that TAP, the role QEMU plays on its own TAP; one userspace hop on the IOU
leg is irreducible (the netio unix fabric is IOU's physical layer), but the
link *segment* becomes the kernel: brctl addif, tc, capture start_kernel,
markers and suspend (= anchor admin-down) all key on the interface name.

This suite needs CAP_NET_ADMIN (tap/veth/bridge creation) — run under sudo
or `unshare -Urn python3 test_tap_anchor.py`; self-skips otherwise. The
fabric side needs no IOL image: we pose as the instance over AF_UNIX, and
observe/inject on the anchor with AF_PACKET (a packet socket sees frames
ubridge writes to the tap fd, and its sends feed the fd reader). Covers the
spec's §E.1–E.8 plus the two §B regressions and the stopped-delete leak:

  E.1  both-direction relay, IOL header stripped/prepended exactly
  E.2  no transient device on an absent name (208, link table unchanged)
  E.3  unknown bridge 208 / name >= IFNAMSIZ 204 / iol_id == app_id refusal
  E.4  delete_nio_tap keeps the persistent device; port re-usable
  E.5  UDP <-> TAP swaps: fds and threads return to baseline, port usable
  E.6  DOWN anchor: 100 fabric frames -> ubridge alive, all dropped (EIO),
       relay restored after `link set up`   [§B.1 regression]
  E.7  idle DOWN port is quiet at the instance (no header-only sends) [§B.2]
  E.8  deployment shape: anchor enslaved in a kernel bridge, frames cross
       bridge <-> fabric through the port
  +    `iol_bridge delete` on a stopped bridge must release anchor fds —
       a leaked fd keeps the persistent tap attached (second TUNSETIFF =
       EBUSY, TUNSETPERSIST 0 = EBADFD) and the server's `tap delete`
       would fail with 207 forever.

Measured on this kernel (§B's premise): write() to an admin-DOWN tap fd
returns exactly EIO, once per frame.
"""
import os
import socket
import struct
import subprocess
import sys
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, prepare_env,
                     iol_sock, iol_frame, fake_iol, free_udp_port,
                     IOL_HDR_SIZE, cleanup_iol_sock)

PORT = 13172
APP_ID = 9320        # the IOL bridge
IOL_ID = 9321        # the fake IOL instance
BRIDGE_SOCK = iol_sock(APP_ID)
TAP = "gi0anchor0p0"          # 12 chars < IFNAMSIZ-1
TAP2 = "gi0leak0p0"           # for the stopped-delete leak regression
ERRLOG = "/tmp/ubridge-iol-tap.err"
BCAST = b"\xff" * 6

# Crafted probe frames use a non-IP ethertype on purpose. When br_netfilter is
# loaded (this host: bridge-nf-call-iptables=1, the usual state on a machine
# with firewalld/docker), a bridge port runs the netfilter hooks, and a frame
# that claims IPv4 (0x0800) without a well-formed IP header is dropped at
# ingress by the bridge's own validation. Measured on this host through a
# tap->bridge->tap chain: 0x0800 + ASCII payload -> dropped, 0x0800 + valid
# IPv4 header -> forwarded, 0x88B5 -> forwarded. None of these paths needs
# real IP, so the frames stay IP-free and the tests measure L2 only.
PROBE_ET = 0x88B5


class UbridgeErr(Ubridge):
    """Ubridge with stderr captured to a file — the §B.1 drop accounting is
    read off the perror("send") lines (one "Input/output error" per EIO)."""

    def __init__(self, port, binary, errlog):
        super().__init__(port=port, binary=binary)
        self.errlog = errlog
        self._errf = None

    def __enter__(self):
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        self._errf = open(self.errlog, "w")
        self.proc = subprocess.Popen(
            [self.binary, "-U", self.sock_path],
            stdout=subprocess.DEVNULL, stderr=self._errf)
        for _ in range(50):
            if os.path.exists(self.sock_path):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    s.connect(self.sock_path)
                    s.close()
                    return self
                except OSError:
                    pass
            time.sleep(0.1)
        raise RuntimeError("ubridge did not open control socket %s" % self.sock_path)

    def __exit__(self, *exc):
        super().__exit__(*exc)
        if self._errf:
            self._errf.close()
        return False


def eio_since(offset):
    """Count 'Input/output error' perror lines appended after `offset`."""
    with open(ERRLOG) as f:
        f.seek(offset)
        return f.read().count("Input/output error")


def err_size():
    return os.path.getsize(ERRLOG)


def eth(etype, payload, src=b"\x02" + b"\x11" * 5):
    return BCAST + src + struct.pack("!H", etype) + payload


def pkt_socket(ifname):
    """Raw listener/injector on a netdev. Note: bound across a down/up cycle
    the socket stays ENETDOWN — re-create it after recovery."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((ifname, 0))
    s.settimeout(1.5)
    return s


def recv_eth(ps, want, r, name, timeout=1.5):
    ps.settimeout(timeout)
    try:
        got, _ = ps.recvfrom(4096)
        return r.check(name, got == want, "len=%d want=%d" % (len(got), len(want)))
    except socket.timeout:
        return r.check(name, False, "timeout")


def nopen(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def nthreads(pid):
    return len(os.listdir("/proc/%d/task" % pid))


def main():
    r = Results()

    if os.geteuid() != 0:
        print("  [SKIP] needs CAP_NET_ADMIN (run under sudo or unshare -Urn)")
        return 0

    prepare_env()
    iol = fake_iol(IOL_ID)
    with UbridgeErr(PORT, ubridge_binary(), ERRLOG) as ub:
        c = ub.connect()
        pid = ub.proc.pid
        try:
            # ---- shared fixtures: one hardened anchor, one bridge ----
            assert c.code("tap create %s" % TAP) == "100"
            assert c.code("link set %s up" % TAP) == "100"    # anchors start DOWN
            assert c.code("iol_bridge create iolt %d" % APP_ID) == "100"

            # ================= E.3 / E.2: validation =================
            rep = c.send("iol_bridge add_nio_tap nosuch %d 0 0 %s" % (IOL_ID, TAP))
            r.check("unknown bridge -> 208", rep.startswith("208"), rep)
            rep = c.send("iol_bridge add_nio_tap iolt %d 0 0 %s" % (IOL_ID, "x" * 16))
            r.check("name >= IFNAMSIZ -> 204", rep.startswith("204"), rep)
            before = subprocess.run(["ip", "-o", "link"], capture_output=True,
                                    text=True).stdout.splitlines()
            rep = c.send("iol_bridge add_nio_tap iolt %d 0 0 nosuchtap0" % IOL_ID)
            after = subprocess.run(["ip", "-o", "link"], capture_output=True,
                                   text=True).stdout.splitlines()
            r.check("absent TAP -> 208", rep.startswith("208"), rep)
            r.check("no transient device created", before == after,
                    "%d links before, %d after" % (len(before), len(after)))
            rep = c.send("iol_bridge add_nio_tap iolt %d 0 0" % IOL_ID)
            r.check("wrong argc -> 203", rep.startswith("203"), rep)
            rep = c.send("iol_bridge add_nio_tap iolt %d 0 0 %s" % (APP_ID, TAP))
            r.check("iol_id == app_id refused", rep.startswith("206") and "same" in rep, rep)

            # ================= E.1: both-direction relay =================
            ps = pkt_socket(TAP)
            assert c.code("iol_bridge add_nio_tap iolt %d 0 0 %s" % (IOL_ID, TAP)) == "100"
            assert c.code("iol_bridge start iolt") == "100"
            time.sleep(0.3)

            frame = eth(PROBE_ET, b"ANCHOR-RELAY-0123456789")
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, frame), BRIDGE_SOCK)
            recv_eth(ps, frame, r, "E.1 fabric->TAP: payload intact, header stripped")

            inj = eth(PROBE_ET, b"ANCHOR-INJECT", src=b"\x02" + b"\x22" * 5)
            ps.sendto(inj, (TAP, 0))
            try:
                data, _ = iol.recvfrom(4096)
                hdr, body = data[:IOL_HDR_SIZE], data[IOL_HDR_SIZE:]
                expect = iol_frame(IOL_ID, APP_ID, 0, 0, b"")[:IOL_HDR_SIZE]
                r.check("E.1 TAP->fabric: payload intact", body == inj, repr(body[:20]))
                r.check("E.1 TAP->fabric: exact IOL header", hdr == expect,
                        "got=%s want=%s" % (hdr.hex(), expect.hex()))
            except socket.timeout:
                r.check("E.1 TAP->fabric: payload intact", False, "timeout")
                r.check("E.1 TAP->fabric: exact IOL header", False, "timeout")

            # ================= E.6/E.7: the anchor goes DOWN =================
            assert c.code("link set %s down" % TAP) == "100"
            time.sleep(0.2)
            mark = err_size()
            for i in range(100):
                iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0,
                                     eth(PROBE_ET, b"DOWN-%03d" % i)), BRIDGE_SOCK)
            time.sleep(0.8)
            r.check("E.6 ubridge alive after 100 frames to DOWN anchor",
                    ub.proc.poll() is None, "rc=%s" % ub.proc.poll())
            dropped = eio_since(mark)
            r.check("E.6 all 100 frames dropped (write = EIO)", dropped == 100,
                    "eio_lines=%d" % dropped)
            quiet = True
            iol.settimeout(0.5)
            try:
                iol.recvfrom(4096)
                quiet = False
            except socket.timeout:
                pass
            r.check("E.7 idle DOWN port quiet at the instance", quiet,
                    "quiet" if quiet else "fabric received something")

            assert c.code("link set %s up" % TAP) == "100"
            ps.close()                       # bound-across-down/up is dead
            ps = pkt_socket(TAP)
            rec = eth(PROBE_ET, b"RECOVERED")
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, rec), BRIDGE_SOCK)
            recv_eth(ps, rec, r, "E.6 relay restored after link set up")
            ps.close()

            # ================= E.4: delete keeps the device =================
            rep = c.send("iol_bridge delete_nio_tap iolt 0 0")
            r.check("E.4 delete_nio_tap -> 100", rep.startswith("100"), rep)
            try:
                socket.if_nametoindex(TAP)   # raises OSError when it is gone
                tap_survives = True
            except OSError:
                tap_survives = False
            r.check("E.4 persistent TAP survives delete", tap_survives, TAP)
            rep = c.send("iol_bridge get_stats iolt")
            r.check("E.4 port holds no NIO (absent from stats)",
                    "port 0/0:" not in rep, rep.replace("\n", " | "))
            rep = c.send("iol_bridge delete_nio_tap iolt 0 0")
            r.check("E.4 delete of empty port is no-op 100",
                    rep.startswith("100"), rep)

            # ================= E.5: UDP <-> TAP swaps =================
            # Baseline in the same shape the swaps must return to: a live TAP
            # NIO with the bridge running costs one fd (the tap) and one
            # listener thread. Measuring against the empty-port state instead
            # would report those two as a "leak" every time.
            assert c.code("iol_bridge add_nio_tap iolt %d 0 0 %s"
                          % (IOL_ID, TAP)) == "100"
            base_fd, base_th = nopen(pid), nthreads(pid)
            lport, rport = free_udp_port(), free_udp_port()

            def swap_to_udp():
                assert c.code("iol_bridge add_nio_udp iolt %d 0 0 %d %s %d"
                              % (IOL_ID, lport, HOST, rport)) == "100"

            def udp_roundtrip(tag):
                """One frame each way through the UDP NIO (port usable)."""
                rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.bind((HOST, rport))
                rx.settimeout(1.5)
                up = eth(PROBE_ET, b"UDP-" + tag.encode())
                iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, up), BRIDGE_SOCK)
                ok = False
                try:
                    got, _ = rx.recvfrom(2048)
                    ok = got == up
                except socket.timeout:
                    pass
                r.check("E.5 %s: fabric->UDP works after swap" % tag, ok, tag)
                rx.close()
                tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tx.bind((HOST, rport))
                tx.sendto(b"UP-" + tag.encode(), (HOST, lport))
                ok = False
                try:
                    data, _ = iol.recvfrom(4096)
                    ok = data[IOL_HDR_SIZE:] == b"UP-" + tag.encode()
                except socket.timeout:
                    pass
                r.check("E.5 %s: UDP->fabric works after swap" % tag, ok, tag)
                tx.close()

            for i in range(3):
                swap_to_udp()
                udp_roundtrip("round%d" % i)
                assert c.code("iol_bridge add_nio_tap iolt %d 0 0 %s"
                              % (IOL_ID, TAP)) == "100"
            ps = pkt_socket(TAP)
            tapback = eth(PROBE_ET, b"BACK-ON-TAP")
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, tapback), BRIDGE_SOCK)
            recv_eth(ps, tapback, r, "E.5 fabric->TAP works after final swap")
            ps.close()
            r.check("E.5 no fd leak after 3 swaps", nopen(pid) == base_fd,
                    "%d before, %d after" % (base_fd, nopen(pid)))
            r.check("E.5 no thread leak after 3 swaps", nthreads(pid) == base_th,
                    "%d before, %d after" % (base_th, nthreads(pid)))

            # ================= E.8: kernel-bridge interop =================
            assert c.code("brctl create iolbr") == "100"
            assert c.code("link veth iolp0 iolp1") == "100"
            assert c.code("link set iolbr up") == "100"
            assert c.code("brctl addif iolbr %s" % TAP) == "100"
            assert c.code("brctl addif iolbr iolp0") == "100"
            assert c.code("link set iolp1 up") == "100"
            time.sleep(0.3)
            p1 = pkt_socket("iolp1")

            crossed = eth(PROBE_ET, b"BRIDGE-CROSS", src=b"\x02" + b"\x33" * 5)
            p1.sendto(crossed, ("iolp1", 0))     # peer -> bridge -> tap -> fabric
            try:
                data, _ = iol.recvfrom(4096)
                r.check("E.8 peer->bridge->anchor->fabric",
                        data[IOL_HDR_SIZE:] == crossed, repr(data[:20]))
            except socket.timeout:
                r.check("E.8 peer->bridge->anchor->fabric", False, "timeout")

            out = eth(PROBE_ET, b"FABRIC-OUT", src=b"\x02" + b"\x44" * 5)
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, out), BRIDGE_SOCK)
            recv_eth(p1, out, r, "E.8 fabric->anchor->bridge->peer")
            p1.close()

            assert c.code("link delete iolp0") == "100"      # detaches iolp0 too
            assert c.code("brctl delif iolbr %s" % TAP) == "100"
            assert c.code("brctl delete iolbr") == "100"

            # ================= leak regression: stopped delete =================
            assert c.code("tap create %s" % TAP2) == "100"
            assert c.code("iol_bridge create iolk %d" % (APP_ID + 2)) == "100"
            assert c.code("iol_bridge add_nio_tap iolk %d 0 0 %s"
                          % (IOL_ID, TAP2)) == "100"
            assert c.code("iol_bridge start iolk") == "100"
            time.sleep(0.2)
            assert c.code("iol_bridge stop iolk") == "100"
            # no delete_nio_tap: the bridge delete must release the anchor fd
            assert c.code("iol_bridge delete iolk") == "100"
            rep = c.send("tap delete %s" % TAP2)
            r.check("stopped iol_bridge delete releases anchor fd (tap delete ok)",
                    rep.startswith("100"), rep)

            # ================= teardown =================
            assert c.code("iol_bridge stop iolt") == "100"
            assert c.code("iol_bridge delete iolt") == "100"
            rep = c.send("tap delete %s" % TAP)
            r.check("anchor tap delete after full teardown", rep.startswith("100"), rep)
        finally:
            c.close()
    iol.close()
    cleanup_iol_sock(IOL_ID)
    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
