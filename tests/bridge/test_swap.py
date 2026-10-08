"""delete_nio_tap: validation, swap semantics, teardown order (CAP_NET_ADMIN).

The deployment shape is the Docker/IOL relay: a per-node bridge holding a
unix-socket NIO (the container leg) for the node's whole life, with the
topology leg swapping between add_nio_udp and add_nio_tap as links come and
go. delete_nio_tap releases only the TAP fd — the persistent anchor (made by
`tap create`) survives for the server's `tap delete`.

Covers:
  S.1  validation: unknown bridge 214, name >= IFNAMSIZ 204, wrong name 214,
       no-TAP bridge 214
  S.2  the running refusal (use-after-free guard, same 214 as delete_nio_udp)
  S.3  delete keeps the device; the fd is really released (re-add succeeds)
  S.4  swap udp -> tap -> udp -> tap; the bridge starts and relays after each
  S.5  the unix NIO keeps its binding across the swap window, and a frame
       sent while the bridge is stopped is picked up after start (no re-bind,
       no lost frame)
  S.6  kernel-truncated names match by their resolved 15 chars
  S.7  teardown order: bridge delete releases the anchor fd, then tap delete
       succeeds (the contract doc/gns3server-integration.md spells out)

Self-skips without CAP_NET_ADMIN (run under sudo or unshare -Urn).
"""
import os
import socket
import subprocess
import sys
import time

from helpers import (Ubridge, Results, ubridge_binary, prepare_env,
                     free_udp_port, ub_sock, clean_sock)

PORT = 13211
D = "/tmp/ubridge-bridge-s"
NAME = "swp"
TAP = "swanchor0p0"          # 12 chars < IFNAMSIZ-1
LONG = "swtrunc1234567890"   # 20 chars -> kernel truncates to 15
TRUNC = LONG[:15]


def _ip(*args):
    return subprocess.run(["ip"] + list(args), capture_output=True, text=True)


def _exists(ifname):
    return subprocess.run(["ip", "-o", "link", "show", ifname],
                          capture_output=True).returncode == 0


def main():
    r = Results()
    if os.geteuid() != 0:
        print("  [SKIP] needs CAP_NET_ADMIN (run under sudo or unshare -Urn)")
        return 0

    prepare_env()
    os.makedirs(D, exist_ok=True)
    b = ub_sock(D, "s-b.sock")                     # source NIO's remote
    a = ub_sock(D, "s-a.sock", bind=False)         # source NIO's local (ubridge binds)

    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # ---- shared fixtures: persistent anchor + bridge ----
            assert c.code("tap create %s" % TAP) == "100"
            assert c.code("link set %s up" % TAP) == "100"    # anchors start DOWN
            assert c.code("bridge create %s" % NAME) == "100"
            assert c.code("bridge add_nio_unix %s %s %s" % (NAME, a, b.getsockname())) == "100"
            p1, p2 = free_udp_port(), free_udp_port()

            # ================= S.1: validation =================
            rep = c.send("bridge delete_nio_tap nosuch %s" % TAP)
            r.check("S.1 unknown bridge -> 214", rep.startswith("214"), rep)
            rep = c.send("bridge delete_nio_tap %s %s" % (NAME, "x" * 16))
            r.check("S.1 name >= IFNAMSIZ -> 204", rep.startswith("204"), rep)
            rep = c.send("bridge delete_nio_tap %s nosuchtap0" % NAME)
            r.check("S.1 no TAP NIO on the bridge -> 214", rep.startswith("214"), rep)

            # ================= S.2: the running refusal =================
            assert c.code("bridge add_nio_tap %s %s" % (NAME, TAP)) == "100"
            assert c.code("bridge start %s" % NAME) == "100"
            rep = c.send("bridge delete_nio_tap %s %s" % (NAME, TAP))
            r.check("S.2 running refusal -> 214", rep.startswith("214"), rep)
            r.check("S.2 ubridge alive", ub.proc.poll() is None)
            assert c.code("bridge stop %s" % NAME) == "100"

            # ================= S.3: delete keeps the device =================
            rep = c.send("bridge delete_nio_tap %s %s" % (NAME, TAP))
            r.check("S.3 delete -> 100", rep.startswith("100"), rep)
            r.check("S.3 device survives the fd release", _exists(TAP))
            rep = c.send("bridge delete_nio_tap %s %s" % (NAME, TAP))
            r.check("S.3 second delete -> 214 (no TAP NIO left)", rep.startswith("214"), rep)
            r.check("S.3 re-add succeeds (fd was really released)",
                    c.code("bridge add_nio_tap %s %s" % (NAME, TAP)) == "100")

            # ================= S.4: swap both ways, relay after each =================
            for leg in ("udp", "tap", "udp", "tap"):
                if leg == "udp":
                    # tap currently attached (previous iteration) or first run
                    c.send("bridge delete_nio_tap %s %s" % (NAME, TAP))
                    assert c.code("bridge add_nio_udp %s %d 127.0.0.1 %d" % (NAME, p1, p2)) == "100", leg
                else:
                    c.send("bridge delete_nio_udp %s %d 127.0.0.1 %d" % (NAME, p1, p2))
                    assert c.code("bridge add_nio_tap %s %s" % (NAME, TAP)) == "100", leg
                assert c.code("bridge start %s" % NAME) == "100"
                time.sleep(0.2)
                assert c.code("bridge stop %s" % NAME) == "100"
            r.check("S.4 four swaps (udp/tap x2) all succeed", True)

            # ================= S.5: binding survives the swap window =================
            # final state: tap attached, stopped. Swap to udp while a frame is
            # "in flight" into the unix local socket.
            c.send("bridge delete_nio_tap %s %s" % (NAME, TAP))
            assert c.code("bridge add_nio_udp %s %d 127.0.0.1 %d" % (NAME, p1, p2)) == "100"
            sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            midframe = b"mid-swap-frame"
            sender.sendto(midframe, a)             # bridge is STOPPED here
            d = ub_sock(D, "s-d.sock")             # udp side: observe at remote p2
            udprx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udprx.bind(("127.0.0.1", p2))
            udprx.settimeout(3.0)
            assert c.code("bridge start %s" % NAME) == "100"
            time.sleep(0.3)
            try:
                got = udprx.recv(4096)
            except socket.timeout:
                got = None
            r.check("S.5 frame sent during the swap window arrives after start",
                    got == midframe, repr(got))
            udprx.close()
            d.close()
            assert c.code("bridge stop %s" % NAME) == "100"

            # ================= S.6: truncated names match by resolution =================
            c.send("bridge delete_nio_udp %s %d 127.0.0.1 %d" % (NAME, p1, p2))
            rep = c.send("bridge add_nio_tap %s %s" % (NAME, LONG))
            r.check("S.6 20-char add -> 100 (legacy create-if-missing)",
                    rep.startswith("100"), rep)
            r.check("S.6 kernel truncated the name to %s" % TRUNC, _exists(TRUNC))
            rep = c.send("bridge delete_nio_tap %s %s" % (NAME, TRUNC))
            r.check("S.6 delete by the resolved 15-char name -> 100",
                    rep.startswith("100"), rep)
            r.check("S.6 truncated device died with its fd (transient)",
                    not _exists(TRUNC))

            # ================= S.7: teardown order =================
            assert c.code("bridge add_nio_tap %s %s" % (NAME, TAP)) == "100"
            assert c.code("bridge start %s" % NAME) == "100"
            rep = c.send("bridge delete %s" % NAME)   # stops + releases every NIO
            r.check("S.7 bridge delete with anchor attached -> 100",
                    rep.startswith("100"), rep)
            rep = c.send("tap delete %s" % TAP)
            r.check("S.7 tap delete succeeds after the fd release -> 100",
                    rep.startswith("100"), rep)
            r.check("S.7 anchor gone", not _exists(TAP))
        finally:
            c.send("bridge delete %s" % NAME)
            c.send("tap delete %s" % TAP)
            _ip("link", "delete", TRUNC)
            c.close()

    b.close()
    for n in ("s-a.sock", "s-b.sock", "s-d.sock"):
        clean_sock(os.path.join(D, n))
    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
