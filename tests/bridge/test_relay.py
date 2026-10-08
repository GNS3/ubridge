"""unix<->tap relay on the generic bridge, and the DOWN anchor (CAP_NET_ADMIN).

The Docker/IOL deployment shape with the TAP leg attached: frames cross
container-socket <-> TAP anchor in both directions, the anchor can join a
kernel bridge (the iol suite covers that interop; here the anchor stands
alone), and an admin-DOWN anchor is a steady state — writes fail EIO and are
dropped, the relay survives, traffic flows again once the link is back up.

Frames use the non-IP probe ethertype (0x88B5) so they survive
br_netfilter's ingress validation on hosts with bridge-nf-call-iptables=1.

Self-skips without CAP_NET_ADMIN (run under sudo or unshare -Urn).
"""
import os
import socket
import subprocess
import sys
import time

from helpers import (Ubridge, Results, ubridge_binary, prepare_env,
                     eth, pkt_socket, ub_sock, clean_sock)

PORT = 13212
D = "/tmp/ubridge-bridge-r"
NAME = "rly"
TAP = "rranchor0p0"           # 12 chars < IFNAMSIZ-1
ERRLOG = "/tmp/ubridge-bridge-relay.err"

BCAST = b"\xff" * 6


class UbridgeErr(Ubridge):
    """Ubridge with stderr captured to a file — the EIO drop accounting is
    read off the perror(\"send\") lines (one \"Input/output error\" per EIO)."""

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
        import time as _t
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
            _t.sleep(0.1)
        raise RuntimeError("ubridge did not open control socket %s" % self.sock_path)

    def __exit__(self, *exc):
        super().__exit__(*exc)
        if self._errf:
            self._errf.close()
        return False


def eio_count():
    try:
        with open(ERRLOG) as f:
            return f.read().count("Input/output error")
    except FileNotFoundError:
        return 0


def main():
    r = Results()
    if os.geteuid() != 0:
        print("  [SKIP] needs CAP_NET_ADMIN (run under sudo or unshare -Urn)")
        return 0

    prepare_env()
    os.makedirs(D, exist_ok=True)
    b = ub_sock(D, "r-b.sock")                     # source NIO's remote
    a = ub_sock(D, "r-a.sock", bind=False)         # source NIO's local (ubridge binds)
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    with UbridgeErr(PORT, ubridge_binary(), ERRLOG) as ub:
        c = ub.connect()
        try:
            # ---- fixtures: anchor up, bridge unix -> tap, started ----
            assert c.code("tap create %s" % TAP) == "100"
            assert c.code("link set %s up" % TAP) == "100"    # anchors start DOWN
            assert c.code("bridge create %s" % NAME) == "100"
            assert c.code("bridge add_nio_unix %s %s %s" % (NAME, a, b.getsockname())) == "100"
            assert c.code("bridge add_nio_tap %s %s" % (NAME, TAP)) == "100"
            assert c.code("bridge start %s" % NAME) == "100"
            time.sleep(0.3)

            # ================= R.1: both-direction relay =================
            ps = pkt_socket(TAP)
            fwd = eth(b"RELAY-FWD-0123456789")
            sender.sendto(fwd, a)
            ps.settimeout(2.0)
            try:
                got, _ = ps.recvfrom(4096)
                r.check("R.1 unix->TAP: frame intact", got == fwd,
                        "len=%d want=%d" % (len(got), len(fwd)))
            except socket.timeout:
                r.check("R.1 unix->TAP: frame intact", False, "timeout")

            rev = eth(b"RELAY-REV", src=b"\x02" + b"\x44" * 5)
            ps.sendto(rev, (TAP, 0))
            b.settimeout(2.0)
            try:
                got2 = b.recv(4096)
                r.check("R.1 TAP->unix: frame intact", got2 == rev, repr(got2[:20]))
            except socket.timeout:
                r.check("R.1 TAP->unix: frame intact", False, "timeout")
            ps.close()   # bound-across-down/up is dead; re-create after recovery

            # ================= R.2: DOWN anchor is a steady state =================
            assert c.code("link set %s down" % TAP) == "100"
            before = eio_count()
            for i in range(50):
                sender.sendto(eth(b"DOWN-%03d" % i), a)
            time.sleep(0.5)
            r.check("R.2 ubridge alive after 50 frames to a DOWN anchor",
                    ub.proc.poll() is None)
            r.check("R.2 every write dropped (EIO accounted)",
                    eio_count() - before == 50,
                    "eio=%d want=50" % (eio_count() - before))
            rep = c.send("bridge get_stats %s" % NAME)
            r.check("R.2 control channel healthy (no half-exit wedge)",
                    rep.startswith("101") and "100-OK" in rep, rep[:40])

            # ================= R.3: recovery =================
            assert c.code("link set %s up" % TAP) == "100"
            ps2 = pkt_socket(TAP)
            rec = eth(b"RECOVERED")
            sender.sendto(rec, a)
            ps2.settimeout(2.0)
            try:
                got3, _ = ps2.recvfrom(4096)
                r.check("R.3 traffic flows again after link set up", got3 == rec)
            except socket.timeout:
                r.check("R.3 traffic flows again after link set up", False, "timeout")
            ps2.close()
        finally:
            c.send("bridge stop %s" % NAME)
            c.send("bridge delete %s" % NAME)
            c.send("tap delete %s" % TAP)
            c.close()

    sender.close()
    b.close()
    for n in ("r-a.sock", "r-b.sock"):
        clean_sock(os.path.join(D, n))
    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
