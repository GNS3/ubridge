"""Zero-length reads must not be forwarded or counted (no caps needed).

The shared relay loop (bridge_nios) used to treat a zero-length recv as a
frame: it counted it, ran the filters and capture over an empty buffer, and
sent zero bytes to the far NIO — which on a datagram NIO delivers an empty
datagram to the peer. A container on the far unix socket reads that as a
frame. The fix skips recv == 0, as the iol listeners already did.

Topology (all AF_UNIX datagrams, no privileges): bridge "z" with
  source_nio      = unix NIO bound z-a.sock, sending to z-b.sock
  destination_nio = unix NIO bound z-c.sock, sending to z-d.sock
The test binds b and d (the NIOs' remotes) and sends into a and c:
  forward:  sendto(z-a.sock) -> relay -> arrives on z-d.sock
  reverse:  sendto(z-c.sock) -> relay -> arrives on z-b.sock
"""
import os
import re
import socket
import sys
import time

from helpers import (Ubridge, Results, ubridge_binary, prepare_env,
                     ub_sock, clean_sock)

PORT = 13210
D = "/tmp/ubridge-bridge-z"
NAME = "zlen"


def _stats_in(c, which):
    """packets-IN for the Source/Destination NIO from bridge get_stats."""
    rep = c.send("bridge get_stats %s" % NAME)
    m = re.search(which + r" NIO:\s+IN: (\d+) packets", rep)
    return int(m.group(1)) if m else None


def _drain_one(sock, timeout=2.0):
    """Receive one datagram or None on timeout."""
    sock.settimeout(timeout)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return None


def main():
    r = Results()
    prepare_env()
    os.makedirs(D, exist_ok=True)

    b = ub_sock(D, "z-b.sock")    # forward output (dest NIO's remote)
    d = ub_sock(D, "z-d.sock")    # reverse output (source NIO's remote)
    a = ub_sock(D, "z-a.sock", bind=False)   # forward input  (source NIO's local)
    cc = ub_sock(D, "z-c.sock", bind=False)  # reverse input (dest NIO's local)
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            c.send("bridge create %s" % NAME)
            assert c.code("bridge add_nio_unix %s %s %s" % (NAME, a, b.getsockname())) == "100"
            assert c.code("bridge add_nio_unix %s %s %s" % (NAME, cc, d.getsockname())) == "100"
            assert c.code("bridge start %s" % NAME) == "100"
            time.sleep(0.3)

            # ---- 1. an empty datagram is not forwarded ----
            sender.sendto(b"", a)            # empty forward datagram
            sender.sendto(b"real-1", a)      # then a real one
            got = _drain_one(d)
            r.check("empty datagram not delivered: only the real frame",
                    got == b"real-1", repr(got))

            # ---- 2. and not counted ----
            r.check("stats count 1 packet in, not 2",
                    _stats_in(c, "Source") == 1, "IN=%s" % _stats_in(c, "Source"))

            # ---- 3. a burst of empties keeps the relay healthy ----
            for _ in range(50):
                sender.sendto(b"", a)
            sender.sendto(b"real-2", a)
            r.check("relay healthy after 50 empty datagrams",
                    _drain_one(d) == b"real-2")

            # ---- 4. reverse direction too ----
            sender.sendto(b"", cc)
            sender.sendto(b"real-3", cc)
            r.check("reverse: empty skipped, real frame delivered",
                    _drain_one(b) == b"real-3")

            r.check("ubridge still alive", ub.proc.poll() is None)
        finally:
            c.send("bridge delete %s" % NAME)
            c.close()

    sender.close()
    for s in (b, d):
        s.close()
    for n in ("z-a.sock", "z-b.sock", "z-c.sock", "z-d.sock"):
        clean_sock(os.path.join(D, n))
    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
