"""Shared helpers for the delay test suite.

Loads the brctl common helpers (Ubridge/Client/Results) by file path, like
tests/link/helpers.py, so the test trees stay independent. Also exposes the
small UDP traffic primitives (bound_udp / send_burst / recv_count / one_way)
and a bridge builder shared across the delay test files.

ubridge's UDP NIO is a *connected* point-to-point tunnel: a NIO on local port
L connected to remote port R only accepts datagrams from R (and sends to R).
So to feed a bridge we send from a socket bound to the NIO's remote port, and
observe on the peer NIO's remote port. No privileges required (high UDP only).
"""
import importlib.util
import os
import socket
import struct
import time

HOST = "127.0.0.1"

_brctl_common = os.path.join(os.path.dirname(__file__), "..", "brctl", "common.py")
_spec = importlib.util.spec_from_file_location("brctl_common", _brctl_common)
_brctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_brctl)

Ubridge = _brctl.Ubridge
Client = _brctl.Client
Results = _brctl.Results


def ubridge_binary():
    """Prefer the just-built repo binary (delay tests need no privileges, and
    the installed /usr/local/bin/ubridge may be a stale pre-fix copy). Honours
    UBRIDGE_BINARY; falls back to the shared resolver."""
    repo = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "ubridge"))
    env = os.environ.get("UBRIDGE_BINARY")
    if env and os.path.exists(env):
        return env
    if os.path.exists(repo):
        return repo
    return _brctl.ubridge_binary()


def bound_udp(port):
    """UDP socket bound to `port` — fixed-source injector or receiver."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    s.settimeout(5.0)
    return s


def send_burst(tx, dst, n, payload=b"x"):
    """Send n datagrams back-to-back; return the monotonic time of the first."""
    t0 = time.monotonic()
    for i in range(n):
        tx.sendto(struct.pack("!I", i) + payload, dst)
    return t0


def recv_count(rx, n, timeout=5.0, maxpkt=2048):
    """Receive up to n datagrams; return (count, time_of_last_arrival)."""
    deadline = time.monotonic() + timeout
    count = 0
    t_last = None
    while count < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rx.settimeout(remaining)
        try:
            rx.recv(maxpkt)
        except socket.timeout:
            break
        count += 1
        t_last = time.monotonic()
    return count, t_last


def one_way(tx, dst, rx, payload=b"ping"):
    """Send one datagram from bound tx, return one-way latency in s (or None)."""
    t0 = time.monotonic()
    tx.sendto(payload, dst)
    try:
        rx.recv(2048)
    except socket.timeout:
        return None
    return time.monotonic() - t0


def build_bridge(c, name, base, filters=None):
    """Create a started bridge with two connected UDP NIOs and zero or more
    packet filters (each "filters" entry is a full filter spec without the
    bridge/name, e.g. "delay 100" or "packet_loss 50"). Returns (L1,R1,L2,R2)."""
    l1, r1, l2, r2 = base, base + 1, base + 2, base + 3
    assert c.code("bridge create %s" % name) == "100", "create %s" % name
    assert c.code("bridge add_nio_udp %s %d %s %d" % (name, l1, HOST, r1)) == "100"
    assert c.code("bridge add_nio_udp %s %d %s %d" % (name, l2, HOST, r2)) == "100"
    for i, spec in enumerate(filters or []):
        assert c.code("bridge add_packet_filter %s f%d %s" % (name, i, spec)) == "100", spec
    assert c.code("bridge start %s" % name) == "100", "start %s" % name
    time.sleep(0.2)  # let the listener threads come up
    return l1, r1, l2, r2
