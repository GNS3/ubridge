"""Shared helpers for the nio_raw test suite (nio_ethernet + nio_linux_raw).

Both backends attach to an EXISTING interface and read/write raw L2 frames:
  * nio_ethernet  — libpcap (pcap_open_live, promisc)
  * nio_linux_raw — AF_PACKET SOCK_RAW (PACKET_MR_PROMISC + PACKET_AUXDATA)

Neither creates its interface (unlike nio_tap), so we stand up a veth pair as
the wire: ubridge binds one end (vnio0), the test injects/observes on the peer
(vnio1) via an AF_PACKET raw socket. A veth pair is a true point-to-point
link, so ubridge's sends on vnio0 egress to vnio1 and never loop back to
vnio0's own reader — no echo loops, no self-capture.

Needs CAP_NET_RAW + CAP_NET_ADMIN (veth create, promisc). Run under sudo or
inside `unshare -Urn`. Re-uses the delay harness (Ubridge/Client/Results) by
file path; stdlib only (AF_PACKET + subprocess ip).
"""
import importlib.util
import os
import socket
import struct
import subprocess
import time

_delay_helpers = os.path.join(os.path.dirname(__file__), "..", "delay", "helpers.py")
_spec = importlib.util.spec_from_file_location("nioraw_delay_helpers", _delay_helpers)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

HOST = _mod.HOST
Ubridge = _mod.Ubridge
Client = _mod.Client
Results = _mod.Results
ubridge_binary = _mod.ubridge_binary

ETH_P_ALL = 0x0003


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sh(*args):
    """Run a command, return the CompletedProcess (don't raise)."""
    return subprocess.run(args, capture_output=True, text=True)


def veth_up(a, b):
    """Create a veth pair a<->b (idempotent: delete a stale pair first) and
    bring both ends UP. Also brings loopback UP — a fresh network namespace
    (e.g. `unshare -Urn`) starts with lo DOWN, which makes 127.0.0.1 binds
    fail; harmless no-op on a normal host where lo is already up. Raises if
    veth creation fails."""
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "link", "del", a)  # best-effort cleanup of a stale pair
    r = sh("ip", "link", "add", a, "type", "veth", "peer", "name", b)
    if r.returncode != 0:
        raise RuntimeError("veth add %s/%s failed: %s" % (a, b, r.stderr.strip()))
    sh("ip", "link", "set", a, "up")
    sh("ip", "link", "set", b, "up")


def veth_del(a):
    """Delete a veth pair by one end (the peer goes too)."""
    sh("ip", "link", "del", a)


def raw_sock(ifname, timeout=3.0):
    """AF_PACKET SOCK_RAW (ETH_P_ALL) bound to ifname — L2 inject + sniff."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname, 0))
    s.settimeout(timeout)
    return s


def eth_frame(payload=b"RAW-NIO-PAYLOAD-0123", etype=0x0800):
    """A minimal Ethernet frame padded to the 60-byte minimum."""
    f = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", etype) + payload
    if len(f) < 60:
        f += b"\x00" * (60 - len(f))
    return f


def drain(s, n=4, timeout=0.4):
    s.settimeout(timeout)
    for _ in range(n):
        try:
            s.recvfrom(4096)
        except socket.timeout:
            break


def recv_match(sock, want, timeout=2.0):
    """Loop recvfrom until a datagram equals `want`, skipping stray traffic.

    An UP veth gets kernel-generated IPv6 ND/MLD (~70-byte) frames that pcap/
    AF_PACKET capture and the bridge dutifully relays — so the next packet at
    the receiver isn't reliably ours. This scans until it sees `want` (matching
    by content) or `timeout` elapses. Returns the matched bytes, else None."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None
        if data == want:
            return data
