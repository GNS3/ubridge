"""Shared helpers for the bridge test suite.

Loads the brctl common helpers (Ubridge/Client/Results) by file path, like
delay/helpers.py, so the test trees stay independent. Adds the fixtures the
generic bridge module's tests need: AF_UNIX datagram socket pairs (one side
for the NIO's remote, one played by the test as the peer), an AF_PACKET
listener/injector for a netdev, and an Ethernet frame builder.

The bridge module is the deployment shape of the Docker/IOL relay ("port
bridge resident for the node's life, second NIO swappable"): a unix-socket
NIO (the container leg) plus a UDP or TAP NIO (the topology leg). The
zero-length suite needs no privileges; the tap suites self-skip without
CAP_NET_ADMIN.
"""
import importlib.util
import os
import socket
import struct
import subprocess

_brctl_common = os.path.join(os.path.dirname(__file__), "..", "brctl", "common.py")
_spec = importlib.util.spec_from_file_location("brctl_common", _brctl_common)
_brctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_brctl)

Ubridge = _brctl.Ubridge
Client = _brctl.Client
Results = _brctl.Results


def ubridge_binary():
    """Prefer the just-built repo binary (the installed /usr/local/bin/ubridge
    may be a stale pre-fix copy). Honours UBRIDGE_BINARY; falls back to the
    shared resolver."""
    repo = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "ubridge"))
    env = os.environ.get("UBRIDGE_BINARY")
    if env and os.path.exists(env):
        return env
    if os.path.exists(repo):
        return repo
    return _brctl.ubridge_binary()

BCAST = b"\xff" * 6
PROBE_ET = 0x88B5  # non-IP ethertype: survives br_netfilter ingress validation


def prepare_env():
    """Bring lo up in a fresh user namespace — the UDP NIO binds 127.0.0.1
    and fails with a mystifying 206 otherwise. No-op where lo is up."""
    subprocess.run(["ip", "link", "set", "lo", "up"], capture_output=True)


def free_udp_port():
    """An ephemeral free UDP port on 127.0.0.1 (grabbed then released)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def eth(payload, src=b"\x02" + b"\x33" * 5):
    """A minimal Ethernet frame with the non-IP probe ethertype."""
    return BCAST + src + struct.pack("!H", PROBE_ET) + payload


def ub_sock(dirpath, name, bind=True):
    """An AF_UNIX datagram socket at dirpath/name. With bind=False the path
    is left for ubridge's NIO to bind (its local end); the caller then
    sendto()s it. Removes a stale file first. Caller closes + unlinks."""
    path = os.path.join(dirpath, name)
    if bind:
        try:
            os.unlink(path)
        except OSError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(path)
        s.settimeout(5.0)
        return s
    return path


def clean_sock(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def pkt_socket(ifname, timeout=1.5):
    """Raw listener/injector on a netdev. Note: bound across a down/up cycle
    the socket stays ENETDOWN — re-create it after recovery."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((ifname, 0))
    s.settimeout(timeout)
    return s
