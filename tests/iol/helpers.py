"""Shared helpers for the iol test suite.

Loads the delay suite's Ubridge/Client/Results harness by file path (like
delay/helpers.py loads brctl/common.py), plus IOL-specific primitives: the
netio unix-socket layout, the 8-byte IOL frame header, and a fake-IOL-instance
socket. These tests need no CAP_NET_ADMIN — IOL bridges talk AF_UNIX over
/tmp/netio{uid}/ and a UDP destination NIO. No IOL image required: we pose as
the IOL instance ourselves.
"""
import importlib.util
import os
import socket

_delay_helpers = os.path.join(os.path.dirname(__file__), "..", "delay", "helpers.py")
_spec = importlib.util.spec_from_file_location("iol_delay_helpers", _delay_helpers)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

HOST = _mod.HOST
Ubridge = _mod.Ubridge
Client = _mod.Client
Results = _mod.Results
ubridge_binary = _mod.ubridge_binary

UID = os.getuid()
NETIO_DIR = "/tmp/netio%u" % UID

# IOL header field offsets (mirror src/hypervisor_iol_bridge.h)
IOL_DST_IDS, IOL_SRC_IDS = 0, 2
IOL_DST_PORT, IOL_SRC_PORT = 4, 5
IOL_MSG_TYPE, IOL_CHANNEL = 6, 7
IOL_HDR_SIZE = 8
IOL_MSG_TYPE_DATA = 1


def ensure_netio_dir():
    """ubridge binds into /tmp/netio{uid}/ but expects it to exist (GNS3 makes
    it). Create it idempotently so the tests are self-contained."""
    try:
        os.makedirs(NETIO_DIR, 0o777)
    except FileExistsError:
        pass


def iol_sock(iol_id):
    """The netio unix-socket path for an IOL id (bridge or instance)."""
    return "%s/%d" % (NETIO_DIR, iol_id)


def iol_frame(dst_id, src_id, dst_port, src_port, payload, msg=IOL_MSG_TYPE_DATA, channel=0):
    """Build an IOL-framed packet: 8-byte header + payload."""
    f = bytearray(IOL_HDR_SIZE)
    f[IOL_DST_IDS] = (dst_id >> 8) & 0xff
    f[IOL_DST_IDS + 1] = dst_id & 0xff
    f[IOL_SRC_IDS] = (src_id >> 8) & 0xff
    f[IOL_SRC_IDS + 1] = src_id & 0xff
    f[IOL_DST_PORT] = dst_port & 0xff
    f[IOL_SRC_PORT] = src_port & 0xff
    f[IOL_MSG_TYPE] = msg
    f[IOL_CHANNEL] = channel
    return bytes(f) + payload


def fake_iol(iol_id, timeout=5.0):
    """Bind an AF_UNIX datagram socket posing as IOL instance `iol_id`.
    Removes any stale socket file first. Caller closes + unlinks."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        os.unlink(iol_sock(iol_id))
    except OSError:
        pass
    s.bind(iol_sock(iol_id))
    s.settimeout(timeout)
    return s


def free_udp_port():
    """An ephemeral free UDP port on HOST (grabbed then released)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def cleanup_iol_sock(iol_id):
    try:
        os.unlink(iol_sock(iol_id))
    except OSError:
        pass
