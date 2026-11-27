"""VLAN-filter regression for kernel markers (`marker add_kernel`).

Same root cause as the capture fix (gns3-server#3116): with vlan_filtering
the 802.1Q tag of bridge-forwarded frames travels as skb metadata at the
AF_PACKET tap points, so the frame data a kernel marker sees is headerless
and a vlan-style filter never matched. The fix re-inserts the metadata tag
after a first-pass (untagged view) filter miss.

Drives two vlan-filtering bridges joined by a veth trunk and asserts:
- `vlan 10` matches bridge-forwarded vid-10 frames in BOTH directions and
  emits the tagged frame length (102 -> the pcap view has the tag);
- `ip proto 1` keeps matching on the untagged view (no L3-offset change);
- QinQ [8100 10][8100 20]: `vlan 20` matches the inner tag on the raw
  data (like tcpdump on the same bytes), `vlan 10` matches only after the
  tagged-view retry, at the full QinQ length;
- the pcap appended on a tagged-view hit contains the frames as injected,
  byte for byte.

Stdlib only. Requires CAP_NET_ADMIN/CAP_NET_RAW — run under sudo (or
unshare -Urn). Uses the in-repo ./ubridge.
"""
import os
import shutil as _sh
import re
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubmkv-"
PORT = 13091
TRUNK_A = PREFIX + "ta"
TRUNK_B = PREFIX + "tb"
HOST_E = PREFIX + "he"
HOST_E2 = PREFIX + "he2"
HOST_C = PREFIX + "hc"
HOST_C2 = PREFIX + "hc2"
BR1 = PREFIX + "br1"
BR2 = PREFIX + "br2"
PCAP = "/tmp/ubmkv.pcap"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))
VID = 10
INNER_VID = 20
N = 3

BRIDGE = _sh.which("bridge")
if BRIDGE is None:
    BRIDGE = next((p for p in ("/sbin/bridge", "/usr/sbin/bridge", "/usr/local/sbin/bridge")
                   if os.path.isfile(p) and os.access(p, os.X_OK)), None)


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _csum(d):
    if len(d) % 2:
        d += b"\0"
    s = sum(struct.unpack("!%dH" % (len(d) // 2), d))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _icmp(seq, src):
    payload = bytes(i & 0xFF for i in range(56))
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, seq) + payload
    icmp = icmp[:2] + struct.pack("!H", _csum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 84, 0x2345, 0, 64, 1, 0,
                     bytes([10, 97, 0, 1]), bytes([10, 97, 0, 2]))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return ip + icmp   # the caller builds the Ethernet header (incl. tags)


def _tagged(seq, src, tags):
    eth = (b"\xff" * 6 + src
           + b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in tags)
           + b"\x08\x00")
    return eth + _icmp(seq, src)


SRC_TX = bytes([0xaa, 0x01]) + b"\x11" * 4
SRC_RX = bytes([0xaa, 0x02]) + b"\x22" * 4


def _inject(iface, frame):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        s.bind((iface, 0))
        s.send(frame)
    finally:
        s.close()


def _drain(sock, timeout):
    out = []
    end = time.time() + timeout
    while True:
        remaining = end - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            break
        out.append(data.decode(errors="replace").strip())
    return out


def _kv(line):
    return dict(tok.split("=", 1) for tok in line.split() if "=" in tok)


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _topology():
    for br in (BR1, BR2):
        subprocess.run(["ip", "link", "add", br, "type", "bridge", "vlan_filtering", "1"],
                       capture_output=True, check=True)
        subprocess.run(["ip", "link", "set", br, "up"], capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", TRUNK_A, "type", "veth", "peer", "name", TRUNK_B],
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", HOST_E, "type", "veth", "peer", "name", HOST_E2],
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", HOST_C, "type", "veth", "peer", "name", HOST_C2],
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "set", TRUNK_A, "master", BR1], capture_output=True, check=True)
    subprocess.run(["ip", "link", "set", HOST_E, "master", BR1], capture_output=True, check=True)
    subprocess.run(["ip", "link", "set", TRUNK_B, "master", BR2], capture_output=True, check=True)
    subprocess.run(["ip", "link", "set", HOST_C, "master", BR2], capture_output=True, check=True)
    for i in (TRUNK_A, TRUNK_B, HOST_E, HOST_E2, HOST_C, HOST_C2):
        subprocess.run(["ip", "link", "set", i, "up"], capture_output=True, check=True)
    for i in (TRUNK_A, TRUNK_B, HOST_E, HOST_C):
        subprocess.run([BRIDGE, "vlan", "add", "dev", i, "vid", str(VID)],
                       capture_output=True, check=True)


def _teardown():
    for i in (BR1, BR2, TRUNK_A, TRUNK_B, HOST_E, HOST_E2, HOST_C, HOST_C2):
        subprocess.run(["ip", "link", "del", i], capture_output=True)


def _pcap_frames(path):
    data = open(path, "rb").read()
    out, off = [], 24
    while off + 16 <= len(data):
        incl = struct.unpack("<I", data[off + 8:off + 12])[0]
        out.append(data[off + 16:off + 16 + incl])
        off += 16 + incl
    return out


def main():
    r = Results()
    if os.geteuid() != 0 or BRIDGE is None:
        print("  [SKIP] needs root + bridge(8) (run under sudo or unshare -Urn)")
        return 0
    if os.path.exists(PCAP):
        os.remove(PCAP)

    subprocess.run(["ip", "link", "set", "lo", "up"], capture_output=True)
    marker_port = _free_udp()
    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ms.bind(("127.0.0.1", marker_port))

    single = [_tagged(i, SRC_TX, [(0x8100, VID)]) for i in range(1, N + 1)]
    single += [_tagged(100 + i, SRC_RX, [(0x8100, VID)]) for i in range(1, N + 1)]
    qinq = [_tagged(200 + i, SRC_TX, [(0x8100, VID), (0x8100, INNER_VID)]) for i in range(1, N + 1)]
    qinq += [_tagged(300 + i, SRC_RX, [(0x8100, VID), (0x8100, INNER_VID)]) for i in range(1, N + 1)]

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                r.check("marker sink", c.code("marker sink 127.0.0.1 %d" % marker_port) == "100")
                r.check("topology", _topology() or True)

                r.check("add vlan 10 marker",
                        c.code('marker add_kernel mvlan %s "vlan 10" tag 10 pcap %s'
                               % (TRUNK_A, PCAP)) == "100")
                r.check("add ip proto 1 marker",
                        c.code('marker add_kernel mip %s "ip proto 1" tag 11'
                               % TRUNK_A) == "100")
                r.check("add vlan 20 marker",
                        c.code('marker add_kernel mvlan20 %s "vlan 20" tag 12'
                               % TRUNK_A) == "100")

                for f in single:
                    # TX frames (seq < 100) enter br1 from the h-e side; RX
                    # frames enter br2 from the h-c side. One side each — the
                    # lists already cover both directions.
                    _inject(HOST_E2 if f[6:12] == SRC_TX else HOST_C2, f)
                    time.sleep(0.02)
                time.sleep(0.8)
                marks = [_kv(l) for l in _drain(ms, 1.0)]

                mvlan = [m for m in marks if m.get("filter") == "mvlan"]
                mip = [m for m in marks if m.get("filter") == "mip"]
                r.check("vlan 10 matched in both directions (%d marks)" % (2 * N),
                        len(mvlan) == 2 * N, "got %d" % len(mvlan))
                r.check("vlan 10 marks carry the tagged length (102)",
                        all(m.get("len") == "102" for m in mvlan))
                r.check("ip proto 1 still matches (untagged view)",
                        len(mip) == 2 * N, "got %d" % len(mip))

                # QinQ: inner tag matches on the raw data, outer only after the retry
                for f in qinq:
                    _inject(HOST_E2 if f[6:12] == SRC_TX else HOST_C2, f)
                    time.sleep(0.02)
                time.sleep(0.8)
                marks = [_kv(l) for l in _drain(ms, 1.0)]
                q10 = [m for m in marks if m.get("filter") == "mvlan" and m.get("len") == "106"]
                q20 = [m for m in marks if m.get("filter") == "mvlan20"]
                r.check("QinQ outer vid 10 matched after the tagged-view retry (%d)" % (2 * N),
                        len(q10) == 2 * N, "got %d" % len(q10))
                r.check("QinQ inner vid 20 matched on the raw data (%d)" % (2 * N),
                        len(q20) == 2 * N, "got %d" % len(q20))

                r.check("vlan 10 marker pcap has the tagged frames",
                        set(_pcap_frames(PCAP)) == set(single + qinq),
                        "%d frames" % len(_pcap_frames(PCAP)))

                r.check("marker off", c.code("marker off") == "100")
            finally:
                c.close()
    finally:
        _teardown()

    npass = sum(1 for _, ok, _ in r.items if ok)
    nfail = sum(1 for _, ok, _ in r.items if not ok)
    r.summary()
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
