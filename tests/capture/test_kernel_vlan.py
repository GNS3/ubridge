"""VLAN-tag regression for kernel captures (gns3-server#3116).

With vlan_filtering, the 802.1Q tag of bridge-forwarded frames travels as
skb metadata at both AF_PACKET tap points (the frame data is headerless),
so without PACKET_AUXDATA a kernel capture wrote such frames 4 bytes
short. This suite drives two vlan-filtering bridges joined by a veth
trunk, injects raw tagged frames (one injector per side so both the TX and
the RX tap directions are exercised), and asserts — byte for byte — that
every captured frame equals the frame as injected:

- single 802.1Q tag (vid 10, bridge protocol 0x8100);
- QinQ with both tags sharing TPID 0x8100 (outer 10 / inner 20): the
  kernel only manages the outer tag in metadata, the inner stays in the
  data, and a wrong re-insertion point mangles the IP header instead;
- QinQ with an 802.1ad outer tag (bridge vlan_protocol 802.1ad), skipped
  with a NOTE when the kernel rejects the attribute.

The byte-for-byte comparison is the point: len/ethertype/vid checks are
blind to a 2-byte shift of the IP header, which is exactly the bug a
first cut of the fix had. Stdlib only. Requires CAP_NET_ADMIN/CAP_NET_RAW
— run under sudo (or unshare -Urn). Uses the in-repo ./ubridge.
"""
import os
import shutil as _sh
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubcapv-"
PORT = 13048
TRUNK_A = PREFIX + "ta"          # br1 side of the trunk (captured)
TRUNK_B = PREFIX + "tb"          # br2 side of the trunk
HOST_E = PREFIX + "he"           # br1 host port; peer he2 is the TX injector
HOST_E2 = PREFIX + "he2"
HOST_C = PREFIX + "hc"           # br2 host port; peer hc2 is the RX injector
HOST_C2 = PREFIX + "hc2"
BR1 = PREFIX + "br1"
BR2 = PREFIX + "br2"
PCAP = "/tmp/ubcapv.pcap"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))
VID = 10
INNER_VID = 20
N = 5

# bridge(8) sits in /sbin on most distros — see tests/brctl/test_vlan.py.
BRIDGE = _sh.which("bridge")
if BRIDGE is None:
    BRIDGE = next((p for p in ("/sbin/bridge", "/usr/sbin/bridge", "/usr/local/sbin/bridge")
                   if os.path.isfile(p) and os.access(p, os.X_OK)), None)


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _icmp(seq, src):
    payload = bytes(i & 0xFF for i in range(56))
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, seq) + payload
    icmp = icmp[:2] + struct.pack("!H", _csum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 84, 0x2345, 0, 64, 1, 0,
                     bytes([10, 97, 0, 1]), bytes([10, 97, 0, 2]))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return ip + icmp   # the caller builds the Ethernet header (incl. tags)


def _csum(d):
    if len(d) % 2:
        d += b"\0"
    s = sum(struct.unpack("!%dH" % (len(d) // 2), d))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _tagged(seq, src, tags):
    """ICMP frame behind the given tag chain: [(tpid, vid), ...]."""
    eth = (b"\xff" * 6 + src
           + b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in tags)
           + b"\x08\x00")
    return eth + _icmp(seq, src)


def _seq(frame):
    """ICMP echo sequence, behind any tag chain — identifies a frame."""
    off = 12
    while frame[off:off + 2] in (b"\x81\x00", b"\x88\xa8", b"\x91\x00"):
        off += 4
    off += 2          # the inner ethertype
    return struct.unpack("!H", frame[off + 20 + 6:off + 20 + 8])[0]   # ip hdr + icmp hdr


def _no_ipv6(*ifaces):
    """The veth/bridge bring-up floods IPv6 multicast; the pcaps must contain
    only the injected frames, so switch IPv6 off on each fixture interface
    (before bring-up). Per-interface, never all/default: this suite shares
    its network namespace with every other suite in the CI job, and a
    netns-wide disable_ipv6 outlives the test — it silently broke the
    nio_raw GSO suite later in the job (its IPv6 address add failed, its
    bind then died with EADDRNOTAVAIL). Per-interface settings die with
    the interface."""
    for k in ifaces:
        try:
            with open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % k, "w") as f:
                f.write("1")
        except OSError:
            pass


SRC_TX = bytes([0xaa, 0x01]) + b"\x11" * 4     # injected into br1 -> out trunk (TX tap)
SRC_RX = bytes([0xaa, 0x02]) + b"\x22" * 4     # injected into br2 -> trunk ingress (RX tap)

SCENARIOS = [
    ("single-8100",     [],                              [(0x8100, VID)]),
    ("qinq-8100-8100",  [],                              [(0x8100, VID), (0x8100, INNER_VID)]),
    ("qinq-88a8-8100",  ["vlan_protocol", "802.1ad"],    [(0x88A8, VID), (0x8100, INNER_VID)]),
]


def _topology(br_args):
    subprocess.run(["ip", "link", "add", BR1, "type", "bridge", "vlan_filtering", "1"] + br_args,
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", BR2, "type", "bridge", "vlan_filtering", "1"] + br_args,
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", TRUNK_A, "type", "veth", "peer", "name", TRUNK_B],
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", HOST_E, "type", "veth", "peer", "name", HOST_E2],
                   capture_output=True, check=True)
    subprocess.run(["ip", "link", "add", HOST_C, "type", "veth", "peer", "name", HOST_C2],
                   capture_output=True, check=True)
    _no_ipv6(BR1, BR2, TRUNK_A, TRUNK_B, HOST_E, HOST_E2, HOST_C, HOST_C2)
    for br in (BR1, BR2):
        subprocess.run(["ip", "link", "set", br, "up"], capture_output=True, check=True)
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


def _inject_sockets():
    s_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s_tx.bind((HOST_E2, 0))
    s_rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s_rx.bind((HOST_C2, 0))
    return s_tx, s_rx


def main():
    r = Results()
    if os.geteuid() != 0 or BRIDGE is None:
        print("  [SKIP] needs root + bridge(8) (run under sudo or unshare -Urn)")
        return 0
    if os.path.exists(PCAP):
        os.remove(PCAP)

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                for name, br_args, tags in SCENARIOS:
                    frames = [_tagged(i, SRC_TX, tags) for i in range(1, N + 1)]
                    frames += [_tagged(100 + i, SRC_RX, tags) for i in range(1, N + 1)]
                    _teardown()   # previous scenario's bridges would collide by name
                    time.sleep(0.2)
                    try:
                        _topology(br_args)
                    except subprocess.CalledProcessError:
                        r.check("%s: topology skipped (kernel rejects %s)" % (name, br_args or "defaults"),
                                name == "qinq-88a8-8100")
                        continue

                    if os.path.exists(PCAP):
                        os.remove(PCAP)
                    r.check("%s: capture start" % name,
                            c.code("capture start_kernel %s %s" % (TRUNK_A, PCAP)) == "100")
                    s_tx, s_rx = _inject_sockets()
                    try:
                        # one direction at a time, matching the frames built above
                        for i in range(1, N + 1):
                            s_tx.send(_tagged(i, SRC_TX, tags))
                            time.sleep(0.02)
                        for i in range(1, N + 1):
                            s_rx.send(_tagged(100 + i, SRC_RX, tags))
                            time.sleep(0.02)
                        time.sleep(0.8)
                    finally:
                        s_tx.close()
                        s_rx.close()
                    r.check("%s: capture stop" % name,
                            c.code("capture stop_kernel %s" % TRUNK_A) == "100")

                    got = _pcap_frames(PCAP)
                    want = set(frames)
                    # every injected frame (both directions) captured byte-identically.
                    # The pcap may also hold kernel-side extras (occasional GRO
                    # concatenations, IGMP reports the bridges emit) — those are
                    # delivered to the tap exactly as libpcap would see them, so
                    # the assertions are: full byte-identical coverage of the
                    # injected set, and no tag-stripped copy anywhere.
                    matched = {f for f in got if f in want}
                    missing = sorted(_seq(f) for f in want - matched)
                    r.check("%s: %d/%d injected frames byte-identical (both directions)"
                            % (name, len(matched), len(want)),
                            matched == want,
                            "matched=%d got=%d missing seqs=%s"
                            % (len(matched), len(got), missing))
                    # and nothing degraded: no frame equal to the tag-stripped view
                    stripped = {f[0:12] + f[16:] for f in want}
                    r.check("%s: no tagless 4-byte-short copies in the pcap" % name,
                            not (set(got) & stripped))
            finally:
                c.send("capture stop_kernel")
                c.close()
    finally:
        _teardown()

    npass = sum(1 for _, ok, _ in r.items if ok)
    nfail = sum(1 for _, ok, _ in r.items if not ok)
    r.summary()
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
