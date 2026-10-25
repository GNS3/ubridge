"""Regression: nio_linux_raw relays wire-sized TCP segments.

An AF_PACKET socket sees TCP frames as the kernel holds them: merged by GRO or
LRO, or not yet split by TSO. They are up to 64 KB long and carry a partial
checksum. Relayed byte for byte, a node drops every one of them (a GNS3 cloud
on a host NIC ran at a few hundred kbit/s). nio_linux_raw must cut them back
into segments and complete the checksums, as the kernel does when it forwards.

A veth pair reproduces this without GRO. TCP from a socket in another network
namespace leaves vgso1 as TSO frames, and veth hands them to vgso0 unsplit.
The test first confirms this with its own AF_PACKET socket on vgso0. Then it
streams a known byte pattern over IPv4 and IPv6 and checks what the bridge
relays over UDP:
  * every frame of the stream fits the MTU;
  * every frame has valid IP and TCP checksums;
  * the payloads, placed by sequence number, are exactly the bytes sent.

Run under sudo (or `unshare -Urn`): veth, netns and AF_PACKET need caps.
"""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from helpers import Ubridge, Results, HOST, ubridge_binary, sh, free_udp_port, ETH_P_ALL

PORT = 13182
A, B = "vgso0", "vgso1"
MTU = 1500
TCP_PORT = 15001
SIZE = 512 * 1024
CHUNK = 64 * 1024

FAMILIES = [
    ("IPv4", socket.AF_INET, "10.199.0.1", "10.199.0.2", 24),
    ("IPv6", socket.AF_INET6, "fd00:c7::1", "fd00:c7::2", 64),
]

STREAM = bytes((i * 7 + i // 251) & 0xFF for i in range(SIZE))

# The client runs in the other namespace and sends STREAM. Each chunk leaves
# as a few large TSO frames. The pauses let the bridge drain its socket
# between bursts (a tap that overflows loses frames only for the relay; TCP
# never notices).
CLIENT = (
    "import socket, sys, time\n"
    "data = bytes((i * 7 + i // 251) & 0xFF for i in range(%d))\n" % SIZE
    + "s = socket.create_connection((sys.argv[1], %d))\n" % TCP_PORT
    + "for i in range(0, len(data), %d):\n" % CHUNK
    + "    s.sendall(data[i:i + %d])\n" % CHUNK
    + "    time.sleep(0.02)\n"
    + "s.close()\n"
)


class Reader(threading.Thread):
    """Collects whatever a socket receives until stopped."""

    def __init__(self, sock):
        super().__init__(daemon=True)
        self.sock = sock
        self.sock.settimeout(0.2)
        self.frames = []
        self.done = threading.Event()

    def run(self):
        while not self.done.is_set():
            try:
                self.frames.append(self.sock.recv(1 << 17))
            except socket.timeout:
                pass

    def stop(self):
        self.done.set()
        self.join()
        self.sock.close()


def wait_netns(pid):
    """Wait until `unshare -n` has moved the child into its own netns."""
    own = os.readlink("/proc/self/ns/net")
    for _ in range(50):
        try:
            if os.readlink("/proc/%d/ns/net" % pid) != own:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("child %d never left this network namespace" % pid)


def setup():
    """veth A here, B in a child netns, an address on each end per family."""
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "link", "del", A)
    child = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    wait_netns(child.pid)
    ns = ("nsenter", "-t", str(child.pid), "-n")
    r = sh("ip", "link", "add", A, "type", "veth", "peer", "name", B)
    if r.returncode != 0:
        child.kill()
        raise RuntimeError("veth add failed: %s" % r.stderr.strip())
    sh("ip", "link", "set", B, "netns", str(child.pid))
    sh("ip", "link", "set", A, "mtu", str(MTU), "up")
    sh(*ns, "ip", "link", "set", "lo", "up")
    sh(*ns, "ip", "link", "set", B, "mtu", str(MTU), "up")
    for _, family, local, peer, plen in FAMILIES:
        extra = ("nodad",) if family == socket.AF_INET6 else ()
        sh("ip", "addr", "add", "%s/%d" % (local, plen), "dev", A, *extra)
        sh(*ns, "ip", "addr", "add", "%s/%d" % (peer, plen), "dev", B, *extra)
    return child


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def stream_frames(frames, family, src, dst):
    """(frame, l3, l4, end) of each TCP frame from src to dst:TCP_PORT."""
    for f in frames:
        if len(f) < 14:
            continue
        etype = struct.unpack("!H", f[12:14])[0]
        l3 = 14
        if family == socket.AF_INET:
            if etype != 0x0800 or len(f) < l3 + 20 or f[l3 + 9] != 6:
                continue
            if f[l3 + 12:l3 + 16] != src or f[l3 + 16:l3 + 20] != dst:
                continue
            l4 = l3 + (f[l3] & 0x0F) * 4
            end = l3 + struct.unpack("!H", f[l3 + 2:l3 + 4])[0]
        else:
            if etype != 0x86DD or len(f) < l3 + 40 or f[l3 + 6] != 6:
                continue
            if f[l3 + 8:l3 + 24] != src or f[l3 + 24:l3 + 40] != dst:
                continue
            l4 = l3 + 40
            end = l4 + struct.unpack("!H", f[l3 + 4:l3 + 6])[0]
        if len(f) >= l4 + 20 and struct.unpack("!H", f[l4 + 2:l4 + 4])[0] == TCP_PORT:
            yield f, l3, l4, min(end, len(f))


def tcp_csum_ok(f, l3, l4, end, family):
    if family == socket.AF_INET:
        pseudo = f[l3 + 12:l3 + 20] + struct.pack("!BBH", 0, 6, end - l4)
    else:
        pseudo = f[l3 + 8:l3 + 40] + struct.pack("!IxxxB", end - l4, 6)
    return csum(pseudo + f[l4:end]) == 0xFFFF


def run_stream(r, name, family, local, peer, child, relay, sniff):
    first_relayed, first_sniffed = len(relay.frames), len(sniff.frames)
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((local, TCP_PORT))
    srv.listen(1)
    srv.settimeout(10)
    client = subprocess.Popen(["nsenter", "-t", str(child.pid), "-n",
                               sys.executable, "-c", CLIENT, local])
    got = bytearray()
    try:
        conn, _ = srv.accept()
        conn.settimeout(10)
        while True:
            data = conn.recv(65536)
            if not data:
                break
            got += data
        conn.close()
    finally:
        srv.close()
        client.wait(timeout=10)
    time.sleep(0.5)  # let the relay drain

    src, dst = socket.inet_pton(family, peer), socket.inet_pton(family, local)
    merged = [len(f) for f, _, _, _ in stream_frames(sniff.frames[first_sniffed:], family, src, dst)
              if len(f) > 14 + MTU]
    relayed = list(stream_frames(relay.frames[first_relayed:], family, src, dst))

    r.check("%s: stream delivered by TCP" % name, bytes(got) == STREAM,
            "%d of %d bytes" % (len(got), SIZE))
    r.check("%s: AF_PACKET readers see TSO frames (the test reproduces)" % name, merged,
            "largest %d bytes" % max(merged, default=0))
    r.check("%s: frames relayed" % name, relayed)

    oversize = [len(f) for f, _, _, _ in relayed if len(f) > 14 + MTU]
    r.check("%s: no relayed frame over the MTU" % name, not oversize,
            "%d over, largest %d bytes" % (len(oversize), max(oversize, default=0)))
    if family == socket.AF_INET:
        bad_ip = sum(1 for f, l3, l4, _ in relayed if csum(f[l3:l4]) != 0xFFFF)
        r.check("%s: IPv4 header checksums valid" % name, not bad_ip, "%d bad" % bad_ip)
    bad_tcp = sum(1 for f, l3, l4, end in relayed if not tcp_csum_ok(f, l3, l4, end, family))
    r.check("%s: TCP checksums valid" % name, not bad_tcp, "%d of %d bad" % (bad_tcp, len(relayed)))

    # place every payload at its sequence offset
    isn = [struct.unpack("!I", f[l4 + 4:l4 + 8])[0] for f, _, l4, _ in relayed if f[l4 + 13] & 0x02]
    buf, seen, wrong = bytearray(SIZE), bytearray(SIZE), 0
    if isn:
        for f, _, l4, end in relayed:
            payload = f[l4 + (f[l4 + 12] >> 4) * 4:end]
            off = (struct.unpack("!I", f[l4 + 4:l4 + 8])[0] - isn[0] - 1) & 0xFFFFFFFF
            if not payload or off >= SIZE:
                continue
            if STREAM[off:off + len(payload)] != payload:
                wrong += 1
            buf[off:off + len(payload)] = payload
            seen[off:off + len(payload)] = b"\1" * len(payload)
    r.check("%s: relayed payloads match the stream at their offsets" % name, isn and not wrong,
            "%d misplaced" % wrong if isn else "SYN not relayed")
    r.check("%s: relayed payloads cover the whole stream" % name, bytes(buf) == STREAM,
            "%d of %d bytes" % (seen.count(1), SIZE))


def main():
    r = Results()
    child = setup()
    try:
        with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
            c = ub.connect()
            try:
                lp, rp = free_udp_port(), free_udp_port()
                rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 23)
                rx.bind((HOST, rp))
                relay = Reader(rx)
                tap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                tap.bind((A, 0))
                sniff = Reader(tap)
                relay.start()
                sniff.start()

                assert c.code("bridge create nrg") == "100"
                assert c.code("bridge add_nio_linux_raw nrg %s" % A) == "100"
                assert c.code("bridge add_nio_udp nrg %d %s %d" % (lp, HOST, rp)) == "100"
                assert c.code("bridge start nrg") == "100"
                time.sleep(0.3)

                for name, family, local, peer, _ in FAMILIES:
                    run_stream(r, name, family, local, peer, child, relay, sniff)

                relay.stop()
                sniff.stop()
                c.send("bridge stop nrg")
                c.send("bridge delete nrg")
            finally:
                c.close()
    finally:
        sh("ip", "link", "del", A)
        child.kill()
        child.wait()
    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
