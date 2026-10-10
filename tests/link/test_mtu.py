"""Jumbo-safe default MTU — the creators' default and where it stops.

A GNS3 guest that raises its interface MTU past 1500 must not have its frames
silently dropped by the host side: the only MTU gate on the kernel datapath is
the bridge egress check (net/bridge/br_forward.c -> is_skb_forwardable, against
the *egress port's* MTU) — the veth and TUN/TAP transports never drop by MTU on
the normal path (the rcv->mtu check in veth_xdp_xmit is the XDP path). So every
plumbing device a creator brings up gets UBRIDGE_DEFAULT_MTU (65521 — a TAP's
max_mtu, 65535 - ETH_HLEN; veth and bridge accept up to 65535) at creation
time, and the endpoint keeps its own MTU.

What is verified here:

* every creator leaves its plumbing at 65521 — link veth (both ends, both
  host-side), docker create_veth (the host anchor only: the guest end is the
  container's eth0 and keeps the kernel default 1500, because the endpoint
  owns its MTU — raising it inside the container then gets jumbo both ways,
  the host end no longer being the bottleneck), tap create, and the transient
  TAP `bridge add_nio_tap` creates for a free name;
* an attach to a pre-existing device is left strictly alone (the l2-anchor
  §B gate's MTU twin): a TAP set to 9000 by hand keeps 9000;
* the bridge itself is deliberately NOT set: the kernel's br_mtu_auto_adjust()
  (net/bridge/br_if.c) tracks the minimum port MTU, so a bridge of 65521
  ports reports 65521 and admits a 1500 external port by dropping to 1500 —
  the honest value for what it can actually carry;
* end to end: a 9000-byte frame crosses a two-port per-link bridge intact,
  in both directions.

Run under sudo, or `unshare -Urn python3 test_mtu.py`. Beyond the CAP_NET_ADMIN
the whole suite needs, two steps use raw `ip` (setting the pre-existing TAP to
9000 and creating a 1500 dummy port) — the same privilege `sudo`/`unshare`
already provide.
"""
import os
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import Ubridge, Results, iface_mtu, no_residual_link  # noqa: E402

PORT = 13011
JUMBO = 65521
A, B = "jmt-a", "jmt-b"                  # link veth pair
DH, DG = "jmt-dh", "jmt-dg"              # docker create_veth: host / guest end
TAP = "jmt-t"
BT, BTU = "jmt-bt", "jmt-btu"            # bridge add_nio_tap: created / pre-existing
BTBR = "jmt-btb"                         # bridge holding the two TAPs
BR, P1, X1, P2, X2 = "jmt-br", "jmt-p1", "jmt-x1", "jmt-p2", "jmt-x2"
DUMMY = "jmt-lo"                         # 1500-MTU external port

ETYPE = 0x88B5       # IEEE local experimental ethertype 1 — nothing else uses it
ETH_P_ALL = 0x0003
E2E_SIZE = 9000

BINARY = os.environ.get("UBRIDGE_BINARY") or None


def _ip(*args):
    return subprocess.run(["ip"] + list(args), capture_output=True, text=True)


def cleanup(c):
    """Best-effort removal of everything this suite creates (deleting one end
    of a veth pair removes the other)."""
    for dev in (A, P1, P2):
        c.send("link delete %s" % dev)
    c.send("docker delete_veth %s" % DH)
    c.send("bridge delete %s" % BTBR)
    c.send("tap delete %s" % TAP)
    c.send("tap delete %s" % BTU)
    c.send("brctl delete %s" % BR)
    _ip("link", "del", DUMMY)


# --- AF_PACKET inject/sniff (the unshare-safe way to move L2 frames) ---

def raw_sock(dev, timeout=3.0):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((dev, 0))
    s.settimeout(timeout)
    return s


def jumbo_frame(size, tag):
    """A `size`-byte Ethernet frame: unicast dst, the local ethertype, and a
    recognizable tagged payload (minimum 60 bytes, like eth_frame in the
    nio_raw helpers)."""
    payload = (b"JUMBO-" + tag.encode() + b"-") + b"\xa5" * (size - 14)
    frame = (b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" +
             struct.pack("!H", ETYPE) + payload)[:size]
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def recv_etype(s, etype, timeout=3.0):
    """Receive the next frame carrying `etype`, skipping stray traffic."""
    deadline = time.monotonic() + timeout
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None
        s.settimeout(remain)
        try:
            data = s.recv(65536)
        except socket.timeout:
            return None
        if len(data) >= 14 and struct.unpack("!H", data[12:14])[0] == etype:
            return data


# --- the checks ---

def creators(c, r):
    r.check("link veth -> 100", c.code("link veth %s %s" % (A, B)) == "100")
    r.check("link veth: both ends at 65521",
            iface_mtu(A) == JUMBO and iface_mtu(B) == JUMBO,
            "%s / %s" % (iface_mtu(A), iface_mtu(B)))

    r.check("docker create_veth -> 100",
            c.code("docker create_veth %s %s" % (DH, DG)) == "100")
    # Host anchor only (the l2-anchor §B "deliberately untouched" spirit): the
    # guest end is the container's eth0, and its MTU is the endpoint's own
    # choice. The host end at 65521 is what lets that choice work both ways.
    r.check("docker: host end at 65521", iface_mtu(DH) == JUMBO,
            str(iface_mtu(DH)))
    r.check("docker: guest end keeps the kernel default 1500",
            iface_mtu(DG) == 1500, str(iface_mtu(DG)))

    # The opt-in, exactly as a container admin would do it: raise eth0 (= DG)
    # and jumbo crosses the veth in both directions.
    c.send("link set %s up" % DG)
    _ip("link", "set", DG, "mtu", "9000")
    r.check("opt-in: guest end raised to 9000", iface_mtu(DG) == 9000,
            str(iface_mtu(DG)))
    sd, sh = raw_sock(DG), raw_sock(DH)
    try:
        fgd = jumbo_frame(E2E_SIZE, "DG-to-DH")
        sd.send(fgd)
        got = recv_etype(sh, ETYPE)
        r.check("opt-in: 9000-byte frame guest -> host intact",
                got == fgd,
                "got %s bytes" % len(got) if got is not None else "timeout")
        fhd = jumbo_frame(E2E_SIZE, "DH-to-DG")
        sh.send(fhd)
        got = recv_etype(sd, ETYPE)
        r.check("opt-in: 9000-byte frame host -> guest intact",
                got == fhd,
                "got %s bytes" % len(got) if got is not None else "timeout")
    finally:
        sd.close()
        sh.close()

    r.check("tap create -> 100", c.code("tap create %s" % TAP) == "100")
    r.check("tap: at 65521", iface_mtu(TAP) == JUMBO, str(iface_mtu(TAP)))

    # The fifth creator: bridge add_nio_tap's create-if-missing TAP.
    r.check("bridge create -> 100", c.code("bridge create %s" % BTBR) == "100")
    r.check("bridge add_nio_tap on a free name -> 100",
            c.code("bridge add_nio_tap %s %s" % (BTBR, BT)) == "100")
    r.check("transient TAP: at 65521", iface_mtu(BT) == JUMBO, str(iface_mtu(BT)))

    # The gate: a pre-existing device must not be re-MTU'd on attach.
    r.check("fixture: tap create -> 100", c.code("tap create %s" % BTU) == "100")
    _ip("link", "set", BTU, "mtu", "9000")
    r.check("fixture: admin MTU 9000 in place", iface_mtu(BTU) == 9000,
            str(iface_mtu(BTU)))
    r.check("bridge add_nio_tap on the pre-existing TAP -> 100",
            c.code("bridge add_nio_tap %s %s" % (BTBR, BTU)) == "100")
    r.check("attach left the admin MTU alone (§B gate)",
            iface_mtu(BTU) == 9000, str(iface_mtu(BTU)))


def bridge_auto_adjust(c, r):
    """The bridge is never MTU'd by ubridge; the kernel derives min(port MTU)."""
    r.check("brctl create -> 100", c.code("brctl create %s" % BR) == "100")
    r.check("fixture: veth ports -> 100",
            c.code("link veth %s %s" % (P1, X1)) == "100" and
            c.code("link veth %s %s" % (P2, X2)) == "100")
    r.check("brctl addif -> 100",
            c.code("brctl addif %s %s" % (BR, P1)) == "100" and
            c.code("brctl addif %s %s" % (BR, P2)) == "100")
    r.check("bridge tracks its ports: 65521", iface_mtu(BR) == JUMBO,
            str(iface_mtu(BR)))

    # A 1500 external port must pull the bridge down with it (br_mtu_min).
    _ip("link", "add", DUMMY, "type", "dummy")
    r.check("fixture: dummy at 1500", iface_mtu(DUMMY) == 1500,
            str(iface_mtu(DUMMY)))
    r.check("brctl addif dummy -> 100",
            c.code("brctl addif %s %s" % (BR, DUMMY)) == "100")
    r.check("bridge drops to the port minimum: 1500", iface_mtu(BR) == 1500,
            str(iface_mtu(BR)))
    r.check("brctl delif dummy -> 100",
            c.code("brctl delif %s %s" % (BR, DUMMY)) == "100")
    r.check("bridge back at 65521", iface_mtu(BR) == JUMBO, str(iface_mtu(BR)))


def e2e_jumbo(c, r):
    """A 9000-byte frame crosses the bridge intact, both directions."""
    for dev in (BR, P1, X1, P2, X2):
        c.send("link set %s up" % dev)
    time.sleep(0.2)

    sx1, sx2 = raw_sock(X1), raw_sock(X2)
    try:
        f12 = jumbo_frame(E2E_SIZE, "X1-to-X2")
        sx1.send(f12)
        got = recv_etype(sx2, ETYPE)
        r.check("%d-byte frame X1 -> X2 intact" % E2E_SIZE,
                got == f12,
                "got %s bytes" % len(got) if got is not None else "timeout")

        f21 = jumbo_frame(E2E_SIZE, "X2-to-X1")
        sx2.send(f21)
        got = recv_etype(sx1, ETYPE)
        r.check("%d-byte frame X2 -> X1 intact" % E2E_SIZE,
                got == f21,
                "got %s bytes" % len(got) if got is not None else "timeout")
    finally:
        sx1.close()
        sx2.close()
    for dev in (BR, X1, X2):
        c.send("link set %s down" % dev)


def main():
    r = Results()

    with Ubridge(port=PORT, binary=BINARY) as ub:
        c = ub.connect()
        try:
            cleanup(c)
            if c.code("link veth %s %s" % (A, B)) != "100":
                # prove the binary can create devices before blaming MTU
                print("  [SKIP] every check -- cannot create a veth pair "
                      "(no CAP_NET_ADMIN for the binary in use? run under "
                      "sudo or `unshare -Urn`, or point UBRIDGE_BINARY at "
                      "the setcap'd binary)")
                cleanup(c)
                return 1
            c.send("link delete %s" % A)

            print("--- creators ---")
            creators(c, r)
            print("--- bridge auto-adjust ---")
            bridge_auto_adjust(c, r)
            print("--- end-to-end jumbo ---")
            e2e_jumbo(c, r)
        finally:
            cleanup(c)
            c.close()

    r.check("no residual interfaces", no_residual_link("jmt"))
    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
