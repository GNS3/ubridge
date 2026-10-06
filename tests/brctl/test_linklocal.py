"""Link-local forwarding tests: every addif port carries group_fwd_mask 0xfffd.

A kernel bridge stands in for a cable in GNS3, but br_handle_frame() drops the
IEEE 802.1D reserved range 01:80:c2:00:00:0X by default — LACP, LLDP, EAPOL
never cross a kernel-datapath link.  addif now opens the per-port
IFLA_BRPORT_GROUP_FWD_MASK (0xfffd = everything except MAC PAUSE, which the
kernel rejects and hard-drops anyway), and `setportgroupfwd` exposes the raw
knob as an escape hatch.

T1 transparency matrix, T2 ingress-port semantics, T3 best-effort on write
failure (fault-injection env), T4 re-addif idempotency, T5 value boundary.
Probes are raw AF_PACKET frames with a non-IP ethertype (0x88B5 survives
br_netfilter ingress validation), injected into one veth peer and observed on
the other; sysfs cross-checks run only where sysfs shows this netns (a bare
`unshare -Urn` pins /sys to the init netns — behavioural asserts carry the
suite there).
"""
import os
import socket
import struct
import subprocess
import time

from common import Ubridge, Results, no_residual

BR = "llreg"
PAIRS = [("llrega", "llregap"), ("llregb", "llregbp"), ("llregc", "llregcp")]
PROBE_ET = 0x88B5
SRC = b"\x02\x33\x44\x55\x66\x01"
RX_WINDOW = 0.6


def ll(nibble):
    """A 01:80:c2:00:00:0X destination for the reserved-range probes."""
    return b"\x01\x80\xc2\x00\x00" + bytes([nibble])


MC = b"\x01\x00\x5e\x00\x00\x01"


def pkt_socket(ifname, timeout=RX_WINDOW):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((ifname, 0))
    s.settimeout(timeout)
    return s


def _drain(rx):
    rx.settimeout(0.05)
    try:
        while True:
            rx.recv(4096)
    except socket.timeout:
        pass


def reaches(tx, rx, dst):
    """True if a frame with destination `dst` injected at tx arrives at rx."""
    tx.send(dst + SRC + struct.pack("!H", PROBE_ET) + b"llreg-probe")
    end = time.time() + RX_WINDOW
    while time.time() < end:
        rx.settimeout(max(0.05, end - time.time()))
        try:
            pkt = rx.recv(4096)
        except socket.timeout:
            break
        if pkt[:6] == dst:
            return True
    return False


def sysfs_mask(port):
    """Port group_fwd_mask via sysfs, or None when sysfs shows another netns."""
    try:
        with open("/sys/class/net/%s/brport/group_fwd_mask" % port) as f:
            return f.read().strip()
    except OSError:
        return None


def make_veths():
    # Pre-clean fixtures a crashed run may have left behind.
    for a, _ in PAIRS:
        subprocess.run(["ip", "link", "del", a], capture_output=True)
    for a, p in PAIRS:
        r = subprocess.run(["ip", "link", "add", a, "type", "veth",
                            "peer", "name", p], capture_output=True)
        if r.returncode != 0:
            return False
        subprocess.run(["ip", "link", "set", p, "up"], capture_output=True)
    return True


def del_veths():
    for a, _ in PAIRS:
        subprocess.run(["ip", "link", "del", a], capture_output=True)


def main():
    r = Results()
    if not make_veths():
        print("  [NOTE] no CAP_NET_ADMIN (veth creation failed) — suite skipped")
        return 0
    try:
        with Ubridge(port=13008) as ub:
            c = ub.connect()
            c.send("brctl create %s" % BR)
            # The datapath bridges gns3-server builds are up; match that.
            subprocess.run(["ip", "link", "set", BR, "up"], capture_output=True)

            r.check("addif A -> 100", c.code("brctl addif %s llrega" % BR) == "100")
            r.check("addif B -> 100", c.code("brctl addif %s llregb" % BR) == "100")

            tx = pkt_socket("llregap")
            rx = pkt_socket("llregbp")

            # --- T1: transparency matrix (default mask, both ports 0xfffd) ---
            for name, dst, want in (
                ("multicast control", MC, True),
                ("STP   01:80:c2:00:00:00", ll(0x00), True),
                ("LACP  01:80:c2:00:00:02", ll(0x02), True),
                ("EAPOL 01:80:c2:00:00:03", ll(0x03), True),
                ("LLDP  01:80:c2:00:00:0e", ll(0x0e), True),
                ("edge  01:80:c2:00:00:10 (outside reserved nibble)", ll(0x10), True),
                ("PAUSE 01:80:c2:00:00:01 (kernel hard-drop)", ll(0x01), False),
            ):
                got = reaches(tx, rx, dst)
                r.check("T1 " + name, got == want,
                        "forwarded" if got else "not forwarded")

            m = sysfs_mask("llrega")
            if m is not None:
                # the kernel prints the mask as %#x, not decimal
                r.check("T1 sysfs group_fwd_mask == 0xfffd", m == "0xfffd", m)

            # --- T2: the mask is consulted on the INGRESS port only ---
            r.check("T2 clear mask on ingress port -> 100",
                    c.code("brctl setportgroupfwd %s llrega 0" % BR) == "100")
            r.check("T2 LACP blocked with ingress 0 / egress 0xfffd",
                    not reaches(tx, rx, ll(0x02)))
            r.check("T2 restore via setportgroupfwd 65533 -> 100",
                    c.code("brctl setportgroupfwd %s llrega 65533" % BR) == "100")
            r.check("T2 LACP flows again", reaches(tx, rx, ll(0x02)))

            # --- T5: value boundary — bit 1 (MAC PAUSE) is rejected whole ---
            r.check("T5 0xfffe (bit 1 set) -> error",
                    c.code("brctl setportgroupfwd %s llrega 65534" % BR) != "100")
            r.check("T5 0xffff (bit 1 set) -> error",
                    c.code("brctl setportgroupfwd %s llrega 65535" % BR) != "100")
            r.check("T5 LACP still flows (rejections changed nothing)",
                    reaches(tx, rx, ll(0x02)))
            m = sysfs_mask("llrega")
            if m is not None:
                r.check("T5 sysfs mask still 0xfffd", m == "0xfffd", m)

            # --- T4: re-addif keeps the mask (gns3-server re-attaches links) ---
            second = c.code("brctl addif %s llrega" % BR)
            r.check("T4 re-addif -> 100 or 206 (kernel EBUSY)",
                    second in ("100", "206"), second)
            r.check("T4 LACP still forwarded after re-addif", reaches(tx, rx, ll(0x02)))

            # --- escape hatch + last-writer-wins (a fresh addif re-applies) ---
            r.check("explicit 0 -> 100 (escape hatch)",
                    c.code("brctl setportgroupfwd %s llrega 0" % BR) == "100")
            r.check("explicit 0 blocks LACP (stock kernel behaviour)",
                    not reaches(tx, rx, ll(0x02)))
            r.check("delif -> 100", c.code("brctl delif %s llrega" % BR) == "100")
            r.check("re-addif -> 100", c.code("brctl addif %s llrega" % BR) == "100")
            r.check("re-addif re-applied the 0xfffd default (reconnect story)",
                    reaches(tx, rx, ll(0x02)))

            tx.close()
            rx.close()
            r.check("delif A -> 100", c.code("brctl delif %s llrega" % BR) == "100")
            r.check("delif B -> 100", c.code("brctl delif %s llregb" % BR) == "100")
            r.check("delete bridge -> 100", c.code("brctl delete %s" % BR) == "100")
            c.close()

        # --- T3: best-effort — an injected write failure never fails addif ---
        os.environ["UBRIDGE_TEST_INJECT_FWD_MASK_FAILURE"] = "1"
        try:
            with Ubridge(port=13009) as ub2:
                c2 = ub2.connect()
                c2.send("brctl create llreg2")
                subprocess.run(["ip", "link", "set", "llreg2", "up"],
                               capture_output=True)
                r.check("T3 addif under injected mask failure -> 100",
                        c2.code("brctl addif llreg2 llregc") == "100")
                m = sysfs_mask("llregc")
                if m is not None:
                    # the kernel prints the mask as %#x, not decimal
                    r.check("T3 mask left untouched (0x0)", m == "0x0", m)
                else:
                    print("  [NOTE] sysfs not visible (namespaced run) "
                          "— T3 mask check skipped")
                c2.send("brctl delif llreg2 llregc")
                c2.send("brctl delete llreg2")
                c2.close()
        finally:
            del os.environ["UBRIDGE_TEST_INJECT_FWD_MASK_FAILURE"]
    finally:
        del_veths()

    r.check("no residual bridges", no_residual(prefix="llreg"))
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
