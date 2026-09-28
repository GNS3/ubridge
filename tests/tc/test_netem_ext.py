"""netem keyword extensions (P6a): rate / reorder / gemodel / distribution /
seed / limit / correl, plus `tc capabilities`.

The strongest check is a byte-compare: the same parameters set through
ubridge on one dummy and through the real `tc` CLI on another must produce
byte-identical TCA_OPTIONS in the kernel (RTM_GETQDISC dump). The kernel
re-serializes qdisc options itself, so identical bytes mean identical state.
One exception: the kernel picks a RANDOM PRNG seed when none was given and
dumps it — the seed attribute is stripped from the comparison unless the
case pins it.

Also covers behavioral semantics on a veth pair with raw AF_PACKET
injection (gemodel extremes, limit overflow, one-sided delay bound) and the
validation/error contract. Stdlib only. Requires CAP_NET_ADMIN and the `tc`
CLI (test-only dependency — ubridge talks netlink directly).

Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import re
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubtx-"
PORT = 13042
IFN = PREFIX + "ub0"     # driven by ubridge
IFT = PREFIX + "tc0"     # driven by the real tc CLI
VA = PREFIX + "va"       # veth pair for behavioral checks
VB = PREFIX + "vb"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))

RTM_NEWQDISC = 36
RTM_GETQDISC = 38
TCA_OPTIONS = 2
TCA_NETEM_PRNG_SEED = 14
TCA_NETEM_DELAY_DIST = 2

import shutil
TC = shutil.which("tc")
if not TC:
    for p in ("/usr/sbin/tc", "/sbin/tc"):
        if os.access(p, os.X_OK):
            TC = p
            break
IP = shutil.which("ip") or "/usr/sbin/ip"


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _tc_qdisc_replace(ifname, params):
    return _run([TC, "qdisc", "replace", "dev", ifname, "root", "netem"] + params)


def qshow(ifname):
    return _run([TC, "qdisc", "show", "dev", ifname]).stdout


def _align(n):
    return (n + 3) & ~3


def get_options(ifindex):
    """RTM_GETQDISC dump -> TCA_OPTIONS payload bytes of the root qdisc.

    (The dump ends with an NLMSG_ERROR(err=0) ack, not NLMSG_DONE; a dump
    with RTM_GETRULE=34 looks superficially the same but returns routing
    rules — use the right message type.)
    """
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.bind((0, 0))
    s.settimeout(3)
    tcmsg = struct.pack("BBHiIII", 0, 0, 0, ifindex, 0, 0xFFFFFFFF, 0)
    hdr = struct.pack("IHHII", 16 + 20, RTM_GETQDISC, 0x301, 0, 0)  # REQUEST|DUMP
    s.send(hdr + tcmsg)
    opts = None
    while True:
        d = s.recv(65536)
        off, done = 0, False
        while off + 16 <= len(d):
            ln, t, fl, seq, pid = struct.unpack_from("IHHII", d, off)
            if t == 2:
                done = True
                break
            if t == 3:
                err = struct.unpack_from("i", d, off + 16)[0]
                if err != 0:
                    raise RuntimeError("netlink error %d" % err)
                off += _align(ln)
                continue
            if t == RTM_NEWQDISC:
                ifidx = struct.unpack_from("i", d, off + 20)[0]
                a = off + 16 + 20  # nlmsghdr + tcmsg
                while a + 4 <= off + ln:
                    l, ty = struct.unpack_from("HH", d, a)
                    if l < 4:
                        break
                    if ifidx == ifindex and (ty & 0x3FFF) == TCA_OPTIONS:
                        opts = d[a + 4: a + l]
                    a += _align(l)
            off += _align(ln)
        if done or opts is not None:
            break
    s.close()
    return opts


def attrs_of(opts):
    """(type, payload) list after the 24-byte qopt prefix."""
    out, off = [], 24
    while off + 4 <= len(opts):
        l, ty = struct.unpack_from("HH", opts, off)
        if l < 4:
            break
        out.append((ty & 0x3FFF, opts[off + 4: off + l]))
        off += _align(l)
    return out


def _mac(name):
    """veth MAC via `ip -o link` (sysfs stays pinned to the init netns)."""
    out = _run([IP, "-o", "link", "show", name]).stdout
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    return m.group(1)


def _frame(dst, src, payload=b"netem-ext-probe"):
    eth = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + b"\x08\x00"
    ipy = bytes([0x45, 0, 0, 20 + 8 + len(payload), 0, 0, 0, 0, 64, 1, 0, 0]) + b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02"
    icmp = b"\x08\x00\x00\x00" + payload
    frame = eth + ipy + icmp
    return frame


def main():
    r = Results()

    if TC is None:
        print("  [SKIP] needs the `tc` tool (ships with iproute2) to verify")
        print("         kernel qdisc state; not in PATH, /usr/sbin or /sbin")
        return 0

    for n in (IFN, IFT):
        _run([IP, "link", "add", n, "type", "dummy"])
        _run([IP, "link", "set", n, "up"])
    i_ub, i_tc = socket.if_nametoindex(IFN), socket.if_nametoindex(IFT)

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                # --- byte-compare vs the real tc CLI -----------------------
                # percent values chosen where our integer percent encoding
                # matches tc's rint() byte-for-byte (0/25/50/100)
                cases = [
                    ("delay+jitter+loss", "delay 100 jitter 10 loss 25",
                     ["delay", "100ms", "10ms", "loss", "25%"]),
                    ("loss/dup correl", "delay 10 loss 25 correl 50 dup 25 correl 50",
                     ["delay", "10ms", "loss", "25%", "50%", "duplicate", "25%", "50%"]),
                    ("reorder correl gap", "delay 100 jitter 10 reorder 25 correl 50 gap 5",
                     ["delay", "100ms", "10ms", "reorder", "25%", "50%", "gap", "5"]),
                    ("reorder default gap", "delay 100 reorder 25",
                     ["delay", "100ms", "reorder", "25%"]),
                    ("gemodel", "delay 10 loss gemodel 25 50 25",
                     ["delay", "10ms", "loss", "gemodel", "25%", "50%", "25%"]),
                    ("rate mbit", "delay 10 rate 10mbit",
                     ["delay", "10ms", "rate", "10mbit"]),
                    ("rate bps (bytes/s)", "delay 10 rate 512kbps",
                     ["delay", "10ms", "rate", "512kbps"]),
                    ("rate gbit (RATE64 path)", "delay 10 rate 40gbit",
                     ["delay", "10ms", "rate", "40gbit"]),
                    ("distribution normal", "delay 100 jitter 10 distribution normal",
                     ["delay", "100ms", "10ms", "distribution", "normal"]),
                    ("distribution paretonormal", "delay 100 jitter 10 distribution paretonormal",
                     ["delay", "100ms", "10ms", "distribution", "paretonormal"]),
                    ("seed+limit", "delay 10 seed 42 limit 2000",
                     ["delay", "10ms", "seed", "42", "limit", "2000"]),
                ]
                for label, ub_params, tc_params in cases:
                    res = c.send("tc netem set %s %s" % (IFN, ub_params))
                    rt = _tc_qdisc_replace(IFT, tc_params)
                    ok = res.startswith("100-") and rt.returncode == 0
                    r.check("%s: accepted" % label, ok, res if not res.startswith("100-") else rt.stderr.strip()[:80])
                    a, b = get_options(i_ub), get_options(i_tc)
                    # strip the random PRNG seed the kernel invents when the
                    # case doesn't pin one (pinned seeds must match exactly)
                    seeded = "seed" in ub_params.split()
                    strip = lambda o: [(t, p) for (t, p) in attrs_of(o) if t != TCA_NETEM_PRNG_SEED]
                    same = strip(a) == strip(b) and (a == b if seeded else len(a) == len(b))
                    r.check("%s: kernel bytes == tc CLI" % label, same,
                            "ub %d bytes / tc %d bytes" % (len(a), len(b)))

                # --- readable kernel state via tc qdisc show ----------------
                # (unpinned seed is random, so substring checks)
                c.send("tc netem set %s delay 100 jitter 10 reorder 25 correl 50 gap 5" % IFN)
                q = qshow(IFN)
                r.check("show: reorder + correl + gap", "reorder 25% 50%" in q and " gap 5" in q, q.strip()[:120])
                c.send("tc netem set %s delay 100 jitter 10 loss gemodel 25 50 25" % IFN)
                q = qshow(IFN)
                r.check("show: gemodel p/r/1-h", "loss gemodel p 25% r 50% 1-h 25%" in q, q.strip()[:120])
                c.send("tc netem set %s delay 10 rate 10mbit seed 42 limit 2000" % IFN)
                q = qshow(IFN)
                r.check("show: rate + seed + limit",
                        "rate 10Mbit" in q and "seed 42" in q and "limit 2000" in q, q.strip()[:120])

                # uniform sends no distribution table at all
                c.send("tc netem set %s delay 100 jitter 10 distribution uniform" % IFN)
                types = [t for t, p in attrs_of(get_options(i_ub))]
                r.check("uniform: no DELAY_DIST attr", TCA_NETEM_DELAY_DIST not in types, str(types))

                # dup correl alone is NOT dropped (tc CLI loses it; we keep it)
                c.send("tc netem set %s delay 10 dup 25 correl 50" % IFN)
                r.check("dup correl alone survives", "duplicate 25% 50%" in qshow(IFN), qshow(IFN).strip()[:120])

                # --- capabilities --------------------------------------------
                r.check("capabilities string",
                        c.send("tc capabilities") ==
                        "100-netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;ebpf=0;cbpf=0",
                        c.send("tc capabilities"))

                # --- error contract ------------------------------------------
                r.check("reorder without delay -> 204 'reorder requires delay'",
                        c.send("tc netem set %s reorder 25" % IFN) == "204-reorder requires delay",
                        c.send("tc netem set %s reorder 25" % IFN))
                for bad, why in [
                    ("rate 10x", "bad unit"), ("rate 10", "no unit"), ("rate 101gbit", "above 100gbit"),
                    ("rate -5mbit", "negative"), ("rate abc", "not a number"),
                ]:
                    r.check("rate %s -> 204" % why,
                            c.send("tc netem set %s %s" % (IFN, bad)).startswith("204-"),
                            c.send("tc netem set %s %s" % (IFN, bad)))
                r.check("unknown distribution -> 204 exact",
                        c.send("tc netem set %s delay 10 distribution weibull" % IFN) ==
                        "204-unknown distribution 'weibull'",
                        c.send("tc netem set %s delay 10 distribution weibull" % IFN))
                for bad in ["seed abc", "seed 4294967296", "seed -1",
                            "limit 0", "limit 1000001", "limit abc",
                            "reorder 25 gap 0", "reorder 25 gap 1001",
                            "loss 5 correl 101", "loss 101", "dup 101",
                            "loss gemodel 101", "loss gemodel 1 101", "loss gemodel 1 2 101"]:
                    r.check("'%s' -> 204" % bad,
                            c.send("tc netem set %s delay 10 %s" % (IFN, bad)).startswith("204-"),
                            c.send("tc netem set %s delay 10 %s" % (IFN, bad)))
                r.check("loss twice -> 204",
                        c.send("tc netem set %s loss 5 loss 7" % IFN).startswith("204-"),
                        c.send("tc netem set %s loss 5 loss 7" % IFN))
                r.check("loss + gemodel -> 204",
                        c.send("tc netem set %s loss 5 loss gemodel 1 2 3" % IFN).startswith("204-"),
                        c.send("tc netem set %s loss 5 loss gemodel 1 2 3" % IFN))
                r.check("gemodel 4th value -> 204",
                        c.send("tc netem set %s loss gemodel 1 2 3 4" % IFN).startswith("204-"),
                        c.send("tc netem set %s loss gemodel 1 2 3 4" % IFN))
                r.check("correl not after loss/dup/reorder -> 204",
                        c.send("tc netem set %s delay 10 correl 5" % IFN).startswith("204-"),
                        c.send("tc netem set %s delay 10 correl 5" % IFN))
                r.check("dangling value -> 203",
                        c.send("tc netem set %s delay" % IFN).startswith("203-"),
                        c.send("tc netem set %s delay" % IFN))
                # 34 tokens (max 32)
                long_cmd = "tc netem set %s %s" % (IFN, " ".join(["jitter", "1"] * 16))
                r.check("too many params -> 203", c.send(long_cmd).startswith("203-"), long_cmd[:60])
                r.check("missing iface -> 207",
                        c.send("tc netem set %s-nope delay 10" % IFN).startswith("207-"),
                        c.send("tc netem set %s-nope delay 10" % IFN))
            finally:
                c.send("tc reset %s" % IFN)
                c.close()

        # --- behavioral: veth + raw injection ------------------------------
        # netem sits on VB (the injector's egress); frames arrive at VA.
        # IPv6 must be disabled on both ends first: the kernel's Router
        # Solicitations traverse VB's qdisc too (filling a small limit and
        # shifting gemodel's state machine).
        _run([IP, "link", "add", VA, "type", "veth", "peer", "name", VB])
        try:
            for n in (VA, VB):
                open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % n, "w").write("1")
                _run([IP, "link", "set", n, "up"])
            mac_a, mac_b = _mac(VA), _mac(VB)
            rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            rx.bind((VA, 0))
            rx.settimeout(3)
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            tx.bind((VB, 0))

            import time

            def inject(n=1):
                """Send n probe frames; returns how many were accepted.
                ENOBUFS is the sender-side face of a qdisc-limit drop;
                netem loss drops are silent (send succeeds, frame vanishes)."""
                sent = 0
                for _ in range(n):
                    try:
                        tx.send(_frame(mac_a, mac_b))
                        sent += 1
                    except OSError:
                        pass
                return sent

            def drain(t=1.0):
                """Collect probe frames until quiet (payload-filtered)."""
                got = []
                try:
                    while True:
                        rx.settimeout(t)
                        data, _ = rx.recvfrom(2048)
                        if b"netem-ext-probe" in data:
                            got.append(data)
                except socket.timeout:
                    pass
                return got

            with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
                c = ub.connect()
                try:
                    # fresh qdisc per case (netem re-set MERGES attr-carried
                    # options rather than clearing them — kernel netem_change)
                    def fresh(params):
                        c.send("tc reset %s" % VB)
                        drain(0.6)
                        res = c.send("tc netem set %s %s" % (VB, params))
                        return res.startswith("100-")

                    # delay: one frame must not arrive early
                    r.check("behavioral: set delay 300", fresh("delay 300"), "")
                    t0 = time.monotonic()
                    inject(1)
                    got = drain(2.0)
                    dt = time.monotonic() - t0
                    r.check("behavioral: delay >= 250ms", len(got) == 1 and dt >= 0.25,
                            "arrived after %.0f ms" % (dt * 1000))

                    # limit: delay 400ms + limit 2, burst of 10 -> only 2 queue
                    r.check("behavioral: set delay 400 limit 2", fresh("delay 400 limit 2"), "")
                    sent = inject(10)
                    got = drain(2.0)
                    r.check("behavioral: limit 2 drops overflow (10 -> 2)",
                            sent == 2 and len(got) == 2,
                            "queued %d, received %d" % (sent, len(got)))

                    # gemodel all-drop: p=100 (go bad), r=0 (never recover),
                    # 1-h=100 (drop while bad); the first packet passes (the
                    # good->bad transition itself is not a drop)
                    r.check("behavioral: set gemodel 100 0 100", fresh("delay 10 loss gemodel 100 0 100"), "")
                    sent = inject(10)
                    got = drain(1.5)
                    r.check("behavioral: gemodel all-drop (<=1 of 10)",
                            sent == 10 and len(got) <= 1,
                            "sent %d, received %d" % (sent, len(got)))

                    # gemodel p=0: never leaves the good state -> nothing drops
                    r.check("behavioral: set gemodel 0 0 0", fresh("delay 10 loss gemodel 0 0 0"), "")
                    sent = inject(10)
                    got = drain(1.5)
                    r.check("behavioral: gemodel p=0 drops none (10/10)",
                            sent == 10 and len(got) == 10,
                            "sent %d, received %d" % (sent, len(got)))
                finally:
                    c.send("tc reset %s" % VB)
                    c.close()
        finally:
            _run([IP, "link", "del", VA])
    finally:
        for n in (IFN, IFT):
            _run([IP, "link", "del", n])

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
