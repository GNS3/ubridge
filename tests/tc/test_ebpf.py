"""eBPF stateful impairment (P6 part B): nth_drop / quota_drop / window_drop /
flow_drop — one SCHED_CLS program per interface at clsact egress prio 1,
configured entirely through its CFG map.

Split by capability, self-degrading:
- `tc capabilities` reports ebpf=0 when the program cannot load (no
  CAP_BPF — e.g. inside unshare -Urn, or an old kernel). Everything that
  needs the load then self-skips, and the enable commands must reply the
  exact spec-210 string.
- The validation/error contract (203/204/207) is checked unconditionally,
  as are static checks of the committed instruction array (no loops at all;
  the hand-unrolled catch-up stays small) — the verifier's non-root path
  cannot bound a loop and rejects the whole program at its jump-sequence
  budget, and that failure is invisible from a root run, so the shape is
  pinned statically instead (see doc/tc.md).
- With CAP_BPF (real sudo) the behavioral section runs: exact nth pattern
  (frame sequence in the payload), byte-quota threshold, window in/out/
  expiry/recurring-period/jitter, flow-hash determinism against a Python
  mirror of the program's Jenkins fold, counter reset on re-set, teardown
  on last off / tc reset.

Stdlib only. Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubeb-"
PORT = 13184
IFN = PREFIX + "d0"
VA = PREFIX + "va"
VB = PREFIX + "vb"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))

CAPS_RE = re.compile(
    r"^100-netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;"
    r"ebpf=([01]);cbpf=1;ebpf_modes=(nth,quota,window,flow)$")
NO_CAP_210 = ("210-uBridge lacks CAP_BPF (setcap cap_bpf,cap_net_admin,cap_net_raw=ep) "
              "and the kernel requires it for stateful filters")

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


def _mac(name):
    out = _run([IP, "-o", "link", "show", name]).stdout
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    return m.group(1)


def _frame(seq, dst, src, payload_prefix=b"ebpf-probe"):
    p = payload_prefix + b"#" + bytes([seq])
    eth = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + b"\x08\x00"
    ipy = bytes([0x45, 0, 0, 20 + 8 + len(p), 0, 0, 0, 0, 64, 1, 0, 0]) + b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02"
    icmp = b"\x08\x00\x00\x00" + p
    return eth + ipy + icmp


def _jenkins(mask, dst=None, src=None, proto=None):
    """Python mirror of the program's Jenkins one-at-a-time flow hash."""
    h = 0
    M = 0xFFFFFFFF

    def fold(b):
        nonlocal h
        h = (h + b) & M
        h = (h + (h << 10)) & M
        h ^= h >> 6

    if mask & 0x2 and dst:
        for b in bytes.fromhex(dst.replace(":", "")):
            fold(b)
    if mask & 0x1 and src:
        for b in bytes.fromhex(src.replace(":", "")):
            fold(b)
    if mask & 0x10 and proto is not None:
        fold(proto)
    h = (h + (h << 3)) & M
    h ^= h >> 11
    h = (h + (h << 15)) & M
    return h


INSNS_H = os.path.join(os.path.dirname(REPO_UBRIDGE), "src", "tc_ebpf_insns.h")
BPF_C = os.path.join(os.path.dirname(REPO_UBRIDGE), "src", "tc_impair.bpf.c")
INSNS_RE = re.compile(r"\.code = (0x[0-9a-fA-F]+), \.dst_reg = \d+, \.src_reg = \d+, "
                      r"\.off = (-?\d+), \.imm = (-?\d+)")
STEP_RE = re.compile(r"start = win_step\(now, start, cur\);")
MAX_STEPS = 32                            # unrolled catch-up steps per packet


def _is_jump(code):
    return (code & 0x07) in (0x05, 0x06)  # BPF_JMP / BPF_JMP32


def _parse_insns():
    """[(code, off, imm)] in program order, from the committed array."""
    with open(INSNS_H) as f:
        return [(int(c, 16), int(off), int(imm))
                for c, off, imm in INSNS_RE.findall(f.read())]


def static_verifier_checks(r):
    """Pin the two shapes the verifier's NON-root path requires.

    Production ubridge never runs as root (it carries CAP_BPF), and that
    path does not keep a loop counter's constant bound: it sees a wide
    scalar, unrolls the loop as if unbounded, and piles up unexplored branch
    states until `push_stack()` trips BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192) —
    E2BIG, "The sequence of N jumps is too complex" (N = pending states),
    the WHOLE program rejected and all four modes down with it. The same
    binary run as root verifies fine, and this host's kernel is lenient
    about the loop anyway — so the shape is pinned statically here, where
    no capability is needed and every run checks it.
    """
    insns = _parse_insns()
    loops = [n for n, (code, off, _i) in enumerate(insns)
             if _is_jump(code) and off < 0]
    r.check("static: no loops (backward jumps) in the committed program",
            not loops, "%d backward jumps in %d insns" % (len(loops), len(insns)))

    with open(BPF_C) as f:
        src = f.read()
    m = re.search(r"#define\s+WIN_CATCHUP_STEPS\s+(\d+)", src)
    steps = int(m.group(1)) if m else 0
    calls = len(STEP_RE.findall(src))
    r.check("static: catch-up unrolled %d times (<=%d), no loop" % (calls, MAX_STEPS),
            0 < steps <= MAX_STEPS and calls == steps,
            "WIN_CATCHUP_STEPS %d, %d win_step() calls" % (steps, calls))

    with open(INSNS_H) as f:
        m = re.search(r"#define\s+TC_IMPAIR_INSNS\s+(\d+)", f.read())
    r.check("static: committed array length matches TC_IMPAIR_INSNS",
            bool(m) and int(m.group(1)) == len(insns),
            "%d insns, header says %s" % (len(insns), m.group(1) if m else "?"))


def main():
    r = Results()

    static_verifier_checks(r)

    if TC is None:
        print("  [SKIP] needs the `tc` tool for kernel-state checks")
        return 0 if r.summary() else 1

    _run([IP, "link", "add", IFN, "type", "dummy"])
    _run([IP, "link", "set", IFN, "up"])
    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                caps = c.send("tc capabilities")
                m = CAPS_RE.match(caps)
                r.check("capabilities shape (ebpf=[01];cbpf=1;ebpf_modes=...)", m is not None, caps)
                # build fact, orthogonal to the runtime ebpf probe: the list
                # is emitted even when the program cannot load here
                r.check("ebpf_modes listed regardless of ebpf",
                        m is not None and m.group(2) == "nth,quota,window,flow", caps)
                ebpf_ok = bool(m and m.group(1) == "1")
                if not ebpf_ok:
                    print("  [INFO] ebpf=0 here (no CAP_BPF) — behavioral section self-skips")

                # --- validation contract (no kernel interaction needed) -----
                for bad, expect in [
                    ("tc nth_drop %s 0" % IFN, "204-invalid nth value '0' (1-1000000)"),
                    ("tc nth_drop %s abc" % IFN, "204-invalid nth value 'abc' (1-1000000)"),
                    ("tc nth_drop %s 1000001" % IFN, "204-invalid nth value '1000001' (1-1000000)"),
                    ("tc quota_drop %s 0 10" % IFN, "204-invalid quota bytes '0'"),
                    ("tc quota_drop %s 10x 10" % IFN, "204-invalid quota bytes '10x'"),
                    ("tc quota_drop %s 100 101" % IFN, "204-invalid quota percent '101' (0-100)"),
                    ("tc window_drop %s 10 0 50" % IFN, "204-invalid window length '0'"),
                    ("tc window_drop %s abc 100 50" % IFN, "204-invalid window start 'abc'"),
                    ("tc window_drop %s 10 100 101" % IFN, "204-invalid window percent '101' (0-100)"),
                    ("tc window_drop %s 10 100 50 50" % IFN, "204-invalid window period '50' (>= outage length)"),
                    ("tc window_drop %s 10 100 50 abc" % IFN, "204-invalid window period 'abc' (>= outage length)"),
                    ("tc window_drop %s 10 100 50 5000 abc" % IFN, "204-invalid window jitter 'abc' (0-1000000000)"),
                    ("tc window_drop %s 10 100 50 5000 1000000001" % IFN, "204-invalid window jitter '1000000001' (0-1000000000)"),
                    ("tc flow_drop %s 32 7" % IFN, "204-invalid flow mask '32' (1-31: 1=src 2=dst 4=sport 8=dport 16=proto)"),
                    ("tc flow_drop %s 0 7" % IFN, "204-invalid flow mask '0' (1-31: 1=src 2=dst 4=sport 8=dport 16=proto)"),
                    ("tc flow_drop %s 3 0" % IFN, "204-invalid flow target '0' (>=1)"),
                ]:
                    res = c.send(bad)
                    r.check("%s -> %s" % (bad.split(" ", 2)[2], expect[:24]), res == expect, res)

                r.check("argc: nth -> 203", c.send("tc nth_drop %s" % IFN).startswith("203-"), "")
                r.check("argc: quota set -> 203", c.send("tc quota_drop %s 100" % IFN).startswith("203-"), "")
                r.check("argc: window set -> 203", c.send("tc window_drop %s 10 100" % IFN).startswith("203-"), "")
                r.check("argc: window 7 tokens -> 203",
                        c.send("tc window_drop %s 0 100 50 5000 100 x" % IFN).startswith("203-"), "")
                r.check("argc: off + extra -> 203", c.send("tc window_drop %s off x" % IFN).startswith("203-"), "")
                r.check("missing iface -> 207",
                        c.send("tc nth_drop %s-nope 5" % IFN).startswith("207-"), "")
                r.check("off before any enable -> 100",
                        c.send("tc nth_drop %s off" % IFN) == "100-nth_drop off on %s" % IFN, "")

                if not ebpf_ok:
                    # without CAP_BPF every enable must reply the exact 210
                    for cmd in ("tc nth_drop %s 5" % IFN,
                                "tc quota_drop %s 1000 10" % IFN,
                                "tc window_drop %s 0 1000 50" % IFN,
                                "tc window_drop %s 0 1000 50 2000" % IFN,
                                "tc window_drop %s 0 1000 50 2000 300" % IFN,
                                "tc flow_drop %s 3 7" % IFN):
                        res = c.send(cmd)
                        r.check("%s -> exact 210" % cmd.split(" ", 1)[1], res == NO_CAP_210, res)
                    r.check("off still idempotent after 210",
                            c.send("tc quota_drop %s off" % IFN) == "100-quota_drop off on %s" % IFN, "")
                    # netem/bpf_drop unaffected by the ebpf failure
                    r.check("netem unaffected",
                            c.send("tc netem set %s delay 10" % IFN).startswith("100-"), "")
                    r.check("bpf_drop unaffected",
                            c.send('tc bpf_drop add %s 10 "icmp"' % IFN).startswith("100-"), "")
                    q = _run([TC, "qdisc", "show", "dev", IFN]).stdout
                    f = _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout
                    r.check("no prio-1 filter left after 210", "pref 1 " not in f, f.strip()[:80])
                    r.check("reset still full-restores",
                            c.send("tc reset %s" % IFN).startswith("100-"), "")
                    return 0 if r.summary() else 1

                # ==========================================================
                # ebpf=1 from here on (real CAP_BPF)
                # ==========================================================
                r.check("nth 3 -> 100", c.send("tc nth_drop %s 3" % IFN) == "100-nth_drop set on %s" % IFN, "")
                f = _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout
                r.check("prio-1 bpf filter attached", "pref 1 bpf" in f, f.strip()[:100])

                # second mode reuses the same program (still one filter).
                # `tc filter show` prints TWO lines per filter (header +
                # handle detail) — count the handle lines, not "pref 1 bpf".
                c.send("tc quota_drop %s 100000000 0" % IFN)
                f = _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout
                r.check("second mode: still exactly one filter",
                        f.count("pref 1 bpf chain 0 handle") == 1, f.strip()[:100])

                # last mode off tears the filter down
                c.send("tc nth_drop %s off" % IFN)
                r.check("second-last off keeps filter",
                        "pref 1 bpf" in _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout, "")
                c.send("tc quota_drop %s off" % IFN)
                f = _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout
                r.check("last mode off removes filter", "pref 1 bpf" not in f, f.strip()[:80])

                # off is idempotent once gone
                r.check("off idempotent", c.send("tc flow_drop %s off" % IFN) == "100-flow_drop off on %s" % IFN, "")

                # reset removes an active impairment program too
                c.send("tc nth_drop %s 5" % IFN)
                c.send("tc netem set %s delay 10" % IFN)
                r.check("reset with ebpf+netem", c.send("tc reset %s" % IFN).startswith("100-"), "")
                q = _run([TC, "qdisc", "show", "dev", IFN]).stdout
                f = _run([TC, "filter", "show", "dev", IFN, "egress"]).stdout
                r.check("reset: filter and netem gone",
                        "pref 1 " not in f and "netem" not in q, (q + f).strip()[:80])
            finally:
                c.send("tc reset %s" % IFN)
                c.close()

        # --- behavioral on a veth (needs ebpf=1) --------------------------
        _run([IP, "link", "add", VA, "type", "veth", "peer", "name", VB])
        try:
            for n in (VA, VB):
                open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % n, "w").write("1")
                _run([IP, "link", "set", n, "up"])
            mac_a, mac_b = _mac(VA), _mac(VB)
            rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            rx.bind((VA, 0))
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            tx.bind((VB, 0))

            def inject_seq(dst, src, n):
                for i in range(1, n + 1):
                    try:
                        tx.send(_frame(i, dst, src))
                    except OSError:
                        pass

            def drain(t=1.2):
                got = []
                try:
                    while True:
                        rx.settimeout(t)
                        data, _ = rx.recvfrom(2048)
                        if b"ebpf-probe#" in data:
                            got.append(data[data.index(b"ebpf-probe#") + 11])
                except socket.timeout:
                    pass
                return got    # payload seq bytes

            with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
                c = ub.connect()
                try:
                    flen = len(_frame(1, mac_a, mac_b))

                    # nth exact pattern: seq % 3 == 0 dropped
                    c.send("tc nth_drop %s 3" % VB)
                    inject_seq(mac_a, mac_b, 12)
                    got = drain()
                    r.check("behavioral: nth 3 exact pattern",
                            got == [i for i in range(1, 13) if i % 3 != 0],
                            "received %s" % got)

                    # re-set restarts the count (counter reset per apply)
                    c.send("tc nth_drop %s 3" % VB)
                    inject_seq(mac_a, mac_b, 2)          # 1,2 pass
                    c.send("tc nth_drop %s 3" % VB)       # count restarts
                    inject_seq(mac_a, mac_b, 3)          # 1,2 pass, 3 drops
                    got = drain()
                    r.check("behavioral: nth re-set resets counter",
                            sorted(got) == [1, 1, 2, 2],
                            "received %s" % sorted(got))
                    c.send("tc nth_drop %s off" % VB)

                    # quota: quota = 2 frames, pct 100 -> first passes, rest drop
                    c.send("tc quota_drop %s %d 100" % (VB, 2 * flen))
                    inject_seq(mac_a, mac_b, 10)
                    got = drain()
                    r.check("behavioral: quota bytes threshold exact (1/10)",
                            sorted(got) == [1], "received %s (flen %d)" % (sorted(got), flen))
                    c.send("tc quota_drop %s off" % VB)

                    # quota pct 0 after threshold: nothing drops
                    c.send("tc quota_drop %s %d 0" % (VB, flen))
                    inject_seq(mac_a, mac_b, 5)
                    got = drain()
                    r.check("behavioral: quota pct 0 passes all (5/5)",
                            sorted(got) == [1, 2, 3, 4, 5], "received %s" % sorted(got))
                    c.send("tc quota_drop %s off" % VB)

                    # window starting now, 10s long, pct 100 -> all dropped
                    c.send("tc window_drop %s 0 10000 100" % VB)
                    inject_seq(mac_a, mac_b, 10)
                    got = drain()
                    r.check("behavioral: window active drops all (0/10)",
                            got == [], "received %s" % got)
                    c.send("tc window_drop %s off" % VB)

                    # window starting in 5s: nothing drops yet
                    c.send("tc window_drop %s 5000 100 100" % VB)
                    inject_seq(mac_a, mac_b, 10)
                    got = drain()
                    r.check("behavioral: future window passes all (10/10)",
                            sorted(got) == list(range(1, 11)), "received %s" % sorted(got))
                    c.send("tc window_drop %s off" % VB)

                    # single window EXPIRES: 300ms outage, then pass again
                    # (the B.2 "outside the window packets pass" contract)
                    c.send("tc window_drop %s 0 300 100" % VB)
                    inject_seq(mac_a, mac_b, 10)
                    got = drain(0.5)
                    r.check("behavioral: single window active drops (0/10)",
                            got == [], "received %s" % got)
                    time.sleep(0.6)                      # past the outage
                    inject_seq(mac_a, mac_b, 10)
                    got = drain(0.8)
                    r.check("behavioral: single window EXPIRED passes (10/10)",
                            sorted(got) == list(range(1, 11)), "received %s" % sorted(got))
                    c.send("tc window_drop %s off" % VB)

                    # recurring: 800ms outage every 2400ms — drop inside
                    # cycles 1 and 2, pass in the gap between them
                    # (anchored on the monotonic clock, not on sleeps)
                    c.send("tc window_drop %s 0 800 100 2400" % VB)
                    t0 = time.monotonic()
                    inject_seq(mac_a, mac_b, 10)         # outage 1 [0, 0.8)
                    got1 = drain(0.4)
                    time.sleep(max(0, (t0 + 2.7) - time.monotonic()))
                    inject_seq(mac_a, mac_b, 10)         # outage 2 [2.4, 3.2)
                    got2 = drain(0.4)
                    time.sleep(max(0, (t0 + 4.2) - time.monotonic()))
                    inject_seq(mac_a, mac_b, 10)         # gap [3.2, 4.8)
                    got3 = drain(0.8)
                    r.check("behavioral: recurring drops in cycles, passes in gap",
                            got1 == [] and got2 == [] and sorted(got3) == list(range(1, 11)),
                            "cyc1 %s cyc2 %s gap %s" % (got1, got2, sorted(got3)))
                    c.send("tc window_drop %s off" % VB)

                    # jittered schedule (outage 200±190ms every 600±190ms):
                    # bursts land at random phase — both dropped and passed
                    # bursts must occur (determinism of jitter 0 is covered
                    # by the fixed-period check above)
                    c.send("tc window_drop %s 0 200 100 600 190" % VB)
                    dropped_bursts = passed_bursts = 0
                    for _ in range(16):
                        inject_seq(mac_a, mac_b, 3)
                        if drain(0.28):
                            passed_bursts += 1
                        else:
                            dropped_bursts += 1
                    c.send("tc window_drop %s off" % VB)
                    r.check("behavioral: jitter schedule drops AND passes bursts",
                            dropped_bursts >= 2 and passed_bursts >= 2,
                            "dropped %d passed %d" % (dropped_bursts, passed_bursts))

                    # flow: src-MAC hash mod 4 == 0 drops; picked via the
                    # Python mirror of the program's Jenkins fold
                    victims, survivors = [], []
                    for i in range(1, 32):
                        mac = "02:00:00:00:01:%02x" % i
                        if _jenkins(0x1, src=mac) % 4 == 0:
                            victims.append(mac)
                        else:
                            survivors.append(mac)
                        if len(victims) >= 2 and len(survivors) >= 2:
                            break
                    r.check("flow: mirror hash picked test MACs",
                            len(victims) >= 2 and len(survivors) >= 2, "")
                    c.send("tc flow_drop %s 1 4" % VB)
                    got_all = []
                    for mac in victims + survivors:
                        inject_seq(mac_a, mac, 3)
                        got_all += [(mac, s) for s in drain(0.8)]
                    got_macs = {mac for mac, _ in got_all}
                    r.check("behavioral: flow drops exactly hash-0 src MACs",
                            got_macs == set(survivors),
                            "received from %s" % sorted(got_macs))
                    c.send("tc flow_drop %s off" % VB)

                    # composition: the impair filter must not shield packets
                    # from lower-prio bpf_drop filters — the program returns
                    # TC_ACT_UNSPEC (continue), not TC_ACT_OK (which would end
                    # the prio chain in direct-action mode)
                    c.send("tc nth_drop %s 2" % VB)
                    r.check("composition: bpf_drop added",
                            c.send('tc bpf_drop add %s 10 "greater 0"' % VB).startswith("100-"), "")
                    inject_seq(mac_a, mac_b, 6)
                    got = drain()
                    r.check("composition: bpf_drop sees the survivors (0/6)",
                            got == [], "received %s" % got)
                    c.send("tc bpf_drop flush %s" % VB)
                    c.send("tc nth_drop %s 3" % VB)      # deterministic again
                    inject_seq(mac_a, mac_b, 6)
                    got = drain()
                    r.check("composition: after flush the nth pattern is back",
                            sorted(got) == [1, 2, 4, 5], "received %s" % sorted(got))
                    c.send("tc nth_drop %s off" % VB)

                    # state ownership: a mode command carries one atomic cfg
                    # write and the program applies the counter resets itself
                    # (userspace no longer read-modify-writes CNT).  An
                    # unrelated window set/off between the quota arming and
                    # the traffic must not disturb the byte tally.
                    c.send("tc quota_drop %s %d 100" % (VB, 3 * flen))
                    c.send("tc window_drop %s 0 50 0" % VB)   # unrelated set, pct 0
                    c.send("tc window_drop %s off" % VB)
                    inject_seq(mac_a, mac_b, 6)               # 1,2 pass; 3+ over quota
                    got = drain()
                    r.check("state: quota cutoff survives interleaved window commands",
                            sorted(got) == [1, 2], "received %s" % sorted(got))
                    c.send("tc quota_drop %s off" % VB)

                    # and an unrelated command mid-outage must not end it
                    c.send("tc window_drop %s 0 3000 100" % VB)
                    inject_seq(mac_a, mac_b, 4)
                    r.check("state: window outage drops (0/4)", drain() == [], "")
                    c.send("tc quota_drop %s 1000000 0" % VB)  # unrelated
                    inject_seq(mac_a, mac_b, 4)
                    r.check("state: outage survives an unrelated mode command",
                            drain() == [], "")
                    c.send("tc window_drop %s off" % VB)
                    c.send("tc quota_drop %s off" % VB)

                    # restart recovery: a SIGKILL leaves the prio-1 filter
                    # attached to the kernel; a fresh daemon must clear it on
                    # `off` and re-arm it on enable (instead of lying "off"
                    # and EEXISTing on the next enable)
                    with Ubridge(port=PORT + 3, binary=REPO_UBRIDGE) as ub_r:
                        cr = ub_r.connect()
                        cr.send("tc nth_drop %s 3" % VB)
                        ub_r.proc.kill()
                    f = _run([TC, "filter", "show", "dev", VB, "egress"]).stdout
                    r.check("restart: stale prio-1 filter survives the kill",
                            "pref 1 bpf" in f, f.strip()[:80])
                    with Ubridge(port=PORT + 4, binary=REPO_UBRIDGE) as ub_r2:
                        cr = ub_r2.connect()
                        r.check("restart: off clears the stale filter",
                                cr.send("tc nth_drop %s off" % VB).startswith("100-"), "")
                        f = _run([TC, "filter", "show", "dev", VB, "egress"]).stdout
                        r.check("restart: filter gone after off",
                                "pref 1 bpf" not in f, f.strip()[:80])
                        r.check("restart: re-enable after stale state",
                                cr.send("tc nth_drop %s 3" % VB).startswith("100-"), "")
                        f = _run([TC, "filter", "show", "dev", VB, "egress"]).stdout
                        r.check("restart: filter attached again",
                                "pref 1 bpf" in f, f.strip()[:80])
                        cr.send("tc reset %s" % VB)
                        cr.close()
                finally:
                    c.send("tc reset %s" % VB)
                    c.close()
        finally:
            _run([IP, "link", "del", VA])
    finally:
        _run([IP, "link", "del", IFN])

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
