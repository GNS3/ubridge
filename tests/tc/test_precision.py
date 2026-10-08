"""F-precision tier (kernel-impairment spec F): the statistical assertions
that need real traffic volumes and a timing budget — the structural
correctness of every keyword is already proven by the other suites
(byte-compare, exact patterns), so what remains is "does the kernel
actually apply the statistics we asked for":

- gemodel loss within ±5 percentage points of the target (p=30,
  r=100, 1-h=100 — independent-ish per-packet loss, N=2000)
- rate within ±10% of the configured bandwidth, measured as received
  byte throughput (10mbit, ~1.4 KB frames; the span excludes the first
  frame so burst credit cannot skew it)
- delay+jitter+reorder observability: median delay inside
  delay±jitter, delay mdev (std) of the same order as the jitter, and
  arrival-order inversions from the reordering
- netem seed determinism: identical seeds must produce the IDENTICAL
  drop bitmap across a reset + re-set (two full runs)

Frames are injected raw on the veth egress (AF_PACKET), sequenced in the
payload, and timestamped on receive; IPv6 is disabled on the test veth so
the kernel's Router Solicitations cannot pollute the statistics. Tolerances
are ~5 sigma wide so a loaded CI runner passes honestly.

Requires CAP_NET_ADMIN and a few seconds of patience. Stdlib only.
Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubpx-"
PORT = 13204
VA = PREFIX + "va"
VB = PREFIX + "vb"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))

MARK = b"px-probe"

import shutil
IP = shutil.which("ip") or "/usr/sbin/ip"


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _mac(name):
    out = _run([IP, "-o", "link", "show", name]).stdout
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    return m.group(1)


def _frame(seq, dst, src, payload):
    p = payload + MARK + struct.pack("<I", seq & 0xFFFFFFFF)
    eth = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + b"\x08\x00"
    total = 20 + 8 + len(p)
    ipy = (bytes([0x45, 0]) + struct.pack(">H", total)
           + bytes([0, 0, 0, 0, 64, 1, 0, 0]) + b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02")
    icmp = b"\x08\x00\x00\x00" + p
    return eth + ipy + icmp


def main():
    r = Results()

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

        small = _frame(0, mac_a, mac_b, b"")            # 14+20+8+4+8 = 54 B
        fat = _frame(0, mac_a, mac_b, b"P" * 1400)      # 14+20+8+1404 = 1446 B
        flen_fat = len(fat)

        def inject_p(n, payload, gap=0.0):
            """Send n sequenced frames; returns {seq: send monotonic ts}."""
            sent = {}
            for i in range(1, n + 1):
                try:
                    tx.send(_frame(i, mac_a, mac_b, payload))
                    sent[i] = time.monotonic()
                except OSError:
                    pass
                if gap:
                    time.sleep(gap)
            return sent

        def drain(t=1.5):
            """[(seq, recv monotonic ts)] — payload-filtered."""
            got = []
            try:
                while True:
                    rx.settimeout(t)
                    data, _ = rx.recvfrom(2048)
                    idx = data.find(MARK)
                    if idx >= 0:
                        seq = struct.unpack_from("<I", data, idx + len(MARK))[0]
                        got.append((seq, time.monotonic()))
            except socket.timeout:
                pass
            return got

        def start_reader():
            """Receive CONCURRENTLY with an injection: a qdisc with no delay
            releases every survivor as one immediate burst, and a receive
            buffer that cannot hold the burst counts its own drops as netem
            loss (measured: a 128 KB rmem inflated a 30% target to 86%).
            Returns (live, stop, thread); `live` collects (seq, ts)."""
            live, stop = [], threading.Event()

            def run():
                while not stop.is_set():
                    try:
                        rx.settimeout(0.2)
                        data, _ = rx.recvfrom(2048)
                        idx = data.find(MARK)
                        if idx >= 0:
                            live.append((struct.unpack_from("<I", data, idx + len(MARK))[0],
                                         time.monotonic()))
                    except socket.timeout:
                        pass

            th = threading.Thread(target=run)
            th.start()
            return live, stop, th

        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                def fresh(params):
                    """Fresh qdisc per case — netem re-set MERGES attr-carried
                    options, so statistics must not accumulate across cases."""
                    c.send("tc reset %s" % VB)
                    drain(0.6)
                    return c.send("tc netem set %s %s" % (VB, params)).startswith("100-")

                # --- gemodel loss within ±5pp of target --------------------
                # Steady-state drop rate of the kernel's Gilbert-Elliot
                # (loss_gilb_ell: drops happen ONLY in the BAD state — the
                # GOOD->BAD transition packet itself passes) follows from
                # the 2-state Markov flux balance pi_G*p = pi_B*r:
                #   rate = (1-h) * p / (p + r)
                # so p=43, r=100, 1-h=100 targets 43/143 = 30.07%.
                # Receive concurrently with a lightly paced injection: with
                # no delay the survivors arrive as a burst, and an unpaced
                # Python sender starves the reader thread long enough to
                # overflow a small socket buffer (see start_reader).
                N = 2000
                p_, r_, one_minus_h = 0.43, 1.0, 1.0
                target_pct = 100.0 * one_minus_h * p_ / (p_ + r_)
                r.check("gemodel: set p=43 r=100 1-h=100",
                        fresh("limit %d loss gemodel 43 100 100" % (N + 100)), "")
                live, stop, th = start_reader()
                inject_p(N, b"", gap=0.0003)
                time.sleep(0.5)          # delivery is immediate; a short tail
                stop.set()
                th.join()
                got = {seq for seq, _ in live}
                lost_pct = 100.0 * (N - len(got)) / N
                r.check("gemodel: measured loss %.1f%% within %.1f±5pp" % (lost_pct, target_pct),
                        abs(lost_pct - target_pct) <= 5.0,
                        "received %d of %d (%.1f%% lost)" % (len(got), N, lost_pct))

                # --- rate within ±10% of the configured bandwidth ----------
                # 10mbit; measure the span between FIRST and LAST received
                # frame so startup burst credit cannot skew the result
                N = 1500
                r.check("rate: set 10mbit",
                        fresh("limit %d rate 10mbit" % (N + 100)), "")
                # Receive concurrently with the injection, like the gemodel
                # case: a serial drain after the fact overflows a small rmem
                # (its drops would read as rate loss) and timestamps the
                # reads, not the kernel arrivals.
                live, stop, th = start_reader()
                inject_p(N, b"P" * 1400)
                deadline = time.monotonic() + 8.0
                while len(live) < N and time.monotonic() < deadline:
                    time.sleep(0.05)
                time.sleep(0.3)          # tail
                stop.set()
                th.join()
                got = list(live)
                if len(got) != N:
                    r.check("rate: all frames received", False,
                            "received %d of %d" % (len(got), N))
                else:
                    t0 = min(t for _, t in got)
                    t1 = max(t for _, t in got)
                    measured_mbit = 8.0 * (N - 1) * flen_fat / (t1 - t0) / 1e6
                    r.check("rate: measured %.2f mbit within 10±10%%" % measured_mbit,
                            9.0 <= measured_mbit <= 11.0,
                            "%.2f mbit over %.2f s (%d B frames)" % (measured_mbit, t1 - t0, flen_fat))

                # --- delay + jitter + reorder observable -------------------
                # Receive CONCURRENTLY with the paced injection: per-frame
                # delay must be (kernel arrival - send); draining after the
                # fact would timestamp the reads, not the arrivals.
                N = 200
                r.check("reorder: set delay 100 jitter 40 reorder 25",
                        fresh("delay 100 jitter 40 reorder 25"), "")
                live, stop, th = start_reader()
                sent = inject_p(N, b"", gap=0.005)
                time.sleep(0.5)          # let the delay tail arrive
                stop.set()
                th.join()
                got = live
                if len(got) != N:
                    r.check("reorder: all frames received", False,
                            "received %d of %d" % (len(got), N))
                else:
                    delays_ms = [1000.0 * (t - sent[seq]) for seq, t in got]
                    med = statistics.median(delays_ms)
                    mdev = statistics.pstdev(delays_ms)
                    seqs = [seq for seq, _ in got]
                    inversions = sum(1 for i in range(len(seqs) - 1) if seqs[i + 1] < seqs[i])
                    late = sum(1 for d in delays_ms if d >= 55.0) / N
                    r.check("reorder: median delay %.0fms in [50,150]" % med,
                            50.0 <= med <= 150.0, "mdev %.0fms, late frac %.2f" % (mdev, late))
                    r.check("reorder: delay mdev %.0fms >= 15 (jitter observable)" % mdev,
                            mdev >= 15.0, "delays min/med/max %.0f/%.0f/%.0f" % (
                                min(delays_ms), med, max(delays_ms)))
                    r.check("reorder: arrival inversions >= 10 (got %d)" % inversions,
                            inversions >= 10, "late-arriving fraction %.2f" % late)

                # --- seed determinism: identical drop bitmap ----------------
                N = 500

                def seeded_run():
                    c.send("tc reset %s" % VB)
                    drain(0.6)
                    res = c.send("tc netem set %s loss 50 seed 42" % VB)
                    assert res.startswith("100-"), res
                    # receive concurrently, like the gemodel/rate cases: with
                    # no delay the survivors arrive as a burst, and a serial
                    # drain on a small rmem drops its own frames — its drops
                    # would contaminate the bitmap being compared
                    live, stop, th = start_reader()
                    inject_p(N, b"")
                    time.sleep(1.0)
                    stop.set()
                    th.join()
                    return {seq for seq, _ in live}

                got1 = seeded_run()
                got2 = seeded_run()
                dropped = N - len(got1)
                r.check("seed: identical drop bitmap across runs",
                        got1 == got2 and len(got1) > 0,
                        "run1 %d / run2 %d received" % (len(got1), len(got2)))
                r.check("seed: loss ~50%% non-degenerate (dropped %d of %d)" % (dropped, N),
                        100 <= dropped <= 400, "dropped %d" % dropped)
            finally:
                c.send("tc reset %s" % VB)
                c.close()
    finally:
        _run([IP, "link", "del", VA])

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
