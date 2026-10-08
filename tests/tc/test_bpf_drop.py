"""bpf_drop (P6 part C): classic-BPF match drop on clsact egress.

`tc bpf_drop add <if> <prio> "<expr>"` compiles the expression with libpcap
(DLT_EN10MB) and installs it as a cls_bpf filter with a gact TC_ACT_SHOT
action; `flush` removes exactly the prios uBridge added; `tc reset` has
grown into the full restore (filters -> clsact -> root qdisc).

Oracles, strongest first:
- kernel dump: RTM_GETTFILTER returns the installed filter's TCA_OPTIONS —
  the bytecode must be byte-identical to what the SAME libpcap compiles
  independently (ctypes), and the action must be gact/TC_ACT_SHOT.
- CLI parity: the same bytecode installed through the real `tc` CLI
  (`bpf bytecode '<insns>' action drop`) must dump identically.
- behavioral on a veth: match frames vanish, non-match frames pass,
  several prios OR together, flush restores the flow.

Stdlib + ctypes. Requires CAP_NET_ADMIN and the `tc` CLI (test-only
dependency — ubridge talks netlink directly and links libpcap itself).

Reuses Ubridge / Results from tests/brctl/common.py.
"""
import ctypes
import os
import re
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubtb-"
PORT = 13144
IFN = PREFIX + "ub0"     # driven by ubridge
IFT = PREFIX + "tc0"     # driven by the real tc CLI
VA = PREFIX + "va"       # veth pair for behavioral checks
VB = PREFIX + "vb"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))

RTM_NEWTFILTER = 44
RTM_GETTFILTER = 46
TCA_KIND = 1
TCA_OPTIONS = 2
TCA_BPF_ACT = 1
TCA_BPF_OPS_LEN = 4
TCA_BPF_OPS = 5
TCA_ACT_KIND = 1
TCA_ACT_OPTIONS = 2
TCA_GACT_PARMS = 2      # TCA_GACT_UNSPEC=0, TM=1, PARMS=2
TC_ACT_SHOT = 2
EGRESS_PARENT = 0xFFFFFFF3   # TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)

DLT_EN10MB = 1
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF

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


def _align(n):
    return (n + 3) & ~3


# --------------------------------------------------------------------------
# independent bytecode oracle: the same libpcap, driven via ctypes
# --------------------------------------------------------------------------

class _BPFInsn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _BPFProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.POINTER(_BPFInsn))]


def _load_libpcap():
    for name in ("libpcap.so.1", "libpcap.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


_PCAP = _load_libpcap()
if _PCAP is not None:
    # explicit prototypes: ctypes defaults c_int returns, which truncates pointers
    _PCAP.pcap_open_dead.restype = ctypes.c_void_p
    _PCAP.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
    _PCAP.pcap_compile.restype = ctypes.c_int
    _PCAP.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BPFProgram),
                                   ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    _PCAP.pcap_freecode.argtypes = [ctypes.POINTER(_BPFProgram)]
    _PCAP.pcap_close.argtypes = [ctypes.c_void_p]


def pcap_compile_insns(expr):
    """Compile <expr> against DLT_EN10MB; returns (len, raw insn bytes)."""
    pd = _PCAP.pcap_open_dead(DLT_EN10MB, 65535)
    if not pd:
        raise RuntimeError("pcap_open_dead failed")
    fp = _BPFProgram()
    if _PCAP.pcap_compile(pd, ctypes.byref(fp), expr.encode(), 1,
                          PCAP_NETMASK_UNKNOWN) < 0:
        _PCAP.pcap_close(pd)
        raise RuntimeError("pcap_compile failed for %r" % expr)
    n = fp.bf_len
    insns = b"".join(struct.pack("=HBBI", i.code, i.jt, i.jf, i.k)
                     for i in fp.bf_insns[:n])
    # pcap_freecode zeroes bf_len — read it before freeing
    _PCAP.pcap_freecode(ctypes.byref(fp))
    _PCAP.pcap_close(pd)
    return n, insns


def bytecode_text(insns):
    """ctypes insns -> tc CLI 'bytecode' string ('len,c jt jf k,...')."""
    out = []
    for off in range(0, len(insns), 8):
        code, jt, jf, k = struct.unpack_from("=HBBI", insns, off)
        out.append("%d %d %d %d" % (code, jt, jf, k))
    return "%d,%s" % (len(insns) // 8, ",".join(out))


# --------------------------------------------------------------------------
# kernel-side dump: RTM_GETTFILTER on the clsact egress parent
# --------------------------------------------------------------------------

def get_filters(ifindex):
    """{prio: {"ops_len", "ops", "action", "kind"}} for clsact egress filters."""
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.bind((0, 0))
    s.settimeout(3)
    # family, pad(3), ifindex, handle, parent, info
    tcmsg = struct.pack("BBHiIII", 0, 0, 0, ifindex, 0, EGRESS_PARENT, 0)
    hdr = struct.pack("IHHII", 16 + 20, RTM_GETTFILTER, 0x301, 0, 0)  # REQUEST|DUMP
    s.send(hdr + tcmsg)
    filters = {}
    while True:
        d = s.recv(65536)
        off, done = 0, False
        while off + 16 <= len(d):
            ln, t, fl, seq, pid = struct.unpack_from("IHHII", d, off)
            if t == 2:      # NLMSG_DONE
                done = True
                break
            if t == 3:      # NLMSG_ERROR — err=0 ends the dump on this kernel
                err = struct.unpack_from("i", d, off + 16)[0]
                if err != 0:
                    raise RuntimeError("netlink error %d" % err)
                done = True
                break
            if t == RTM_NEWTFILTER:
                _fam, _p1, _p2, ifidx, _handle, parent, info = struct.unpack_from("BBHiIII", d, off + 16)
                if ifidx == ifindex and parent == EGRESS_PARENT:
                    prio = info >> 16
                    f = {}
                    a = off + 16 + 20
                    while a + 4 <= off + ln:
                        l, ty = struct.unpack_from("HH", d, a)
                        if l < 4:
                            break
                        ty &= 0x3FFF
                        if ty == TCA_OPTIONS:
                            _parse_options(d, a + 4, a + l, f)
                        a += _align(l)
                    # a filter dumps as two messages: the filter itself
                    # (TCA_OPTIONS) and a stats continuation (none) — keep
                    # only the one carrying the options
                    if "ops" in f:
                        filters[prio] = f
            off += _align(ln)
        if done:
            break
    s.close()
    return filters


def _parse_options(d, start, end, f):
    """TCA_OPTIONS payload -> ops_len/ops/action/kind in <f>."""
    a = start
    while a + 4 <= end:
        l, ty = struct.unpack_from("HH", d, a)
        if l < 4:
            break
        ty &= 0x3FFF
        payload = d[a + 4: a + l]
        if ty == TCA_BPF_OPS_LEN:
            f["ops_len"] = struct.unpack_from("=H", payload, 0)[0]
        elif ty == TCA_BPF_OPS:
            f["ops"] = payload
        elif ty == TCA_BPF_ACT:
            _parse_action(payload, f)
        a += _align(l)


def _parse_action(p, f):
    """TCA_BPF_ACT payload: slot 1 -> {TCA_ACT_KIND, TCA_ACT_OPTIONS{GACT_PARMS}}."""
    a = 0
    while a + 4 <= len(p):
        l, ty = struct.unpack_from("HH", p, a)
        if l < 4:
            break
        slot = p[a + 4: a + l]
        if (ty & 0x3FFF) == 1:
            b = 0
            while b + 4 <= len(slot):
                l2, ty2 = struct.unpack_from("HH", slot, b)
                if l2 < 4:
                    break
                ty2 &= 0x3FFF
                inner = slot[b + 4: b + l2]
                if ty2 == TCA_ACT_KIND:
                    f["kind"] = inner.rstrip(b"\0").decode()
                elif ty2 == TCA_ACT_OPTIONS:
                    c = 0
                    while c + 4 <= len(inner):
                        l3, ty3 = struct.unpack_from("HH", inner, c)
                        if l3 < 4:
                            break
                        if (ty3 & 0x3FFF) == TCA_GACT_PARMS:
                            # struct tc_gact: index, capab, action, refcnt, bindcnt
                            f["action"] = struct.unpack_from("=IIiII", inner, c + 4)[2]
                        c += _align(l3)
                b += _align(l2)
        a += _align(l)


def _mac(name):
    out = _run([IP, "-o", "link", "show", name]).stdout
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    return m.group(1)


def _frame(dst, src, payload=b"bpf-drop-probe"):
    eth = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + b"\x08\x00"
    ipy = bytes([0x45, 0, 0, 20 + 8 + len(payload), 0, 0, 0, 0, 64, 1, 0, 0]) + b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02"
    icmp = b"\x08\x00\x00\x00" + payload
    return eth + ipy + icmp


def main():
    r = Results()

    if TC is None:
        print("  [SKIP] needs the `tc` tool (ships with iproute2) to verify")
        print("         kernel filter state; not in PATH, /usr/sbin or /sbin")
        return 0
    if _PCAP is None:
        print("  [SKIP] needs libpcap (ctypes) as the independent compile oracle")
        return 0

    for n in (IFN, IFT):
        _run([IP, "link", "add", n, "type", "dummy"])
        _run([IP, "link", "set", n, "up"])
    i_ub, i_tc = socket.if_nametoindex(IFN), socket.if_nametoindex(IFT)
    expr_a = "ether host 11:22:33:44:55:66"
    expr_b = "icmp"
    expr_c = "tcp port 80"

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                # --- capabilities: cbpf now probed for real ------------------
                # ebpf varies with CAP_BPF (0 under unshare, 1 with it);
                # ebpf_modes is a build constant
                res = c.send("tc capabilities")
                r.check("capabilities: cbpf=1, ebpf=[01], ebpf_modes listed",
                        re.match(r"^100-netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;ebpf=[01];cbpf=1;ebpf_modes=nth,quota,window,flow$", res) is not None,
                        res)

                # --- add: kernel dump == independent libpcap compile --------
                res = c.send('tc bpf_drop add %s 10 "%s"' % (IFN, expr_a))
                r.check("add -> 100 + exact reply",
                        res == "100-bpf_drop filter added on %s (prio 10)" % IFN, res)

                n_a, insns_a = pcap_compile_insns(expr_a)
                f = get_filters(i_ub)
                ok = (10 in f and f[10].get("ops_len") == n_a
                      and f[10].get("ops") == insns_a
                      and f[10].get("kind") == "gact"
                      and f[10].get("action") == TC_ACT_SHOT)
                r.check("kernel bytecode == independent libpcap compile",
                        ok, "dump %s vs %d insns" % (sorted(f), n_a))

                # --- parity with the real tc CLI ----------------------------
                # same bytecode, installed by iproute2, must dump the same
                # (the CLI does not auto-create clsact — attach it first)
                _run([TC, "qdisc", "add", "dev", IFT, "clsact"])
                r.check("tc CLI reference install ok",
                        _run([TC, "filter", "add", "dev", IFT, "egress", "pref", "10",
                              "protocol", "all", "bpf", "bytecode",
                              bytecode_text(insns_a), "action", "drop"]).returncode == 0)
                f_tc = get_filters(i_tc)
                same = (10 in f_tc and f_tc[10].get("ops") == f[10].get("ops")
                        and f_tc[10].get("action") == TC_ACT_SHOT
                        and f_tc[10].get("kind") == "gact")
                r.check("ubridge filter == tc CLI filter (dump parity)", same,
                        "ub %s / tc %s" % (sorted(f), sorted(f_tc)))

                # --- multiple prios ------------------------------------------
                c.send('tc bpf_drop add %s 20 "%s"' % (IFN, expr_b))
                n_b, insns_b = pcap_compile_insns(expr_b)
                f = get_filters(i_ub)
                ok = (sorted(f) == [10, 20] and f[20].get("ops") == insns_b
                      and f[20].get("action") == TC_ACT_SHOT)
                r.check("second prio 20 installed (OR semantics)",
                        ok, "prios %s" % sorted(f))

                # --- re-add at the same prio replaces, no stacking ----------
                c.send('tc bpf_drop add %s 10 "%s"' % (IFN, expr_c))
                n_c, insns_c = pcap_compile_insns(expr_c)
                f = get_filters(i_ub)
                ok = (sorted(f) == [10, 20] and f[10].get("ops") == insns_c)
                r.check("re-add prio 10 replaces (not stacks)",
                        ok, "prios %s, ops %d bytes" % (sorted(f), len(f.get(10, {}).get("ops", b""))))

                # --- error contract ------------------------------------------
                for bad_prio in ("9", "100", "abc", "-1", "10.5"):
                    res = c.send('tc bpf_drop add %s %s "icmp"' % (IFN, bad_prio))
                    r.check("prio %s -> 204" % bad_prio,
                            res == "204-invalid prio value '%s' (10-99)" % bad_prio, res)
                res = c.send('tc bpf_drop add %s 10 "this is not (a filter"')
                r.check("compile fail -> 209 'Cannot compile filter' prefix",
                        res.startswith("209-Cannot compile filter 'this is not (a filter': "), res)
                r.check("unknown verb -> 204",
                        c.send("tc bpf_drop frob %s" % IFN).startswith("204-"), "")
                r.check("add: missing expr -> 203",
                        c.send("tc bpf_drop add %s 10" % IFN).startswith("203-"), "")
                r.check("flush: extra arg -> 203",
                        c.send("tc bpf_drop flush %s now" % IFN).startswith("203-"), "")
                r.check("bare bpf_drop -> 203",
                        c.send("tc bpf_drop").startswith("203-"), "")
                r.check("add: missing iface -> 207",
                        c.send('tc bpf_drop add %s-nope 10 "icmp"' % IFN).startswith("207-"), "")
                r.check("flush: missing iface -> 207",
                        c.send("tc bpf_drop flush %s-nope" % IFN).startswith("207-"), "")

                # --- coexistence with netem (clsact never touches the root) --
                c.send("tc netem set %s delay 10" % IFN)
                q = _run([TC, "qdisc", "show", "dev", IFN]).stdout
                ok = "netem" in q and "clsact" in q
                r.check("netem root + clsact coexist", ok, q.strip()[:100])

                # --- flush: only OUR prios, never clsact/netem --------------
                # a foreign filter at prio 50 (installed by the CLI, unknown
                # to ubridge's registry) must survive a flush
                _, insns_f = pcap_compile_insns("udp")
                _run([TC, "filter", "add", "dev", IFN, "egress", "pref", "50",
                      "protocol", "all", "bpf", "bytecode", bytecode_text(insns_f), "action", "drop"])
                r.check("flush -> 100",
                        c.send("tc bpf_drop flush %s" % IFN).startswith("100-"), "")
                f = get_filters(i_ub)
                ok = sorted(f) == [50]
                r.check("flush removes only tracked prios (foreign prio 50 stays)",
                        ok, "remaining prios %s" % sorted(f))
                q = _run([TC, "qdisc", "show", "dev", IFN]).stdout
                ok = "clsact" in q and "netem" in q
                r.check("flush keeps clsact + netem", ok, q.strip()[:100])
                r.check("flush idempotent",
                        c.send("tc bpf_drop flush %s" % IFN).startswith("100-"), "")

                # --- reset: the full restore ---------------------------------
                c.send('tc bpf_drop add %s 10 "%s"' % (IFN, expr_a))
                _run([TC, "filter", "del", "dev", IFN, "egress", "pref", "50"])
                res = c.send("tc reset %s" % IFN)
                f = get_filters(i_ub)
                q = _run([TC, "qdisc", "show", "dev", IFN]).stdout
                ok = (res.startswith("100-") and not f
                      and "clsact" not in q and "netem" not in q)
                r.check("reset removes filters + clsact + netem", ok,
                        "reply %s, prios %s, qdiscs: %s" % (res[:20], sorted(f), q.strip()[:80]))
                r.check("reset idempotent (clean iface -> 100)",
                        c.send("tc reset %s" % IFN).startswith("100-"), "")
                r.check("reset missing iface -> 207",
                        c.send("tc reset %s-nope" % IFN).startswith("207-"), "")
            finally:
                c.send("tc reset %s" % IFN)
                c.close()

        # --- behavioral: veth + raw injection ------------------------------
        _run([IP, "link", "add", VA, "type", "veth", "peer", "name", VB])
        try:
            for n in (VA, VB):
                open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % n, "w").write("1")
                _run([IP, "link", "set", n, "up"])
            mac_a, mac_b = _mac(VA), _mac(VB)
            other1, other2 = "02:00:00:00:00:99", "02:00:00:00:00:98"
            rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            rx.bind((VA, 0))
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            tx.bind((VB, 0))

            def inject(dst, n=10):
                for _ in range(n):
                    try:
                        tx.send(_frame(dst, mac_b))
                    except OSError:
                        pass

            def drain(t=1.0):
                got = []
                try:
                    while True:
                        rx.settimeout(t)
                        data, _ = rx.recvfrom(2048)
                        if b"bpf-drop-probe" in data:
                            got.append(data)
                except socket.timeout:
                    pass
                return got

            with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
                c = ub.connect()
                try:
                    # match drop: frames TO mac_a dropped, others pass
                    res = c.send('tc bpf_drop add %s 10 "ether dst %s"' % (VB, mac_a))
                    r.check("behavioral: add match filter", res.startswith("100-"), res)
                    inject(mac_a)
                    got = drain()
                    r.check("behavioral: matching frames dropped (0/10)",
                            len(got) == 0, "received %d" % len(got))
                    inject(other1)
                    got = drain()
                    r.check("behavioral: non-matching frames pass (10/10)",
                            len(got) == 10, "received %d" % len(got))

                    # a second prio ORs in: now other1 dies too, other2 lives
                    c.send('tc bpf_drop add %s 20 "ether dst %s"' % (VB, other1))
                    inject(mac_a)
                    inject(other1)
                    got = drain()
                    inject(other2)
                    got2 = drain()
                    r.check("behavioral: two prios OR (both match sets dropped)",
                            len(got) == 0 and len(got2) == 10,
                            "dropped-set received %d, pass-set received %d" % (len(got), len(got2)))

                    # flush restores the flow
                    c.send("tc bpf_drop flush %s" % VB)
                    inject(mac_a)
                    got = drain()
                    r.check("behavioral: flush restores traffic (10/10)",
                            len(got) == 10, "received %d" % len(got))
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
