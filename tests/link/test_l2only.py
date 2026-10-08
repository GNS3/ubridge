"""L2-only host anchors — `link l2only` and the five creators that apply it.

Spec: `gns3-server/docs/design/ubridge-l2-anchor-spec.md` (uBridge side, §E).
A host-side anchor that is UP gets an IPv6 link-local address from the kernel
with no user-space actor involved, and with it MLD reports, DAD neighbour
solicitations and router solicitations — which flood into the emulated segment
and let the host answer ND for an address inside it.

What is verified here:

* the command contract (§A/§D): 100/203/204/208, default `on`, idempotency,
  and that a missing device is never created as a side effect (§E.4);
* every creator leaves its device with `addrgenmode none` and no address
  (§E.1) — tap create, docker create_veth (host end), link veth (both ends),
  brctl create, and the transient TAP `bridge add_nio_tap` creates for a free
  name — with the container/VM side deliberately untouched (§E.5), and an
  attach to a pre-existing device left strictly alone (§B);
* an anchor that was already UP is cleaned up, not just "no new addresses"
  (§A): the link-local the kernel assigned is deleted, and stays gone, while
  the other device of the pair keeps its address;
* `off` restores the kernel default, and the link-local returns on the next
  down/up cycle (§E.3);
* an idle hardened anchor in each of the three roles of §E.2 (TAP with an open
  fd / veth with its peer up / bridge with two attached ports) sends no
  neighbour discovery, no DAD and no router solicitation, and is completely
  idle once settled; the same roles unhardened do, which is the control that
  keeps this from passing vacuously.

Run under sudo, or `unshare -Urn python3 test_l2only.py`. The binary defaults
to the installed one (with its file capabilities, as in CI); set
`UBRIDGE_BINARY=$PWD/ubridge` to drive the in-repo build instead.

Three kernel behaviours this suite has to work around, all measured on 7.2 and
all noted in doc/link.md:

* **The chatter is one-shot at bring-up.** The kernel emits its own IPv6
  traffic when it *creates* an address, plus the DAD/RS retransmissions that
  follow — not at a steady rate, and not on a later down/up of an address it
  already has. So the measurement window starts right after the device comes
  up, and the "settled" half of the window is what §E.2's 5 s of silence maps
  to.
* **A capture started while its device is DOWN never receives anything**, not
  even after the device comes up. Hence "bring the device up, settle, then
  capture" — see doc/capture.md.
* **Hardening does not stop group membership reports.** A hardened anchor
  still emits one or two MLDv2 reports at bring-up (dst ff02::16, source `::`,
  hop-by-hop Router Alert) and, on an unhardened bridge, the IPv4 twin — an
  IGMP report (dst 224.0.0.22, source 0.0.0.0). Group membership is not
  address generation, and neither report carries an address of the device, so
  neither can make the host answer ND/ARP for one. The identity traffic
  (NS/NA/RS/RA) is what must be — and is — gone; the reports are allowed by
  the checks below and named in their detail.
* **On a bridge those reports are multicast snooping**, which `brctl create`
  turns off, so the bridge role is the one place held to *literal* silence
  rather than to "no identity traffic": `allow_group=False` below. Measured
  over the full `create` → `link set up` → `addif` ×2 → `delif` ×2 sequence,
  a bridge with snooping on emits 5 such frames over 0.5–1.7 s — repeating,
  not the one-shot burst the first bullet assumes — and none with it off.
"""
import fcntl
import os
import re
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import Ubridge, Results as _Results, no_residual_link  # noqa: E402

PORT = 13009
A, B = "l2o-a", "l2o-b"                  # veth pair (creator-hardened)
C, D = "l2o-c", "l2o-d"                  # control pair, hardening undone
TAP = "l2o-t"
DH, DG = "l2o-dh", "l2o-dg"              # docker create_veth: host / guest end
BR, P1, P2, X1, X2 = "l2o-br", "l2o-p1", "l2o-p2", "l2o-x1", "l2o-x2"
BT, BTU = "l2o-bt", "l2o-btu"            # bridge add_nio_tap: created / pre-existing
BTBR = "l2o-btb"                         # scratch bridge holding the two
PCAP = "/tmp/ubridge-l2only-%d.pcap" % PORT

WINDOW = 8          # seconds captured per role
SETTLED_AT = 3      # ... of which the last 5 are the "idle and settled" phase
MTU_SETTLE = 1.0    # DAD is still running this soon after bring-up

ENV6 = False        # set by control(): does this kernel provision IPv6 at all
BINARY = os.environ.get("UBRIDGE_BINARY") or None   # None -> installed first

# ICMPv6 multicast listener query / report / done — group maintenance, not
# identity (see the module docstring).
MLD_TYPES = (130, 131, 132, 143)
HOP_BY_HOP = 0


# --------------------------------------------------------------------------
# helpers — every kernel query here is read-only
# --------------------------------------------------------------------------

def _ip(*args):
    return subprocess.run(["ip"] + list(args), capture_output=True, text=True).stdout


def fmt(lines):
    return " | ".join(lines) if lines else "-"


def addrs(dev, family="-6"):
    """Address lines for <dev> ([] when it has none, or does not exist)."""
    return [l.strip() for l in
            _ip(family, "-o", "addr", "show", "dev", dev).splitlines() if l.strip()]


def wait_addrs(dev, family="-6", want=False, timeout=4.0):
    """Poll until <dev> has (want=True) or has no (want=False) addresses."""
    deadline = time.time() + timeout
    while True:
        have = bool(addrs(dev, family))
        if have == want or time.time() > deadline:
            return have
        time.sleep(0.2)


def addrgenmode(dev):
    """The device's IPv6 address generation mode, as `ip -d link` reports it."""
    m = re.search(r"addrgenmode\s+(\S+)", _ip("-d", "-o", "link", "show", dev))
    return m.group(1) if m else "?"


def bridge_attr(dev, key):
    """A bridge attribute as `ip -d link` reports it (e.g. `mcast_snooping`)."""
    m = re.search(r"\b%s\s+(\S+)" % re.escape(key), _ip("-d", "-o", "link", "show", dev))
    return m.group(1) if m else "?"


def flags(dev):
    out = _ip("-o", "link", "show", dev)
    return out.split("<")[1].split(">")[0] if "<" in out else "?"


def link_names():
    return {l.split(":")[1].strip().split("@")[0]
            for l in _ip("-o", "link", "show").splitlines()}


def open_tap(name):
    """Open the persistent TAP the way the emulator does — a TAP only has
    carrier (and so only acquires a link-local) while an fd is attached.
    Returns the fd, or None if this user may not attach to it."""
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(fd, 0x400454ca,   # TUNSETIFF
                    struct.pack("16sH", name.encode(), 0x0002 | 0x1000))
        return fd
    except OSError:
        return None


def pcap_records(path):
    """Decode a libpcap file into frames.

    Each record carries the frame's time relative to the first frame in the
    file, its ethertype, IPv6/IPv4 source and destination, the sender's MAC and
    a decoded note (ICMPv6 type, IGMP/IPv4, or the raw bytes when it is neither
    family).
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None

    out, off, base = [], 24, None
    while off + 16 <= len(data):
        ts, tus, incl, _orig = struct.unpack_from("<IIII", data, off)
        t = ts + tus / 1e6
        if base is None:
            base = t
        frame = data[off + 16:off + 16 + incl]
        eth = frame[:14]
        rec = {"t": t - base, "eth": eth[12:14].hex(), "smac": eth[6:12].hex(),
               "src": "-", "proto": None, "dst": "-", "note": ""}
        if eth[12:14] == b"\x86\xdd" and len(frame) >= 54:
            ip6 = frame[14:54]
            nexthdr = ip6[6]
            rec["src"] = ip6[8:24].hex()
            rec["dst"] = ip6[24:40].hex()
            rec["proto"] = "ipv6"
            if nexthdr == HOP_BY_HOP and len(frame) > 54:
                rec["note"] = "hop-by-hop->%d" % frame[54]   # MLD rides a Router Alert
            elif nexthdr == 58 and len(frame) > 54:
                rec["note"] = "ICMPv6 %d" % frame[54]
            else:
                rec["note"] = "nexthdr %d" % nexthdr
        elif eth[12:14] == b"\x08\x00" and len(frame) > 34:
            ip4 = frame[14:]
            rec["src"] = ip4[12:16].hex()
            rec["dst"] = ip4[16:20].hex()
            rec["proto"] = "igmp" if ip4[9] == 2 else "ipv4/%d" % ip4[9]
            rec["note"] = "%s %s->%s" % (rec["proto"], rec["src"], rec["dst"])
        else:
            # Neither family: report enough to identify the sender (its MAC and
            # the first bytes) rather than just "something else was on the wire".
            rec["note"] = "raw " + frame[14:34].hex()
        out.append(rec)
        off += 16 + incl
    return out


def is_group_maintenance(rec):
    """True for a group-membership report the stack sends with no source
    address: MLD for IPv6 (joining ff02::1/ff02::16) and its IPv4 twin, IGMP
    (joining 224.0.0.x).

    Neither carries an address of the device — source `::` / `0.0.0.0` — so
    neither can make the host answer ND/ARP for one, and both are sent even
    with address generation off. They are what hardening does not remove on
    the anchors. A bridge is the exception: `brctl create` turns multicast
    snooping off, which is where a bridge's own pair of these comes from, so
    the bridge role does not use this exemption (see `allow_group` in
    idle_checks). See doc/link.md.
    """
    if rec["src"] in ("0" * 32, "00000000"):
        if rec["eth"] == "86dd" and (
                rec["note"].startswith("hop-by-hop")
                or rec["note"] in ["ICMPv6 %d" % t for t in MLD_TYPES]):
            return True
        if rec["eth"] == "0800" and rec["proto"] == "igmp" and \
                rec["dst"].startswith("e00000"):     # 224.0.0.0/24
            return True
    return False


def describe(recs):
    if not recs:
        return "none"
    return ", ".join("%s@%.2fs(%s)" % (r["eth"], r["t"], r["note"] or "-")
                     if r["eth"] == "86dd" else
                     "%s from %s @%.2fs(%s)" % (r["eth"], r["smac"], r["t"], r["note"])
                     for r in recs)


def capture(c, dev, bring_up):
    """Bring <dev> into its role and record every frame it emits for WINDOW.

    The capture has to start after the device is up: a socket bound while the
    device is DOWN never receives, not even once it comes up (see the module
    docstring).
    """
    if os.path.exists(PCAP):
        os.unlink(PCAP)
    bring_up()
    time.sleep(MTU_SETTLE)
    if c.code("capture start_kernel %s %s" % (dev, PCAP)) != "100":
        return None
    time.sleep(WINDOW)
    c.send("capture stop_kernel")
    time.sleep(0.4)
    return pcap_records(PCAP)


def keep_capture(role):
    """Preserve the capture behind a failed check: every role writes the same
    pcap path, so the next one would overwrite it. Returns the kept path."""
    dest = "/tmp/ubridge-l2only-%s-%d.pcap" % (re.sub(r"\W+", "-", role), PORT)
    try:
        shutil.copyfile(PCAP, dest)
        return dest
    except OSError:
        return "?"


def idle_checks(c, r, role, dev, bring_up, baseline_ok, allow_group=True):
    """§E.2 for one role: no identity chatter, and idle once settled.

    `allow_group=False` holds the role to literal silence instead of only to
    "no identity traffic". The bridge role needs it: with multicast snooping
    off it has no group membership of its own to report, so any frame at all
    is a defect there.
    """
    recs = capture(c, dev, bring_up)
    if recs is None:
        r.skip("%s: idle silence (§E.2)" % role, "capture start_kernel unavailable")
        return
    if not baseline_ok:
        r.skip("%s: idle silence (§E.2)" % role,
               "the unhardened control emitted nothing, so silence proves nothing")
        return

    if allow_group:
        noise = [x for x in recs if not is_group_maintenance(x)]
        label = "%s: no ND/DAD/RS after hardening (§E.2)" % role
        quiet = "group reports only: %s" % describe(recs)
    else:
        noise = list(recs)
        label = "%s: silent, not even a group report (§E.2)" % role
        quiet = "none"
    settled = [x for x in recs if x["t"] >= SETTLED_AT]
    r.check(label, not noise,
            "%s (capture kept: %s)" % (describe(noise), keep_capture(role))
            if noise else quiet)
    r.check("%s: idle and settled, nothing for %ds (§E.2)"
            % (role, WINDOW - SETTLED_AT), not settled,
            "%s (capture kept: %s)" % (describe(settled), keep_capture(role))
            if settled else "none")


def env_check(r, name, cond, detail=""):
    """A check that only means something where the kernel provisions IPv6."""
    if ENV6:
        r.check(name, cond, detail)
    else:
        r.skip(name, "kernel provisions no IPv6 here, so there is nothing to suppress")


class Results(_Results):
    """Results that can also record a skip (reported, never counted as a pass)."""

    def __init__(self):
        _Results.__init__(self)
        self.skips = []

    def skip(self, name, reason):
        self.skips.append((name, reason))

    def summary(self):
        for name, reason in self.skips:
            print("  [SKIP] %s  -- %s" % (name, reason))
        ok = _Results.summary(self)
        if self.skips:
            print("(%d check(s) skipped)" % len(self.skips))
        return ok


def cleanup(c):
    """Best-effort removal of everything this suite creates (deleting one end
    of a veth pair removes the other)."""
    for dev in (A, C, P1, P2):
        c.send("link delete %s" % dev)
    c.send("docker delete_veth %s" % DH)
    c.send("brctl delete %s" % BR)
    c.send("tap delete %s" % TAP)
    c.send("bridge delete %s" % BTBR)
    c.send("tap delete %s" % BTU)   # the §B gate fixture (persistent); the
                                    # attach fd is released by the delete above


# --------------------------------------------------------------------------
# the control — does this kernel assign a link-local, and does it talk?
# --------------------------------------------------------------------------

def control(c, r):
    """Unhardened pair, in the same role the hardened ones are measured in.

    Gives both references the rest of the suite needs: that an unhardened
    device does acquire a link-local (§E.1's absence would be vacuous
    otherwise), and that an idle unhardened anchor does emit ND/DAD/RS.
    """
    global ENV6
    if c.code("link veth %s %s" % (C, D)) != "100":
        return False, False

    # The creator hardened both ends; the control needs them as the kernel
    # would leave them.
    c.send("link l2only %s off" % C)
    c.send("link l2only %s off" % D)
    c.send("link set %s down" % C)
    c.send("link set %s down" % D)
    recs = capture(c, C, lambda: (c.send("link set %s up" % D),
                                  c.send("link set %s up" % C)))
    ENV6 = wait_addrs(C, "-6", want=True, timeout=4.0)
    if ENV6:
        r.check("control: an unhardened device acquires a link-local",
                True, fmt(addrs(C, "-6"))[:72])
    else:
        r.skip("control: an unhardened device acquires a link-local",
               "kernel provisioned none (no IPv6 in this netns) — the address "
               "checks below are skipped")

    if recs is None:
        return True, False
    identity = [x for x in recs if not is_group_maintenance(x)]
    ok = bool(identity)
    if ok:
        r.check("control: an unhardened anchor sends ND/DAD/RS (§E.2 baseline)",
                True, describe(identity)[:120])
    else:
        r.skip("control: an unhardened anchor sends ND/DAD/RS (§E.2 baseline)",
               "kernel emitted %d frames, none of them ND/DAD/RS — nothing to "
               "suppress here" % len(recs))
    return True, ok


# --------------------------------------------------------------------------
# §A/§D — the command surface
# --------------------------------------------------------------------------

def contract(c, r):
    before = link_names()
    r.check("l2only on a missing device -> 208",
            c.code("link l2only nosuchif0") == "208",
            c.send("link l2only nosuchif0"))
    r.check("no transient device was created (§E.4)", link_names() == before)

    r.check("bad state -> 204",
            c.code("link l2only %s sideways" % C) == "204",
            c.send("link l2only %s sideways" % C))
    r.check("no state argument -> 203", c.code("link l2only") == "203")
    r.check("too many arguments -> 203",
            c.code("link l2only %s on extra" % C) == "203")

    # `link veth` hardens both ends; `on` below is the idempotent re-apply.
    r.check("create the pair to harden -> 100",
            c.code("link veth %s %s" % (A, B)) == "100")
    want = "100-L2-only set on %s" % A
    first = c.send("link l2only %s" % A)
    r.check("default state is on -> 100", first == want, first)
    r.check("on is idempotent, same reply (§E.3)",
            c.send("link l2only %s on" % A) == want and first == want, first)


# --------------------------------------------------------------------------
# §B/§E.1/§E.2/§E.5 — the five creators, each in its normal role
# --------------------------------------------------------------------------

def veth_role(c, r, baseline_ok):
    """link veth: both ends host-side, so both are hardened. This is also
    §E.2's "veth with its peer up" role."""
    c.send("link delete %s" % A)
    r.check("link veth -> 100", c.code("link veth %s %s" % (A, B)) == "100")
    c.send("link set %s up" % B)
    r.check("link veth: both ends addrgenmode none",
            addrgenmode(A) == "none" and addrgenmode(B) == "none",
            "%s / %s" % (addrgenmode(A), addrgenmode(B)))
    env_check(r, "link veth: neither end has an IPv6 address (§E.1)",
              not addrs(A, "-6") and not addrs(B, "-6"),
              fmt(addrs(A, "-6") + addrs(B, "-6")))
    idle_checks(c, r, "veth pair", A, lambda: c.send("link set %s up" % A),
                baseline_ok)


def docker_role(c, r):
    """docker create_veth: the host end is the anchor, the guest end moves into
    a container netns and is deliberately left alone (§E.5).

    No silence check here: the guest end is *not* hardened by design, so its
    own ND/DAD arrives over the veth and would be measured instead of this
    anchor's. The equivalent role is covered by the veth pair above.
    """
    r.check("docker create_veth -> 100",
            c.code("docker create_veth %s %s" % (DH, DG)) == "100")
    c.send("link set %s up" % DG)          # what the container's netns does
    r.check("docker: host end addrgenmode none",
            addrgenmode(DH) == "none", addrgenmode(DH))
    env_check(r, "docker: host end has no IPv6 address (§E.1)",
              not addrs(DH, "-6"), fmt(addrs(DH, "-6")))
    r.check("docker: host end has no IPv4 address (§E.1)",
            not addrs(DH, "-4"), fmt(addrs(DH, "-4")))
    r.check("docker: guest end left at the kernel default (§E.5)",
            addrgenmode(DG) != "none", addrgenmode(DG))
    env_check(r, "docker: guest end keeps its IPv6 (§E.5)",
              wait_addrs(DG, "-6", want=True, timeout=4.0), fmt(addrs(DG, "-6")))


def tap_role(c, r, baseline_ok):
    """tap create: the TAP, in its normal role — open fd (carrier), UP."""
    r.check("tap create -> 100", c.code("tap create %s" % TAP) == "100")
    r.check("tap set_owner -> 100",
            c.code("tap set_owner %s %d" % (TAP, os.getuid())) == "100")
    fd = open_tap(TAP)
    c.send("link set %s up" % TAP)

    r.check("TAP: addrgenmode none", addrgenmode(TAP) == "none", addrgenmode(TAP))
    env_check(r, "TAP: no IPv6 address (§E.1)", not addrs(TAP, "-6"), fmt(addrs(TAP, "-6")))
    r.check("TAP: no IPv4 address (§E.1)", not addrs(TAP, "-4"), fmt(addrs(TAP, "-4")))

    if fd is None:
        r.skip("TAP: idle silence (§E.2)",
               "cannot open %s (needs to be the TAP owner)" % TAP)
    else:
        c.send("link set %s down" % TAP)
        idle_checks(c, r, "TAP with an open fd", TAP,
                    lambda: c.send("link set %s up" % TAP), baseline_ok)
        os.close(fd)


def bridge_tap_role(c, r):
    """bridge add_nio_tap: the §B table's fifth creator. TUNSETIFF's by-name
    branch *creates* a transient TAP when the name is free (cloud's
    bridge-interface path, and the create-if-missing half of the swap
    contract); that device is hardened like tap create hardens its persistent
    one. An attach to a pre-existing device is left strictly alone — a
    user-owned TAP keeps its address (the gate that makes this safe)."""
    c.send("bridge delete %s" % BTBR)
    r.check("bridge create -> 100", c.code("bridge create %s" % BTBR) == "100")
    r.check("bridge add_nio_tap on a free name -> 100",
            c.code("bridge add_nio_tap %s %s" % (BTBR, BT)) == "100")
    c.send("link set %s up" % BT)
    r.check("created TAP: addrgenmode none", addrgenmode(BT) == "none", addrgenmode(BT))
    env_check(r, "created TAP: no IPv6 address (§E.1)", not addrs(BT, "-6"), fmt(addrs(BT, "-6")))
    r.check("created TAP: no IPv4 address (§E.1)", not addrs(BT, "-4"), fmt(addrs(BT, "-4")))

    # The gate: a pre-existing device must not be hardened on attach. Build
    # the fixture through ubridge — every privileged step in this suite goes
    # through the capped binary, and raw `ip` is unprivileged in CI. tap
    # create hardens what it makes, so give the device an identity back: the
    # kernel's default generator plus an address of its own.
    r.check("fixture: tap create -> 100", c.code("tap create %s" % BTU) == "100")
    r.check("fixture: link l2only off -> 100",
            c.code("link l2only %s off" % BTU) == "100")
    r.check("fixture: link addr -> 100",
            c.code("link addr %s 10.99.0.1/24" % BTU) == "100")
    mode_before = addrgenmode(BTU)
    r.check("pre-existing TAP: address + kernel-default addrgenmode before the attach",
            any("10.99.0.1" in a for a in addrs(BTU, "-4")) and mode_before == "eui64",
            "%s, %s" % (fmt(addrs(BTU, "-4")), mode_before))
    r.check("bridge add_nio_tap on the pre-existing TAP -> 100",
            c.code("bridge add_nio_tap %s %s" % (BTBR, BTU)) == "100")
    r.check("attach left the address alone (§B gate)",
            any("10.99.0.1" in a for a in addrs(BTU, "-4")), fmt(addrs(BTU, "-4")))
    r.check("attach left addrgenmode alone (§B gate)",
            addrgenmode(BTU) == mode_before,
            "%s -> %s" % (mode_before, addrgenmode(BTU)))


def bridge_role(c, r, baseline_ok):
    """brctl create: the per-link bridge, with two ports attached and up."""
    r.check("brctl create -> 100", c.code("brctl create %s" % BR) == "100")
    for port, peer in ((P1, X1), (P2, X2)):
        c.send("link veth %s %s" % (port, peer))
    r.check("brctl addif -> 100",
            c.code("brctl addif %s %s" % (BR, P1)) == "100" and
            c.code("brctl addif %s %s" % (BR, P2)) == "100")
    c.send("link set %s up" % X1)
    c.send("link set %s up" % X2)

    r.check("bridge: addrgenmode none", addrgenmode(BR) == "none", addrgenmode(BR))
    env_check(r, "bridge: no IPv6 address (§E.1)", not addrs(BR, "-6"), fmt(addrs(BR, "-6")))
    r.check("bridge: no IPv4 address (§E.1)", not addrs(BR, "-4"), fmt(addrs(BR, "-4")))
    # Snooping off is what makes the bridge's own group reports go away, so it
    # is checked here and not just implied by the silence below.
    r.check("bridge: multicast snooping off on create",
            bridge_attr(BR, "mcast_snooping") == "0",
            bridge_attr(BR, "mcast_snooping"))

    # The ports are hardened too, so anything captured on the bridge is the
    # bridge's own. allow_group=False: with no snooping there is no group
    # membership left for the bridge to report, so silence here is literal.
    c.send("link set %s down" % BR)
    idle_checks(c, r, "bridge with two ports", BR,
                lambda: c.send("link set %s up" % BR), baseline_ok,
                allow_group=False)


# --------------------------------------------------------------------------
# §A — an anchor that was already UP ends up clean, not just "no new ones"
# --------------------------------------------------------------------------

def already_up(c, r):
    # A/B are hardened; undo that on both ends and let the kernel assign the
    # link-local an unhardened anchor would have had all along.
    c.send("link l2only %s off" % A)
    c.send("link l2only %s off" % B)
    c.send("link set %s down" % A)
    c.send("link set %s up" % A)
    env_check(r, "an unhardened, UP anchor acquires a link-local",
              wait_addrs(A, "-6", want=True, timeout=4.0), fmt(addrs(A, "-6")))

    got = c.send("link l2only %s" % A)
    r.check("l2only on an already-UP anchor -> 100",
            got == "100-L2-only set on %s" % A, got)
    r.check("the existing link-local was removed", not addrs(A, "-6"), fmt(addrs(A, "-6")))
    r.check("addrgenmode none after the cleanup", addrgenmode(A) == "none",
            addrgenmode(A))
    r.check("only the named device was touched (the peer keeps its address)",
            addrgenmode(B) == "eui64", addrgenmode(B))
    time.sleep(2)
    r.check("the removed address does not come back (no regeneration)",
            not addrs(A, "-6"), fmt(addrs(A, "-6")))


# --------------------------------------------------------------------------
# §E.3 — off restores the kernel default
# --------------------------------------------------------------------------

def revert(c, r):
    got = c.send("link l2only %s off" % A)
    r.check("off -> 100", got == "100-L2-only cleared on %s" % A, got)
    r.check("addrgenmode back to the kernel default (eui64)",
            addrgenmode(A) == "eui64", addrgenmode(A))

    # The kernel re-provisions on the next down/up cycle; the mode change alone
    # does not bring the address back.
    c.send("link set %s down" % A)
    c.send("link set %s up" % A)
    env_check(r, "the link-local returns after a down/up cycle (§E.3)",
              wait_addrs(A, "-6", want=True, timeout=4.0), fmt(addrs(A, "-6")))

    # ... and hardening it again takes it straight back out.
    c.send("link l2only %s" % A)
    r.check("re-hardening after the cycle removes it again",
            not addrs(A, "-6"), fmt(addrs(A, "-6")))


def main():
    r = Results()

    with Ubridge(port=PORT, binary=BINARY) as ub:
        c = ub.connect()
        try:
            cleanup(c)
            print("--- control ---")
            created, baseline_ok = control(c, r)
            if not created:
                r.skip("every check",
                       "cannot create a veth pair — no CAP_NET_ADMIN for the "
                       "binary in use? (run under sudo or `unshare -Urn`, or "
                       "point UBRIDGE_BINARY at the setcap'd binary)")
                cleanup(c)
                return 1

            print("--- command contract ---")
            contract(c, r)
            print("--- creators ---")
            veth_role(c, r, baseline_ok)
            docker_role(c, r)
            tap_role(c, r, baseline_ok)
            bridge_tap_role(c, r)
            bridge_role(c, r, baseline_ok)
            print("--- an anchor that was already UP ---")
            already_up(c, r)
            print("--- off / revert ---")
            revert(c, r)
        finally:
            cleanup(c)
            c.close()

    r.check("no residual interfaces", no_residual_link("l2o"))
    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
