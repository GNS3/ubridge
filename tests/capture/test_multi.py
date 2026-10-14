"""Multi-instance regression for the capture module.

Two kernel captures on two veth pairs at once: both pcaps grow, per-interface
stop leaves the other capture running, a duplicate start on the same interface
is refused (209), `capture status` lists one line per active capture, and the
argument-less `capture stop_kernel` stops everything. Stdlib only. Requires
CAP_NET_ADMIN — run under sudo.

Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import sys
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubcapm-"
PORT = 13042
IF_A1, IF_A2 = PREFIX + "a1", PREFIX + "a2"   # veth pair A
IF_B1, IF_B2 = PREFIX + "b1", PREFIX + "b2"   # veth pair B
PCAP_A = "/tmp/ubcapma.pcap"
PCAP_B = "/tmp/ubcapmb.pcap"


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _exists(name):
    return _ip(["-o", "link", "show", name]).returncode == 0


def main():
    r = Results()

    for p in (PCAP_A, PCAP_B):
        if os.path.exists(p):
            os.remove(p)

    try:
        with Ubridge(port=PORT) as ub:
            c = ub.connect()
            try:
                for a, b, ip1, ip2 in ((IF_A1, IF_A2, "10.99.1.1", "10.99.1.2"),
                                       (IF_B1, IF_B2, "10.99.2.1", "10.99.2.2")):
                    r.check("link veth pair %s" % a, c.code("link veth %s %s" % (a, b)) == "100")
                    c.code("link addr %s %s/24" % (a, ip1))
                    c.code("link addr %s %s/24" % (b, ip2))
                    c.code("link set %s up" % a)
                    c.code("link set %s up" % b)

                def ping(iface, ip):
                    subprocess.run(["ping", "-c", "3", "-W", "1", "-I", iface, ip],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                def capture_lines():
                    # Read until the final 100- line itself: interface names
                    # contain '-', so Client.send's stop condition (any '-'
                    # in the buffer) can stop at the first line.
                    c.s.sendall(b"capture status\n")
                    buf = b""
                    while not any(l.startswith(b"100-") for l in buf.split(b"\r\n")):
                        chunk = c.s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    return [l for l in buf.decode(errors="replace").splitlines()
                            if l.startswith("101 ")]

                # two captures at once, one per interface
                res = c.send("capture start_kernel %s %s" % (IF_A1, PCAP_A))
                r.check("start_kernel A", res.startswith("100-"), res)
                res = c.send("capture start_kernel %s %s" % (IF_B1, PCAP_B))
                r.check("start_kernel B (second capture allowed)", res.startswith("100-"), res)

                # a third start on an already-captured interface is refused
                r.check("duplicate start on %s -> 209" % IF_A1,
                        c.code("capture start_kernel %s %s" % (IF_A1, PCAP_A)) == "209")

                r.check("status lists 2 captures", len(capture_lines()) == 2, str(capture_lines()))

                # traffic on both pairs; both pcaps must be non-empty
                ping(IF_A1, "10.99.1.2")
                ping(IF_B1, "10.99.2.2")
                time.sleep(0.3)  # let the last frames drain into the pcaps
                size_a = os.path.getsize(PCAP_A) if os.path.exists(PCAP_A) else 0
                size_b = os.path.getsize(PCAP_B) if os.path.exists(PCAP_B) else 0
                r.check("pcap A captured packets (size>24)", size_a > 24, "size=%d" % size_a)
                r.check("pcap B captured packets (size>24)", size_b > 24, "size=%d" % size_b)

                # per-interface stop: A stops, B keeps capturing
                r.check("stop_kernel %s" % IF_A1, c.code("capture stop_kernel %s" % IF_A1) == "100")
                r.check("stop_kernel on idle iface -> 208",
                        c.code("capture stop_kernel %s" % IF_A2) == "208")
                r.check("status lists 1 capture", len(capture_lines()) == 1, str(capture_lines()))

                ping(IF_A1, "10.99.1.2")   # A's pair still carries traffic...
                ping(IF_B1, "10.99.2.2")
                time.sleep(0.3)
                r.check("pcap A frozen after stop", os.path.getsize(PCAP_A) == size_a)
                r.check("pcap B keeps growing", os.path.getsize(PCAP_B) > size_b)

                # stop-all form, then the idempotent reply when nothing is left
                r.check("stop_kernel (all)", c.code("capture stop_kernel") == "100")
                r.check("status lists 0 captures", len(capture_lines()) == 0)
                r.check("stop again -> 100 (idempotent)", c.code("capture stop_kernel") == "100")
            finally:
                c.send("capture stop_kernel")
                c.close()
    finally:
        # cleanup veth pairs (deleting one end removes the pair) + pcaps
        for iface in (IF_A1, IF_B1):
            if _exists(iface):
                _ip(["link", "del", iface])
        for p in (PCAP_A, PCAP_B):
            if os.path.exists(p):
                os.remove(p)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
