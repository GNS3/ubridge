"""Basic regression for the capture module (kernel-side AF_PACKET capture).

Captures frames on one end of a veth pair while ping generates traffic, then
confirms the pcap file is written and non-empty. Also covers the
start/stop lifecycle and error paths. Stdlib only. Requires CAP_NET_ADMIN —
run under sudo.

Reuses Ubridge / Results from tests/brctl/common.py.
"""
import os
import sys
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PREFIX = "ubcap-"
PORT = 13041
VETH_A = PREFIX + "a"
VETH_B = PREFIX + "b"
PCAP = "/tmp/%s.pcap" % PREFIX.rstrip("-")


def _ip(args):
    return subprocess.run(["ip"] + args, capture_output=True, text=True)


def _exists(name):
    return _ip(["-o", "link", "show", name]).returncode == 0


def main():
    r = Results()

    if os.path.exists(PCAP):
        os.remove(PCAP)

    try:
        with Ubridge(port=PORT) as ub:
            c = ub.connect()
            try:
                # veth pair + IPs to generate real frames between the ends
                r.check("link veth pair", c.code("link veth %s %s" % (VETH_A, VETH_B)) == "100")
                c.code("link addr %s 10.99.0.1/24" % VETH_A)
                c.code("link addr %s 10.99.0.2/24" % VETH_B)
                c.code("link set %s up" % VETH_A)
                c.code("link set %s up" % VETH_B)

                # start capturing on VETH_A
                res = c.send("capture start_kernel %s %s" % (VETH_A, PCAP))
                r.check("start_kernel", res.startswith("100-"), res)

                # double start is rejected
                r.check("double start -> 209", c.code("capture start_kernel %s %s" % (VETH_A, PCAP)) == "209")

                # generate traffic (ARP + ICMP) between the two ends
                subprocess.run(["ping", "-c", "3", "-W", "1", "-I", VETH_A, "10.99.0.2"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.3)  # let the last frames drain into the pcap

                # stop
                r.check("stop_kernel", c.code("capture stop_kernel") == "100")

                # the pcap file must exist and contain more than just its header
                r.check("pcap file created", os.path.exists(PCAP))
                if os.path.exists(PCAP):
                    size = os.path.getsize(PCAP)
                    r.check("pcap captured packets (size>24)", size > 24, "size=%d" % size)

                # idempotent stop (no active capture) is OK
                r.check("stop again -> 100 (idempotent)", c.code("capture stop_kernel") == "100")

                # error paths
                r.check("start on missing iface -> 208",
                        c.code("capture start_kernel %s-nope %s" % (VETH_A, PCAP)) == "208")
            finally:
                c.send("capture stop_kernel")
                c.close()
    finally:
        # cleanup veth (deleting one end removes the pair) + pcap
        if _exists(VETH_A):
            _ip(["link", "del", VETH_A])
        if os.path.exists(PCAP):
            os.remove(PCAP)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
