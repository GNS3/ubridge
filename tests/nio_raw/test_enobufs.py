"""ENOBUFS resilience: a full transmit queue must not kill the relay.

Regression for issue #141: a send failing with ENOBUFS (transmit queue full)
broke out of bridge_nios(), the listener wrapper called exit(EXIT_FAILURE)
and the whole process — every link in the topology — went away. The relay
now drops the frame and carries on, reporting at most once per second.

The queue is filled deterministically: netem with a tiny limit and a 2 s
delay on the veth end ubridge sends into, then a UDP flood at the bridge's
UDP NIO. Every relay send past the limit fails with ENOBUFS — the exact
path the field report took (pcap_sendpacket into a veth), just with the
congestion onset moved from "8 s into an iperf" to "immediately".

Topology (bridge "neb", 2 NIOs):
  nio_ethernet vnio0  <-->  nio_udp lp<->rp      (netem limit 5, delay 2s on vnio0)

  flood:  bound rp.sendto(frame, lp) x N  -> bridge -> pcap_sendpacket vnio0
          -> netem takes 5, every further send returns ENOBUFS

Checks:
  1. ubridge is still alive after the flood (the old code exited here)
  2. stderr shows the drop report, rate-limited: tens of thousands of
     drops produce at most a handful of lines (per-frame perror would be
     one line per drop)
  3. once the qdisc is gone, frames flow again — congestion is transient

Run under sudo (or `unshare -Urn`) — veth + tc netem need CAP_NET_ADMIN,
pcap promisc needs CAP_NET_RAW.
"""
import re
import socket
import tempfile
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, veth_up, veth_del,
                     raw_sock, eth_frame, free_udp_port, drain, recv_match, sh)

PORT = 13190
FLOOD_BURSTS = 5       # bursts spread over ~2.5 s so the 1/s rate limit and
FLOOD_PER_BURST = 4000 # the growing drop count are both observable
FLOOD = FLOOD_BURSTS * FLOOD_PER_BURST
MAX_REPORT_LINES = 10  # rate limit sanity bound; one line per drop would be FLOOD
MIN_DROPS = 500        # the ENOBUFS path was actually exercised, en masse


def main():
    r = Results()
    veth_up("vnio0", "vnio1")
    q = sh("tc", "qdisc", "add", "dev", "vnio0", "root", "netem",
           "limit", "5", "delay", "2000ms")
    if q.returncode != 0:
        veth_del("vnio0")
        raise RuntimeError("tc qdisc add netem failed: %s" % q.stderr.strip())
    try:
        with tempfile.NamedTemporaryFile("r+", prefix="ubridge-enobufs-") as log:
            with Ubridge(port=PORT, binary=ubridge_binary(), stderr=log) as ub:
                c = ub.connect()
                try:
                    lp, rp = free_udp_port(), free_udp_port()
                    assert c.code("bridge create neb") == "100"
                    assert c.code("bridge add_nio_ethernet neb vnio0") == "100"
                    assert c.code("bridge add_nio_udp neb %d %s %d" % (lp, HOST, rp)) == "100"
                    assert c.code("bridge start neb") == "100"
                    time.sleep(0.3)

                    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    tx.bind((HOST, rp))
                    frame = eth_frame(b"ENObUFS-FLOOD-PAYLOAD")
                    for _ in range(FLOOD_BURSTS):
                        for _ in range(FLOOD_PER_BURST):
                            tx.sendto(frame, (HOST, lp))
                        time.sleep(0.5)  # bursts span seconds: the report
                                        # rate limit (1/s) and the growing
                                        # cumulative count become observable
                    time.sleep(0.5)  # let the relay work through its UDP backlog

                    # ---- 1. liveness: the relay dropped frames, not the process
                    alive = ub.proc.poll() is None
                    r.check("process alive after ENOBUFS flood", alive,
                            "exit code %s" % ub.proc.poll())

                    # ---- 2. the drop report fired, rate-limited
                    log.seek(0)
                    err = log.read()
                    lines = [l for l in err.splitlines() if "No buffer space available" in l]
                    counts = [int(m) for m in re.findall(r"\((\d+) dropped so far\)", err)]
                    r.check("drop report present", len(lines) >= 1,
                            "stderr: %r" % err[-200:] if err else "stderr empty")
                    r.check("drop report rate-limited (%d lines for %s frames)"
                            % (len(lines), FLOOD),
                            1 <= len(lines) <= MAX_REPORT_LINES,
                            "got %d lines" % len(lines))
                    r.check("drop count reached (%d+ drops)" % MIN_DROPS,
                            bool(counts) and max(counts) >= MIN_DROPS,
                            "max reported count: %s" % (max(counts) if counts else None))

                    # ---- 3. recovery: delete the qdisc, the queue drains, frames flow
                    sh("tc", "qdisc", "del", "dev", "vnio0", "root")
                    time.sleep(0.2)
                    mark = eth_frame(b"ENObUFS-RECOVER-MARK")
                    raw = raw_sock("vnio1")
                    tx.sendto(mark, (HOST, lp))
                    got = recv_match(raw, mark, timeout=3.0)
                    r.check("relay recovers after queue drains", got == mark,
                            "len %d vs %d" % (len(got) if got else 0, len(mark)))
                    tx.close(); raw.close()

                    # a dead control socket just means ubridge died — the
                    # liveness check above already reports that
                    try:
                        c.send("bridge stop neb"); c.send("bridge delete neb")
                    except OSError:
                        pass
                finally:
                    c.close()
    finally:
        sh("tc", "qdisc", "del", "dev", "vnio0", "root")
        veth_del("vnio0")
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
