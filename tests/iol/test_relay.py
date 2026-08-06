"""Dataplane regression for the IOL bridge: header correctness and routing.

test_iol.py (in the delay suite) proves delay timing in both directions but
never checks the bytes. This suite verifies the IOL-specific dataplane logic:

  * IOL->NIO: an IOL frame's payload is delivered intact (the 8-byte header is
    stripped) to the right destination NIO.
  * port routing: the bridge routes by pkt[DOL_DST_PORT] (byte 4), so a frame
    addressed to port 0 exits NIO-0 and port 1 exits NIO-1 (not a hub flood).
  * NIO->IOL: ubridge builds the IOL header itself (dst=iol_id, src=app_id,
    ports=port_key, msg=DATA, channel=0) and prepends it — we assert the exact
    header bytes ubridge is supposed to emit.

No CAP_NET_ADMIN (AF_UNIX + high UDP only); no IOL image — we pose as the IOL
instance over the netio unix socket.
"""
import socket
import time

from helpers import (Ubridge, Results, HOST, ubridge_binary, ensure_netio_dir,
                     iol_sock, iol_frame, fake_iol, free_udp_port,
                     IOL_HDR_SIZE, cleanup_iol_sock)

PORT = 13171
APP_ID = 9201      # the IOL bridge
IOL_ID = 9202      # the fake IOL instance
BRIDGE_SOCK = iol_sock(APP_ID)


def _drain(s, n=4, timeout=0.4):
    """Read up to n pending datagrams with a short timeout."""
    s.settimeout(timeout)
    for _ in range(n):
        try:
            s.recvfrom(4096)
        except socket.timeout:
            break


def main():
    r = Results()
    ensure_netio_dir()
    iol = fake_iol(IOL_ID)
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # two destination NIOs on distinct ports: port_key 0 (bay=0/unit=0)
            # and port_key 1 (bay=1/unit=0).
            l1, r1 = free_udp_port(), free_udp_port()
            l2, r2 = free_udp_port(), free_udp_port()
            assert c.code("iol_bridge create iolr %d" % APP_ID) == "100"
            assert c.code("iol_bridge add_nio_udp iolr %d 0 0 %d %s %d" % (IOL_ID, l1, HOST, r1)) == "100"
            assert c.code("iol_bridge add_nio_udp iolr %d 1 0 %d %s %d" % (IOL_ID + 1, l2, HOST, r2)) == "100"
            assert c.code("iol_bridge start iolr") == "100"
            time.sleep(0.3)

            # ---- PHASE 1: IOL -> NIO ----
            # The destination NIO sends to its remote rport; we observe there.
            # The NIO->IOL injector must ALSO bind that same rport (the connected
            # NIO only accepts from its configured remote), so we keep rx and tx
            # on the same port OPEN AT DIFFERENT TIMES — never simultaneously,
            # or Linux hands the bridge's relayed datagram to whichever socket.
            rx1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); rx1.bind((HOST, r1)); rx1.settimeout(2.0)
            rx2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); rx2.bind((HOST, r2)); rx2.settimeout(2.0)

            # payload fidelity on port 0
            payload = b"IOL-PAYLOAD-0123456789"
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, b"warmup"), BRIDGE_SOCK)  # prime
            _drain(rx1)
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, payload), BRIDGE_SOCK)
            try:
                got, _ = rx1.recvfrom(2048)
                r.check("IOL->NIO payload intact", got == payload, "len=%d want=%d" % (len(got), len(payload)))
            except socket.timeout:
                r.check("IOL->NIO payload intact", False, "timeout")

            # port routing: dst_port selects the NIO
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, b"TO-PORT0"), BRIDGE_SOCK)
            try:
                g0, _ = rx1.recvfrom(2048)
                ok0 = (g0 == b"TO-PORT0")
            except socket.timeout:
                ok0, g0 = False, b""
            r.check("dst_port=0 -> NIO-0", ok0, repr(g0))

            iol.sendto(iol_frame(APP_ID, IOL_ID, 1, 1, b"TO-PORT1"), BRIDGE_SOCK)
            try:
                g1, _ = rx2.recvfrom(2048)
                ok1 = (g1 == b"TO-PORT1")
            except socket.timeout:
                ok1, g1 = False, b""
            r.check("dst_port=1 -> NIO-1", ok1, repr(g1))

            # not a hub flood: port-0 frame must NOT appear at NIO-1
            iol.sendto(iol_frame(APP_ID, IOL_ID, 0, 0, b"ONLY-PORT0"), BRIDGE_SOCK)
            _drain(rx1)  # consume the legitimate port-0 delivery
            leaked = False
            rx2.settimeout(0.4)
            try:
                rx2.recvfrom(2048)
                leaked = True
            except socket.timeout:
                pass
            r.check("no hub flood (port-0 not on NIO-1)", not leaked, "leaked" if leaked else "clean")

            rx1.close(); rx2.close()

            # ---- PHASE 2: NIO -> IOL (now r1 is free for the injector) ----
            tx1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); tx1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); tx1.bind((HOST, r1))
            tx1.sendto(b"warmup", (HOST, l1))   # prime
            _drain(iol)
            tx1.sendto(b"WORLD", (HOST, l1))
            try:
                data, _ = iol.recvfrom(4096)
                hdr, body = data[:IOL_HDR_SIZE], data[IOL_HDR_SIZE:]
                # header ubridge must build for port 0: dst=IOL_ID, src=APP_ID,
                # dst_port=src_port=0, msg=DATA, channel=0
                expect = iol_frame(IOL_ID, APP_ID, 0, 0, b"")[:IOL_HDR_SIZE]
                r.check("NIO->IOL payload intact", body == b"WORLD", repr(body))
                r.check("NIO->IOL header correct", hdr == expect,
                        "got=%s want=%s" % (hdr.hex(), expect.hex()))
            except socket.timeout:
                r.check("NIO->IOL payload intact", False, "timeout")
                r.check("NIO->IOL header correct", False, "timeout")
            tx1.close()

            c.send("iol_bridge stop iolr")
            c.send("iol_bridge delete iolr")
        finally:
            c.close()
    iol.close()
    cleanup_iol_sock(IOL_ID)
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
