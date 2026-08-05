"""IOL bridge delay regression.

A naive delay-line fix only wired bridge_nios (the UDP bridge); IOL bridges
run their own filter->handler loops and would silently lose delay. This drives
the IOL bridge end-to-end — acting as a fake IOL instance over the netio
unix-domain socket — and checks delay applies in BOTH directions, plus that
teardown with delay active doesn't hang.

IOL bridge add_nio_udp: <bridge> <iol_id> <bay> <unit> <lport> <rhost> <rport>
The bridge binds /tmp/netio{uid}/{app_id}; an IOL instance lives at
/tmp/netio{uid}/{iol_id}. destination_nio is a connected UDP NIO (lport<->rport).
"""
import os
import socket
import time

from helpers import Ubridge, Results, HOST, ubridge_binary

UID = os.getuid()
NETIO_DIR = "/tmp/netio%u" % UID
APP_ID = 9001      # the IOL bridge
IOL_ID = 9002      # the fake IOL instance
BRIDGE_SOCK = "%s/%d" % (NETIO_DIR, APP_ID)
IOL_SOCK = "%s/%d" % (NETIO_DIR, IOL_ID)

LPORT, RPORT = 15010, 15011        # destination_nio: local LPORT, remote RPORT
PK = 0                             # port_key (bay=0, unit=0)


def iol_frame(dst_id, src_id, port_key, payload):
    f = bytearray(8)
    f[0], f[1] = (dst_id >> 8) & 0xff, dst_id & 0xff    # DST_IDS
    f[2], f[3] = (src_id >> 8) & 0xff, src_id & 0xff    # SRC_IDS
    f[4] = port_key & 0xff                              # DST_PORT
    f[5] = port_key & 0xff                              # SRC_PORT
    f[6] = 1                                            # MSG_TYPE = DATA
    f[7] = 0                                            # CHANNEL
    return bytes(f) + payload


def main():
    r = Results()
    # GNS3 creates /tmp/netio{uid}/; ubridge just binds into it, so make it.
    try:
        os.makedirs(NETIO_DIR, 0o777)
    except FileExistsError:
        pass

    with Ubridge(port=14900, binary=ubridge_binary()) as ub:
        c = ub.connect()
        iol = None
        try:
            # fake IOL instance unix socket
            iol = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                os.unlink(IOL_SOCK)
            except OSError:
                pass
            iol.bind(IOL_SOCK)
            iol.settimeout(5)

            assert c.code("iol_bridge create iol1 %d" % APP_ID) == "100"
            assert c.code("iol_bridge add_nio_udp iol1 %d 0 0 %d %s %d" % (IOL_ID, LPORT, HOST, RPORT)) == "100"
            assert c.code("iol_bridge add_packet_filter iol1 0 0 d1 delay 100") == "100"
            assert c.code("iol_bridge start iol1") == "100"
            time.sleep(0.3)

            # ---- IOL -> NIO direction (iol_bridge_listener) ----
            # IOL instance sends a framed packet to the bridge; bridge strips the
            # IOL header and forwards the payload out the destination NIO (UDP).
            rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rx.bind((HOST, RPORT))
            rx.settimeout(5)
            iol.sendto(iol_frame(APP_ID, IOL_ID, PK, b"warmup"), BRIDGE_SOCK)  # prime
            try:
                rx.recv(2048)
            except socket.timeout:
                pass
            t0 = time.monotonic()
            iol.sendto(iol_frame(APP_ID, IOL_ID, PK, b"ping"), BRIDGE_SOCK)
            try:
                rx.recv(2048)
                ow = (time.monotonic() - t0) * 1000
            except socket.timeout:
                ow = None
            r.check("IOL: IOL->NIO delay ~100ms",
                    ow is not None and 50 < ow < 300, "%.0fms" % (ow or -1))
            rx.close()

            # ---- NIO -> IOL direction (iol_nio_listener) ----
            # Inject into the destination NIO (source = RPORT so the connected
            # NIO accepts); bridge prepends the IOL header and sends to the
            # IOL instance socket.
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tx.bind((HOST, RPORT))
            tx.sendto(b"warmup", (HOST, LPORT))  # prime
            try:
                iol.recv(4096)
            except socket.timeout:
                pass
            t0 = time.monotonic()
            tx.sendto(b"pong", (HOST, LPORT))
            try:
                iol.recv(4096)
                ow2 = (time.monotonic() - t0) * 1000
            except socket.timeout:
                ow2 = None
            r.check("IOL: NIO->IOL delay ~100ms",
                    ow2 is not None and 50 < ow2 < 300, "%.0fms" % (ow2 or -1))
            tx.close()

            # ---- teardown with delay active doesn't hang ----
            t0 = time.monotonic()
            assert c.code("iol_bridge stop iol1") == "100"
            assert c.code("iol_bridge delete iol1") == "100"
            r.check("IOL: stop+delete with delay active < 3s",
                    (time.monotonic() - t0) < 3.0, "%.0fms" % ((time.monotonic() - t0) * 1000))
        finally:
            if iol is not None:
                iol.close()
            c.close()
            for p in (IOL_SOCK, BRIDGE_SOCK):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    return 0 if r.summary() else 1


if __name__ == "__main__":
    raise SystemExit(main())
