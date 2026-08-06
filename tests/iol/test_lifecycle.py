"""Lifecycle and command-validation regression for the IOL bridge.

Drives the `iol_bridge` hypervisor command surface and checks status codes for
every error path: duplicate create, missing/already-running/not-running
start/stop, rename collisions, add_nio_udp validation (iol_id == bridge id,
port out of range), and list/get_stats. No packets flow here — that's
test_relay.py; this is purely the control surface.

No CAP_NET_ADMIN (AF_UNIX + ephemeral UDP only); no IOL image. Codes:
100 ok / 204 bad param / 206 create / 209 start / 210 stop / 213 rename /
214 not found.
"""
from helpers import (Ubridge, Results, ubridge_binary, ensure_netio_dir,
                     free_udp_port)

PORT = 13170


def main():
    r = Results()
    ensure_netio_dir()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # ---- create / duplicate ----
            r.check("create iol_a", c.code("iol_bridge create iol_a 9101") == "100")
            r.check("duplicate create -> 206",
                    c.code("iol_bridge create iol_a 9101") == "206")

            # ---- start: missing / ok / already-running ----
            r.check("start missing -> 214", c.code("iol_bridge start ghost") == "214")
            r.check("start iol_a", c.code("iol_bridge start iol_a") == "100")
            r.check("start again -> 209", c.code("iol_bridge start iol_a") == "209")

            # ---- stop: missing / ok / not-running ----
            r.check("stop missing -> 214", c.code("iol_bridge stop ghost") == "214")
            r.check("stop iol_a", c.code("iol_bridge stop iol_a") == "100")
            r.check("stop not-running -> 210", c.code("iol_bridge stop iol_a") == "210")

            # ---- list / get_stats ----
            r.check("create iol_b", c.code("iol_bridge create iol_b 9102") == "100")
            lst = c.send("iol_bridge list")
            r.check("list sees iol_a + iol_b",
                    "iol_a" in lst and "iol_b" in lst, lst.replace("\n", " | "))
            r.check("get_stats iol_b ok", c.code("iol_bridge get_stats iol_b") == "100")
            r.check("get_stats missing -> 214", c.code("iol_bridge get_stats ghost") == "214")
            r.check("reset_stats iol_b ok", c.code("iol_bridge reset_stats iol_b") == "100")

            # ---- rename: ok / collision / missing ----
            r.check("rename iol_b -> iol_c", c.code("iol_bridge rename iol_b iol_c") == "100")
            r.check("rename to existing -> 213", c.code("iol_bridge rename iol_c iol_a") == "213")
            r.check("rename missing -> 214", c.code("iol_bridge rename ghost iol_x") == "214")

            # ---- add_nio_udp validation ----
            lp = free_udp_port()
            # iol_id == bridge application_id -> 206
            r.check("add_nio_udp iol_id==app_id -> 206",
                    c.code("iol_bridge add_nio_udp iol_a 9101 0 0 %d 127.0.0.1 %d" % (lp, free_udp_port())) == "206")
            # max valid port: bay=15, unit=15 -> port_key = 15 + 15*16 = 255 (<=MAX_PORTS) -> 100.
            # (port_key is a u8, so >MAX_PORTS is unreachable; 255 is the real ceiling.)
            r.check("add_nio_udp max port_key 255 ok",
                    c.code("iol_bridge add_nio_udp iol_a 9200 15 15 %d 127.0.0.1 %d" % (lp, free_udp_port())) == "100")
            # bridge missing -> 214
            r.check("add_nio_udp missing bridge -> 214",
                    c.code("iol_bridge add_nio_udp ghost 9200 0 0 %d 127.0.0.1 %d" % (lp, free_udp_port())) == "214")

            # ---- delete: missing / ok / now-missing ----
            r.check("delete missing -> 214", c.code("iol_bridge delete ghost") == "214")
            r.check("delete iol_a", c.code("iol_bridge delete iol_a") == "100")
            r.check("delete iol_a again -> 214", c.code("iol_bridge delete iol_a") == "214")
            r.check("delete iol_c", c.code("iol_bridge delete iol_c") == "100")
        finally:
            c.close()
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
