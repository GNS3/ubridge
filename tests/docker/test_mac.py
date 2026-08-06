"""Regression for `docker set_mac_addr <if> <mac>`.

Sets an interface MAC via SIOCSIFHWADDR ioctl, after validating the MAC against
a strict regex. Verified by reading /sys/class/net/<if>/address. Error paths:
bad MAC format -> 206, interface name too long -> 206, missing interface ->
206 (ioctl fails). Run under sudo (or `unshare -Urn`).
"""
from helpers import (Ubridge, Results, ubridge_binary, iface_exists, iface_mac,
                     ip_link_del, IFNAMSIZ)

PORT = 13201
A, B = "udkm0", "udkm1"


def main():
    r = Results()
    ip_link_del(A)
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # stand up a veth to set the MAC on
            assert c.code("docker create_veth %s %s" % (A, B)) == "100"
            mac = "00:11:22:33:44:55"
            r.check("set_mac_addr ok", c.code("docker set_mac_addr %s %s" % (A, mac)) == "100")
            got = iface_mac(A)
            r.check("MAC applied", got == mac.lower(), "got=%s want=%s" % (got, mac))

            # a different MAC replaces the previous one
            mac2 = "de:ad:be:ef:00:01"
            r.check("set_mac_addr replaces", c.code("docker set_mac_addr %s %s" % (A, mac2)) == "100")
            got2 = iface_mac(A)
            r.check("MAC replaced", got2 == mac2.lower(), "got=%s want=%s" % (got2, mac2))

            # ---- error paths ----
            r.check("bad MAC (non-hex) -> 206",
                    c.code("docker set_mac_addr %s zz:zz:zz:zz:zz:zz" % A) == "206")
            r.check("bad MAC (too short) -> 206",
                    c.code("docker set_mac_addr %s 00:11:22:33:44" % A) == "206")
            r.check("overlong iface name -> 206",
                    c.code("docker set_mac_addr %s %s" % ("x" * IFNAMSIZ, mac)) == "206")
            r.check("missing interface -> 206",
                    c.code("docker set_mac_addr does_not_exist %s" % mac) == "206")

            assert c.code("docker delete_veth %s" % A) == "100"
        finally:
            c.close()
    ip_link_del(A)
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
