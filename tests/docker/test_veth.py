"""Regression for `docker create_veth` and `docker delete_veth`.

create_veth builds a veth pair via netlink (RTM_NEWLINK, kind=veth), brings
the first end UP, and turns off TX checksum on the second. delete_veth tears
one end down (the peer goes with it — veth semantics).

Verified via `ip link`: both ends appear, if1 is UP, duplicates are rejected
(NLM_F_EXCL -> 206), overlong names -> 206, and deleting a missing iface ->
207. Run under sudo (or `unshare -Urn`); CAP_NET_ADMIN needed.
"""
from helpers import (Ubridge, Results, ubridge_binary, iface_exists, iface_is_up,
                     ip_link_del, IFNAMSIZ)

PORT = 13200
A, B = "udkv0", "udkv1"


def main():
    r = Results()
    ip_link_del(A)  # best-effort cleanup of a stale pair
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            # ---- create: both ends exist, if1 UP ----
            ok = c.code("docker create_veth %s %s" % (A, B)) == "100"
            r.check("create_veth ok", ok)
            r.check("if1 exists", iface_exists(A))
            r.check("if2 exists", iface_exists(B))
            r.check("if1 is UP", iface_is_up(A))

            # ---- duplicate create -> 206 (NLM_F_EXCL) ----
            r.check("duplicate create_veth -> 206",
                    c.code("docker create_veth %s %s" % (A, B)) == "206")

            # ---- overlong name -> 206 (strlen >= IFNAMSIZ) ----
            long_name = "x" * IFNAMSIZ
            r.check("overlong name -> 206",
                    c.code("docker create_veth %s %s" % (long_name, B)) == "206")

            # ---- delete: both ends gone (veth pair semantics) ----
            r.check("delete_veth ok", c.code("docker delete_veth %s" % A) == "100")
            r.check("if1 gone after delete", not iface_exists(A))
            r.check("if2 gone after delete (peer)", not iface_exists(B))

            # ---- delete missing -> 207 ----
            r.check("delete missing -> 207", c.code("docker delete_veth %s" % A) == "207")
        finally:
            c.close()
    ip_link_del(A)
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
