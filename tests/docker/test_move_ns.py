"""Regression for `docker move_to_ns <if> <pid> <dst_name>`.

Moves an interface into another network namespace (identified by a PID) via
IFLA_NET_NS_PID and renames it there — the core of wiring a veth into a
container's netns. The target namespace is a child process in its own fresh
netns (`unshare -n sleep`); we verify the move with `nsenter`.

Asserts: the interface leaves the current netns, appears (renamed) inside the
target, the peer stays put; missing interface -> 206; bogus pid -> 206. Run
under sudo (or `unshare -Urn`).
"""
from helpers import Ubridge, Results, ubridge_binary, iface_exists, ip_link_del, NetnsChild

PORT = 13202
A, B = "udkn0", "udkn1"
MOVED = "udkmved"


def main():
    r = Results()
    ip_link_del(A)
    child = NetnsChild()
    with Ubridge(port=PORT, binary=ubridge_binary()) as ub:
        c = ub.connect()
        try:
            assert c.code("docker create_veth %s %s" % (A, B)) == "100"

            # ---- move A into the child netns, renamed ----
            ok = c.code("docker move_to_ns %s %d %s" % (A, child.pid, MOVED)) == "100"
            r.check("move_to_ns ok", ok)
            r.check("iface left current netns", not iface_exists(A))
            r.check("iface arrived in target netns", child.has_iface(MOVED))
            r.check("peer stayed in current netns", iface_exists(B))

            # ---- error: missing interface -> 206 ----
            r.check("move missing iface -> 206",
                    c.code("docker move_to_ns does_not_exist %d %s" % (child.pid, MOVED)) == "206")

            # ---- error: bogus pid -> 206 ----
            r.check("move to bogus pid -> 206",
                    c.code("docker move_to_ns %s 999999 %s" % (B, MOVED)) == "206")

            assert c.code("docker delete_veth %s" % B) == "100"
        finally:
            c.close()
    child.stop()   # destroys the child netns (and MOVED with it)
    ip_link_del(A)
    return 0 if r.summary() else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
