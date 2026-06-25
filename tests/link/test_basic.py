"""Basic lifecycle + error-path regression for the link module.

Covers link veth/addr/set/delete and common error paths. Requires
CAP_NET_ADMIN (the installed ubridge has it; the helper detects missing
privileges and skips).
"""
from helpers import (Ubridge, Results, iface_exists, link_flags,
                     has_ipv4, no_residual_link)


def main():
    r = Results()

    A = "ltest-a"
    B = "ltest-b"

    with Ubridge(port=13008) as ub:
        c = ub.connect()

        # --- veth create ---
        r.check("veth create -> 100",
                c.code("link veth %s %s" % (A, B)) == "100")
        r.check("both ends exist", iface_exists(A) and iface_exists(B))
        r.check("duplicate veth -> 206",
                c.code("link veth %s %s" % (A, B)) == "206")
        r.check("overlong name -> 204",
                c.code("link veth thisnameistoolong peer") == "204")

        # --- set up/down ---
        r.check("set up -> 100", c.code("link set %s up" % A) == "100")
        r.check("UP flag set", "UP" in link_flags(A))
        r.check("set down -> 100", c.code("link set %s down" % A) == "100")
        r.check("UP flag cleared", "UP" not in link_flags(A))
        r.check("set bad state -> 204",
                c.code("link set %s sideways" % A) == "204")
        r.check("set on missing iface -> 206",
                c.code("link set nope-xyz up") == "206")

        # --- addr ---
        r.check("addr -> 100", c.code("link addr %s 10.40.0.5/24" % A) == "100")
        r.check("kernel sees the IP", has_ipv4(A, "10.40.0.5/24"))
        # addr also brings the iface UP
        r.check("addr brings iface UP", "UP" in link_flags(A))
        r.check("addr bad cidr -> 204",
                c.code("link addr %s 1.2.3.4" % A) == "204")
        r.check("addr prefix>32 -> 204",
                c.code("link addr %s 9.9.9.9/33" % A) == "204")
        r.check("addr on missing iface -> 206",
                c.code("link addr nope-xyz 1.2.3.4/24") == "206")

        # --- delete (removes both ends of the pair) ---
        r.check("delete -> 100", c.code("link delete %s" % A) == "100")
        r.check("deleted end gone", not iface_exists(A))
        r.check("peer end also gone", not iface_exists(B))
        r.check("delete missing -> 207",
                c.code("link delete nope-xyz") == "207")
        r.check("delete no args -> 203",
                c.code("link delete") == "203")

        c.close()

    r.check("no residual interfaces", no_residual_link())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
