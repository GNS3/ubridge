"""Boundary values + the bridge-attach orchestration path for the vxlan module.

Range edges (VNI, dstport, ttl, IFNAMSIZ name length), address-family cases
(IPv6 unicast remote, IPv4/IPv6 multicast group and the group-requires-dev
rule), and the dataplane attach path used by orchestration: a vxlan endpoint
enslaved to a brctl bridge, including the EBUSY-protected delete ordering.
"""
from common import Ubridge, Results, kernel_vxlan_attr, no_residual


def main():
    r = Results()
    with Ubridge(port=13502) as ub:
        c = ub.connect()

        # --- VNI range edges ---
        r.check("vni 1 accepted", c.code("vxlan create vxt_lo 1") == "100")
        r.check("vni 1 in show", "vni 1" in c.send("vxlan show vxt_lo"))
        r.check("vni max accepted", c.code("vxlan create vxt_hi 16777215") == "100")
        r.check("vni max in show", "vni 16777215" in c.send("vxlan show vxt_hi"))
        r.check("delete vxt_lo", c.code("vxlan delete vxt_lo") == "100")
        r.check("delete vxt_hi", c.code("vxlan delete vxt_hi") == "100")

        # --- dstport edges ---
        r.check("dstport 1 accepted",
                c.code("vxlan create vxt_p 5 dstport=1") == "100"
                and kernel_vxlan_attr("vxt_p", "dstport").get("dstport") == "1")
        r.check("delete vxt_p", c.code("vxlan delete vxt_p") == "100")
        r.check("dstport 65535 accepted",
                c.code("vxlan create vxt_p 5 dstport=65535") == "100"
                and kernel_vxlan_attr("vxt_p", "dstport").get("dstport") == "65535")
        r.check("delete vxt_p", c.code("vxlan delete vxt_p") == "100")
        r.check("dstport 0 -> 204", c.code("vxlan create vxt_p 5 dstport=0") == "204")
        r.check("dstport 65536 -> 204", c.code("vxlan create vxt_p 5 dstport=65536") == "204")
        r.check("dstport garbage -> 204", c.code("vxlan create vxt_p 5 dstport=go") == "204")

        # --- ttl edges ---
        r.check("ttl 255 accepted",
                c.code("vxlan create vxt_t 5 ttl=255") == "100"
                and "ttl 255" in c.send("vxlan show vxt_t"))
        r.check("delete vxt_t", c.code("vxlan delete vxt_t") == "100")
        r.check("ttl 256 -> 204", c.code("vxlan create vxt_t 5 ttl=256") == "204")

        # --- learning toggle ---
        r.check("learning off reflected",
                c.code("vxlan create vxt_l 5 learning=off") == "100"
                and "learning off" in c.send("vxlan show vxt_l"))
        r.check("delete vxt_l", c.code("vxlan delete vxt_l") == "100")

        # --- address families ---
        r.check("IPv6 unicast remote",
                c.code("vxlan create vxt_6 6 remote=::1 dev=lo") == "100"
                and "remote ::1" in c.send("vxlan show vxt_6"))
        r.check("delete vxt_6", c.code("vxlan delete vxt_6") == "100")
        r.check("IPv4 multicast group",
                c.code("vxlan create vxt_m 8 group=239.1.1.1 dev=lo") == "100"
                and "group 239.1.1.1" in c.send("vxlan show vxt_m"))
        r.check("delete vxt_m", c.code("vxlan delete vxt_m") == "100")
        r.check("group without dev -> 204",
                c.code("vxlan create vxt_m 8 group=239.1.1.1") == "204")
        r.check("IPv6 multicast group",
                c.code("vxlan create vxt_m6 9 group=ff02::1:5 dev=lo") == "100"
                and "group ff02::1:5" in c.send("vxlan show vxt_m6"))
        r.check("delete vxt_m6", c.code("vxlan delete vxt_m6") == "100")

        # --- name length: IFNAMSIZ-1 is the longest the kernel accepts ---
        import subprocess as _sp
        n15 = "v" + "x" * 13 + "5"   # 15 chars: ok
        n16 = "v" + "x" * 14 + "6"   # 16 chars: kernel rejects with EINVAL
        r.check("15-char name accepted", c.code("vxlan create %s 5" % n15) == "100")
        r.check("delete 15-char", c.code("vxlan delete %s" % n15) == "100")
        r.check("16-char name -> 206",
                c.code("vxlan create %s 5" % n16) == "206",
                c.send("vxlan create %s 5" % n16))

        # --- orchestration path: vxlan endpoint as a bridge port ---
        r.check("brctl create vxt_br", c.code("brctl create vxt_br") == "100")
        r.check("vxlan create vxt_o 99 remote=127.0.0.1 dev=lo",
                c.code("vxlan create vxt_o 99 remote=127.0.0.1 dev=lo") == "100")
        r.check("brctl addif vxt_br vxt_o", c.code("brctl addif vxt_br vxt_o") == "100")
        master = _sp.run(["ip", "-o", "link", "show", "vxt_o"],
                         capture_output=True, text=True).stdout
        r.check("kernel sees vxt_o enslaved", "master vxt_br" in master, master.strip())
        r.check("bridge delete with port -> 207",
                c.code("brctl delete vxt_br") == "207")
        # Documented contract: deleting an enslaved vxlan succeeds — the
        # kernel detaches the port on unregister (doc/vxlan.md, delete).
        r.check("vxlan delete while enslaved", c.code("vxlan delete vxt_o") == "100")
        ports = _sp.run(["ip", "-o", "link", "show", "master", "vxt_br"],
                        capture_output=True, text=True).stdout
        r.check("bridge left empty", ports.strip() == "", ports.strip())
        r.check("brctl delete vxt_br", c.code("brctl delete vxt_br") == "100")

        c.close()

    r.check("no residual vxlan devices", no_residual())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
