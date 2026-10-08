"""Basic lifecycle + error-path regression for the vxlan module.

Covers create/delete/show, the create key=value surface (remote/group/dev/
dstport/ttl/learning), kernel cross-verification via `ip -d link`, and the
common error paths (duplicate create, missing device, bad VNI, bad address
classification, remote/group exclusivity). See test_boundary.py for range
edges and the bridge-attach orchestration path.
"""
from common import Ubridge, Results, kernel_vxlan_attr, no_residual


def main():
    r = Results()
    with Ubridge(port=13501) as ub:
        c = ub.connect()

        # --- lifecycle with the full parameter surface ---
        r.check("create vxt_a full params",
                c.code("vxlan create vxt_a 42 remote=127.0.0.1 dev=lo dstport=14789 ttl=64 learning=on") == "100")
        show = c.send("vxlan show vxt_a")
        r.check("show reports every field",
                all(s in show for s in
                    ("vni 42", "remote 127.0.0.1", "dev lo", "dstport 14789", "ttl 64", "learning on")),
                show)
        kern = kernel_vxlan_attr("vxt_a", "id", "remote", "dev", "dstport", "ttl")
        r.check("kernel agrees (id/remote/dev/dstport)",
                kern.get("id") == "42" and kern.get("remote") == "127.0.0.1"
                and kern.get("dev") == "lo" and kern.get("dstport") == "14789",
                str(kern))

        # --- bare create: kernel defaults visible through show ---
        r.check("create vxt_b bare", c.code("vxlan create vxt_b 7") == "100")
        show = c.send("vxlan show vxt_b")
        r.check("bare show has vni, no remote, ttl auto",
                "vni 7" in show and "remote" not in show and "ttl auto" in show,
                show)
        # The kernel's own default dstport is 8472 (pre-IANA), not 4789 —
        # pin the fact so a kernel default change is noticed here first.
        r.check("kernel default dstport is 8472",
                kernel_vxlan_attr("vxt_b", "dstport").get("dstport") == "8472")

        # creators harden their device against IPv6 link-local chatter
        # (addrgenmode none), the l2-only rule every creator applies —
        # read back through iproute2
        import shutil as _shutil
        import subprocess as _sp
        ip = _shutil.which("ip") or "/usr/sbin/ip"
        d = _sp.run([ip, "-d", "link", "show", "vxt_b"],
                    capture_output=True, text=True).stdout
        r.check("create hardens: addrgenmode none",
                "addrgenmode none" in d, d.strip()[:100])

        # --- error paths ---
        r.check("duplicate create -> 206/EEXIST",
                c.code("vxlan create vxt_a 42") == "206",
                c.send("vxlan create vxt_a 42"))
        r.check("vni 0 -> 204", c.code("vxlan create vxt_c 0") == "204")
        r.check("vni > 2^24-1 -> 204", c.code("vxlan create vxt_c 16777216") == "204")
        r.check("vni garbage -> 204", c.code("vxlan create vxt_c 12x") == "204")
        r.check("remote+group -> 204",
                c.code("vxlan create vxt_c 7 remote=1.2.3.4 group=239.1.1.1 dev=lo") == "204")
        r.check("multicast passed as remote -> 204",
                c.code("vxlan create vxt_c 7 remote=239.1.1.1") == "204")
        r.check("unicast passed as group -> 204",
                c.code("vxlan create vxt_c 7 group=1.2.3.4 dev=lo") == "204")
        r.check("bad ip -> 204", c.code("vxlan create vxt_c 7 remote=not-an-ip") == "204")
        r.check("unknown key -> 204", c.code("vxlan create vxt_c 7 frobnicate=1") == "204")
        r.check("missing = -> 204", c.code("vxlan create vxt_c 7 remote") == "204")
        r.check("learning=maybe -> 204", c.code("vxlan create vxt_c 7 learning=maybe") == "204")
        msg = c.send("vxlan create vxt_c 7 dev=nope0")
        r.check("missing dev -> 204 naming the dev",
                msg.startswith("204") and "nope0" in msg, msg)

        # --- show/delete error paths ---
        r.check("show missing -> 206", c.code("vxlan show nope0") == "206")
        r.check("show non-vxlan -> 212", c.code("vxlan show lo") == "212")
        r.check("delete missing -> 207", c.code("vxlan delete nope0") == "207")

        # --- cleanup ---
        r.check("delete vxt_a", c.code("vxlan delete vxt_a") == "100")
        r.check("delete vxt_b", c.code("vxlan delete vxt_b") == "100")
        c.close()

    r.check("no residual vxlan devices", no_residual())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
